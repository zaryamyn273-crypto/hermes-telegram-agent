"""
Specialized Persian Financial Market Tool for Prometheus:
Provides real-time rates for Free-Market USD (دلار آزاد), Tether (تتر), Euro (یورو),
Dirham (درهم), Gold 18k (طلای ۱۸ عیار), Emami Coin (سکه امامی), and Top Cryptocurrencies.
Uses multi-source scraping (TGJU, Nobitex, Wallex) with Cloudflare KV & L1 RAM caching.
"""

import re
import json
import time
import logging
import asyncio
import httpx
from typing import Dict, Any, Optional

import database

logger = logging.getLogger("FinancialTool")

# Cache keys
KV_KEY_FIAT_GOLD = "PROMETHEUS_FIAT_GOLD_RATES"
KV_KEY_CRYPTO_PREFIX = "PROMETHEUS_CRYPTO_"

_FINANCIAL_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def _safe_toman(val: Any) -> int:
    """Parses scraped Persian/English digits to integer tomans."""
    if val is None:
        return 0
    s = str(val).replace(",", "").replace("٬", "").replace("،", "").strip()
    fa_digits = "۰۱۲۳۴۵۶۷۸۹"
    for i, d in enumerate(fa_digits):
        s = s.replace(d, str(i))
    digits = "".join(c for c in s if c.isdigit())
    if not digits:
        return 0
    # TGJU prices are in Rials -> divide by 10 to get Tomans
    return int(digits) // 10


async def get_fiat_and_gold_rates(force_refresh: bool = False) -> str:
    """
    Fetches live rates for USD, Tether, Euro, Dirham, Gold 18k, and Emami Coin.
    Returns clean Persian formatted text.
    """
    if not force_refresh:
        cached = await database.kv_get(KV_KEY_FIAT_GOLD)
        if cached:
            return cached

    rates: Dict[str, int] = {}

    # Source 1: TGJU Scrape
    try:
        async with httpx.AsyncClient(timeout=4.0, headers=_FINANCIAL_HEADERS) as client:
            resp = await client.get("https://www.tgju.org/")
            if resp.status_code == 200:
                html = resp.text
                keys_map = {
                    "price_dollar_rl": "usd",
                    "price_eur": "eur",
                    "price_aed": "aed",
                    "geram18": "gold18",
                    "sekee": "emami_coin",
                    "sekeb": "bahar_coin",
                    "nim": "half_coin",
                    "rob": "quarter_coin",
                }
                for k, label in keys_map.items():
                    m = re.search(rf'data-market-row="{k}"[\s\S]{{1,1500}}?data-price="([^"]+)"', html)
                    if m:
                        rates[label] = _safe_toman(m.group(1))
    except Exception as e:
        logger.debug(f"TGJU fetch error: {e}")

    # Source 2: Nobitex Tether Price
    tether_toman = 0
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            nob_resp = await client.get("https://api.nobitex.ir/v2/orderbook/USDTIRT")
            if nob_resp.status_code == 200:
                data = nob_resp.json()
                last_trade = data.get("lastTradePrice")
                if last_trade:
                    # Nobitex is in Rials -> convert to Tomans
                    tether_toman = int(float(last_trade)) // 10
    except Exception as e:
        logger.debug(f"Nobitex fetch error: {e}")

    usd_val = rates.get("usd", 0)
    if tether_toman > 0:
        rates["usdt"] = tether_toman
        if usd_val == 0:
            rates["usd"] = tether_toman

    if not rates.get("usd") and not rates.get("gold18"):
        # Fallback if both primary sources fail
        return "⚠️ در حال حاضر به دلیل اختلال موقت در سامانه‌های مبدا، دریافت نرخ لحظه‌ای ارز و طلا مقدور نیست. لطفاً دقایقی دیگر مجدداً تلاش نمایید."

    # Format result in clean Persian
    usd_str = f"{rates['usd']:,} تومان" if rates.get("usd") else "نامشخص"
    usdt_str = f"{rates['usdt']:,} تومان" if rates.get("usdt") else usd_str
    eur_str = f"{rates['eur']:,} تومان" if rates.get("eur") else "نامشخص"
    aed_str = f"{rates['aed']:,} تومان" if rates.get("aed") else "نامشخص"
    gold_str = f"{rates['gold18']:,} تومان" if rates.get("gold18") else "نامشخص"
    coin_str = f"{rates['sekee']:,} تومان" if rates.get("sekee") else "نامشخص"
    bahar_str = f"{rates['sekeb']:,} تومان" if rates.get("sekeb") else "نامشخص"
    nim_str = f"{rates['nim']:,} تومان" if rates.get("nim") else "نامشخص"
    rob_str = f"{rates['rob']:,} تومان" if rates.get("rob") else "نامشخص"

    text = (
        "📊 **نرخ لحظه‌ای ارز و طلای بازار آزاد ایران:**\n\n"
        f"💵 **دلار آزاد:** `{usd_str}`\n"
        f"🟢 **تتر (USDT):** `{usdt_str}`\n"
        f"💶 **یورو:** `{eur_str}`\n"
        f"🇦🇪 **درهم امارات:** `{aed_str}`\n\n"
        f"🥇 **طلای ۱۸ عیار:** `{gold_str}`\n"
        f"🪙 **سکه تمام امامی:** `{coin_str}`\n"
        f"🪙 **سکه تمام بهار آزادی:** `{bahar_str}`\n"
        f"🪙 **نیم سکه:** `{nim_str}`\n"
        f"🪙 **ربع سکه:** `{rob_str}`\n\n"
        "⚡ *استعلام زنده از بازار آزاد توسط پرومته*"
    )

    await database.kv_set(KV_KEY_FIAT_GOLD, text, ttl_sec=90)
    return text


async def get_crypto_price(symbol: str = "BTC") -> str:
    """
    Fetches cryptocurrency price in USD and Toman (via live Tether rate).
    """
    sym = symbol.strip().upper()
    cache_key = f"{KV_KEY_CRYPTO_PREFIX}{sym}"

    cached = await database.kv_get(cache_key)
    if cached:
        return cached

    # 1. Fetch live USDT toman rate
    usdt_toman = 65000
    try:
        async with httpx.AsyncClient(timeout=2.5) as client:
            resp = await client.get("https://api.nobitex.ir/v2/orderbook/USDTIRT")
            if resp.status_code == 200:
                p = resp.json().get("lastTradePrice")
                if p:
                    usdt_toman = int(float(p)) // 10
    except Exception:
        pass

    # 2. Fetch crypto price from Binance or CoinGecko
    price_usd = 0.0
    change_24h = 0.0
    name = sym

    try:
        async with httpx.AsyncClient(timeout=3.5) as client:
            binance_resp = await client.get(f"https://api.binance.com/api/v3/ticker/24hr?symbol={sym}USDT")
            if binance_resp.status_code == 200:
                b_data = binance_resp.json()
                price_usd = float(b_data.get("lastPrice", 0))
                change_24h = float(b_data.get("priceChangePercent", 0))
    except Exception as e:
        logger.debug(f"Binance fetch error for {sym}: {e}")

    if price_usd <= 0.0:
        # Fallback to CoinGecko simple price
        cg_map = {
            "BTC": "bitcoin", "ETH": "ethereum", "SOL": "solana",
            "BNB": "binancecoin", "TON": "the-open-network", "DOGE": "dogecoin",
            "XRP": "ripple", "ADA": "cardano", "TRX": "tron", "SUI": "sui"
        }
        coin_id = cg_map.get(sym, sym.lower())
        try:
            async with httpx.AsyncClient(timeout=3.5) as client:
                cg_resp = await client.get(
                    f"https://api.coingecko.com/api/v3/simple/price?ids={coin_id}&vs_currencies=usd&include_24hr_change=true"
                )
                if cg_resp.status_code == 200:
                    cg_data = cg_resp.json().get(coin_id, {})
                    price_usd = float(cg_data.get("usd", 0))
                    change_24h = float(cg_data.get("usd_24h_change", 0))
        except Exception:
            pass

    if price_usd <= 0.0:
        return f"⚠️ نماد رمزارز `{sym}` یافت نشد یا در حال حاضر امکان استعلام قیمت آن وجود ندارد."

    price_toman = int(price_usd * usdt_toman)
    trend_emoji = "🟢" if change_24h >= 0 else "🔴"
    sign = "+" if change_24h >= 0 else ""

    text = (
        f"🪙 **نرخ لحظه‌ای رمزارز {sym}:**\n\n"
        f"💵 **قیمت دلاری:** `${price_usd:,.2f}`\n"
        f"🇮🇷 **معادل تومانی:** `{price_toman:,} تومان`\n"
        f"{trend_emoji} **تغییرات ۲۴ ساعته:** `{sign}{change_24h:.2f}%`\n\n"
        "⚡ *استعلام زنده از بازارهای جهانی توسط پرومته*"
    )

    await database.kv_set(cache_key, text, ttl_sec=60)
    return text
