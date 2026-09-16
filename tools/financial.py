"""
Specialized Persian Financial Market Tool for Prometheus:
Provides real-time rates for Free-Market USD (دلار آزاد), Tether (تتر), Euro (یورو),
Dirham (درهم), Gold 18k (طلای ۱۸ عیار), Emami Coin (سکه امامی), Bahar Coin (بهار آزادی),
Half/Quarter Coins, and Top Cryptocurrencies.
Uses multi-source resilient scraping (TGJU, Wallex, Nobitex, KuCoin, CoinGecko)
with Cloudflare KV & L1 RAM caching.
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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
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


async def _fetch_tgju_rates(rates: Dict[str, int]):
    keys_needed = {
        "price_dollar_rl": "usd",
        "price_eur": "eur",
        "price_aed": "aed",
        "geram18": "gold18",
        "sekee": "emami_coin",
        "sekeb": "bahar_coin",
        "nim": "half_coin",
        "rob": "quarter_coin",
    }
    buf = ""
    try:
        async with httpx.AsyncClient(headers=_FINANCIAL_HEADERS, timeout=5.0, follow_redirects=True) as client:
            async with client.stream("GET", "https://www.tgju.org/") as resp:
                if resp.status_code == 200:
                    async for chunk in resp.aiter_text():
                        buf += chunk
                        for tag, label in list(keys_needed.items()):
                            m = re.search(rf'data-market-row="{tag}"[\s\S]{{1,1500}}?data-price="([^"]+)"', buf)
                            if m:
                                rates[label] = _safe_toman(m.group(1))
                                del keys_needed[tag]
                        if not keys_needed or len(buf) > 350000:
                            break
    except Exception as e:
        logger.debug(f"TGJU fetch error: {e}")


async def _fetch_usdt_rate() -> int:
    try:
        async with httpx.AsyncClient(timeout=3.0, headers=_FINANCIAL_HEADERS) as client:
            wallex_resp = await client.get("https://api.wallex.ir/v1/markets")
            if wallex_resp.status_code == 200:
                data = wallex_resp.json()
                usdt_market = data.get("result", {}).get("symbols", {}).get("USDTTMN", {})
                last_p = usdt_market.get("stats", {}).get("lastPrice")
                if last_p:
                    return int(float(last_p))
    except Exception as e:
        logger.debug(f"Wallex fetch error: {e}")

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            nob_resp = await client.get("https://api.nobitex.ir/v2/orderbook/USDTIRT")
            if nob_resp.status_code == 200:
                data = nob_resp.json()
                last_trade = data.get("lastTradePrice")
                if last_trade:
                    return int(float(last_trade)) // 10
    except Exception as e:
        logger.debug(f"Nobitex fetch error: {e}")

    return 0


async def get_fiat_and_gold_rates(force_refresh: bool = False) -> str:
    """
    Fetches live rates for USD, Tether, Euro, Dirham, Gold 18k, and Coins.
    Returns clean Persian formatted text.
    """
    if not force_refresh:
        cached = await database.kv_get(KV_KEY_FIAT_GOLD)
        if cached:
            return cached

    rates: Dict[str, int] = {}
    tether_toman, _ = await asyncio.gather(_fetch_usdt_rate(), _fetch_tgju_rates(rates), return_exceptions=True)

    if tether_toman > 0:
        rates["usdt"] = tether_toman
        if not rates.get("usd"):
            rates["usd"] = tether_toman

    if not rates.get("usd") and not rates.get("gold18") and not rates.get("usdt"):
        return "⚠️ در حال حاضر به دلیل اختلال موقت در سامانه‌های مبدا، دریافت نرخ لحظه‌ای ارز و طلا مقدور نیست. لطفاً دقایقی دیگر مجدداً تلاش نمایید."

    # Format result in clean Persian
    usd_str = f"{rates['usd']:,} تومان" if rates.get("usd") else "نامشخص"
    usdt_str = f"{rates['usdt']:,} تومان" if rates.get("usdt") else usd_str
    eur_str = f"{rates['eur']:,} تومان" if rates.get("eur") else "نامشخص"
    aed_str = f"{rates['aed']:,} تومان" if rates.get("aed") else "نامشخص"
    gold_str = f"{rates['gold18']:,} تومان" if rates.get("gold18") else "نامشخص"
    coin_str = f"{rates['emami_coin']:,} تومان" if rates.get("emami_coin") else "نامشخص"
    bahar_str = f"{rates['bahar_coin']:,} تومان" if rates.get("bahar_coin") else "نامشخص"
    nim_str = f"{rates['half_coin']:,} تومان" if rates.get("half_coin") else "نامشخص"
    rob_str = f"{rates['quarter_coin']:,} تومان" if rates.get("quarter_coin") else "نامشخص"

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
    Supports KuCoin, Binance, and CoinGecko with multi-tier failover.
    """
    sym = symbol.strip().upper()
    cache_key = f"{KV_KEY_CRYPTO_PREFIX}{sym}"

    cached = await database.kv_get(cache_key)
    if cached:
        return cached

    # 1. Fetch live USDT toman rate
    usdt_toman = 75000
    try:
        # Check Wallex
        async with httpx.AsyncClient(timeout=3.0, headers=_FINANCIAL_HEADERS) as client:
            wallex_resp = await client.get("https://api.wallex.ir/v1/markets")
            if wallex_resp.status_code == 200:
                data = wallex_resp.json()
                usdt_market = data.get("result", {}).get("symbols", {}).get("USDTTMN", {})
                last_p = usdt_market.get("stats", {}).get("lastPrice")
                if last_p:
                    usdt_toman = int(float(last_p))
    except Exception:
        pass

    usd_price: Optional[float] = None
    change_24h: Optional[float] = None

    # 2. Source A: KuCoin API (Fast, no geoblock)
    try:
        async with httpx.AsyncClient(timeout=4.0, headers=_FINANCIAL_HEADERS) as client:
            resp = await client.get(f"https://api.kucoin.com/api/v1/market/orderbook/level1?symbol={sym}-USDT")
            if resp.status_code == 200:
                data = resp.json()
                p = data.get("data", {}).get("price")
                if p:
                    usd_price = float(p)
    except Exception as e:
        logger.debug(f"KuCoin fetch error for {sym}: {e}")

    # 3. Source B: CoinGecko Fallback
    if usd_price is None:
        coingecko_id_map = {
            "BTC": "bitcoin",
            "ETH": "ethereum",
            "SOL": "solana",
            "TON": "the-open-network",
            "DOGE": "dogecoin",
            "XRP": "ripple",
            "ADA": "cardano",
            "BNB": "binancecoin",
            "TRX": "tron",
            "SHIB": "shiba-inu",
            "AVAX": "avalanche-2",
            "DOT": "polkadot",
            "NEAR": "near",
            "LTC": "litecoin",
        }
        cg_id = coingecko_id_map.get(sym, sym.lower())
        try:
            async with httpx.AsyncClient(timeout=4.0, headers=_FINANCIAL_HEADERS) as client:
                cg_url = f"https://api.coingecko.com/api/v3/simple/price?ids={cg_id}&vs_currencies=usd&include_24hr_change=true"
                resp = await client.get(cg_url)
                if resp.status_code == 200:
                    data = resp.json().get(cg_id, {})
                    if "usd" in data:
                        usd_price = float(data["usd"])
                        change_24h = data.get("usd_24h_change")
        except Exception as e:
            logger.debug(f"CoinGecko fetch error for {sym}: {e}")

    # 4. Source C: Binance Fallback
    if usd_price is None:
        try:
            async with httpx.AsyncClient(timeout=3.0, headers=_FINANCIAL_HEADERS) as client:
                resp = await client.get(f"https://api.binance.com/api/v3/ticker/price?symbol={sym}USDT")
                if resp.status_code == 200:
                    data = resp.json()
                    usd_price = float(data["price"])
        except Exception:
            pass

    if usd_price is None:
        return f"⚠️ استعلام نرخ رمزارز `{sym}` با خطا مواجه شد. لطفاً از صحت نماد اختصاری اطمینان حاصل کنید."

    toman_price = int(usd_price * usdt_toman)
    formatted_usd = f"${usd_price:,.4f}" if usd_price < 1.0 else f"${usd_price:,.2f}"
    formatted_toman = f"{toman_price:,} تومان"

    change_str = ""
    if change_24h is not None:
        sign = "+" if change_24h > 0 else ""
        icon = "🟢" if change_24h >= 0 else "🔴"
        change_str = f"\n{icon} **تغییرات ۲۴ ساعته:** `{sign}{change_24h:.2f}%`"

    text = (
        f"🪙 **نرخ لحظه‌ای رمزارز {sym}:**\n\n"
        f"💵 **قیمت دلاری:** `{formatted_usd}`\n"
        f"🇮🇷 **معادل تومانی:** `{formatted_toman}`"
        f"{change_str}\n\n"
        f"⚡ *استعلام زنده توسط پرومته (محاسبه بر مبنای تتر {usdt_toman:,} تومان)*"
    )

    await database.kv_set(cache_key, text, ttl_sec=60)
    return text
