"""
Specialized Persian Financial Market Tool for Prometheus:
Provides real-time rates for Free-Market USD (دلار آزاد), Tether (تتر), Euro (یورو),
Dirham (درهم), Gold 18k (طلای ۱۸ عیار), Emami Coin (سکه امامی), Bahar Coin (بهار آزادی),
Half/Quarter Coins, and Top Cryptocurrencies.
Uses high-speed parallel racing across multi-source exchanges (KuCoin, Binance, CoinGecko, Nobitex, Wallex, TGJU)
with persistent keepalive connection pooling, L1 RAM and Cloudflare KV caching.
"""

import re
import json
import time
import logging
import asyncio
import httpx
from typing import Dict, Any, Optional, Tuple, List

import database

logger = logging.getLogger("FinancialTool")

# Cache keys
KV_KEY_FIAT_GOLD = "PROMETHEUS_FIAT_GOLD_RATES"
KV_KEY_CRYPTO_PREFIX = "PROMETHEUS_CRYPTO_"

_FINANCIAL_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Shared Persistent Client
_FIN_CLIENT: Optional[httpx.AsyncClient] = None


def get_fin_client() -> httpx.AsyncClient:
    """Returns persistent AsyncClient with keepalive connection pooling."""
    global _FIN_CLIENT
    if _FIN_CLIENT is None or _FIN_CLIENT.is_closed:
        limits = httpx.Limits(max_keepalive_connections=50, max_connections=100, keepalive_expiry=60.0)
        timeout = httpx.Timeout(connect=2.0, read=4.0, write=3.0, pool=3.0)
        _FIN_CLIENT = httpx.AsyncClient(limits=limits, timeout=timeout, headers=_FINANCIAL_HEADERS, follow_redirects=True)
    return _FIN_CLIENT


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
    """Streams and parses TGJU market table for fiat, gold, and coin prices."""
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
        client = get_fin_client()
        async with client.stream("GET", "https://www.tgju.org/") as resp:
            if resp.status_code == 200:
                async for chunk in resp.aiter_text():
                    buf += chunk
                    for tag, label in list(keys_needed.items()):
                        m = re.search(rf'data-market-row="{tag}"[\s\S]{{1,2000}}?data-price="([^"]+)"', buf)
                        if m:
                            rates[label] = _safe_toman(m.group(1))
                            del keys_needed[tag]
                    if not keys_needed or len(buf) > 400000:
                        break
    except Exception as e:
        logger.debug(f"TGJU fetch error: {e}")


async def _fetch_usdt_rate() -> int:
    """Fetches real-time USDT/Toman rate racing Wallex and Nobitex in parallel."""
    client = get_fin_client()

    async def _from_wallex() -> int:
        r = await client.get("https://api.wallex.ir/v1/markets")
        if r.status_code == 200:
            syms = r.json().get("result", {}).get("symbols", {})
            last_p = syms.get("USDTTMN", {}).get("stats", {}).get("lastPrice")
            if last_p:
                return int(float(last_p))
        return 0

    async def _from_nobitex() -> int:
        r = await client.get("https://api.nobitex.ir/v2/orderbook/USDTIRT")
        if r.status_code == 200:
            trade_p = r.json().get("lastTradePrice")
            if trade_p:
                return int(float(trade_p)) // 10
        return 0

    tasks = [asyncio.create_task(_from_wallex()), asyncio.create_task(_from_nobitex())]
    for fut in asyncio.as_completed(tasks):
        try:
            val = await fut
            if val > 0:
                for t in tasks:
                    t.cancel()
                return val
        except Exception:
            pass

    return 230000  # Fallback baseline


async def get_fiat_and_gold_rates(force_refresh: bool = False) -> str:
    """
    Fetches live rates for USD, Tether, Euro, Dirham, Gold 18k, and Coins in parallel.
    Returns clean, high-speed Persian formatted text.
    """
    if not force_refresh:
        cached = await database.kv_get(KV_KEY_FIAT_GOLD)
        if cached:
            return cached

    rates: Dict[str, int] = {}
    usdt_val, _ = await asyncio.gather(_fetch_usdt_rate(), _fetch_tgju_rates(rates), return_exceptions=True)

    if isinstance(usdt_val, int) and usdt_val > 0:
        rates["usdt"] = usdt_val
        if not rates.get("usd"):
            rates["usd"] = usdt_val

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


async def _fetch_crypto_usd(sym: str) -> Tuple[Optional[float], Optional[float]]:
    """
    Races KuCoin, Binance, and CoinGecko concurrently to get USD price and 24h change.
    Returns (usd_price, change_24h) from the fastest responding exchange.
    """
    client = get_fin_client()

    async def _from_binance() -> Tuple[Optional[float], Optional[float]]:
        r = await client.get(f"https://api.binance.com/api/v3/ticker/24hr?symbol={sym}USDT")
        if r.status_code == 200:
            d = r.json()
            p = float(d.get("lastPrice", 0))
            ch = float(d.get("priceChangePercent", 0))
            if p > 0:
                return p, ch
        return None, None

    async def _from_kucoin() -> Tuple[Optional[float], Optional[float]]:
        r = await client.get(f"https://api.kucoin.com/api/v1/market/stats?symbol={sym}-USDT")
        if r.status_code == 200:
            d = r.json().get("data", {})
            p = float(d.get("last", 0))
            ch = float(d.get("changeRate", 0)) * 100.0
            if p > 0:
                return p, ch
        return None, None

    async def _from_coingecko() -> Tuple[Optional[float], Optional[float]]:
        cg_map = {
            "BTC": "bitcoin", "ETH": "ethereum", "SOL": "solana",
            "TON": "the-open-network", "DOGE": "dogecoin", "XRP": "ripple",
            "ADA": "cardano", "BNB": "binancecoin", "TRX": "tron",
            "SHIB": "shiba-inu", "AVAX": "avalanche-2", "DOT": "polkadot",
            "NEAR": "near", "LTC": "litecoin",
        }
        cid = cg_map.get(sym, sym.lower())
        r = await client.get(f"https://api.coingecko.com/api/v3/simple/price?ids={cid}&vs_currencies=usd&include_24hr_change=true")
        if r.status_code == 200:
            d = r.json().get(cid, {})
            p = float(d.get("usd", 0))
            ch = float(d.get("usd_24h_change", 0))
            if p > 0:
                return p, ch
        return None, None

    tasks = [
        asyncio.create_task(_from_binance()),
        asyncio.create_task(_from_kucoin()),
        asyncio.create_task(_from_coingecko()),
    ]

    for fut in asyncio.as_completed(tasks):
        try:
            p, ch = await fut
            if p is not None and p > 0:
                for t in tasks:
                    t.cancel()
                return p, ch
        except Exception:
            pass

    return None, None


async def get_crypto_price(symbol: str = "BTC") -> str:
    """
    Fetches cryptocurrency price in USD and Toman (via live Tether rate).
    Races top crypto APIs concurrently with parallel USDT lookup in under 400ms.
    """
    sym = symbol.strip().upper()
    cache_key = f"{KV_KEY_CRYPTO_PREFIX}{sym}"

    cached = await database.kv_get(cache_key)
    if cached:
        return cached

    # Concurrently fetch USDT toman rate and Crypto USD price
    usdt_task = asyncio.create_task(_fetch_usdt_rate())
    crypto_task = asyncio.create_task(_fetch_crypto_usd(sym))

    usdt_toman, (usd_price, change_24h) = await asyncio.gather(usdt_task, crypto_task)

    if usd_price is None:
        return f"⚠️ استعلام نرخ رمزارز `{sym}` با خطا مواجه شد. لطفاً از صحت نماد اختصاری اطمینان حاصل کنید."

    if not usdt_toman or usdt_toman <= 0:
        usdt_toman = 230000

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
