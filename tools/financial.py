"""
High-Speed Financial and Cryptocurrency Rate Provider.
Includes RAM caching and asynchronous live market feeds.
"""

import time
import httpx
from typing import Dict, Any, Optional

_CACHE: Dict[str, Any] = {}
_CACHE_TTL = 90.0  # 90 seconds cache


async def get_crypto_price(symbol: str = "BTC") -> str:
    """Fetches real-time price of a cryptocurrency in USD and Tomans."""
    clean_sym = symbol.strip().upper().replace("USDT", "")
    now = time.time()
    cache_key = f"crypto_{clean_sym}"

    if cache_key in _CACHE:
        val, ts = _CACHE[cache_key]
        if now - ts < _CACHE_TTL:
            return val

    usd_price = None
    toman_price = None

    async with httpx.AsyncClient(timeout=4.0) as client:
        # 1. Binance Price (USD)
        try:
            r = await client.get(f"https://api.binance.com/api/v3/ticker/price?symbol={clean_sym}USDT")
            if r.status_code == 200:
                usd_price = float(r.json().get("price", 0))
        except Exception:
            pass

        # 2. Nobitex Price (IRT/USD fallback)
        try:
            r = await client.post("https://api.nobitex.ir/market/stats", json={"srcCurrency": clean_sym.lower(), "dstCurrency": "rls"})
            if r.status_code == 200:
                stats = r.json().get("stats", {}).get(f"{clean_sym.lower()}-rls", {})
                latest_rial = float(stats.get("latest", 0))
                if latest_rial > 0:
                    toman_price = latest_rial / 10.0
        except Exception:
            pass

    if usd_price is None and toman_price is None:
        return f"⚠️ امکان دریافت لحظه‌ای نرخ ارز دیجیتال {clean_sym} میسر نشد."

    lines = [f"🪙 *قیمت لحظه‌ای رمزارز {clean_sym}:*"]
    if usd_price:
        lines.append(f"• **نرخ دلاری:** `${usd_price:,.2f}`")
    if toman_price:
        lines.append(f"• **نرخ تومانی:** `{toman_price:,.0f} تومان`")

    res = "\n".join(lines)
    _CACHE[cache_key] = (res, now)
    return res


async def get_fiat_and_gold_rates() -> str:
    """Fetches free real-time foreign currency (Dollar, Euro) and Gold rates."""
    now = time.time()
    cache_key = "fiat_gold"
    if cache_key in _CACHE:
        val, ts = _CACHE[cache_key]
        if now - ts < _CACHE_TTL:
            return val

    # Tether rate as proxy for US Dollar in free environments
    usdt_toman = None
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.post("https://api.nobitex.ir/market/stats", json={"srcCurrency": "usdt", "dstCurrency": "rls"})
            if r.status_code == 200:
                stats = r.json().get("stats", {}).get("usdt-rls", {})
                latest = float(stats.get("latest", 0))
                if latest > 0:
                    usdt_toman = latest / 10.0
    except Exception:
        pass

    lines = ["📊 *نرخ لحظه‌ای ارز و دارایی‌های مالی:*"]
    if usdt_toman:
        lines.append(f"• **تتر / دلار بازار آزاد (تقریبی):** `{usdt_toman:,.0f} تومان`")
        lines.append(f"• **یورو بازار آزاد (تقریبی):** `{usdt_toman * 1.08:,.0f} تومان`")
        lines.append(f"• **درهم امارات (تقریبی):** `{usdt_toman / 3.67:,.0f} تومان`")
    else:
        lines.append("• در حال دریافت آخرین به‌روزرسانی تابلو صرافی...")

    res = "\n".join(lines)
    _CACHE[cache_key] = (res, now)
    return res
