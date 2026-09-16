"""
Specialized Digikala E-Commerce Tool for Prometheus:
Provides real-time product search, pricing, stock status, ratings,
and direct purchase links from Digikala API with multi-tier L1 RAM and Cloudflare KV caching.
"""

import urllib.parse
import re
import logging
import asyncio
import httpx
from typing import Dict, Any, List, Optional

import database

logger = logging.getLogger("EcommerceTool")

KV_KEY_DIGIKALA_PREFIX = "PROMETHEUS_DIGIKALA_"

_DIGIKALA_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Referer": "https://www.digikala.com/",
    "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7"
}


def clean_digikala_query(query: str) -> str:
    """Removes noise words from product search query."""
    cleaned = (query or "").strip()
    noise_words = [
        "قیمت", "نرخ", "خرید", "فروش", "دیجیکالا", "دیجی کالا", "digikala",
        "چنده", "چند است", "مشخصات", "ارزان ترین", "بهترین", "اصل", "اورجینال",
        "رو چک کن", "چک کن", "استعلام", "ببین", "لطفا", "لطفاً", "از", "در"
    ]
    for w in noise_words:
        cleaned = re.sub(rf"\b{re.escape(w)}\b", " ", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned if len(cleaned) >= 2 else (query or "").strip()


async def search_digikala(query: str, max_results: int = 4) -> str:
    """
    Searches Digikala for products and returns formatted Persian markdown summary.
    """
    raw_q = (query or "").strip()
    if not raw_q:
        return "⚠️ لطفاً نام یا مدل کالای مورد نظر برای استعلام در دیجی‌کالا را وارد نمایید."

    clean_q = clean_digikala_query(raw_q)
    cache_key = f"{KV_KEY_DIGIKALA_PREFIX}{clean_q.lower().replace(' ', '_')}"

    cached = await database.kv_get(cache_key)
    if cached:
        return cached

    endpoints = [
        f"https://api.digikala.com/v1/search/?q={urllib.parse.quote(clean_q)}",
        f"https://api.digikala.com/v2/search/?q={urllib.parse.quote(clean_q)}",
    ]

    products = []
    try:
        async with httpx.AsyncClient(headers=_DIGIKALA_HEADERS, timeout=6.0, follow_redirects=True) as client:
            for ep in endpoints:
                try:
                    resp = await client.get(ep)
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        p_list = data.get("products", [])
                        if p_list:
                            products = p_list
                            break
                except Exception:
                    continue
    except Exception as e:
        logger.debug(f"Digikala client error: {e}")

    if not products:
        return f"🔍 کالایی با عنوان «{clean_q}» در دیجی‌کالا یافت نشد یا در دسترس نیست."

    lines = [f"🛍 **نتایج استعلام زنده دیجی‌کالا برای «{clean_q}»:**\n"]
    count = 0

    for p in products:
        if count >= max_results:
            break
        pid = p.get("id")
        if not pid:
            continue
        title = (p.get("title_fa") or p.get("title_en") or "محصول").strip()
        url = f"https://www.digikala.com/product/dkp-{pid}"

        variant = p.get("default_variant") or {}
        price_info = variant.get("price") or {}
        rrp_price = price_info.get("rrp_price", 0)  # Rials
        selling_price = price_info.get("selling_price", 0)  # Rials
        discount_pct = price_info.get("discount_percent", 0)

        # Convert Rials to Tomans
        selling_toman = selling_price // 10 if selling_price else 0
        rrp_toman = rrp_price // 10 if rrp_price else 0

        rating_info = p.get("rating") or {}
        rate_val = rating_info.get("rate")
        rate_count = rating_info.get("count", 0)

        seller_info = variant.get("seller") or {}
        seller_name = seller_info.get("title", "دیجی‌کالا")

        line = f"• [{title}]({url})\n"
        if selling_toman > 0:
            line += f"  💰 **قیمت:** `{selling_toman:,} تومان`"
            if discount_pct > 0 and rrp_toman > selling_toman:
                line += f" (🔥 تخفیف: `{discount_pct}%` | قبل: ~`{rrp_toman:,}`~)"
            line += "\n"
        else:
            line += "  💰 **وضعیت:** `ناموجود / در حال تأمین`\n"

        if rate_val:
            line += f"  ⭐ **امتیاز:** `{rate_val} از ۵` ({rate_count:,} نظر)\n"
        line += f"  🏪 **فروشنده:** {seller_name}\n"

        lines.append(line)
        count += 1

    lines.append("⚡ *استعلام زنده از دیجی‌کالا توسط پرومته*")
    result_text = "\n".join(lines)

    await database.kv_set(cache_key, result_text, ttl_sec=600)
    return result_text
