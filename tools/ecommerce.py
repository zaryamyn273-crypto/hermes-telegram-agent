"""
Specialized Digikala E-Commerce Tool for Prometheus:
Provides real-time product search, pricing, stock status, ratings,
and direct purchase links from Digikala API with persistent keepalive connection pooling,
multi-tier L1 RAM, and Cloudflare KV caching.
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

_DK_CLIENT: Optional[httpx.AsyncClient] = None


def get_digikala_client() -> httpx.AsyncClient:
    """Returns shared AsyncClient with cookie jar and keepalive connection pooling."""
    global _DK_CLIENT
    if _DK_CLIENT is None or _DK_CLIENT.is_closed:
        limits = httpx.Limits(max_keepalive_connections=20, max_connections=40, keepalive_expiry=60.0)
        timeout = httpx.Timeout(connect=2.0, read=3.8, write=2.0, pool=2.0)
        _DK_CLIENT = httpx.AsyncClient(limits=limits, timeout=timeout, headers=_DIGIKALA_HEADERS, follow_redirects=True)
    return _DK_CLIENT


def clean_digikala_query(query: str) -> str:
    """Removes conversational noise words, prepositions, and Digikala brand mentions from product search query."""
    cleaned = (query or "").strip()
    # Normalize ZWNJ to spaces
    cleaned = cleaned.replace("\u200c", " ")

    # Remove Digikala brand variations
    cleaned = re.sub(r"(?i)\b(?:digikala)\b", " ", cleaned)
    cleaned = re.sub(r"دیجی\s*کالا|دیجیکالا", " ", cleaned)

    # Conversational and action phrases to strip
    noise_phrases = [
        r"رو\s+چک\s+کن", r"چک\s+کن", r"سرچ\s+کن", r"جستجو\s+کن", r"پیدا\s+کن",
        r"رو\s+بیار", r"رو\s+ببین", r"نشون\s+بده", r"استعلام\s+کن", r"قیمت\s+بگیر",
        r"قیمت\s+در\s*بیار", r"بگرد\s+دنبال", r"بگرد", r"ارزان\s*ترین", r"ارزون\s*ترین",
        r"بهترین", r"جدیدترین", r"اصل", r"اورجینال", r"مشخصات", r"رو\s+بگو",
        r"چند\s+تومنه", r"چند\s+تومن", r"چند\s+است", r"چند\s+شد", r"چنده", r"چند",
        r"قیمت", r"نرخ", r"خرید", r"فروش", r"استعلام", r"سرچ", r"جستجوی", r"جستجو",
        r"محصولات", r"کالاهای", r"کالای", r"محصول", r"کالا", r"لینک",
        r"لطفا", r"لطفاً", r"بی\s*زحمت", r"دمت\s*گرم", r"ممنون", r"ببینم", r"ببین",
    ]
    for np in noise_phrases:
        cleaned = re.sub(rf"(?<!\w){np}(?!\w)", " ", cleaned, flags=re.IGNORECASE)

    # Remove leading/trailing prepositions and connector particles
    connector_pattern = r"^(?:در|از|توی|تویِ|برای|واسه|رو|را|به)\s+|\s+(?:در|از|توی|برای|واسه|رو|را)$"
    for _ in range(3):
        cleaned = re.sub(connector_pattern, " ", cleaned.strip(), flags=re.IGNORECASE).strip()

    cleaned = re.sub(r"[^\w\s\u0600-\u06FF\d\.\-\+]", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" :،,.-")
    return cleaned if len(cleaned) >= 2 else (query or "").strip()


async def search_digikala(query: str, max_results: int = 4) -> str:
    """
    Searches Digikala for products and returns formatted Persian markdown summary.
    Employs persistent keepalive connection pooling and multi-tier caching (RAM + KV).
    """
    raw_q = (query or "").strip()
    if not raw_q:
        return (
            "ℹ️ لطفاً نام یا مدل کالای مورد نظر برای استعلام در دیجی‌کالا را وارد نمایید.\n"
            "مثال: `/digikala آیفون 16` یا `دیجیکالا لپ تاپ ایسوس`"
        )

    clean_q = clean_digikala_query(raw_q)
    if not clean_q or len(clean_q) < 2:
        clean_q = raw_q

    cache_key = f"{KV_KEY_DIGIKALA_PREFIX}{clean_q.lower().replace(' ', '_')}"

    # L1 In-Memory & Cloudflare KV cache check
    l1_cached = database.l1_get(cache_key)
    if l1_cached:
        return l1_cached

    kv_cached = await database.kv_get(cache_key)
    if kv_cached:
        database.l1_set(cache_key, kv_cached, ttl_sec=600)
        return kv_cached

    client = get_digikala_client()
    products: List[Dict[str, Any]] = []
    enc_q = urllib.parse.quote(clean_q)

    try:
        resp = await client.get(f"https://api.digikala.com/v1/search/?q={enc_q}&page=1")
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            products = data.get("products", [])
    except Exception as e:
        logger.debug(f"Digikala client error for '{clean_q}': {e}")

    if not products:
        return f"🔍 کالایی با عنوان «{clean_q}» در دیجی‌کالا یافت نشد یا در حال حاضر در دسترس نیست."

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
        price_info = variant.get("price") or p.get("price") or {}
        rrp_price = price_info.get("rrp_price", 0)  # Rials
        selling_price = price_info.get("selling_price", 0)  # Rials
        discount_pct = price_info.get("discount_percent", 0)

        # Convert Rials to Tomans
        selling_toman = selling_price // 10 if selling_price else 0
        rrp_toman = rrp_price // 10 if rrp_price else 0

        # Special badge (e.g. فروش ویژه, شگفت‌انگیز)
        badge_obj = price_info.get("badge")
        badge_title = badge_obj.get("title") if isinstance(badge_obj, dict) else None
        if not badge_title and price_info.get("is_incredible"):
            badge_title = "پیشنهاد شگفت‌انگیز"

        rating_info = p.get("rating") or {}
        rate_val = rating_info.get("rate")
        rate_count = rating_info.get("count", 0)

        seller_info = variant.get("seller") or {}
        seller_name = seller_info.get("title", "دیجی‌کالا")
        warranty_info = variant.get("warranty") or {}
        warranty_name = warranty_info.get("title_fa")

        line = f"• [{title}]({url})\n"
        if selling_toman > 0:
            promo_tag = f" `⚡ {badge_title}`" if badge_title else ""
            line += f"  💰 **قیمت:** `{selling_toman:,} تومان`{promo_tag}"
            if discount_pct > 0 and rrp_toman > selling_toman:
                line += f" (🔥 تخفیف: `{discount_pct}%` | قبل: ~`{rrp_toman:,}`~)"
            line += "\n"
        else:
            line += "  💰 **وضعیت:** `ناموجود / در حال تأمین`\n"

        if rate_val is not None and rate_val > 0:
            if rate_val > 5.0:
                # Digikala API returns satisfaction on a 0-100 scale
                score_5 = round(rate_val / 20.0, 1)
                satisfaction_pct = int(round(rate_val))
                if rate_count:
                    line += f"  ⭐ **امتیاز:** `{score_5} از ۵` ({satisfaction_pct}٪ رضایت | {rate_count:,} نظر)\n"
                else:
                    line += f"  ⭐ **امتیاز:** `{score_5} از ۵` ({satisfaction_pct}٪ رضایت)\n"
            else:
                if rate_count:
                    line += f"  ⭐ **امتیاز:** `{rate_val} از ۵` ({rate_count:,} نظر)\n"
                else:
                    line += f"  ⭐ **امتیاز:** `{rate_val} از ۵`\n"

        line += f"  🏪 **فروشنده:** {seller_name}"
        if warranty_name:
            line += f" | 🛡 {warranty_name}"
        line += "\n"

        lines.append(line)
        count += 1

    all_url = f"https://www.digikala.com/search/?q={enc_q}"
    lines.append(f"🔗 [مشاهده همه نتایج «{clean_q}» در دیجی‌کالا]({all_url})\n")
    lines.append("⚡ *استعلام لحظه‌ای توسط پرومته*")
    result_text = "\n".join(lines)

    database.l1_set(cache_key, result_text, ttl_sec=600)
    await database.kv_set(cache_key, result_text, ttl_sec=600)
    return result_text
