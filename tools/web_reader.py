"""
Specialized Webpage Reader Tool for Prometheus:
Fetches, extracts, cleans, and structures textual content from any public web page (URL).
Strips scripts, ads, trackers, styles, and junk HTML, returning pure readable content.
Protected by SSRF guardrails and backed by persistent keepalive connection pooling, L1 RAM, and Cloudflare KV caching.
"""

import re
import ipaddress
import urllib.parse
import logging
import asyncio
import httpx
from bs4 import BeautifulSoup
from typing import Optional

import database

logger = logging.getLogger("WebReader")

KV_KEY_URL_PREFIX = "PROMETHEUS_URL_"

_BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fa,en-US;q=0.9,en;q=0.8",
}

_BLOCKED_HOSTNAMES = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "metadata.google.internal", "169.254.169.254"
}

_WEB_CLIENT: Optional[httpx.AsyncClient] = None


def get_web_client() -> httpx.AsyncClient:
    """Returns persistent AsyncClient with keepalive connection pooling."""
    global _WEB_CLIENT
    if _WEB_CLIENT is None or _WEB_CLIENT.is_closed:
        limits = httpx.Limits(max_keepalive_connections=30, max_connections=60, keepalive_expiry=60.0)
        timeout = httpx.Timeout(connect=2.5, read=6.0, write=2.5, pool=2.5)
        _WEB_CLIENT = httpx.AsyncClient(limits=limits, timeout=timeout, headers=_BROWSER_HEADERS, follow_redirects=True)
    return _WEB_CLIENT


def is_safe_public_url(url: str) -> bool:
    """Validates that URL points to a safe public destination (SSRF protection)."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = (parsed.hostname or "").lower().strip()
        if not hostname:
            return False
        if hostname in _BLOCKED_HOSTNAMES or hostname.endswith(".internal") or hostname.endswith(".local"):
            return False
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        except ValueError:
            pass  # Domain name
        return True
    except Exception:
        return False


async def fetch_webpage_text(url: str, max_chars: int = 5000) -> str:
    """
    Fetches clean text from a public web page with streaming byte cap to avoid downloading bloated assets.
    """
    clean_url = url.strip()
    if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
        clean_url = f"https://{clean_url}"

    if not is_safe_public_url(clean_url):
        return "⛔ دسترسی به این آدرس به دلایل امنیتی مسدود است (فقط آدرس‌های عمومی مجاز هستند)."

    cache_key = f"{KV_KEY_URL_PREFIX}{clean_url}"
    cached = await database.kv_get(cache_key)
    if cached:
        return cached

    client = get_web_client()
    html = ""
    try:
        async with client.stream("GET", clean_url) as resp:
            if resp.status_code != 200:
                return f"⚠️ خطا در بازخوانی صفحه اینترنتی (کد وضعیت HTTP: {resp.status_code})."

            total_bytes = 0
            chunks = []
            async for chunk in resp.aiter_text():
                chunks.append(chunk)
                total_bytes += len(chunk)
                if total_bytes > 200_000:  # Cap at 200KB of HTML
                    break
            html = "".join(chunks)

        # Parse and strip unwanted elements
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "noscript", "svg", "form", "aside", "iframe"]):
            tag.decompose()

        # Extract title
        title_tag = soup.find("title")
        page_title = title_tag.get_text().strip() if title_tag else ""

        # Extract main content
        main_el = soup.find("article") or soup.find("main") or soup.find(id=re.compile(r"content|main|article|post", re.I)) or soup.body
        if not main_el:
            main_el = soup

        parts = []
        for el in main_el.find_all(["h1", "h2", "h3", "h4", "p", "li"]):
            t = el.get_text(" ", strip=True)
            if t and len(t) > 3:
                parts.append(t)

        extracted = "\n\n".join(parts) if parts else soup.get_text(" ", strip=True)
        cleaned = re.sub(r"\s+", " ", extracted).strip()

        if len(cleaned) > max_chars:
            cleaned = cleaned[:max_chars] + "... [بقیه محتوا کوتاه شد]"

        if not cleaned:
            return "⚠️ متنی از این صفحه استخراج نشد (ممکن است محتوا با جاوااسکریپت سنگین لود شود)."

        result = f"🌐 **عنوان صفحه:** {page_title}\n🔗 **آدرس:** {clean_url}\n\n📄 **محتوای استخراج‌شده:**\n{cleaned}"
        await database.kv_set(cache_key, result, ttl_sec=600)
        return result

    except Exception as e:
        logger.warning(f"Error fetching URL {clean_url}: {e}")
        return f"⚠️ امکان بازخوانی محتوای این صفحه وجود ندارد: {str(e)}"
