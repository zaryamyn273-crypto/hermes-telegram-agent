"""
High-Performance Web Intelligence, Search & Webpage Reader Engine.
Supports Tavily AI, DuckDuckGo Lite, and direct URL scraping.
"""

import httpx
import re
import urllib.parse
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Optional
from config import settings


async def web_search(query: str, max_results: int = 4) -> str:
    """Performs live web search using Tavily AI or high-speed DuckDuckGo fallback."""
    clean_q = query.strip()
    if not clean_q:
        return "عبارت جستجو خالی است."

    # 1. Tavily AI Search (Preferred for AI agents)
    tavily_key = settings.TAVILY_API_KEYS.split(",")[0].strip() if settings.TAVILY_API_KEYS else ""
    if tavily_key:
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                r = await client.post(
                    "https://api.tavily.com/search",
                    json={
                        "api_key": tavily_key,
                        "query": clean_q,
                        "search_depth": "basic",
                        "max_results": max_results,
                        "include_answer": True
                    }
                )
                if r.status_code == 200:
                    data = r.json()
                    results = []
                    answer = data.get("answer")
                    if answer:
                        results.append(f"💡 *خلاصه مستقیم:* {answer}\n")
                    for item in data.get("results", []):
                        title = item.get("title", "")
                        url = item.get("url", "")
                        snippet = item.get("content", "").replace("\n", " ")[:250]
                        results.append(f"• **{title}**\n  🔗 {url}\n  {snippet}\n")
                    if results:
                        return "\n".join(results)
        except Exception:
            pass

    # 2. DuckDuckGo High-Speed HTML Search Fallback
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                "https://html.duckduckgo.com/html/",
                data={"q": clean_q},
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Referer": "https://html.duckduckgo.com/"
                },
                follow_redirects=True
            )
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                results = []
                for res in soup.find_all("div", class_="result")[:max_results]:
                    a_title = res.find("a", class_="result__a")
                    a_snippet = res.find("a", class_="result__snippet")
                    if not a_title:
                        continue
                    href = a_title.get("href", "")
                    if "uddg=" in href:
                        try:
                            href = urllib.parse.unquote(href.split("uddg=")[1].split("&")[0])
                        except Exception:
                            pass
                    title = a_title.get_text(strip=True)
                    snippet = a_snippet.get_text(strip=True) if a_snippet else ""
                    if title and href.startswith("http"):
                        results.append(f"• **{title}**\n  🔗 {href}\n  {snippet[:200]}\n")
                if results:
                    return "\n".join(results)
    except Exception:
        pass

    return f"🔍 نتیجه‌ای برای جستجوی «{clean_q}» یافت نشد یا سرور جستجو در دسترس نیست."


async def fetch_webpage(url: str) -> str:
    """Extracts readable article text from a given web URL."""
    clean_url = url.strip()
    if not clean_url.startswith("http"):
        clean_url = f"https://{clean_url}"

    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            resp = await client.get(clean_url, headers=headers)
            if resp.status_code != 200:
                return f"خطا در باز کردن صفحه: کد وضعیت HTTP {resp.status_code}"

            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup(["script", "style", "nav", "footer", "header", "noscript", "svg"]):
                tag.decompose()

            title = soup.title.string.strip() if soup.title and soup.title.string else clean_url
            body_text = re.sub(r"\s+", " ", soup.get_text(separator=" ")).strip()

            preview = body_text[:2500]
            return f"📄 *عنوان صفحه:* {title}\n🔗 *آدرس:* {clean_url}\n\n*محتوای متنی:*\n{preview}"
    except Exception as e:
        return f"خطا در واکشی صفحه وب: {str(e)}"
