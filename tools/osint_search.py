"""
Prometheus OSINT Suite - Web Search & Deep Web Crawler / Page Reader
Fast multi-engine search (Tavily, DuckDuckGo, SearXNG) and deep webpage layer analysis,
extracting emails, phones, social links, subdomains, internal links, technologies, and metadata.
"""

import re
import html
import base64
import urllib.parse
import logging
from typing import Dict, Any, List, Optional, Set
import httpx
from bs4 import BeautifulSoup

from config import get_tavily_api_keys
from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_Search")

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
_HEADERS = {
    "User-Agent": _USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
}

# Regex patterns for intelligence extraction
_EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    re.IGNORECASE
)
_PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",
    re.ASCII
)
_CRYPTO_PATTERNS = {
    "Bitcoin": re.compile(r"\b(?:1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b"),
    "Ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "Tron": re.compile(r"\bT[a-zA-Z0-9]{33}\b"),
}
_SOCIAL_DOMAINS = {
    "linkedin": ("linkedin.com/in/", "linkedin.com/company/"),
    "github": ("github.com/",),
    "twitter": ("twitter.com/", "x.com/"),
    "telegram": ("t.me/", "telegram.me/"),
    "instagram": ("instagram.com/",),
    "youtube": ("youtube.com/", "youtu.be/"),
    "facebook": ("facebook.com/",),
    "reddit": ("reddit.com/user/", "reddit.com/r/"),
}


# =========================================================================
# 1. Multi-Engine Fast Web Search
# =========================================================================

async def search_web_osint(
    query: str,
    max_results: int = 7,
    search_depth: str = "basic",
    include_answer: bool = True,
    include_domains: Optional[List[str]] = None,
    exclude_domains: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    High-speed multi-engine search with Tavily primary and DuckDuckGo fallback.
    Returns: {"success": bool, "engine": str, "query": str, "answer": str, "results": List[dict], "error": str}
    """
    clean_query = query.strip()
    if not clean_query:
        return {"success": False, "engine": "none", "query": "", "answer": "", "results": [], "error": "کوئری جستجو خالی است."}

    # 1. Tavily Search
    tavily_keys = get_tavily_api_keys()
    for api_key in tavily_keys:
        try:
            payload: Dict[str, Any] = {
                "api_key": api_key,
                "query": clean_query,
                "search_depth": search_depth,
                "include_answer": include_answer,
                "max_results": max_results
            }
            if include_domains:
                payload["include_domains"] = include_domains
            if exclude_domains:
                payload["exclude_domains"] = exclude_domains

            async with httpx.AsyncClient(timeout=12.0) as client:
                res = await client.post(
                    "https://api.tavily.com/search",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                if res.status_code == 200:
                    data = res.json()
                    answer = data.get("answer", "") or ""
                    items = []
                    for r in data.get("results", []):
                        items.append({
                            "title": r.get("title", ""),
                            "url": r.get("url", ""),
                            "snippet": r.get("content", ""),
                            "score": r.get("score", 0.0)
                        })
                    if items or answer:
                        return {
                            "success": True,
                            "engine": "Tavily",
                            "query": clean_query,
                            "answer": answer,
                            "results": items,
                            "error": ""
                        }
        except Exception as e:
            logger.debug(f"Tavily search attempt failed: {e}")

    # 2. Bing Search Fallback
    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=8.0, follow_redirects=True) as client:
            res = await client.get("https://www.bing.com/search", params={"q": clean_query})
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, "html.parser")
                items = []
                results_elements = soup.find_all("li", class_="b_algo")
                for r in results_elements[:max_results]:
                    h2 = r.find("h2")
                    if not h2:
                        continue
                    a_tag = h2.find("a")
                    if not a_tag:
                        continue
                    title = h2.get_text(strip=True)
                    raw_url = a_tag.get("href", "")
                    actual_url = raw_url
                    if "u=" in raw_url:
                        try:
                            parsed = urllib.parse.urlparse(raw_url)
                            params = urllib.parse.parse_qs(parsed.query)
                            if "u" in params:
                                u_val = params["u"][0]
                                if u_val.startswith("a1"):
                                    raw_b64 = u_val[2:]
                                    padded = raw_b64 + "=" * (-len(raw_b64) % 4)
                                    decoded_url = base64.b64decode(padded).decode("utf-8", errors="ignore")
                                    if decoded_url.startswith(("http://", "https://")):
                                        actual_url = decoded_url
                        except Exception:
                            pass
                    p_tag = r.find("p")
                    snippet = p_tag.get_text(strip=True) if p_tag else ""
                    if title and actual_url:
                        items.append({
                            "title": title,
                            "url": actual_url,
                            "snippet": snippet,
                            "score": 0.0
                        })
                if items:
                    return {
                        "success": True,
                        "engine": "Bing",
                        "query": clean_query,
                        "results": items,
                        "error": ""
                    }
    except Exception as e:
        logger.debug(f"Bing search fallback failed: {e}")

    # 3. DuckDuckGo Instant Answer API Fallback
    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=8.0, follow_redirects=True) as client:
            res = await client.get("https://api.duckduckgo.com/", params={"q": clean_query, "format": "json"})
            if res.status_code in (200, 202):
                try:
                    data = res.json()
                    items = []
                    if data.get("AbstractText") and data.get("AbstractURL"):
                        items.append({
                            "title": data.get("Heading") or clean_query,
                            "url": data.get("AbstractURL"),
                            "snippet": data.get("AbstractText"),
                            "score": 1.0
                        })
                    for topic in data.get("RelatedTopics", []):
                        if isinstance(topic, dict) and topic.get("FirstURL") and topic.get("Text"):
                            items.append({
                                "title": topic.get("Text", "").split(" - ")[0],
                                "url": topic.get("FirstURL"),
                                "snippet": topic.get("Text"),
                                "score": 0.5
                            })
                        if len(items) >= max_results:
                            break
                    if items:
                        return {
                            "success": True,
                            "engine": "DuckDuckGo-API",
                            "query": clean_query,
                            "results": items,
                            "error": ""
                        }
                except Exception:
                    pass
    except Exception as e:
        logger.debug(f"DDG API fallback failed: {e}")

    # 4. DuckDuckGo HTML Fallback
    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=12.0, follow_redirects=True) as client:
            res = await client.post(
                "https://html.duckduckgo.com/html/",
                data={"q": clean_query, "b": ""},
                headers={"Referer": "https://duckduckgo.com/"}
            )
            if res.status_code == 200:
                soup = BeautifulSoup(res.text, "html.parser")
                items = []
                results_elements = soup.find_all("div", class_="result")
                for r in results_elements[:max_results]:
                    title_elem = r.find("a", class_="result__a")
                    snippet_elem = r.find("a", class_="result__snippet")
                    if title_elem:
                        raw_url = title_elem.get("href", "")
                        # DuckDuckGo wraps URLs in /l/?kh=-1&uddg=
                        actual_url = raw_url
                        if "uddg=" in raw_url:
                            try:
                                parsed = urllib.parse.urlparse(raw_url)
                                params = urllib.parse.parse_qs(parsed.query)
                                if "uddg" in params:
                                    actual_url = params["uddg"][0]
                            except Exception:
                                pass

                        items.append({
                            "title": title_elem.get_text(strip=True),
                            "url": actual_url,
                            "snippet": snippet_elem.get_text(strip=True) if snippet_elem else "",
                            "score": 0.0
                        })
                if items:
                    return {
                        "success": True,
                        "engine": "DuckDuckGo",
                        "query": clean_query,
                        "results": items,
                        "error": ""
                    }
    except Exception as e:
        logger.debug(f"DuckDuckGo search fallback failed: {e}")

    return {
        "success": False,
        "engine": "none",
        "query": clean_query,
        "results": [],
        "error": "نتیجه‌ای یافت نشد یا ارتباط با موتورهای جستجو با خطا مواجه شد."
    }


# =========================================================================
# 2. Deep Web Crawler & Page Layer Reader
# =========================================================================

async def crawl_webpage_layers(url: str, max_text_len: int = 3500) -> Dict[str, Any]:
    """
    Crawls and analyzes layers of a webpage:
    - Metadata (title, description, author, CMS/Tech fingerprints)
    - Extracted text
    - Discovered Emails, Phones, Crypto Wallets
    - Social profile links (LinkedIn, GitHub, X, Telegram)
    - Internal and External links
    """
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    parsed_root = urllib.parse.urlparse(clean_url)
    root_domain = parsed_root.netloc.lower()

    from tools.web_reader import is_safe_public_url
    if not is_safe_public_url(clean_url):
        return {
            "success": False,
            "url": clean_url,
            "error": "دسترسی به آدرس‌های لوکال، شبکه محلی و سرورهای داخلی مسدود است (حفاظت SSRF)."
        }

    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(clean_url)
            status_code = resp.status_code
            content_type = resp.headers.get("content-type", "").lower()

            if "text/html" not in content_type and "application/xhtml" not in content_type:
                # Binary or non-HTML content
                return {
                    "success": True,
                    "url": clean_url,
                    "final_url": str(resp.url),
                    "status_code": status_code,
                    "content_type": content_type,
                    "title": "",
                    "description": "",
                    "text": resp.text[:max_text_len],
                    "emails": list(set(_EMAIL_REGEX.findall(resp.text)))[:10],
                    "phones": [],
                    "crypto": {},
                    "social_links": {},
                    "internal_links": [],
                    "external_links": [],
                    "technologies": _detect_tech_headers(resp.headers),
                }

            html_text = resp.text
            soup = BeautifulSoup(html_text, "html.parser")

            # Extract Title & Metadata
            title = ""
            if soup.title and soup.title.string:
                title = soup.title.string.strip()

            meta_desc = ""
            desc_tag = soup.find("meta", attrs={"name": "description"}) or soup.find("meta", attrs={"property": "og:description"})
            if desc_tag and desc_tag.get("content"):
                meta_desc = desc_tag.get("content").strip()

            # Remove scripts, styles, forms, navs for clean text extraction
            for tag in soup(["script", "style", "noscript", "svg"]):
                tag.decompose()

            page_text = soup.get_text(separator=" ", strip=True)
            # Normalize excessive whitespace
            page_text = re.sub(r"\s+", " ", page_text)

            # 1. Extract Emails
            found_emails: Set[str] = set()
            for em in _EMAIL_REGEX.findall(html_text):
                em_clean = em.strip(".,;:()")
                # Filter out image/font file false-positives
                if not re.search(r"\.(png|jpg|jpeg|gif|svg|webp|woff|woff2|ttf|css|js)$", em_clean, re.I):
                    if len(em_clean) < 60:
                        found_emails.add(em_clean)

            # 2. Extract Phones
            found_phones: Set[str] = set()
            for ph in _PHONE_REGEX.findall(page_text):
                clean_ph = ph.strip()
                # Must have at least 7 digits
                digits = re.sub(r"\D", "", clean_ph)
                if 7 <= len(digits) <= 15:
                    found_phones.add(clean_ph)

            # 3. Extract Crypto Addresses
            found_crypto: Dict[str, List[str]] = {}
            for coin, pat in _CRYPTO_PATTERNS.items():
                matches = list(set(pat.findall(page_text)))
                if matches:
                    found_crypto[coin] = matches[:5]

            # 4. Extract Social Links & Classify Links
            social_links: Dict[str, List[str]] = {k: [] for k in _SOCIAL_DOMAINS}
            internal_links: Set[str] = set()
            external_links: Set[str] = set()

            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue

                abs_url = urllib.parse.urljoin(clean_url, href)
                parsed_href = urllib.parse.urlparse(abs_url)
                href_domain = parsed_href.netloc.lower()

                # Social media detection
                matched_social = False
                for soc_name, prefixes in _SOCIAL_DOMAINS.items():
                    if any(p in abs_url.lower() for p in prefixes):
                        if abs_url not in social_links[soc_name]:
                            social_links[soc_name].append(abs_url)
                        matched_social = True
                        break

                if not matched_social:
                    if href_domain == root_domain or href_domain.endswith("." + root_domain):
                        internal_links.add(abs_url)
                    elif href_domain:
                        external_links.add(abs_url)

            # Clean empty social lists
            active_social = {k: v for k, v in social_links.items() if v}

            # 5. Technology & Server Fingerprinting
            technologies = _detect_technologies(resp.headers, html_text)

            return {
                "success": True,
                "url": clean_url,
                "final_url": str(resp.url),
                "status_code": status_code,
                "title": title,
                "description": meta_desc,
                "text": page_text[:max_text_len],
                "emails": sorted(list(found_emails))[:15],
                "phones": sorted(list(found_phones))[:10],
                "crypto": found_crypto,
                "social_links": active_social,
                "internal_links": sorted(list(internal_links))[:25],
                "external_links": sorted(list(external_links))[:25],
                "technologies": technologies,
            }

    except Exception as e:
        logger.error(f"Error crawling webpage {url}: {e}")
        return {
            "success": False,
            "url": clean_url,
            "error": f"خطا در خواندن صفحه وب: {str(e)}"
        }


def _detect_tech_headers(headers: httpx.Headers) -> List[str]:
    tech = []
    if "server" in headers:
        tech.append(f"Server: {headers['server']}")
    if "x-powered-by" in headers:
        tech.append(f"Powered-By: {headers['x-powered-by']}")
    return tech


def _detect_technologies(headers: httpx.Headers, html_text: str) -> List[str]:
    techs: Set[str] = set()

    # Headers inspection
    server = headers.get("server", "").lower()
    if "cloudflare" in server:
        techs.add("Cloudflare CDN/Proxy")
    elif "nginx" in server:
        techs.add("Nginx Web Server")
    elif "apache" in server:
        techs.add("Apache HTTP Server")
    elif "litespeed" in server:
        techs.add("LiteSpeed Web Server")

    powered = headers.get("x-powered-by", "").lower()
    if powered:
        techs.add(f"X-Powered-By: {powered}")

    # Body inspection
    h_lower = html_text.lower()
    if "wp-content" in h_lower or "wp-includes" in h_lower:
        techs.add("WordPress CMS")
    if "drupal" in h_lower:
        techs.add("Drupal CMS")
    if "joomla" in h_lower:
        techs.add("Joomla CMS")
    if "_next" in h_lower or "__next" in h_lower:
        techs.add("Next.js / React")
    if "react" in h_lower and "react-dom" in h_lower:
        techs.add("React.js")
    if "vue.js" in h_lower or "vuejs" in h_lower:
        techs.add("Vue.js")
    if "bootstrap" in h_lower:
        techs.add("Bootstrap CSS")
    if "tailwind" in h_lower:
        techs.add("Tailwind CSS")
    if "shopify" in h_lower:
        techs.add("Shopify Platform")

    return sorted(list(techs))


def format_osint_search_results(res: Dict[str, Any]) -> str:
    """Formats multi-engine OSINT search results cleanly into Persian Telegram HTML."""
    if not res.get("success"):
        return f"🔍 <b>نتیجه‌ای یافت نشد:</b> {html.escape(res.get('error', 'خطا در ارتباط با موتورهای جستجو'))}"

    q = html.escape(res.get("query", ""))
    engine = res.get("engine", "Web")
    engine_badge = "⚡️ Tavily AI OSINT" if engine == "Tavily" else f"🌐 {engine}"
    lines = [
        f"🌐 <b>نتایج کاوش وب (OSINT Search)</b> [{engine_badge}]\n"
        f"🎯 <b>کوئری:</b> <code>{q}</code>\n"
    ]

    answer = res.get("answer", "")
    if answer:
        ans_clean = html.escape(answer.strip())
        lines.append(f"💡 <b>سنتز و تحلیل هوشمند (Intelligence Synthesis):</b>\n{wrap_in_expandable_blockquote(ans_clean)}\n")

    results = res.get("results", [])
    if results:
        lines.append(f"📚 <b>منابع و مستندات کشف‌شده ({len(results)} مورد):</b>")
        for i, r in enumerate(results, 1):
            title = html.escape(r.get("title") or "بدون عنوان")
            url = r.get("url") or "#"
            snippet = html.escape(r.get("snippet") or "")
            score_txt = f" [امتیاز: {r['score']:.2f}]" if r.get("score") else ""
            lines.append(f"<b>{i}. <a href=\"{url}\">{title}</a></b>{score_txt}\n{snippet}\n")
    else:
        if not answer:
            lines.append("موردی برای این جستجو یافت نشد.")

    lines.append("⚡️ <i>جستجوی چندلایه اینترنت و وب تاریک/روشن - ۱۰۰٪ مستند</i>")
    return "\n".join(lines)


def format_crawler_report(data: Dict[str, Any]) -> str:
    """Formats deep webpage layer crawl results into Persian Telegram HTML."""
    if not data.get("success"):
        return f"❌ <b>خطا در کاوش صفحه:</b> {html.escape(str(data.get('error', 'ناشناخته')))}"

    title = html.escape(data.get("title") or "بدون عنوان")
    url = html.escape(data.get("final_url") or data.get("url") or "")
    status_code = data.get("status_code", 0)
    tech = data.get("technologies") or []
    emails = data.get("emails") or []
    phones = data.get("phones") or []
    wallets = data.get("crypto") or {}
    subdomains = data.get("subdomains") or []
    internal_links = data.get("internal_links") or []
    external_links = data.get("external_links") or []

    lines = [
        "🎯 <b>گزارش کاوش عمیق لایه‌های وب (Webpage Layer Analysis)</b>\n",
        f"🔗 <b>آدرس:</b> <code>{url}</code>",
        f"📄 <b>عنوان:</b> {title}",
        f"📡 <b>کد وضعیت:</b> <code>{status_code}</code>",
    ]

    if tech:
        lines.append(f"\n⚙️ <b>فناوری‌ها و سرور شناسایی‌شده:</b> {html.escape(', '.join(tech))}")

    if emails:
        lines.append(f"\n📧 <b>ایمیل‌های کشف‌شده ({len(emails)}):</b>")
        for em in emails[:8]:
            lines.append(f"  • <code>{html.escape(em)}</code>")

    if phones:
        lines.append(f"\n📞 <b>شماره‌های تماس ({len(phones)}):</b>")
        for ph in phones[:8]:
            lines.append(f"  • <code>{html.escape(ph)}</code>")

    active_wallets = {k: v for k, v in wallets.items() if v}
    if active_wallets:
        lines.append("\n💰 <b>آدرس‌های کیف‌پول رمزارز:</b>")
        for wtype, wlist in active_wallets.items():
            for w in wlist[:3]:
                lines.append(f"  • {wtype.upper()}: <code>{html.escape(w)}</code>")

    if subdomains:
        lines.append(f"\n🌐 <b>ساب‌دامین‌های استخراج‌شده ({len(subdomains)}):</b>")
        for s in subdomains[:6]:
            lines.append(f"  • <code>{html.escape(s)}</code>")

    lines.append(f"\n🔗 <b>آمار لینک‌ها:</b> داخلی: <code>{len(internal_links)}</code> | خارجی: <code>{len(external_links)}</code>")
    lines.append("\n⚡️ <i>کاوش بلادرنگ ساختار و متاداده صفحه وب</i>")
    return "\n".join(lines)

