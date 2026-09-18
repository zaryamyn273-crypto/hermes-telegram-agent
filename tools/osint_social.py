"""
Prometheus OSINT Suite - Cross-Platform Social Media Intelligence & Deep Reconnaissance Engine.
Performs multi-network profile discovery, targeted social Google Dorking, live web hits synthesis,
and generates direct 1-click investigation pivots across global social ecosystems.
"""

import re
import html
import logging
import urllib.parse
from typing import Dict, Any, List, Optional

from utils.cache import social_cache
from utils.formatter import wrap_in_expandable_blockquote
from tools.osint_search import search_web_osint

logger = logging.getLogger("OSINT_Social")

# High-priority social and community domains for targeted web search
SOCIAL_RECON_DOMAINS = [
    "t.me",
    "x.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "youtube.com",
    "reddit.com",
    "tiktok.com",
    "threads.net",
    "facebook.com",
    "medium.com",
    "pinterest.com",
]

_DOMAIN_ICONS = {
    "telegram": ("Telegram", "✈️"),
    "twitter": ("Twitter / X", "🐦"),
    "x.com": ("Twitter / X", "🐦"),
    "instagram": ("Instagram", "📸"),
    "linkedin": ("LinkedIn", "💼"),
    "github": ("GitHub", "🐙"),
    "youtube": ("YouTube", "▶️"),
    "reddit": ("Reddit", "🤖"),
    "tiktok": ("TikTok", "🎵"),
    "threads": ("Threads", "🧵"),
    "facebook": ("Facebook", "👥"),
    "medium": ("Medium", "📝"),
    "pinterest": ("Pinterest", "📌"),
}


def parse_social_target(raw_target: str) -> Dict[str, str]:
    """
    Cleans and classifies a social media target query.
    Detects if the query is a handle (@username), a person's full name, or a topic/keyword.
    """
    target = (raw_target or "").strip()
    # Strip URL prefixes if user passed a link (e.g. https://x.com/username)
    target = re.sub(
        r"^https?://(?:www\.)?(?:twitter\.com|x\.com|instagram\.com|t\.me|github\.com|reddit\.com/user|threads\.net/@|tiktok\.com/@|linkedin\.com/in)/?",
        "",
        target,
        flags=re.IGNORECASE,
    )
    # Strip trailing slashes or query parameters
    target = target.split("/")[0].split("?")[0].strip()

    # Determine handle vs full name
    cleaned_handle = target.lstrip("@").strip()
    if " " in cleaned_handle:
        query_type = "fullname"
    elif re.match(r"^[a-zA-Z0-9_.-]+$", cleaned_handle):
        query_type = "username"
    else:
        query_type = "topic"

    return {
        "raw": raw_target.strip(),
        "target": target,
        "clean_handle": cleaned_handle,
        "query_type": query_type,
    }


def generate_social_profile_links(clean_target: str, query_type: str = "username") -> Dict[str, Dict[str, str]]:
    """
    Generates direct profile and platform search links.
    """
    h = urllib.parse.quote(clean_target)
    q = urllib.parse.quote_plus(clean_target)

    links: Dict[str, Dict[str, str]] = {
        "telegram": {
            "name": "Telegram",
            "icon": "✈️",
            "url": f"https://t.me/{h}",
            "search_url": f"https://t.me/s/{h}",
        },
        "twitter": {
            "name": "Twitter / X",
            "icon": "🐦",
            "url": f"https://x.com/{h}",
            "search_url": f"https://x.com/search?q={q}&f=user",
        },
        "instagram": {
            "name": "Instagram",
            "icon": "📸",
            "url": f"https://www.instagram.com/{h}/",
            "search_url": f"https://www.instagram.com/explore/tags/{h}/",
        },
        "linkedin": {
            "name": "LinkedIn",
            "icon": "💼",
            "url": f"https://www.linkedin.com/in/{h}/",
            "search_url": f"https://www.linkedin.com/search/results/all/?keywords={q}",
        },
        "github": {
            "name": "GitHub",
            "icon": "🐙",
            "url": f"https://github.com/{h}",
            "search_url": f"https://github.com/search?q={q}&type=users",
        },
        "youtube": {
            "name": "YouTube",
            "icon": "▶️",
            "url": f"https://www.youtube.com/@{h}",
            "search_url": f"https://www.youtube.com/results?search_query={q}",
        },
        "reddit": {
            "name": "Reddit",
            "icon": "🤖",
            "url": f"https://www.reddit.com/user/{h}",
            "search_url": f"https://www.reddit.com/search/?q={q}",
        },
        "tiktok": {
            "name": "TikTok",
            "icon": "🎵",
            "url": f"https://www.tiktok.com/@{h}",
            "search_url": f"https://www.tiktok.com/search?q={q}",
        },
        "threads": {
            "name": "Threads",
            "icon": "🧵",
            "url": f"https://www.threads.net/@{h}",
            "search_url": f"https://www.threads.net/search?q={q}",
        },
        "pinterest": {
            "name": "Pinterest",
            "icon": "📌",
            "url": f"https://www.pinterest.com/{h}/",
            "search_url": f"https://www.pinterest.com/search/pins/?q={q}",
        },
    }
    return links


def generate_social_dorks(target: str) -> List[Dict[str, str]]:
    """
    Generates specialized Google Dork queries to uncover social footprint,
    mentions, leaks, and profiles.
    """
    quoted = f'"{target}"'
    dorks = [
        {
            "category": "تلگرام و کانال‌ها (Telegram)",
            "query": f'site:t.me {quoted}',
            "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(f'site:t.me {quoted}')}",
        },
        {
            "category": "توییتر / اکس (Twitter/X Mentions & Profiles)",
            "query": f'(site:twitter.com OR site:x.com) {quoted}',
            "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(f'(site:twitter.com OR site:x.com) {quoted}')}",
        },
        {
            "category": "پروفایل‌های لینکدین (LinkedIn People & Companies)",
            "query": f'(site:linkedin.com/in/ OR site:linkedin.com/company/) {quoted}',
            "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(f'(site:linkedin.com/in/ OR site:linkedin.com/company/) {quoted}')}",
        },
        {
            "category": "اینستاگرام (Instagram Bios & Posts)",
            "query": f'site:instagram.com {quoted}',
            "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(f'site:instagram.com {quoted}')}",
        },
        {
            "category": "گیت‌هاب و پروژه‌ها (GitHub Users & Repos)",
            "query": f'site:github.com {quoted}',
            "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(f'site:github.com {quoted}')}",
        },
        {
            "category": "ردیت و انجمن‌ها (Reddit Discussions)",
            "query": f'site:reddit.com {quoted}',
            "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(f'site:reddit.com {quoted}')}",
        },
        {
            "category": "لیک‌ها و اسناد متنی (Pastebin / Text Leaks)",
            "query": f'(site:pastebin.com OR site:justpaste.it OR site:rentry.co) {quoted}',
            "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(f'(site:pastebin.com OR site:justpaste.it OR site:rentry.co) {quoted}')}",
        },
    ]
    return dorks


def _identify_platform(url: str) -> Dict[str, str]:
    """Identifies the social platform and icon from a URL."""
    u_lower = url.lower()
    for key, (name, icon) in _DOMAIN_ICONS.items():
        if key in u_lower:
            return {"name": name, "icon": icon}
    return {"name": "وب‌سایت", "icon": "🌐"}


async def search_social_media_profiles(target: str, max_results: int = 10) -> Dict[str, Any]:
    """
    Performs full cross-network social intelligence reconnaissance on a target handle, name, or topic.
    Combines live web searches across social domains with direct pivots and specialized Google Dorks.
    """
    parsed = parse_social_target(target)
    clean_target = parsed["clean_handle"]
    if not clean_target:
        return {
            "success": False,
            "target": target,
            "error": "نام کاربری یا عبارت جستجوی شبکه اجتماعی وارد نشده است.",
        }

    # 1. Check in-memory cache
    cache_key = f"social:{clean_target.lower()}:{max_results}"
    cached_data = await social_cache.get(cache_key)
    if cached_data:
        logger.debug(f"Social recon cache hit for {clean_target}")
        return cached_data

    # 2. Build direct profile links and Google Dorks
    direct_links = generate_social_profile_links(clean_target, parsed["query_type"])
    dorks = generate_social_dorks(clean_target)

    # 3. Live Search across social domains
    web_hits: List[Dict[str, Any]] = []
    engine_used = "none"

    try:
        # Search query crafted for social footprint
        search_q = f'"{clean_target}" (site:t.me OR site:x.com OR site:twitter.com OR site:instagram.com OR site:linkedin.com OR site:github.com OR site:reddit.com OR site:youtube.com)'
        search_res = await search_web_osint(
            query=search_q,
            max_results=max_results,
            search_depth="basic",
            include_answer=False,
            include_domains=SOCIAL_RECON_DOMAINS,
        )

        if search_res.get("success"):
            engine_used = search_res.get("engine", "Tavily")
            for r in search_res.get("results", []):
                p_info = _identify_platform(r.get("url", ""))
                web_hits.append({
                    "platform": p_info["name"],
                    "icon": p_info["icon"],
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "snippet": r.get("snippet", ""),
                })
        else:
            # Fallback to broader query without strict domain locks if nothing returned
            broader_res = await search_web_osint(
                query=f'"{clean_target}" profile account',
                max_results=max_results,
                search_depth="basic",
                include_answer=False,
            )
            if broader_res.get("success"):
                engine_used = broader_res.get("engine", "Tavily")
                for r in broader_res.get("results", []):
                    p_info = _identify_platform(r.get("url", ""))
                    web_hits.append({
                        "platform": p_info["name"],
                        "icon": p_info["icon"],
                        "title": r.get("title", ""),
                        "url": r.get("url", ""),
                        "snippet": r.get("snippet", ""),
                    })
    except Exception as e:
        logger.warning(f"Error during live social media web search for {clean_target}: {e}")

    result: Dict[str, Any] = {
        "success": True,
        "target": target,
        "clean_target": clean_target,
        "query_type": parsed["query_type"],
        "direct_links": direct_links,
        "dorks": dorks,
        "web_hits": web_hits,
        "total_hits": len(web_hits),
        "search_engine": engine_used,
    }

    # Store in cache (15m TTL)
    await social_cache.set(cache_key, result)
    return result


def format_social_search_report(data: Dict[str, Any]) -> str:
    """
    Formats social intelligence reconnaissance results into a structured Telegram HTML message.
    """
    if not data.get("success"):
        err = html.escape(data.get("error", "خطای نامشخص رخ داد."))
        return f"❌ <b>خطا در جستجوی شبکه‌های اجتماعی:</b>\n{err}"

    target = html.escape(data.get("clean_target", ""))
    q_type = data.get("query_type", "username")
    q_type_str = "یوزرنیم / شناسه" if q_type == "username" else ("نام کامل / شخص" if q_type == "fullname" else "کلیدواژه عمومی")

    lines = [
        f"🌐 <b>ردگیری و جستجوی شبکه‌های اجتماعی (Social Media OSINT):</b>\n<code>{target}</code>\n",
        f"• <b>نوع شناسه:</b> {q_type_str}",
        f"• <b>یافته‌های زنده وب:</b> <code>{data.get('total_hits', 0)}</code> نتیجه\n",
    ]

    # Direct profile and search pivots
    direct = data.get("direct_links", {})
    if direct:
        direct_rows = []
        for key, info in direct.items():
            name = info.get("name", key)
            icon = info.get("icon", "🔗")
            u = info.get("url", "")
            s_url = info.get("search_url", "")
            direct_rows.append(
                f"• {icon} <b>{name}:</b> <a href=\"{u}\">پروفایل</a> | <a href=\"{s_url}\">جستجو</a>"
            )
        lines.append("⚡️ <b>دسترسی مستقیم به پروفایل و جستجوی پلتفرم‌ها:</b>\n" + "\n".join(direct_rows) + "\n")

    # Live OSINT Web Hits
    hits = data.get("web_hits", [])
    if hits:
        hit_items = []
        for h in hits[:8]:
            icon = h.get("icon", "🌐")
            p_name = html.escape(h.get("platform", "وب"))
            t = html.escape(h.get("title", ""))
            u = html.escape(h.get("url", ""))
            s = html.escape(h.get("snippet", ""))[:140]
            hit_items.append(f"• {icon} <b>{p_name}:</b> <a href=\"{u}\">{t}</a>\n  <i>{s}</i>")

        block_content = "\n\n".join(hit_items)
        lines.append(f"🔍 <b>نتایج زنده کشف‌شده از شبکه‌ها (Web Hits):</b>\n{wrap_in_expandable_blockquote(block_content)}\n")
    else:
        lines.append("🔍 <b>یافته‌های زنده وب:</b> <i>هیچ پیج مستقیمی در ایندکس سریع وب یافت نشد. می‌توانید از دورک‌های زیر یا چک یوزرنیم استفاده کنید.</i>\n")

    # Google Dorks for deeper investigation
    dorks = data.get("dorks", [])
    if dorks:
        dork_rows = []
        for d in dorks:
            cat = html.escape(d.get("category", "دورک"))
            u = d.get("url", "")
            dork_rows.append(f"• <a href=\"{u}\"><b>{cat}</b></a>")
        lines.append("🔎 <b>دورک‌های اختصاصی گوگل جهت کاوش عمیق‌تر:</b>\n" + "\n".join(dork_rows) + "\n")

    lines.append("💡 <i>پیشنهاد: جهت اسکن ۶۵+ پلتفرم اختصاصی، از دستور <code>/pb_usercheck {target}</code> استفاده فرمایید.</i>")

    return "\n".join(lines)
