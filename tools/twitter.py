"""
Twitter / X Exploration & Tweet Reader Tool for Prometheus:
Provides zero-API-key tweet extraction, user profile lookup, and live topic search on X/Twitter.
Features:
- Reads full tweet text, long notes, poll results, and timestamps
- Extracts media (high-res images, direct MP4 video URLs, GIFs)
- Retrieves author metadata, followers, verification badge, and bio
- Live Twitter search for news, trending topics, and specific discussions
"""

import re
import html
import logging
import urllib.parse
from typing import Optional, Tuple, Dict, Any, List
import httpx
from bs4 import BeautifulSoup

import database
from agent_engine import get_http_client

logger = logging.getLogger("TwitterTool")

# Regex patterns for Twitter/X URLs
TWEET_URL_REGEX = re.compile(
    r"https?://(?:www\.)?(?:twitter\.com|x\.com)/(?:#!/)?([a-zA-Z0-9_]{1,25})/status/(\d+)",
    re.IGNORECASE
)

PROFILE_URL_REGEX = re.compile(
    r"https?://(?:www\.)?(?:twitter\.com|x\.com)/([a-zA-Z0-9_]{1,25})(?:/)?(?:\s|$|\?|#)",
    re.IGNORECASE
)


def extract_tweet_url_and_id(text: str) -> Tuple[Optional[str], Optional[str]]:
    """Extracts (screen_name, tweet_id) from text containing a tweet link."""
    m = TWEET_URL_REGEX.search(text)
    if m:
        return m.group(1), m.group(2)
    return None, None


async def fetch_tweet_data(screen_name: str, tweet_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetches comprehensive tweet metadata from FxTwitter API.
    Cached in Cloudflare L1 RAM.
    """
    cache_key = f"TWEET_DATA_{screen_name.lower()}_{tweet_id}"
    cached = database.l1_get(cache_key)
    if cached and isinstance(cached, dict):
        return cached

    client = get_http_client()
    url = f"https://api.fxtwitter.com/{screen_name}/status/{tweet_id}"
    try:
        r = await client.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            timeout=10.0
        )
        if r.status_code == 200:
            data = r.json()
            tweet = data.get("tweet")
            if tweet:
                database.l1_set(cache_key, tweet, ttl_sec=1800)
                return tweet
    except Exception as e:
        logger.warning(f"Failed to fetch tweet {url}: {e}")

    return None


async def fetch_twitter_profile(screen_name: str) -> Optional[Dict[str, Any]]:
    """
    Fetches Twitter user profile details from FxTwitter API.
    Cached in Cloudflare L1 RAM.
    """
    clean_handle = screen_name.lstrip("@").strip()
    cache_key = f"TWITTER_USER_{clean_handle.lower()}"
    cached = database.l1_get(cache_key)
    if cached and isinstance(cached, dict):
        return cached

    client = get_http_client()
    url = f"https://api.fxtwitter.com/{clean_handle}"
    try:
        r = await client.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            timeout=10.0
        )
        if r.status_code == 200:
            data = r.json()
            user = data.get("user")
            if user:
                database.l1_set(cache_key, user, ttl_sec=3600)
                return user
    except Exception as e:
        logger.warning(f"Failed to fetch user profile {url}: {e}")

    return None


def format_tweet_report(tweet: Dict[str, Any]) -> str:
    """Formats full tweet data into a clean, rich Telegram HTML message."""
    author = tweet.get("author") or {}
    name = author.get("name") or "کاربر"
    screen_name = author.get("screen_name") or "نامشخص"
    verified = " 🔹" if author.get("verification", {}).get("verified") else ""
    followers = author.get("followers")

    text = tweet.get("text") or "(بدون متن)"
    created_at = tweet.get("created_at") or ""
    url = tweet.get("url") or f"https://x.com/{screen_name}/status/{tweet.get('id')}"

    # Stats
    likes = tweet.get("likes") or 0
    retweets = tweet.get("retweets") or 0
    replies = tweet.get("replies") or 0
    views = tweet.get("views")

    parts = [
        f"🐦 <b>توییت از <a href=\"https://x.com/{screen_name}\">{html.escape(name)}</a> (@{html.escape(screen_name)}){verified}</b>"
    ]

    if followers:
        parts.append(f"👥 دنبال‌کنندگان نویسنده: <code>{followers:,}</code>")
    if created_at:
        parts.append(f"🕒 زمان انتشار: <code>{html.escape(created_at)}</code>")

    parts.append("\n📝 <b>متن توییت:</b>\n" + html.escape(text))

    # Media
    media = tweet.get("media") or {}
    photos = media.get("photos") or []
    videos = media.get("videos") or []

    media_notes = []
    if photos:
        p_links = [f'<a href="{p.get("url")}">تصویر {i}</a>' for i, p in enumerate(photos, 1) if p.get("url")]
        if p_links:
            media_notes.append("🖼 <b>تصاویر:</b> " + " | ".join(p_links))

    if videos:
        v_links = []
        for i, v in enumerate(videos, 1):
            v_url = v.get("url") or (v.get("variants") or [{}])[0].get("url")
            if v_url:
                v_links.append(f'<a href="{v_url}">دانلود مستقیم ویدیو {i}</a>')
        if v_links:
            media_notes.append("🎥 <b>ویدیوها:</b> " + " | ".join(v_links))

    if media_notes:
        parts.append("\n" + "\n".join(media_notes))

    # Quote tweet
    quote = tweet.get("quote")
    if quote:
        q_author = quote.get("author", {}).get("name") or "کاربر"
        q_screen = quote.get("author", {}).get("screen_name") or ""
        q_text = quote.get("text") or ""
        parts.append(f"\n🔄 <b>نقل‌قول (Quote) از {html.escape(q_author)} (@{html.escape(q_screen)}):</b>\n<i>{html.escape(q_text[:200])}</i>")

    # Stats block
    stat_parts = [f"❤️ {likes:,}", f"🔁 {retweets:,}", f"💬 {replies:,}"]
    if views:
        stat_parts.append(f"👁️ {views:,}")
    parts.append("\n📊 <b>تعاملات:</b> " + " | ".join(stat_parts))
    parts.append(f"🔗 <a href=\"{url}\">مشاهده مستقیم در X (توییتر)</a>")

    return "\n".join(parts)


def format_profile_report(user: Dict[str, Any]) -> str:
    """Formats Twitter user profile details into Telegram HTML."""
    name = user.get("name") or "کاربر"
    screen_name = user.get("screen_name") or "نامشخص"
    desc = user.get("description") or "(بدون بیوگرافی)"
    followers = user.get("followers") or 0
    following = user.get("following") or 0
    tweets = user.get("tweets") or user.get("media_count") or 0
    joined = user.get("joined") or ""
    verified = " 🔹" if user.get("verification", {}).get("verified") else ""
    url = user.get("url") or f"https://x.com/{screen_name}"
    website = user.get("website", {}).get("url") if isinstance(user.get("website"), dict) else None

    parts = [
        f"👤 <b>پروفایل X (توییتر): <a href=\"{url}\">{html.escape(name)}</a> (@{html.escape(screen_name)}){verified}</b>\n",
        f"🆔 شناسه کاربری: <code>@{html.escape(screen_name)}</code>",
        f"📝 <b>بیوگرافی:</b>\n{html.escape(desc)}\n",
        f"📊 <b>آمار:</b>",
        f"• 👥 <b>دنبال‌کنندگان (Followers):</b> <code>{followers:,}</code>",
        f"• 👣 <b>دنبال‌شوندگان (Following):</b> <code>{following:,}</code>",
        f"• 🔢 <b>تعداد توییت‌ها:</b> <code>{tweets:,}</code>",
    ]

    if joined:
        parts.append(f"📅 <b>تاریخ عضویت:</b> <code>{html.escape(joined)}</code>")
    if website:
        parts.append(f"🌐 <b>وب‌سایت:</b> <a href=\"{website}\">{html.escape(website)}</a>")

    parts.append(f"\n🔗 <a href=\"{url}\">باز کردن حساب در توییتر/X</a>")
    return "\n".join(parts)


async def search_twitter_live(query: str, max_results: int = 4) -> Optional[str]:
    """
    Performs live search on X/Twitter without API keys via DuckDuckGo POST query.
    Returns structured list of relevant tweets, authors, and snippets.
    """
    clean_q = query.strip()
    if not clean_q:
        return None

    cache_key = f"TWITTER_SEARCH_{clean_q.lower()}"
    cached = database.l1_get(cache_key)
    if cached and isinstance(cached, str):
        return cached

    search_query = f"site:x.com {clean_q}"
    client = get_http_client()
    try:
        data = urllib.parse.urlencode({"q": search_query})
        r = await client.post(
            "https://html.duckduckgo.com/html/",
            content=data,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=8.0
        )
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            snippets = soup.find_all("div", class_="result")
            items = []

            for div in snippets[:max_results]:
                snippet_elem = div.find("a", class_="result__snippet")
                url_elem = div.find("a", class_="result__url")
                title_elem = div.find("a", class_="result__title")

                content = snippet_elem.get_text(strip=True) if snippet_elem else ""
                url = url_elem.get("href") if url_elem else (title_elem.get("href") if title_elem else "")
                title = title_elem.get_text(strip=True) if title_elem else "توییت"

                if content and url:
                    # Clean URL if it is a DDG redirect
                    if "uddg=" in url:
                        m_url = re.search(r"uddg=([^&]+)", url)
                        if m_url:
                            url = urllib.parse.unquote(m_url.group(1))

                    items.append(f"📌 <b>{html.escape(title)}</b>\n{html.escape(content)}\n🔗 <a href=\"{url}\">مشاهده در X</a>")

            if items:
                report = (
                    f"🔍 <b>نتایج جستجو در شبکه X (توییتر) برای «{html.escape(clean_q)}»:</b>\n\n"
                    + "\n\n".join(items)
                )
                database.l1_set(cache_key, report, ttl_sec=600)
                return report
    except Exception as e:
        logger.warning(f"Twitter search failed: {e}")

    return None


def parse_twitter_request(text: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Parses user input to identify Twitter/X actions.
    Returns:
        (is_matched, action_type ['tweet', 'profile', 'search'], target_query)
    """
    t = text.strip()

    # 1. Direct tweet link found anywhere in text
    screen_name, tweet_id = extract_tweet_url_and_id(t)
    if screen_name and tweet_id:
        return True, "tweet", f"{screen_name}:{tweet_id}"

    # 2. Commands: /tweet, /twitter, /x
    cmd_match = re.match(r"^/(?:tweet|twitter|توییت|توییتر)(?:@\w+)?(?:\s+(.+))?$", t, re.IGNORECASE)
    if cmd_match:
        arg = (cmd_match.group(1) or "").strip()
        if not arg:
            return True, "help", None
        # Check if arg is a tweet URL
        sn, tid = extract_tweet_url_and_id(arg)
        if sn and tid:
            return True, "tweet", f"{sn}:{tid}"
        # Check if arg is a user handle (@username or username without spaces)
        if arg.startswith("@") or (not " " in arg and len(arg) <= 25 and not any(p in arg for p in ["سرچ", "جستجو"])):
            return True, "profile", arg.lstrip("@")
        # Otherwise search query
        return True, "search", arg

    # 3. Natural language queries for Twitter search
    search_patterns = [
        r"(?:توی|در)\s*(?:توییتر|ایکس|x|twitter)\s*(?:سرچ\s*کن|بگرد|جستجو\s*کن|چی\s*میگن|چه\s*خبره|درباره)\s*[:\s]?\s*(.+)",
        r"(?:سرچ|جستجو)\s*(?:توییتر|توییت)\s*[:\s]?\s*(.+)",
    ]
    for sp in search_patterns:
        m = re.search(sp, t, re.IGNORECASE)
        if m:
            q = m.group(1).strip()
            if q:
                return True, "search", q

    # 4. Natural language queries for user profiles
    profile_pattern = re.search(r"(?:توییت‌های|توییت\s*های|پروفایل|اکانت|پیج|حساب)\s*(?:توییتر|ایکس)?\s*@?([a-zA-Z0-9_]{2,25})\s*(?:رو\s*ببین|چیه|نشون\s*بده|بده)?", t, re.IGNORECASE)
    if profile_pattern:
        handle = profile_pattern.group(1).strip()
        return True, "profile", handle

    return False, None, None
