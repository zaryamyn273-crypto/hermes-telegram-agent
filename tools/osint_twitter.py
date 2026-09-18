"""
Prometheus OSINT Suite - Twitter / X Deep Reconnaissance Engine (شناسایی پیشرفته توییتر و شبکه ایکس)
Extracts live user profiles, numeric Twitter IDs, account creation date, bio, followers,
tweets, likes, media counts, and historical Wayback Machine / Google Dorking pivots.
"""

import re
import html
import logging
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from utils.formatter import wrap_in_expandable_blockquote
from tools.public_db_intel import query_wayback_snapshots
from tools.osint_search import search_web_osint

logger = logging.getLogger("OSINT_Twitter")

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
}


def clean_twitter_handle(input_text: str) -> str:
    """Extracts clean Twitter / X screen name from user input or URL."""
    if not input_text:
        return ""
    t = input_text.strip()
    # Strip URL structures
    t = re.sub(r"^https?://(?:www\.)?(?:x\.com|twitter\.com)/", "", t, flags=re.IGNORECASE)
    t = t.split("/")[0].split("?")[0].split("#")[0].strip()
    t = t.lstrip("@").strip()
    # Sanitize valid Twitter screen names (1-15 chars, alphanumeric + underscore)
    t = re.sub(r"[^a-zA-Z0-9_]", "", t)
    return t[:15]


async def investigate_twitter_profile(target: str) -> Dict[str, Any]:
    """
    Performs full OSINT reconnaissance on a Twitter / X account:
    - Queries real-time public Twitter syndication & edge endpoints
    - Extracts Numeric User ID, Display Name, Bio, Creation Date, Followers, Following, Tweets, Likes
    - In case of 404/suspension, queries Wayback Machine and Google Dorking for historical footprint
    """
    handle = clean_twitter_handle(target)
    if not handle:
        return {
            "success": False,
            "handle": target,
            "error": "نام کاربری توییتر / X نامعتبر است (صرفاً حروف انگلیسی، اعداد و آندرلاین مجاز است)."
        }

    api_url = f"https://api.fxtwitter.com/{handle}"
    user_data = None
    is_live = False

    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(api_url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("code") == 200 and data.get("user"):
                    user_data = data["user"]
                    is_live = True
            elif resp.status_code == 404:
                is_live = False
            else:
                logger.debug(f"FxTwitter responded with {resp.status_code} for {handle}")
    except Exception as e:
        logger.warning(f"Error querying FxTwitter for {handle}: {e}")

    # Generate Google Dork Queries for Twitter/X
    q_posts = f"site:x.com/{handle}/status"
    q_mentions = f'(site:x.com OR site:twitter.com) "@{handle}"'
    q_media = f'site:x.com/{handle}/status ("pic.twitter.com" OR "video")'

    dorks = [
        {
            "title": "توییت‌ها و پست‌های مستقیم",
            "query": q_posts,
            "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(q_posts)}"
        },
        {
            "title": "منشن‌ها و ریپلای‌های دریافتی",
            "query": q_mentions,
            "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(q_mentions)}"
        },
        {
            "title": "رسانه‌ها، ویدیوها و تصاویر کاربر",
            "query": q_media,
            "url": f"https://www.google.com/search?q={urllib.parse.quote_plus(q_media)}"
        }
    ]

    wayback_target = f"https://x.com/{handle}"

    if is_live and user_data:
        # User is active and verified
        raw_joined = user_data.get("joined", "")
        # Format human-readable date if possible
        joined_fmt = raw_joined
        if raw_joined and " " in raw_joined:
            parts = raw_joined.split()
            if len(parts) >= 6:
                # e.g. "Tue Jun 02 20:12:29 +0000 2009" -> "Jun 2009"
                joined_fmt = f"{parts[1]} {parts[5]}"

        raw_web = user_data.get("website", "")
        website_str = raw_web.get("url", "") if isinstance(raw_web, dict) else (str(raw_web) if raw_web else "")

        return {
            "success": True,
            "found": True,
            "handle": handle,
            "name": user_data.get("name", handle),
            "numeric_id": str(user_data.get("id", "")),
            "bio": user_data.get("description", "").strip(),
            "followers": user_data.get("followers", 0),
            "following": user_data.get("following", 0),
            "tweets": user_data.get("tweets", 0),
            "likes": user_data.get("likes", 0),
            "media_count": user_data.get("media_count", 0),
            "joined_raw": raw_joined,
            "joined_date": joined_fmt,
            "avatar_url": user_data.get("avatar_url", ""),
            "banner_url": user_data.get("banner_url", ""),
            "website": website_str,
            "url": f"https://x.com/{handle}",
            "dorks": dorks,
            "wayback_url": f"https://web.archive.org/web/*/{wayback_target}"
        }

    # If not found on live API (Suspended / Deleted / Never existed)
    # Perform OSINT fallback: Wayback Machine check and web mentions
    archive_info = await query_wayback_snapshots(wayback_target)
    web_hits = await search_web_osint(f'(site:x.com OR site:twitter.com) "@{handle}"', max_results=3)

    return {
        "success": True,
        "found": False,
        "handle": handle,
        "name": "",
        "numeric_id": "",
        "bio": "",
        "message": f"حساب کاربری @{handle} در حال حاضر روی سرورهای زنده X/Twitter یافت نشد (ممکن است حذف شده، تغییر نام داده یا تعلیق/Suspended شده باشد).",
        "url": f"https://x.com/{handle}",
        "dorks": dorks,
        "archive_info": archive_info,
        "web_hits": web_hits.get("results", []) if web_hits.get("success") else [],
        "wayback_url": f"https://web.archive.org/web/*/{wayback_target}"
    }


def format_twitter_report(data: Dict[str, Any]) -> str:
    """Formats Twitter / X intelligence results into rich Persian Telegram HTML."""
    if not data.get("success"):
        return f"❌ <b>خطا در استعلام حساب توییتر:</b> {html.escape(data.get('error', 'نامشخص'))}"

    handle = data.get("handle", "")
    found = data.get("found", False)

    lines = [
        "🕊 <b>گزارش شناسایی و OSINT حساب توییتر / X:</b>",
        f"▫️ نام کاربری (Handle): <code>@{html.escape(handle)}</code>",
    ]

    if found:
        name = data.get("name", handle)
        num_id = data.get("numeric_id", "")
        joined = data.get("joined_date", "نامشخص")
        bio = data.get("bio", "")
        followers = data.get("followers", 0)
        following = data.get("following", 0)
        tweets = data.get("tweets", 0)
        likes = data.get("likes", 0)
        media = data.get("media_count", 0)
        url = data.get("url", f"https://x.com/{handle}")
        website = data.get("website", "")

        lines.append(f"▫️ نام نمایشی: <b>{html.escape(name)}</b>")
        if num_id:
            lines.append(f"▫️ 🆔 <b>شناسه عددی (Numeric Twitter ID):</b> <code>{num_id}</code>")
        if joined:
            lines.append(f"▫️ 📅 <b>تاریخ ثبت‌نام:</b> <code>{html.escape(joined)}</code>")
        if website:
            lines.append(f"▫️ 🌐 <b>وب‌سایت درج‌شده:</b> <a href=\"{website}\">{html.escape(website[:40])}</a>")

        lines.append(f"\n🔗 <b>لینک مستقیم پروفایل:</b> <a href=\"{url}\">{url}</a>\n")

        # Metrics Block
        metrics_block = (
            f"• 👥 <b>تعداد دنبال‌کنندگان (Followers):</b> <code>{followers:,}</code>\n"
            f"• 👤 <b>دنبال‌شدگان (Following):</b> <code>{following:,}</code>\n"
            f"• 📝 <b>تعداد کل توییت‌ها:</b> <code>{tweets:,}</code>\n"
            f"• ❤️ <b>تعداد لایک‌ها:</b> <code>{likes:,}</code>\n"
            f"• 🖼 <b>رسانه‌های ارسالی:</b> <code>{media:,}</code>"
        )
        lines.append(f"📊 <b>آمار تعاملات و وضعیت حساب:</b>\n{wrap_in_expandable_blockquote(metrics_block)}")

        if bio:
            lines.append(f"\n📝 <b>بیوگرافی و توضیحات نمایه (Bio):</b>\n{wrap_in_expandable_blockquote(html.escape(bio))}")

    else:
        # Not found on live X
        msg = data.get("message", "حساب در شبکه زنده یافت نشد.")
        lines.append(f"\n⚠️ <b>وضعیت حساب:</b> {msg}\n")

        archive = data.get("archive_info", {})
        if archive.get("found"):
            lines.append(
                f"🏛 <b>ردپای آرشیوی در Wayback Machine:</b>\n"
                f"• تعداد نسخه‌های ذخیره‌شده: <code>{archive.get('total_snapshots', 0)}</code>\n"
                f"• تاریخ اولین ثبت: <code>{archive.get('first_seen', 'نامشخص')}</code>\n"
                f"• <a href=\"{archive.get('archive_url')}\">مشاهده آخرین نسخه آرشیو شده</a>\n"
            )

        hits = data.get("web_hits", [])
        if hits:
            hit_lines = []
            for h in hits[:3]:
                t = html.escape(h.get("title", "نتیجه وب"))
                u = h.get("url", "#")
                s = html.escape(h.get("snippet", "")[:120])
                hit_lines.append(f"• <a href=\"{u}\">{t}</a>: <i>{s}...</i>")
            lines.append(f"🔍 <b>سوابق و منشن‌های کشف‌شده در وب:</b>\n{wrap_in_expandable_blockquote(chr(10).join(hit_lines))}\n")

    # Dorks Section
    dorks = data.get("dorks", [])
    if dorks:
        dork_lines = []
        for d in dorks:
            t = d.get("title", "جستجو")
            u = d.get("url", "#")
            q = html.escape(d.get("query", ""))
            dork_lines.append(f"• <a href=\"{u}\">{t}</a>\n  <code>{q}</code>")
        lines.append(f"\n🎯 <b>دورک‌های اختصاصی گوگل برای ردیابی این اکانت:</b>\n{wrap_in_expandable_blockquote(chr(10).join(dork_lines))}")

    lines.append("\n⚡️ <i>استعلام بلادرنگ داده‌های هویتی، آمار و شناسه یکتای عددی پلتفرم X</i>")
    return "\n".join(lines)
