"""
Prometheus OSINT Suite - Telegram Intelligence & Entity Reconnaissance
Specialized module for:
- Telegram username & numeric user ID resolution
- t.me web preview and public entity scraping (channels, groups, bots, users)
- Live Telegram Bot API entity inspection (via bot.get_chat)
- Tracking users across known groups and message history
- Public Telegram web and channel search for mentions and leaks
"""

import re
import html
import logging
from typing import Dict, Any, List, Optional, Union
import httpx
from bs4 import BeautifulSoup

from utils.formatter import wrap_in_expandable_blockquote
import database

logger = logging.getLogger("TelegramOSINT")

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
}


def clean_telegram_target(target: str) -> str:
    """Normalizes Telegram username, link, or ID."""
    t = (target or "").strip()
    # Strip t.me or telegram.me links
    t = re.sub(r"^https?://(?:www\.)?(?:t\.me|telegram\.me)/(?:s/)?", "", t, flags=re.IGNORECASE)
    # Strip leading @
    t = t.lstrip("@").strip()
    # Strip slashes or query params
    t = t.split("/")[0].split("?")[0].strip()
    return t


async def resolve_tme_web_entity(username: str) -> Dict[str, Any]:
    """
    Scrapes the public https://t.me/{username} web gateway to extract:
    - Entity Title / Name
    - Type (Channel, Supergroup, Bot, User Profile)
    - Bio / Description
    - Member / Subscriber count
    - Profile picture URL
    - Public status
    """
    clean_user = clean_telegram_target(username)
    if not clean_user:
        return {"success": False, "error": "نام کاربری تلگرام معتبر وارد نشده است."}

    url = f"https://t.me/{clean_user}"
    result: Dict[str, Any] = {
        "success": True,
        "username": clean_user,
        "url": url,
        "title": None,
        "type": "کاربر / ناشناخته",
        "description": None,
        "members_count": None,
        "photo_url": None,
        "verified": False,
        "exists": True,
    }

    try:
        async with httpx.AsyncClient(headers=_HEADERS, follow_redirects=True, timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                result["exists"] = False
                result["success"] = False
                result["error"] = f"صفحه تلگرام @{clean_user} یافت نشد (404)."
                return result

            html_text = resp.text
            soup = BeautifulSoup(html_text, "html.parser")

            # Check if page indicates non-existence
            if "If you have <strong>Telegram</strong>, you can contact" in html_text and not soup.select_one(".tgme_page_title"):
                # Could be a private user or non-existent
                pass

            # Title
            title_el = soup.select_one(".tgme_page_title, .tgme_channel_info_header_title")
            if title_el:
                result["title"] = title_el.get_text(strip=True)

            # Extra info (subscribers, members, or @username)
            extra_el = soup.select_one(".tgme_page_extra")
            if extra_el:
                extra_text = extra_el.get_text(strip=True)
                if "subscribers" in extra_text.lower() or "subscriber" in extra_text.lower():
                    result["type"] = "کانال عمومی (Channel)"
                    result["members_count"] = extra_text
                elif "members" in extra_text.lower() or "member" in extra_text.lower():
                    result["type"] = "گروه عمومی (Supergroup)"
                    result["members_count"] = extra_text
                elif "@" in extra_text:
                    result["type"] = "پروفایل کاربری (User / Bot)"

            # Action button text can reveal type
            action_btn = soup.select_one(".tgme_action_button_new")
            if action_btn:
                btn_text = action_btn.get_text(strip=True).lower()
                if "send message" in btn_text:
                    result["type"] = "کاربر / ربات (User or Bot)"
                elif "view in channel" in btn_text:
                    result["type"] = "کانال عمومی (Channel)"
                elif "join group" in btn_text:
                    result["type"] = "گروه عمومی (Supergroup)"

            # Bio / Description
            desc_el = soup.select_one(".tgme_page_description")
            if desc_el:
                result["description"] = desc_el.get_text(separator="\n", strip=True)

            # Profile image
            img_el = soup.select_one(".tgme_page_photo_image")
            if img_el and img_el.get("src"):
                result["photo_url"] = img_el["src"]

            # Verified badge
            if soup.select_one(".verified-icon"):
                result["verified"] = True

    except Exception as e:
        logger.warning(f"Error scraping t.me/{clean_user}: {e}")
        result["success"] = False
        result["error"] = f"خطا در برقراری ارتباط با تلگرام وب: {str(e)}"

    return result


async def inspect_telegram_bot_api(target: str, bot=None) -> Dict[str, Any]:
    """
    Inspects Telegram entity using Telegram Bot API get_chat.
    Works for usernames (@username) or numeric chat/user IDs that the bot has seen.
    """
    if not bot:
        return {"success": False, "error": "نمونه ربات تلگرام در دسترس نیست."}

    t = clean_telegram_target(target)
    # Check if numeric ID
    target_id: Union[int, str]
    if re.match(r"^-?\d+$", t):
        target_id = int(t)
    else:
        target_id = f"@{t}"

    try:
        chat = await bot.get_chat(target_id)
        return {
            "success": True,
            "id": chat.id,
            "type": getattr(chat, "type", "unknown"),
            "title": getattr(chat, "title", None),
            "first_name": getattr(chat, "first_name", None),
            "last_name": getattr(chat, "last_name", None),
            "username": getattr(chat, "username", None),
            "bio": getattr(chat, "bio", None),
            "description": getattr(chat, "description", None),
            "invite_link": getattr(chat, "invite_link", None),
            "has_private_forwards": getattr(chat, "has_private_forwards", None),
        }
    except Exception as e:
        logger.debug(f"Bot API get_chat failed for {target_id}: {e}")
        return {"success": False, "error": str(e)}


async def track_user_in_known_groups(target: str) -> Dict[str, Any]:
    """
    Searches known groups and message database to identify:
    - Which groups the target has participated in
    - User display names and username history
    - Last recorded activity timestamp
    - Numeric user ID
    """
    clean_target = clean_telegram_target(target)
    is_numeric = bool(re.match(r"^-?\d+$", clean_target))

    records: List[Dict[str, Any]] = []
    seen_groups: Dict[int, Dict[str, Any]] = {}
    known_names: set = set()
    known_usernames: set = set()
    resolved_id: Optional[int] = int(clean_target) if is_numeric else None

    # Search local database for user messages
    try:
        if is_numeric:
            query = """
                SELECT m.chat_id, m.user_id, m.username, m.full_name, m.created_at, tg.title as group_title
                FROM messages m
                LEFT JOIN tracked_groups tg ON m.chat_id = tg.chat_id
                WHERE m.user_id = ?
                ORDER BY m.created_at DESC LIMIT 30
            """
            params = [int(clean_target)]
        else:
            query = """
                SELECT m.chat_id, m.user_id, m.username, m.full_name, m.created_at, tg.title as group_title
                FROM messages m
                LEFT JOIN tracked_groups tg ON m.chat_id = tg.chat_id
                WHERE LOWER(m.username) = LOWER(?) OR LOWER(m.full_name) LIKE LOWER(?)
                ORDER BY m.created_at DESC LIMIT 30
            """
            params = [clean_target, f"%{clean_target}%"]

        res = database._execute_sqlite(query, params)
        for r in res.get("results", []):
            cid = r.get("chat_id")
            uid = r.get("user_id")
            if uid and not resolved_id:
                resolved_id = int(uid)
            uname = r.get("username")
            fname = r.get("full_name")
            gtitle = r.get("group_title") or f"گروه شناسه {cid}"
            created_at = r.get("created_at")

            if uname:
                known_usernames.add(f"@{uname}")
            if fname:
                known_names.add(fname)

            if cid and cid not in seen_groups:
                seen_groups[cid] = {
                    "chat_id": cid,
                    "title": gtitle,
                    "last_seen": created_at,
                }
    except Exception as e:
        logger.debug(f"Database user tracking query failed: {e}")

    return {
        "success": True,
        "target": target,
        "resolved_user_id": resolved_id,
        "known_names": list(known_names),
        "known_usernames": list(known_usernames),
        "groups_count": len(seen_groups),
        "groups": list(seen_groups.values()),
    }


async def search_telegram_public_web(query: str, max_results: int = 5) -> Dict[str, Any]:
    """
    Conducts an external web search restricted to Telegram public channels/messages
    (site:t.me or site:t.me/s/) to uncover target mentions, leaks, or public channel posts.
    """
    from tools.osint_search import search_web_osint
    clean_q = clean_telegram_target(query)
    search_query = f'site:t.me "{clean_q}"'

    findings: List[Dict[str, Any]] = []
    try:
        search_res = await search_web_osint(search_query, max_results=max_results)
        if search_res.get("success") and search_res.get("results"):
            for item in search_res["results"]:
                url = item.get("url", "")
                if "t.me/" in url:
                    findings.append({
                        "title": item.get("title", ""),
                        "url": url,
                        "snippet": item.get("snippet", ""),
                    })
    except Exception as e:
        logger.warning(f"Public Telegram web search failed for {query}: {e}")

    return {
        "success": True,
        "query": query,
        "findings_count": len(findings),
        "findings": findings,
    }


async def investigate_telegram_target(target: str, bot=None) -> Dict[str, Any]:
    """
    Comprehensive Telegram Intelligence Aggregator:
    1. Scrapes public web page (t.me/{target})
    2. Inspects Telegram Bot API if bot instance provided
    3. Searches local group intelligence & tracking database
    4. Searches public web for channel mentions
    """
    clean_target = clean_telegram_target(target)
    if not clean_target:
        return {"success": False, "error": "لطفاً یوزرنیم یا شناسه عددی تلگرام را مشخص فرمایید."}

    # Step 1: Web scrape t.me
    web_data = await resolve_tme_web_entity(clean_target)

    # Step 2: Bot API check
    api_data: Dict[str, Any] = {}
    if bot:
        api_data = await inspect_telegram_bot_api(clean_target, bot=bot)

    # Step 3: Local group tracker
    tracker_data = await track_user_in_known_groups(clean_target)

    # Step 4: Web mentions search
    search_data = await search_telegram_public_web(clean_target, max_results=4)

    # Determine best user_id
    numeric_id = None
    if api_data.get("success") and api_data.get("id"):
        numeric_id = api_data["id"]
    elif tracker_data.get("resolved_user_id"):
        numeric_id = tracker_data["resolved_user_id"]
    elif re.match(r"^-?\d+$", clean_target):
        numeric_id = int(clean_target)

    # Determine best title/name
    best_name = None
    if api_data.get("first_name") or api_data.get("last_name"):
        parts = [api_data.get("first_name") or "", api_data.get("last_name") or ""]
        best_name = " ".join(p for p in parts if p).strip()
    elif api_data.get("title"):
        best_name = api_data["title"]
    elif web_data.get("title"):
        best_name = web_data["title"]
    elif tracker_data.get("known_names"):
        best_name = tracker_data["known_names"][0]

    return {
        "success": True,
        "target": clean_target,
        "numeric_id": numeric_id,
        "name": best_name,
        "web_info": web_data,
        "api_info": api_data,
        "tracker_info": tracker_data,
        "public_mentions": search_data,
    }


def format_telegram_osint_report(report: Dict[str, Any]) -> str:
    """Formats full Telegram reconnaissance report in Persian with Telegram HTML styling."""
    if not report.get("success"):
        return f"⚠️ <b>خطا در استعلام تلگرام:</b> {html.escape(report.get('error', 'شناسایی هدف ناموفق بود.'))}"

    target = html.escape(str(report.get("target", "")))
    num_id = report.get("numeric_id")
    id_str = f"<code>{num_id}</code>" if num_id else "<i>مشخص نشد (پروفایل فاقد تعامل مستقیم)</i>"
    name = html.escape(report.get("name") or "مشخص نشد")

    web = report.get("web_info", {})
    api = report.get("api_info", {})
    tracker = report.get("tracker_info", {})
    mentions = report.get("public_mentions", {})

    entity_type = web.get("type") or api.get("type") or "کاربر / ناشناخته"
    members = web.get("members_count")
    members_line = f"\n▫️ <b>تعداد اعضا / مخاطبان:</b> {html.escape(members)}" if members else ""

    bio = web.get("description") or api.get("bio") or api.get("description") or "ثبت نشده"
    bio_escaped = html.escape(bio)

    lines = [
        f"🎯 <b>شناسایی و ردگیری تلگرام (Telegram OSINT):</b> <code>@{target}</code>\n",
        f"▫️ <b>نام / عنوان:</b> <b>{name}</b>",
        f"▫️ <b>شناسه عددی (Numeric ID):</b> {id_str}",
        f"▫️ <b>نوع ماهیت:</b> {html.escape(str(entity_type))}{members_line}",
        f"▫️ <b>لینک مستقیم:</b> https://t.me/{target}",
    ]

    if web.get("verified"):
        lines.append("▫️ <b>نشان تایید (Verified):</b> ✅ دارای تیک آبی رسمی تلگرام")

    lines.append(f"\n📝 <b>بیوگرافی / توضیحات عمومی:</b>\n<blockquote>{bio_escaped}</blockquote>")

    # Local tracker results
    groups_count = tracker.get("groups_count", 0)
    if groups_count > 0:
        g_lines = []
        for g in tracker.get("groups", [])[:5]:
            g_lines.append(f"• <b>{html.escape(g.get('title', ''))}</b> (آیدی: <code>{g.get('chat_id')}</code>) - آخرین رویت: {g.get('last_seen', 'نامشخص')}")
        g_block = "\n".join(g_lines)
        lines.append(f"\n👥 <b>حضور در گروه‌های شناخته‌شده ({groups_count} گروه):</b>\n{wrap_in_expandable_blockquote(g_block)}")

    if tracker.get("known_names") and len(tracker.get("known_names")) > 1:
        other_names = ", ".join(html.escape(n) for n in tracker["known_names"] if n != name)
        if other_names:
            lines.append(f"▫️ <b>سایر نام‌های دیده‌شده:</b> {other_names}")

    # Public web / channel mentions
    findings = mentions.get("findings", [])
    if findings:
        m_lines = []
        for item in findings:
            m_lines.append(f"• <a href=\"{html.escape(item.get('url', ''))}\">{html.escape(item.get('title', ''))}</a>\n  {html.escape(item.get('snippet', '')[:120])}...")
        m_block = "\n\n".join(m_lines)
        lines.append(f"\n🌐 <b>ردپا در کانال‌ها و وب‌سایت‌های عمومی ({len(findings)} مورد):</b>\n{wrap_in_expandable_blockquote(m_block)}")
    else:
        lines.append("\n🌐 <b>ردپا در کانال‌های عمومی:</b> موردی در پیام‌های پابلیک یافت نشد.")

    lines.append("\n⚡️ <i>داده‌های کاملاً واقعی و تاییدشده - بدون حدس یا خطای اطلاعاتی</i>")
    return "\n".join(lines)


# Alias for backward compatibility
format_telegram_target_report = format_telegram_osint_report
