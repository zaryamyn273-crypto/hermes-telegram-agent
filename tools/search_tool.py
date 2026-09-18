"""
High-Speed Group Message Search Tool for Prometheus (Hermes Telegram Agent):
- Executes lightning-fast, full-text FTS5 BM25 search over past messages.
- Strict chat isolation: messages are partitioned per chat_id.
- Employs Telegram-native Expandable Blockquotes (<blockquote expandable>) for clean, collapsible message snippets.
"""

import re
import html
import logging
from typing import Dict, Any, List, Optional, Tuple

import database

logger = logging.getLogger("SearchTool")


def parse_search_request(text: str) -> Tuple[bool, str]:
    """
    Detects if the user query is asking to search within past messages.
    Returns (is_search, search_query).
    """
    if not text:
        return False, ""

    t = text.strip()

    # Digikala, Google, or general web searches must NOT be hijacked by internal chat history search
    if re.search(r"(?:دیجی[\s\u200c]*کالا|دیجیکالا|digikala|گوگل|google|اینترنت|وب\b)", t, re.IGNORECASE):
        return False, ""

    # 1. Specific Persian natural search patterns
    patterns = [
        r"^(?:جستجو|سرچ|پیدا)\s*(?:کن|بکن)?\s+(?:توی|در)\s+(?:پیام‌ها|چت‌ها|پیامها|گروه|چت)(?:\s*[:،\-]?\s*)(.+)$",
        r"^(?:توی|در)\s+(?:پیام‌ها|چت‌ها|گروه|چت)\s*(?:جستجو|سرچ|پیدا)\s*(?:کن|بکن)(?:\s*[:،\-]?\s*)(.+)$",
        r"^(?:پیام‌های|پیامهای)\s+مربوط\s+به\s+(.+)$",
        r"^(?:توی|در)\s+گروه\s+کی\s+گفته\s+بود\s+(.+)$",
        r"^کی\s+(?:توی|در)\s+گروه\s+گفته\s+بود\s+(.+)$",
        r"^دنبال\s+(.+)\s+(?:توی|در)\s+(?:پیام‌ها|چت|گروه)\s*بگرد$",
        r"^(?:پیام‌های|پیامهای|چت‌های|چتهای)\s+(.+)\s+رو\s+(?:پیدا|سرچ|جستجو)\s*(?:کن|بکن)$",
    ]
    for pat in patterns:
        m2 = re.search(pat, t, re.IGNORECASE)
        if m2:
            q = m2.group(1).strip()
            if q:
                return True, q

    # 2. Explicit slash commands: /search <query>, /find <query>, /search_msg <query>
    m = re.match(r"^/(?:search_msg|find_msg|search|find|جستجو|سرچ)\s+(.+)$", t, re.IGNORECASE)
    if m:
        q = m.group(1).strip()
        # Clean potential 'در پیام‌ها: ' prefix if present
        q = re.sub(r"^(?:در\s+(?:پیام‌ها|چت‌ها|گروه|پیامها|چت)\s*[:،\-]?\s*)", "", q).strip()
        if q:
            return True, q


    return False, ""


async def search_group_messages(
    chat_id: int,
    query: str,
    limit: int = 10,
    chat_title: str = ""
) -> str:
    """
    Searches past messages in the specified chat_id using SQLite FTS5 / indexed query.
    Returns formatted, copy-ready HTML with expandable message snippets.
    """
    clean_query = query.strip()
    clean_limit = min(20, max(1, limit))

    results = await database.search_messages_db(chat_id, clean_query, limit=clean_limit)

    title_label = f" «{html.escape(chat_title)}»" if chat_title else ""

    if not results:
        return (
            f"🔍 <b>نتیجه جستجو در گفتگو{title_label}:</b>\n\n"
            f"⚠️ پیامی حاوی عبارت <code>{html.escape(clean_query)}</code> در تاریخچه این گروه یافت نشد.\n\n"
            "💡 <i>نکته: پیام‌های جدید رد و بدل شده در گروه به مرور در حافظه پرومته ثبت و قابل جستجو خواهند بود.</i>"
        )

    res_parts = [
        f"🔍 <b>نتایج جستجو برای عبارت <code>{html.escape(clean_query)}</code>{title_label}:</b>",
        f"<i>تعداد {len(results)} پیام مرتبط یافت شد:</i>\n"
    ]

    for idx, r in enumerate(results, start=1):
        name = r.get("full_name") or r.get("username") or f"کاربر {r.get('user_id', '')}"
        uname = f" (@{r.get('username')})" if r.get("username") else ""
        date_str = str(r.get("created_at") or "")[:16]
        msg_id = r.get("message_id") or ""
        msg_id_tag = f" | #️⃣ پیام: <code>{msg_id}</code>" if msg_id else ""
        content = (r.get("content") or "").strip()

        # Highlighting query occurrence if applicable
        escaped_content = html.escape(content)
        escaped_q = html.escape(clean_query)
        try:
            highlighted = re.sub(
                re.escape(escaped_q),
                rf"<b><u>{escaped_q}</u></b>",
                escaped_content,
                flags=re.IGNORECASE
            )
        except Exception:
            highlighted = escaped_content

        res_parts.append(
            f"<b>{idx}. {html.escape(name)}{html.escape(uname)}</b>\n"
            f"⏱ <code>{date_str}</code>{msg_id_tag}\n"
            f"<blockquote expandable>\n{highlighted}\n</blockquote>"
        )

    res_parts.append("\n💡 <i>روی هر کادر ضربه بزنید تا متن کامل پیام باز شود.</i>")
    return "\n\n".join(res_parts)
