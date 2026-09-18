"""
Autonomous Conversation Summarization Tool for Prometheus (Hermes Telegram Agent):
- Capable of analyzing up to 3,000 messages per group/chat.
- Utilizes dual lightweight sub-agents (Map-Reduce architecture) with fast models to process large conversations.
- Strict chat isolation: only reads messages belonging to the requested chat_id.
- Employs Telegram-native Expandable Blockquotes (<blockquote expandable>) for collapsible executive reports.
"""

import re
import html
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple

import database
from config import get_candidate_endpoints, settings

logger = logging.getLogger("SummaryTool")

_PERSIAN_DIGITS_MAP = {
    '۰': '0', '۱': '1', '۲': '2', '۳': '3', '۴': '4',
    '۵': '5', '۶': '6', '۷': '7', '۸': '8', '۹': '9',
    '٠': '0', '١': '1', '٢': '2', '٣': '3', '٤': '4',
    '٥': '5', '٦': '6', '٧': '7', '٨': '8', '٩': '9'
}


def _normalize_persian_digits(text: str) -> str:
    """Converts Persian and Arabic digits into standard ASCII digits."""
    return "".join(_PERSIAN_DIGITS_MAP.get(ch, ch) for ch in text)


def parse_summary_request(text: str) -> Tuple[bool, int]:
    """
    Detects if the user query is asking to summarize group conversation history.
    Returns (is_summary_request, requested_count).
    Default count is 100 messages (capped between 10 and 3000).
    """
    if not text:
        return False, 0

    t = _normalize_persian_digits(text.strip().lower())
    t = t.replace("ي", "ی").replace("ك", "ک").replace("\u200c", " ")

    # 1. Slash commands: /summarize [N], /summary [N], /recap [N], /kholase [N], /خلاصه [N]
    slash_match = re.match(r"^/(?:summarize|summary|recap|kholase|خلاصه|گزارش)(?:@\w+)?(?:\s+(\d+))?$", t)
    if slash_match:
        cnt_str = slash_match.group(1)
        cnt = int(cnt_str) if cnt_str else 100
        return True, min(3000, max(10, cnt))

    # Standalone exact keywords
    exact_triggers = {
        "خلاصه", "خلاصه کن", "خلاصه بکن", "خلاصه بده", "خلاصه بگو", "گزارش بده",
        "خلاصه چت", "خلاصه گفتگو", "خلاصه پیام‌ها", "خلاصه پیام ها",
        "recap", "summary", "summarize", "خلاصه ساز", "خلاصه کننده"
    }
    if t in exact_triggers:
        return True, 100

    # Extract count if explicitly mentioned in text (e.g. "۵۰ پیام", "100 تا پیام", "خلاصه 200 پیام")
    cnt = 100
    num_m = re.search(r"(\d+)\s*(?:پیام|چت|مسیج|تا|مورد)?", t)
    if num_m and num_m.group(1):
        try:
            val = int(num_m.group(1))
            if 10 <= val <= 3000:
                cnt = val
        except ValueError:
            pass

    # 2. Comprehensive Persian natural patterns
    patterns = [
        r"(?:خلاصه|سامری|recap|گزارش)\s*(?:کن|بکن|بده|بگو|بفرست|ساز|کننده)?",
        r"(?:چت|پیام|مسیج|گفتگو|گروه|روم|کانال|بحث)\s*(?:ها|های)?\s*(?:اخیر)?\s*(?:رو|را)?\s*(?:خلاصه|سامری)\s*(?:کن|بکن|بده|بگو|بفرست)",
        r"(?:خلاصه|سامری|گزارش)\s+(?:از\s+)?(?:\d+\s+)?(?:چت|پیام|مسیج|گفتگو|گروه|روم|کانال|بحث)",
        r"(?:یک\s+)?(?:خلاصه|گزارش|سامری)\s+(?:از\s+)?(?:چت|پیام|گفتگو|بحث)",
        r"(?:چی\s+گفتن|بحث\s+سر\s+چی\s+بود|کی\s+چی\s+گفت|موضوع\s+چی\s+بود|چه\s+خبر\s+بود|از\s+چی\s+صحبت\s+شد)",
        r"(\d+)\s*(?:پیام|چت|گفتگو)\s*(?:اخیر)?\s*(?:رو|را)?\s*خلاصه\s*(?:کن|بکن|بده)",
        r"(?:خلاصه|گزارش)\s+(?:امروز|دیشب|اخیر|گروه|چت)",
    ]

    for pat in patterns:
        if re.search(pat, t):
            return True, min(3000, max(10, cnt))

    return False, 0


async def _call_fast_subagent(messages: List[Dict[str, str]], max_tokens: int = 1200) -> Optional[str]:
    """Dispatches a lightweight prompt to fast model endpoints for high-speed sub-agent execution."""
    from agent_engine import get_http_client
    from utils.formatter import strip_thinking
    client = get_http_client()

    candidate_endpoints = get_candidate_endpoints(force_fast=True)
    hermes_candidates = get_candidate_endpoints(force_hermes=True)
    all_endpoints = candidate_endpoints + [ep for ep in hermes_candidates if ep not in candidate_endpoints]

    for api_url, api_key, model in all_endpoints:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "temperature": 0.2,
            "max_tokens": max_tokens,
        }
        try:
            resp = await client.post(
                f"{api_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=25.0
            )
            if resp.status_code == 200:
                data = resp.json()
                choices = data.get("choices") or []
                if choices:
                    content = (choices[0].get("message") or {}).get("content") or ""
                    clean_content = strip_thinking(content).strip()
                    if clean_content:
                        return clean_content
        except Exception as e:
            logger.debug(f"Fast subagent call to {api_url} failed: {e}")
            continue

    return None


def _format_messages_for_llm(raw_messages: List[Dict[str, Any]]) -> str:
    """Formats a list of message dicts into a clean, compact chronological transcript."""
    lines = []
    for m in raw_messages:
        time_part = str(m.get("created_at") or "")[11:16] or "--:--"
        name = m.get("full_name") or m.get("username") or f"کاربر {m.get('user_id', '')}"
        role_tag = "[ربات]" if m.get("is_bot") or m.get("role") == "assistant" else ""
        content = (m.get("content") or "").strip().replace("\n", " ")
        if len(content) > 250:
            content = content[:250] + "..."
        lines.append(f"[{time_part}] {name}{role_tag}: {content}")
    return "\n".join(lines)


async def summarize_group_messages(
    chat_id: int,
    count: int = 100,
    chat_title: str = ""
) -> str:
    """
    Core Autonomous Summarizer for Prometheus:
    - Fetches up to `count` messages (max 3000) for `chat_id` with strict database isolation.
    - If messages > 150, deploys dual parallel sub-agents (Part 1 & Part 2 Analyzers) and synthesizes.
    - Encapsulates detailed output inside Telegram Expandable Blockquotes (<blockquote expandable>).
    """
    clean_count = min(3000, max(10, count))
    logger.info(f"Summarizing up to {clean_count} messages for chat {chat_id} ('{chat_title}')...")

    # 1. Fetch messages strictly scoped to chat_id
    raw_msgs = await database.get_chat_messages_for_summary(chat_id, limit=clean_count)
    total_found = len(raw_msgs)

    if total_found == 0:
        from agent_engine import get_session_history
        session_msgs = get_session_history(chat_id)
        if session_msgs:
            raw_msgs = [
                {
                    "full_name": m.get("username") or ("پرومته" if m.get("role") == "assistant" else "کاربر"),
                    "username": m.get("username") or "",
                    "user_id": m.get("user_id") or 0,
                    "role": m.get("role") or "user",
                    "content": m.get("content") or "",
                    "created_at": "",
                    "is_bot": 1 if m.get("role") == "assistant" else 0
                }
                for m in session_msgs[-clean_count:]
                if (m.get("content") or "").strip()
            ]
            total_found = len(raw_msgs)

    if total_found == 0:
        return (
            "ℹ️ <b>هنوز پیامی برای این گفتگو در پایگاه داده ثبت نشده است.</b>\n\n"
            "💡 <i>پرومته از این پس پیام‌های جدید ارسالی در گروه را به صورت خودکار و تفکیک‌شده ثبت می‌کند "
            "تا در هر زمان بتوانید گزارش و خلاصه هوشمند تا سقف ۳۰۰۰ پیام را دریافت نمایید.</i>"
        )

    # 2. Compute metadata metrics
    unique_users = {
        m.get("full_name") or m.get("username") or str(m.get("user_id"))
        for m in raw_msgs
        if not m.get("is_bot") and m.get("role") != "assistant"
    }
    first_time = str(raw_msgs[0].get("created_at") or "")[:16]
    last_time = str(raw_msgs[-1].get("created_at") or "")[:16]
    time_span = f"از {first_time} تا {last_time}" if first_time and last_time else "اخیر"
    title_label = f" «{html.escape(chat_title)}»" if chat_title else ""

    header_box = (
        f"📊 <b>گزارش هوشمند گفتگو{title_label}:</b>\n"
        f"• ✉️ <b>پیام‌های بررسی‌شده:</b> <code>{total_found}</code> پیام (از درخواست <code>{clean_count}</code>)\n"
        f"• ⏱ <b>بازه زمانی:</b> {time_span}\n"
        f"• 👥 <b>کاربران فعال:</b> <code>{len(unique_users)}</code> نفر"
    )

    # 3. Execution Path: Single Agent vs Dual Sub-Agents (Map-Reduce)
    summary_body = ""

    if total_found <= 150:
        # Single fast pass
        transcript = _format_messages_for_llm(raw_msgs)
        prompt = (
            "شما ساب‌اجنت تحلیل گفتگو برای پرومته هستید. "
            "متن زیر تاریخچه پیام‌های یک گروه تلگرامی است. یک گزارش خلاصه بسیار حرفه‌ای، دقیق، روان و ساختاریافته به زبان فارسی ارائه دهید.\n"
            "گزارش باید شامل بخش‌های زیر باشد:\n"
            "💡 موضوعات و مباحث کلیدی مطرح‌شده (با ذکر نکات برجسته)\n"
            "👥 مشارکت اعضا و نظرات محوری کاربران فعال\n"
            "📌 تصمیمات، نتایج یا توافقات صورت‌گرفته\n"
            "❓ پرسش‌ها یا چالش‌های باز و بی‌پاسخ\n\n"
            f"متن گفتگو ({total_found} پیام):\n{transcript}"
        )
        res = await _call_fast_subagent([{"role": "user", "content": prompt}], max_tokens=1400)
        if res:
            summary_body = res
    else:
        # Dual Sub-Agent Architecture for large conversations (150 to 3000 messages)
        half_idx = total_found // 2
        part1_msgs = raw_msgs[:half_idx]
        part2_msgs = raw_msgs[half_idx:]

        transcript1 = _format_messages_for_llm(part1_msgs)
        transcript2 = _format_messages_for_llm(part2_msgs)

        subagent1_prompt = (
            "شما ساب‌اجنت ۱ (تحلیل‌گر نیمه اول گفتگو) هستید. "
            "پیام‌های نیمه اول یک گفتگوی گروهی تلگرام را تحلیل کنید و موارد زیر را خلاصه نمایید:\n"
            "۱. شروع مباحث و موضوعات کلیدی مطرح‌شده\n"
            "۲. دغدغه‌ها و سوالات مهمی که کاربران مطرح کردند\n"
            "۳. کاربران فعال و مواضع اصلی آن‌ها\n\n"
            f"نیمه اول پیام‌ها ({len(part1_msgs)} پیام):\n{transcript1}"
        )

        subagent2_prompt = (
            "شما ساب‌اجنت ۲ (تحلیل‌گر نیمه دوم گفتگو) هستید. "
            "پیام‌های نیمه دوم همان گفتگوی گروهی تلگرام را تحلیل کنید و موارد زیر را خلاصه نمایید:\n"
            "۱. روند ادامه گفتگو و موضوعات جدید شکل‌گرفته\n"
            "۲. پاسخ‌ها، راه‌حل‌ها، واکنش‌ها و نتایج\n"
            "۳. تصمیمات اتخاذ شده، توافقات یا مسائل حل‌نشده پایانی\n\n"
            f"نیمه دوم پیام‌ها ({len(part2_msgs)} پیام):\n{transcript2}"
        )

        logger.info(f"Dispatching Dual Sub-Agents concurrently for {total_found} messages...")
        # Run Sub-Agent 1 and Sub-Agent 2 concurrently!
        task1 = _call_fast_subagent([{"role": "user", "content": subagent1_prompt}], max_tokens=1000)
        task2 = _call_fast_subagent([{"role": "user", "content": subagent2_prompt}], max_tokens=1000)
        res1, res2 = await asyncio.gather(task1, task2, return_exceptions=True)

        part1_summary = res1 if isinstance(res1, str) and res1 else "(اطلاعات نیمه اول در دسترس نیست)"
        part2_summary = res2 if isinstance(res2, str) and res2 else "(اطلاعات نیمه دوم در دسترس نیست)"

        # Chief Synthesizer Sub-Agent combines findings into master report
        synthesizer_prompt = (
            "شما اجنت ارشد تجمیع و گزارش‌دهی پرومته هستید. "
            "دو ساب‌اجنت شما نیمه اول و نیمه دوم یک گفتگوی گروهی بزرگ تلگرام را بررسی کرده‌اند. "
            "این دو تحلیل را تجمیع نموده و یک گزارش جامع، پیوسته، ساختاریافته و فوق‌العاده کاربردی به زبان فارسی بنویسید.\n"
            "ساختار الزامی گزارش:\n"
            "💡 مباحث و محورهای کلیدی گفتگو (سیر کلی موضوعات از ابتدا تا انتها)\n"
            "👥 مشارکت و دیدگاه‌های کاربران فعال\n"
            "📌 تصمیمات نهایی، جمع‌بندی‌ها و توافقات حاصل‌شده\n"
            "❓ ابهامات، سوالات بی‌پاسخ یا چالش‌های باقی‌مانده\n\n"
            f"[تحلیل ساب‌اجنت ۱ - نیمه اول]:\n{part1_summary}\n\n"
            f"[تحلیل ساب‌اجنت ۲ - نیمه دوم]:\n{part2_summary}"
        )

        master_res = await _call_fast_subagent([{"role": "user", "content": synthesizer_prompt}], max_tokens=1800)
        if master_res:
            summary_body = master_res

    # Fallback if LLM sub-agents temporarily failed
    if not summary_body:
        top_users = ", ".join(list(unique_users)[:5])
        sample_snippets = []
        for m in raw_msgs[-5:]:
            content = (m.get("content") or "").strip().replace("\n", " ")
            name = m.get("full_name") or m.get("username") or "کاربر"
            if content:
                sample_snippets.append(f"• <b>{html.escape(name)}:</b> {html.escape(content[:100])}")
        sample_text = "\n".join(sample_snippets)
        summary_body = (
            "💡 <b>خلاصه اجمالی پیام‌ها:</b>\n"
            f"در این بازه، گفتگو بین اعضا ({html.escape(top_users)}) جریان داشته و آخرین پیام‌های تبادل‌شده به شرح زیر است:\n\n"
            f"{sample_text}"
        )

    # Format output with Telegram native Expandable Blockquote (<blockquote expandable>)
    from utils.formatter import markdown_to_telegram_html, strip_thinking
    clean_summary = strip_thinking(summary_body).strip()
    formatted_body = markdown_to_telegram_html(clean_summary)

    final_report = (
        f"{header_box}\n\n"
        f"<blockquote expandable>\n"
        f"{formatted_body}\n"
        f"</blockquote>\n\n"
        f"💡 <i>روی کادر بالا کلیک کنید تا متن کامل گزارش باز شود.</i>"
    )

    return final_report
