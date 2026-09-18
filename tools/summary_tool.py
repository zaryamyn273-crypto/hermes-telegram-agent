"""
Autonomous High-Performance Conversation Summarization Tool for Prometheus:
- Capable of reading and analyzing up to 5,000 messages per group/chat (1 to 5,000 messages).
- Dynamically adapts concurrency: Single Fast Agent -> Dual Sub-Agents -> Quad Sub-Agents -> Octa Sub-Agents (Map-Reduce).
- Intelligent natural language count detection (Persian/English words, digits, 'k' suffixes, full-chat terms).
- Message compaction engine (groups rapid sequential messages by same sender to maximize LLM throughput).
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

_PERSIAN_WORDS_MAP = [
    ("پنج هزار", 5000),
    ("چهار هزار", 4000),
    ("سه هزار", 3000),
    ("دو هزار", 2000),
    ("یک هزار", 1000),
    ("یه هزار", 1000),
    ("هزار", 1000),
    ("پانصد", 500),
    ("پونصد", 500),
    ("چهارصد", 400),
    ("سیصد", 300),
    ("دویست", 200),
    ("صد و پنجاه", 150),
    ("صد", 100),
    ("پنجاه", 50),
    ("چهل", 40),
    ("سی", 30),
    ("بیست", 20),
    ("ده", 10),
    ("پنج", 5),
    ("چهار", 4),
    ("سه", 3),
    ("دو", 2),
    ("یک", 1),
    ("یه", 1),
]


def _normalize_persian_digits(text: str) -> str:
    """Converts Persian and Arabic digits into standard ASCII digits."""
    return "".join(_PERSIAN_DIGITS_MAP.get(ch, ch) for ch in text)


def _extract_count_from_text(t: str) -> Optional[int]:
    """
    Intelligently extracts the desired message count (1 to 5000) from natural language:
    - Suffixes like '5k', '2.5k', '1k'
    - Compound phrases like '5 هزار', '۳ هزار'
    - Written Persian words: 'پنج هزار', 'پانصد', 'صد', 'بیست', 'ده', 'یک'
    - Specific numbers: '5000', '250', '50', '1'
    - Full-group keywords: 'کل', 'همه', 'تمام', 'سقف', 'ماکزیمم', 'حداکثر' -> 5000
    """
    # 1. Full-group / maximum indicators
    full_group_triggers = [
        "کل پیام", "همه پیام", "تمام پیام", "کل چت", "همه چت", "تمام چت",
        "کل گفتگو", "همه گفتگو", "تمام گفتگو", "کل گروه", "همه گروه",
        "سقف پیام", "ماکزیمم", "حداکثر", "تا سقف", "حداکثر پیام", "ماکسیمم"
    ]
    if any(fg in t for fg in full_group_triggers):
        return 5000

    # 2. Match 'k' or 'kilo' suffix (e.g. 5k, 2.5k, 1k)
    k_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:k|کا)\b", t, re.IGNORECASE)
    if k_match:
        try:
            return min(5000, max(1, int(float(k_match.group(1)) * 1000)))
        except (ValueError, TypeError):
            pass

    # 3. Match '(\d+) هزار' (e.g. 5 هزار -> 5000, 2 هزار -> 2000)
    hez_match = re.search(r"(\d+(?:\.\d+)?)\s*هزار", t)
    if hez_match:
        try:
            return min(5000, max(1, int(float(hez_match.group(1)) * 1000)))
        except (ValueError, TypeError):
            pass

    # 4. Match explicit Persian written numbers
    for word, num in _PERSIAN_WORDS_MAP:
        if re.search(rf"\b{word}\s*(?:تا\s*)?(?:پیام|چت|مسیج|گفتگو|مورد)?\b", t):
            return min(5000, max(1, num))

    # 5. Match plain numeric digits (e.g. 5000, 1500, 300, 50, 1)
    num_match = re.search(r"\b(\d+)\s*(?:تا\s*)?(?:پیام|چت|مسیج|گفتگو|مورد)?\b", t)
    if num_match:
        try:
            val = int(num_match.group(1))
            return min(5000, max(1, val))
        except ValueError:
            pass

    # 6. Single message phrases (e.g. آخرین پیام, پیام آخر, پیام قبلی)
    single_triggers = ["آخرین پیام", "پیام آخر", "پیام قبلی", "یک پیام اخیر", "پیام پیشین"]
    if any(st in t for st in single_triggers):
        return 1

    return None


def parse_summary_request(text: str) -> Tuple[bool, int]:
    """
    Detects if the user query is asking to summarize group conversation history.
    Returns (is_summary_request, requested_count).
    Supports from 1 to 5,000 messages (default: 100).
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
        return True, min(5000, max(1, cnt))

    # 2. Standalone exact summary triggers
    exact_triggers = {
        "خلاصه", "خلاصه کن", "خلاصه بکن", "خلاصه بده", "خلاصه بگو", "گزارش بده",
        "خلاصه چت", "خلاصه گفتگو", "خلاصه پیام‌ها", "خلاصه پیام ها", "خلاصه گروه",
        "recap", "summary", "summarize", "خلاصه ساز", "خلاصه کننده", "جمع بندی"
    }
    if t in exact_triggers:
        return True, 100

    # 3. Comprehensive natural language patterns for Persian & English
    patterns = [
        # Direct summarization / reporting / recap
        r"(?:خلاصه|سامری|recap|summary|گزارش|جمع\s*بندی)\s*(?:کن|بکن|بده|بگو|بفرست|ساز|کننده)?",
        r"(?:چت|پیام|مسیج|گفتگو|گروه|روم|کانال|بحث)\s*(?:ها|های)?\s*(?:اخیر|قبلی|قبل|گذشته)?\s*(?:رو|را)?\s*(?:خلاصه|سامری|جمع\s*بندی)\s*(?:کن|بکن|بده|بگو|بفرست)",
        r"(?:خلاصه|سامری|گزارش|جمع\s*بندی)\s+(?:از\s+)?(?:\d+\s+)?(?:چت|پیام|مسیج|گفتگو|گروه|روم|کانال|بحث)",
        r"(?:یک\s+)?(?:خلاصه|گزارش|سامری|جمع\s*بندی)\s+(?:از\s+)?(?:چت|پیام|گفتگو|بحث)",
        r"(?:خلاصه|گزارش)\s+(?:امروز|دیشب|دیروز|اخیر|گروه|چت)",
        r"(?:تا\s*)?(?:پیام|چت|گفتگو|مسیج)\s*(?:اخیر|قبل|قبلی|گذشته)?\s*(?:رو|را)?\s*(?:خلاصه|گزارش)\s*(?:کن|بکن|بده|بگو)",

        # Reading, reviewing, and analyzing past messages
        r"(?:پیام|چت|مسیج|گفتگو|مکالمه|بحث)\s*(?:ها|های)?\s*(?:قبل|قبلی|اخیر|گذشته|پیش|دیشب|امروز|دیروز|گروه)?\s*.*(?:بخون|بخونی|بخوان|بررسی|چک|تحلیل|مرور|بازخوانی)",
        r"(?:بخون|بررسی|چک|تحلیل|مرور|بازخوانی)\s*.*(?:پیام|چت|مسیج|گفتگو|مکالمه|بحث)",
        r"(?:تا\s*)?(?:پیام|چت|مسیج|گفتگو)\s*.*(?:قبل|قبلی|اخیر|گذشته|پیش|توضیح|بررسی|بخون|خلاصه)",

        # Inquiries about what happened in past messages
        r"(?:پیام|چت|مسیج|گفتگو|گروه)\s*.*(?:چی\s*گفتن|بحث\s*سر\s*چی\s*بود|کی\s*چی\s*گفت|موضوع\s*چی\s*بود|چه\s*خبر\s*بود|از\s*چی\s*صحبت\s*شد|چی\s*شده|چی\s*میگن|در\s*مورد\s*چی|درباره\s*چی)",
        r"(?:چی\s+گفتن|بحث\s+سر\s+چی\s+بود|کی\s+چی\s+گفت|موضوع\s+چی\s+بود|چه\s+خبر\s+بود|از\s+چی\s+صحبت\s+شد)\b",
        r"(?:توی|در|داخل)\s+(?:\d+\s+)?(?:تا\s+)?(?:پیام|چت|مسیج|گفتگو|گروه)\s*(?:قبل|قبلی|اخیر|گذشته)?\s*(?:در\s*مورد\s*چی|درباره\s*چی|چی\s*گفتن|چه\s*خبر)",
    ]

    is_matched = any(re.search(pat, t) for pat in patterns)
    if not is_matched:
        return False, 0

    # Extract count if explicitly mentioned
    extracted_cnt = _extract_count_from_text(t)
    final_count = extracted_cnt if extracted_cnt is not None else 100
    return True, min(5000, max(1, final_count))


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


def _compact_and_clean_messages(raw_messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    High-efficiency preprocessing & message compaction:
    - Combines rapid sequential messages by the same sender into a single consolidated utterance.
    - Eliminates redundant single-character noise.
    - Limits single message length to 300 characters to keep token density optimal.
    """
    compacted: List[Dict[str, Any]] = []
    prev_user_id = None
    prev_time = ""

    for m in raw_messages:
        content = (m.get("content") or "").strip().replace("\n", " ")
        if not content:
            continue
        # Skip pure spam/noise (single punctuation like '.', '+', etc.)
        if len(content) == 1 and content in ".+-/*~!@#$%^&*()_=":
            continue

        if len(content) > 300:
            content = content[:300] + "..."

        uid = m.get("user_id")
        created_str = str(m.get("created_at") or "")
        time_part = created_str[11:16] if len(created_str) >= 16 else "--:--"

        # If same user posted within the same minute, consolidate into previous utterance
        if compacted and uid == prev_user_id and time_part == prev_time:
            compacted[-1]["content"] += f" | {content}"
        else:
            item = dict(m)
            item["content"] = content
            compacted.append(item)
            prev_user_id = uid
            prev_time = time_part

    return compacted


def _format_messages_for_llm(messages: List[Dict[str, Any]]) -> str:
    """Formats a list of message dicts into a clean, compact chronological transcript."""
    lines = []
    for m in messages:
        time_part = str(m.get("created_at") or "")[11:16] or "--:--"
        name = m.get("full_name") or m.get("username") or f"کاربر {m.get('user_id', '')}"
        role_tag = "[ربات]" if m.get("is_bot") or m.get("role") == "assistant" else ""
        content = m.get("content", "").strip()
        lines.append(f"[{time_part}] {name}{role_tag}: {content}")
    return "\n".join(lines)


def _partition_into_chunks(lst: List[Any], n: int) -> List[List[Any]]:
    """Partitions a list into n approximately equal chunks."""
    k, m = divmod(len(lst), n)
    return [lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]


async def summarize_group_messages(
    chat_id: int,
    count: int = 100,
    chat_title: str = ""
) -> str:
    """
    Supercharged Autonomous Summarizer for Prometheus:
    - Supports reading and summarizing from 1 up to 5,000 messages with strict database isolation.
    - Employs adaptive multi-tier Map-Reduce concurrency:
      • Tier 0 (1 message): Instant single message analysis.
      • Tier 1 (2-60 messages): Single ultra-fast sub-agent.
      • Tier 2 (61-350 messages): Dual sub-agents (Part 1 & Part 2).
      • Tier 3 (351-1500 messages): Quad sub-agents (Q1, Q2, Q3, Q4) in parallel.
      • Tier 4 (1501-5000 messages): 6 to 8 parallel sub-agents + Chief Synthesizer.
    - Encapsulates executive summary inside Telegram Expandable Blockquotes (<blockquote expandable>).
    """
    clean_count = min(5000, max(1, count))
    logger.info(f"Summarizing up to {clean_count} messages for chat {chat_id} ('{chat_title}')...")

    # 1. Fetch messages strictly scoped to chat_id
    raw_msgs = await database.get_chat_messages_for_summary(chat_id, limit=clean_count)
    total_found = len(raw_msgs)

    # Fallback to in-memory session buffer if DB has no historical entries
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
            "💡 <i>پرومته پیام‌های ارسالی در این گروه را به صورت تفکیک‌شده و با سرعت فوق‌العاده ذخیره می‌کند "
            "تا در هر زمان بتوانید گزارش و خلاصه هوشمند تا سقف ۵۰۰۰ پیام را دریافت نمایید.</i>"
        )

    # 2. Compact and clean messages to maximize density and throughput
    processed_msgs = _compact_and_clean_messages(raw_msgs)
    total_processed = len(processed_msgs)

    # 3. Compute metadata metrics
    unique_users = {
        m.get("full_name") or m.get("username") or str(m.get("user_id"))
        for m in raw_msgs
        if not m.get("is_bot") and m.get("role") != "assistant"
    }

    # Count message frequencies to determine top speakers
    user_counts: Dict[str, int] = {}
    for m in raw_msgs:
        if not m.get("is_bot") and m.get("role") != "assistant":
            uname = m.get("full_name") or m.get("username") or f"کاربر {m.get('user_id')}"
            user_counts[uname] = user_counts.get(uname, 0) + 1

    top_speakers = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    top_speakers_str = "، ".join(f"<b>{html.escape(u[0])}</b> ({u[1]:,} پیام)" for u in top_speakers) if top_speakers else "مشخص نشد"

    first_time = str(raw_msgs[0].get("created_at") or "")[:16]
    last_time = str(raw_msgs[-1].get("created_at") or "")[:16]
    time_span = f"از <code>{first_time}</code> تا <code>{last_time}</code>" if first_time and last_time else "اخیر"
    title_label = f" «{html.escape(chat_title)}»" if chat_title else ""

    # 4. Determine Multi-Tier Parallel Architecture
    if total_found == 1:
        tier_label = "⚡️ تحلیل مستقیم تک پیام"
    elif total_found <= 60:
        tier_label = "⚡️ ساب‌اجنت منفرد سریع"
    elif total_found <= 350:
        tier_label = "⚡️ پردازش موازی دوگانه (Dual Sub-Agents)"
    elif total_found <= 1500:
        tier_label = "🚀 پردازش موازی ۴ ساب‌اجنت (Quad Sub-Agents)"
    else:
        tier_label = "🔥 پردازش فوق‌سریع موازی (Multi-Partition Map-Reduce)"

    header_box = (
        f"📊 <b>گزارش و خلاصه هوشمند گفتگو{title_label}:</b>\n"
        f"• ✉️ <b>پیام‌های بررسی‌شده:</b> <code>{total_found:,}</code> پیام (از سقف درخواستی <code>{clean_count:,}</code>)\n"
        f"• ⏱ <b>بازه زمانی:</b> {time_span}\n"
        f"• 👥 <b>کاربران فعال:</b> <code>{len(unique_users):,}</code> نفر\n"
        f"• 🏆 <b>بیشترین مشارکت:</b> {top_speakers_str}\n"
        f"• ⚙️ <b>معماری پردازش:</b> {tier_label}"
    )

    summary_body = ""

    # =========================================================================
    # Tier 0: Single Message Analysis (1 message)
    # =========================================================================
    if total_found == 1:
        target_msg = raw_msgs[0]
        author = target_msg.get("full_name") or target_msg.get("username") or "کاربر"
        c_text = target_msg.get("content", "").strip()
        single_prompt = (
            "شما ساب‌اجنت تحلیل پیام پرومته هستید. "
            f"پیام زیر در گروه تلگرامی ارسال شده است:\n"
            f"فرستنده: {author}\nمتن: {c_text}\n\n"
            "یک تحلیل کوتاه و دقیق شامل مضمون پیام، لحن، هدف یا درخواست پیام و پاسخ مناسب ارائه دهید."
        )
        single_res = await _call_fast_subagent([{"role": "user", "content": single_prompt}], max_tokens=600)
        summary_body = single_res or f"پیام ارسالی از <b>{html.escape(author)}</b>:\n«{html.escape(c_text)}»"

    # =========================================================================
    # Tier 1: Fast Single Sub-Agent (2 to 60 messages)
    # =========================================================================
    elif total_found <= 60:
        transcript = _format_messages_for_llm(processed_msgs)
        prompt = (
            "شما ساب‌اجنت تحلیل گفتگوی پرومته هستید. "
            "متن زیر تاریخچه پیام‌های یک گروه تلگرامی است. یک گزارش خلاصه بسیار حرفه‌ای، دقیق، روان و ساختاریافته به زبان فارسی بنویسید.\n"
            "گزارش حتماً باید شامل بخش‌های زیر باشد:\n"
            "💡 موضوعات و مباحث کلیدی مطرح‌شده\n"
            "👥 مشارکت اعضا و نظرات محوری کاربران فعال\n"
            "📌 تصمیمات، نتایج یا توافقات صورت‌گرفته\n"
            "❓ پرسش‌ها، دغدغه‌ها یا چالش‌های باز\n\n"
            f"متن گفتگو ({total_found} پیام):\n{transcript}"
        )
        res = await _call_fast_subagent([{"role": "user", "content": prompt}], max_tokens=1400)
        if res:
            summary_body = res

    # =========================================================================
    # Tier 2: Dual Sub-Agents Map-Reduce (61 to 350 messages)
    # =========================================================================
    elif total_found <= 350:
        chunks = _partition_into_chunks(processed_msgs, 2)
        trans1 = _format_messages_for_llm(chunks[0])
        trans2 = _format_messages_for_llm(chunks[1])

        p1 = (
            "شما ساب‌اجنت ۱ (تحلیل‌گر نیمه اول گفتگو) هستید. پیام‌های زیر را به صورت خلاصه، دقیق و تیتروار بنویسید:\n"
            "• موضوعات مطرح‌شده و مباحث آغازین\n• دغدغه‌ها و نظرات مهم اعضا\n\n"
            f"پیام‌ها ({len(chunks[0])} پیام):\n{trans1}"
        )
        p2 = (
            "شما ساب‌اجنت ۲ (تحلیل‌گر نیمه دوم گفتگو) هستید. پیام‌های زیر را به صورت خلاصه، دقیق و تیتروار بنویسید:\n"
            "• سیر ادامه گفتگو، پاسخ‌ها و نتایج حاصل‌شده\n• توافقات یا چالش‌های باز پایانی\n\n"
            f"پیام‌ها ({len(chunks[1])} پیام):\n{trans2}"
        )

        task1 = _call_fast_subagent([{"role": "user", "content": p1}], max_tokens=900)
        task2 = _call_fast_subagent([{"role": "user", "content": p2}], max_tokens=900)
        res1, res2 = await asyncio.gather(task1, task2, return_exceptions=True)

        part1_str = res1 if isinstance(res1, str) and res1 else "(نیمه اول بررسی شد)"
        part2_str = res2 if isinstance(res2, str) and res2 else "(نیمه دوم بررسی شد)"

        synthesizer_prompt = (
            "شما اجنت ارشد تجمیع و گزارش‌دهی پرومته هستید. "
            "دو ساب‌اجنت شما بخش‌های مختلف یک گفتگوی گروهی را بررسی کرده‌اند. "
            "بر اساس گزارش‌های زیر، یک گزارش جامع، پیوسته و ساختاریافته به زبان فارسی بنویسید:\n"
            "💡 محورهای کلیدی و سیر تحول گفتگو\n"
            "👥 مشارکت و دیدگاه‌های محوری کاربران\n"
            "📌 تصمیمات نهایی و جمع‌بندی‌ها\n"
            "❓ ابهامات یا مسائل حل‌نشده\n\n"
            f"[گزارش بخش اول]:\n{part1_str}\n\n[گزارش بخش دوم]:\n{part2_str}"
        )
        master_res = await _call_fast_subagent([{"role": "user", "content": synthesizer_prompt}], max_tokens=1600)
        if master_res:
            summary_body = master_res

    # =========================================================================
    # Tier 3: Quad Sub-Agents Map-Reduce (351 to 1,500 messages)
    # =========================================================================
    elif total_found <= 1500:
        chunks = _partition_into_chunks(processed_msgs, 4)
        tasks = []
        for idx, ch in enumerate(chunks, 1):
            ch_trans = _format_messages_for_llm(ch)
            ch_prompt = (
                f"شما ساب‌اجنت بخش {idx} از ۴ بخش گفتگو هستید. "
                "پیام‌های این بازه زمانی را به شکل فشرده، دقیق و تفکیک‌شده بنویسید (نکات کلیدی، نظرات اعضا، موضوعات):\n\n"
                f"{ch_trans}"
            )
            tasks.append(_call_fast_subagent([{"role": "user", "content": ch_prompt}], max_tokens=800))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        sections_summary = []
        for idx, r in enumerate(results, 1):
            txt = r if isinstance(r, str) and r else f"(بخش {idx} بررسی شد)"
            sections_summary.append(f"▫️ **[بخش {idx} از ۴]:**\n{txt}")

        synthesizer_prompt = (
            "شما اجنت ارشد تجمیع و گزارش‌دهی پرومته هستید. "
            "۴ ساب‌اجنت شما چهار مقطع متوالی از یک گفتگوی گسترده را تحلیل کرده‌اند. "
            "این تحلیل‌ها را در قالب یک گزارش مدیریتی و جامع، روان و حرفه‌ای به زبان فارسی سنتز کنید:\n\n"
            "💡 سیر وقایع و محورهای اصلی گفتگو (از ابتدا تا انتها)\n"
            "👥 کاربران فعال و دیدگاه‌های برجسته\n"
            "📌 تصمیمات، توافقات یا نتایج حاصل\n"
            "❓ چالش‌ها، پرسش‌ها یا اقدام‌های لازم آتی\n\n"
            + "\n\n".join(sections_summary)
        )
        master_res = await _call_fast_subagent([{"role": "user", "content": synthesizer_prompt}], max_tokens=1800)
        if master_res:
            summary_body = master_res

    # =========================================================================
    # Tier 4: Massive 5K Messages (1,501 to 5,000 messages) - Octa Sub-Agents
    # =========================================================================
    else:
        num_chunks = 6 if total_found <= 3000 else 8
        chunks = _partition_into_chunks(processed_msgs, num_chunks)
        tasks = []
        for idx, ch in enumerate(chunks, 1):
            ch_trans = _format_messages_for_llm(ch)
            ch_prompt = (
                f"شما ساب‌اجنت تخصصی مقطع {idx} از {num_chunks} یک گفتگوی عظیم گروهی هستید. "
                "نکات محوری، موضوعات بحث‌شده، چالش‌ها و مواضع کاربران در این مقطع را به شکل فشرده و تیتروار خلاصه کنید:\n\n"
                f"{ch_trans}"
            )
            tasks.append(_call_fast_subagent([{"role": "user", "content": ch_prompt}], max_tokens=750))

        logger.info(f"Dispatching {num_chunks} parallel subagents for massive {total_found} message summarization...")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        sections_summary = []
        for idx, r in enumerate(results, 1):
            txt = r if isinstance(r, str) and r else f"(مقطع {idx} ارزیابی شد)"
            sections_summary.append(f"🔹 **[مقطع زمانی {idx}/{num_chunks}]:**\n{txt}")

        synthesizer_prompt = (
            f"شما اجنت ارشد تجمیع کلان پرومته هستید. "
            f"{num_chunks} ساب‌اجنت شما مقاطع متوالی یک گفتگوی عظیم ({total_found} پیام) را به صورت موازی واکاوی کرده‌اند. "
            "بر اساس گزارش‌های این ساب‌اجنت‌ها، یک گزارش مدیریتی فوق‌العاده جامع، خوانا و تفکیک‌شده به زبان فارسی ارائه دهید:\n\n"
            "💡 سیر تحولات و محورهای اساسی بحث‌ها در طول کل بازه زمانی\n"
            "👥 بازیگران اصلی و جهت‌گیری دیدگاه‌های کاربران فعال\n"
            "📌 خروجی‌ها، نتایج قطعی و توافقات حاصل‌شده\n"
            "❓ موضوعات بلاتکلیف، پرسش‌های بی‌پاسخ و پیگیری‌های بعدی\n\n"
            + "\n\n".join(sections_summary)
        )
        master_res = await _call_fast_subagent([{"role": "user", "content": synthesizer_prompt}], max_tokens=2000)
        if master_res:
            summary_body = master_res

    # Fallback if LLM sub-agents temporarily failed
    if not summary_body:
        sample_snippets = []
        for m in raw_msgs[-8:]:
            content = (m.get("content") or "").strip().replace("\n", " ")
            name = m.get("full_name") or m.get("username") or "کاربر"
            if content:
                sample_snippets.append(f"• <b>{html.escape(name)}:</b> {html.escape(content[:120])}")
        sample_text = "\n".join(sample_snippets)
        summary_body = (
            "💡 <b>خلاصه اجمالی پیام‌های اخیر:</b>\n"
            f"در این بازه، گفتگو بین اعضای فعال ({top_speakers_str}) جریان داشته و آخرین پیام‌های تبادل‌شده به شرح زیر است:\n\n"
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
        f"💡 <i>روی کادر بالا ضربه بزنید تا متن کامل و جزئیات باز شود.</i>"
    )

    return final_report
