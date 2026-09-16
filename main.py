"""
Hermes Telegram Agent - Production Entrypoint (Prometheus AI)
Modern asynchronous architecture powered by python-telegram-bot v20+
Features:
- Silence-by-default group trigger policy
- Sub-millisecond local fast-paths (<50ms for rates, crypto, time, weather, math, digikala)
- Direct delegation to autonomous Hermes Agent brain (ag/gemini-3.8-flash-low)
- Cloudflare D1 serverless SQL database & Cloudflare KV global caching
- Zero typing animations or message stream edits to strictly protect Prometheus identity
"""

import re
import os
import html
import time
import logging
import asyncio
from typing import Optional, Tuple

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode, ChatType, ChatAction
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters
)
from telegram.request import HTTPXRequest

from config import settings, is_admin
from agent_engine import (
    execute_hermes_agent,
    clear_session,
    sanitize_identity,
    get_user_mode,
    set_user_mode,
)
from tools.financial import get_fiat_and_gold_rates, get_crypto_price
from tools.system import (
    get_current_time,
    calculate_math,
    record_chat_latency,
    format_last_latency_response,
    run_live_speed_test,
)
from tools.weather import get_weather
from tools.ecommerce import search_digikala
from tools.web_reader import fetch_webpage_text
from tools.telegraph import create_telegraph_article, extract_telegraph_args
from tools.music import handle_music_request, is_music_request, extract_music_query
from tools.rate_limiter import check_user_rate_limit, get_user_quota_info
from tools.id_tool import is_id_request, format_id_report
from tools.barcode_tool import generate_qr_code, generate_barcode, parse_barcode_request
from tools.vision import (
    analyze_image_with_vision,
    is_reconstruction_query,
    build_reconstruction_image_url,
)
from utils.formatter import markdown_to_telegram_html, split_message, strip_thinking

# Setup Logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("HermesTelegramAgent")


def check_rate_limit(user_id: int) -> bool:
    """Microsecond in-memory & multi-tier rate limiter wrapper."""
    allowed, _ = check_user_rate_limit(user_id)
    return allowed


# =========================================================================
# Common Response Delivery (Zero Typing Animations)
# =========================================================================

async def _deliver_reply(message, final_text: str):
    """
    Delivers finalized response cleanly to Telegram without streaming or typing animations.
    """
    cleaned = sanitize_identity(final_text).strip()
    if not cleaned:
        cleaned = "درود بر شما! پاسخی برای این پرسش دریافت نشد. لطفاً مجدداً سوال خود را بفرمایید."

    try:
        formatted = markdown_to_telegram_html(cleaned)
        chunks = split_message(formatted, max_len=3900) if len(formatted) > 3900 else [formatted]
        for ch in chunks:
            try:
                await message.reply_text(ch, parse_mode=ParseMode.HTML)
            except Exception as html_err:
                logger.warning(f"HTML delivery failed ({html_err}), falling back to plain text")
                plain_ch = strip_thinking(cleaned)[:3900]
                await message.reply_text(plain_ch)
    except BadRequest as e:
        logger.warning(f"Telegram BadRequest in response delivery: {e}")
    except Exception as e:
        logger.error(f"Failed to deliver message: {e}")
        try:
            await message.reply_text(cleaned[:3900])
        except Exception:
            pass


async def _send_typing_loop(bot, chat_id: int):
    """Periodically sends typing chat action to Telegram while processing query."""
    try:
        while True:
            await bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)
            await asyncio.sleep(4.0)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.debug(f"Chat action TYPING error: {e}")


async def _process_and_reply(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    prompt: str,
    force_agent: bool = False,
    force_fast: bool = False,
):
    """
    Dispatches query directly to autonomous agent engine with active Telegram typing indicator
    and tiered speed/agent routing.
    """
    message = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    if not message or not chat:
        return

    typing_task = asyncio.create_task(_send_typing_loop(context.bot, chat.id))
    t_start = time.perf_counter()
    try:
        final_answer = await execute_hermes_agent(
            chat_id=chat.id,
            user_prompt=prompt,
            user_id=user.id if user else 0,
            username=user.username or "" if user else "",
            force_agent=force_agent,
            force_fast=force_fast,
        )
    except Exception as e:
        logger.error(f"Error executing Prometheus Agent: {e}")
        final_answer = f"❌ متأسفانه خطایی در پردازش پاسخ رخ داد: {str(e)}"
    finally:
        typing_task.cancel()
        try:
            await typing_task
        except asyncio.CancelledError:
            pass

    elapsed = time.perf_counter() - t_start
    engine_label = "مغز خودمختار هرمس ایجنت (Titan Brain)" if force_agent else "شبکه اختصاصی فوق‌سریع هرمس (Flash Low)"
    record_chat_latency(chat.id, elapsed, engine_label)

    await _deliver_reply(message, final_answer)


# =========================================================================
# Fast-Path Intent Detectors
# =========================================================================

_SPECIFIC_FIAT_PHRASES = (
    "سکه امامی", "بهار آزادی", "طلای ۱۸", "طلا ۱۸", "طلای ۱۸ عیار", "نیم سکه", "ربع سکه", "سکه گرمی",
    "قیمت دلار", "نرخ دلار", "دلار چنده", "دلار چند است", "دلار چند شد", "دلار چند شده", "دلار امروز", "دلار الان",
    "قیمت تتر", "نرخ تتر", "تتر چنده", "تتر چند است", "تتر چند شد",
    "قیمت طلا", "نرخ طلا", "طلا چنده", "طلا چند است", "طلا چند شد", "مظنه طلا", "انس طلا",
    "قیمت سکه", "نرخ سکه", "سکه چنده", "سکه چند است", "سکه چند شد",
    "نرخ ارز", "قیمت ارز", "وضعیت دلار", "وضعیت بازار ارز",
    "بازار ارز", "ارز و طلا", "طلا و ارز", "ارز آزاد", "ارز دولتی", "دلار آزاد",
    "قیمت یورو", "نرخ یورو", "یورو چنده", "قیمت درهم", "نرخ درهم", "درهم امارات"
)

_FIAT_PHRASE_REGEXES = [
    re.compile(rf"(?<!\w){re.escape(sp)}(?!\w)", re.IGNORECASE)
    for sp in _SPECIFIC_FIAT_PHRASES
]

_FIAT_ASSETS_PATTERN = re.compile(
    r"(?<!\w)(?:دلار|dollar|usd|تتر|usdt|طلا|طلای|سکه|مظنه|یورو|eur|درهم|aed)(?!\w)",
    re.IGNORECASE
)

_FIAT_INTENT_PATTERN = re.compile(
    r"(?<!\w)(?:قیمت|نرخ|چند|چنده|چقدر|امروز|لحظه|بازار|وضعیت|استعلام|چند شد|چند است)(?!\w)",
    re.IGNORECASE
)

_FIAT_EXCLUDED_TOPICS_PATTERN = re.compile(
    r"(?<!\w)(?:اینترنت|هند|هندوستان|سیمکارت|شارژ|بسته|لپ\s*تاپ|لپتاپ|موبایل|گوشی|بلیت|بلیط|هواپیما|هتل|تور|ماشین|خودرو|پایتون|برنامه|کد|سهام|بورس)(?!\w)",
    re.IGNORECASE
)


def is_fiat_or_gold_query(text: str) -> bool:
    """Matches natural Persian queries strictly asking about dollar, euro, dirham, gold, or coin rates."""
    t = text.lower().strip()
    if t in ("دلار", "dollar", "usd", "تتر", "usdt", "طلا", "سکه", "ارز", "یورو", "eur", "درهم", "aed", "مظنه", "درهم امارات"):
        return True

    # Check unambiguous specific phrases with strict boundary
    if any(p.search(t) for p in _FIAT_PHRASE_REGEXES):
        return True

    # If general non-financial context is present without a specific phrase, reject
    if _FIAT_EXCLUDED_TOPICS_PATTERN.search(t):
        return False

    # Check asset + intent with strict word boundaries
    has_asset = bool(_FIAT_ASSETS_PATTERN.search(t))
    has_intent = bool(_FIAT_INTENT_PATTERN.search(t))
    return has_asset and has_intent


def extract_fiat_target(text: str) -> Optional[str]:
    """
    Determines if user asked for a specific single currency or gold asset:
    - 'usd': dollar
    - 'usdt': tether
    - 'eur': euro
    - 'aed': dirham
    - 'gold': gold
    - 'coin': coin (emami, bahar, etc.)
    - None: general market overview (all assets)
    """
    t = text.lower().strip()
    has_general_arz = bool(re.search(r"(?<!\w)(?:ارز|ارزها)(?!\w)", t))
    has_usd = bool(re.search(r"(?<!\w)(?:دلار|dollar|usd)(?!\w)", t))
    has_usdt = bool(re.search(r"(?<!\w)(?:تتر|usdt)(?!\w)", t))
    has_eur = bool(re.search(r"(?<!\w)(?:یورو|eur)(?!\w)", t))
    has_aed = bool(re.search(r"(?<!\w)(?:درهم|aed)(?!\w)", t))
    has_gold = bool(re.search(r"(?<!\w)(?:طلا|طلای|مظنه|انس)(?!\w)", t))
    has_coin = bool(re.search(r"(?<!\w)(?:سکه|امامی|بهار\s*آزادی|نیم\s*سکه|ربع\s*سکه)(?!\w)", t))

    count = sum([has_general_arz, has_usd, has_usdt, has_eur, has_aed, has_gold, has_coin])
    if count > 1 or count == 0:
        return None  # Full table

    if has_usd:
        return "usd"
    if has_usdt:
        return "usdt"
    if has_eur:
        return "eur"
    if has_aed:
        return "aed"
    if has_gold:
        return "gold"
    if has_coin:
        return "coin"
    return None


_PREV_LATENCY_PATTERN = re.compile(
    r"(?:(?:این\s*جواب|این\s*پاسخ|پاسخ\s*قبلی|جواب\s*قبلی)\s*(?:رو\s*)?(?:چقدر|چند\s*ثانیه)\s*(?:طول\s*کشید|زمان\s*برد)|(?:چقدر|چند\s*ثانیه)\s*(?:طول\s*کشید|زمان\s*برد)\s*(?:این\s*رو\s*)?(?:بدی|پاسخ\s*بدی|جواب\s*بدی|بگی))",
    re.IGNORECASE
)

_BENCHMARK_PATTERN = re.compile(
    r"(?:چقدر\s*(?:طول\s*میکشه|زمان\s*میبره)\s*(?:جواب|پاسخ)\s*بدی|تست\s*(?:کن|بکن|بزن)?\s*(?:ببین|و\s*اعلام\s*کن|رو)?\s*چقدر\s*طول\s*میکشه|تست\s*سرعت|تست\s*پینگ|سرعتت\s*چقدره|پینگت\s*چقدره|سرعت\s*پاسخگویی|تاخیر\s*پاسخگویی|سرعت\s*ربات|پینگ\s*ربات)",
    re.IGNORECASE
)


def is_latency_query(text: str) -> Optional[str]:
    """
    Returns 'previous' if user asks how long the previous answer took.
    Returns 'benchmark' if user asks to test response time / latency.
    Returns None otherwise.
    """
    t = text.lower().strip()
    if _PREV_LATENCY_PATTERN.search(t):
        return "previous"
    if _BENCHMARK_PATTERN.search(t):
        return "benchmark"
    return None


_CRYPTO_MAP = {
    "بیتکوین": "BTC", "بیت کوین": "BTC", "بیت": "BTC", "btc": "BTC", "bitcoin": "BTC",
    "اتریوم": "ETH", "اتر": "ETH", "eth": "ETH", "ethereum": "ETH",
    "سولانا": "SOL", "sol": "SOL", "solana": "SOL",
    "تون": "TON", "تون کوین": "TON", "ton": "TON",
    "دوج": "DOGE", "دوج کوین": "DOGE", "doge": "DOGE", "dogecoin": "DOGE",
    "ریپل": "XRP", "xrp": "XRP", "ripple": "XRP",
    "کاردانو": "ADA", "ada": "ADA", "cardano": "ADA",
    "بایننس کوین": "BNB", "بی ان بی": "BNB", "bnb": "BNB",
    "ترون": "TRX", "trx": "TRX", "tron": "TRX",
    "شیبا": "SHIB", "shib": "SHIB", "shiba": "SHIB",
    "اوکس": "AVAX", "avax": "AVAX", "avalanche": "AVAX",
    "پولکادات": "DOT", "dot": "DOT",
    "نیر": "NEAR", "near": "NEAR",
    "لایت کوین": "LTC", "ltc": "LTC", "litecoin": "LTC",
}

def extract_crypto_query(text: str) -> Optional[str]:
    """Extracts target cryptocurrency symbol if the query asks about crypto price."""
    t = text.lower().strip()
    for kw, sym in _CRYPTO_MAP.items():
        if t == kw:
            return sym
        if re.search(rf"(?<!\w)(?:قیمت|نرخ)\s+{re.escape(kw)}(?!\w)", t):
            return sym
        if re.search(rf"(?<!\w){re.escape(kw)}\s+(?:چنده|چند است|چند شد|چند شده)(?!\w)", t):
            return sym
    return None


_TIME_EXCLUSIONS = (
    "ساعت هوشمند", "ساعت مچی", "ساعت دیواری", "ساعت کاری", "ساعت کار", "ساعت خواب",
    "چند ساعت", "یک ساعت", "دو ساعت", "۲ ساعت", "سه ساعت", "۳ ساعت", "چهار ساعت",
    "۴ ساعت", "ساعت قبل", "ساعت بعد", "ساعت پیش", "ساعت طول"
)

_TIME_STANDALONES = {
    "ساعت", "تاریخ", "تقویم", "زمان", "time", "date", "clock",
    "امروز چندمه", "امروز چنده", "الان چندمه", "امروز چندم است",
    "امروز چه روزیه", "امروز چه روزی است", "امروز چند شنبه است", "امروز چندشنبه است",
    "تاریخ امروز", "تاریخ شمسی", "تقویم امروز", "تقویم شمسی",
    "سال چندیم", "امسال چه سالیه", "امسال چه سالی است"
}

_TIME_REGEXES = [
    re.compile(r"(?<!\w)(?:امروز|الان)\s*(?:چندمه|چنده|چه\s*روزیه|چه\s*روزی\s*است|چندم\s*(?:ماهه|ماه\s*است|است)?)(?!\w)", re.IGNORECASE),
    re.compile(r"(?<!\w)(?:امروز|الان)\s+چند\s*شنبه\s*(?:است|هست|ایم|یم)?(?!\w)", re.IGNORECASE),
    re.compile(r"(?<!\w)(?:تاریخ|تقویم)\s+(?:امروز|روز|شمسی|الان|کنونی)(?!\w)", re.IGNORECASE),
    re.compile(r"(?<!\w)(?:ساعت)\s+(?:چنده|چند است|چند شد|رسمی|تهران|ایران|الان)(?!\w)", re.IGNORECASE),
    re.compile(r"(?<!\w)(?:سال\s+چندیم|امسال\s+چه\s*سالیه|امسال\s+چه\s*سالی\s*است|سال\s+چنده)(?!\w)", re.IGNORECASE),
    re.compile(r"(?<!\w)تاریخ\s+(?:امروز\s+به\s+شمسی|الان\s+چیه|روز\s+رو\s+بگو)(?!\w)", re.IGNORECASE),
]

_TIME_PHRASES = (
    "ساعت چنده", "ساعت چند است", "ساعت چند شد", "ساعت چنده الان", "ساعت الان چنده",
    "ساعت رسمی", "ساعت تهران", "ساعت رسمی کشور", "ساعت به وقت تهران", "ساعت ایران",
    "امروز چندمه", "امروز چندم است", "تاریخ امروز", "تاریخ روز", "امروز چه روزیه",
    "امروز چه روزی است", "امروز چند شنبه است", "امروز چندشنبه است", "تاریخ شمسی",
    "تقویم امروز", "تقویم شمسی", "زمان فعلی", "زمان کنونی", "امروز چنده", "الان چندمه"
)

_TIME_PHRASE_REGEXES = [
    re.compile(rf"(?<!\w){re.escape(tp)}(?!\w)", re.IGNORECASE)
    for tp in _TIME_PHRASES
]


def is_time_query(text: str) -> bool:
    """Matches natural Persian queries asking about current time, date, day of week, or calendar."""
    t = text.lower().strip()
    if t in _TIME_STANDALONES:
        return True
    if any(ex in t for ex in _TIME_EXCLUSIONS):
        return False
    if any(p.search(t) for p in _TIME_PHRASE_REGEXES):
        return True
    for r in _TIME_REGEXES:
        if r.search(t):
            return True
    if re.search(r"^(?:ساعت|زمان|تاریخ|تقویم)\s*(?:چنده|چند است|چند شد|الان|امروز|رسمی|تهران|شمسی)?[\?؟]?$", t):
        return True
    if re.search(r"^(?:الان|امروز)\s+ساعت\s+چنده[\?؟]?$", t):
        return True
    return False


# =========================================================================
# Bot Message Deletion & Replied-To Message Context Extraction
# =========================================================================

_DELETE_PATTERNS = [
    r"^(?:/del|/delete|/پاک)(?:@\w+)?$",
    r"^(?:این\s*(?:رو|پیام\s*رو)?\s*)?پاک\s*(?:کن|ش\s*کن|کنید)[\!؟\.]*$",
    r"^(?:این\s*(?:رو|پیام\s*رو)?\s*)?حذف\s*(?:کن|ش\s*کن|کنید)[\!؟\.]*$",
    r"^(?:پاکش\s*کن|حذفش\s*کن|دلیت\s*کن|delete|del)[\!؟\.]*$",
]


def is_delete_request(text: str) -> bool:
    """Matches requests to delete the bot's own message."""
    t = text.lower().strip()
    return any(bool(re.search(p, t, re.IGNORECASE)) for p in _DELETE_PATTERNS)


def extract_replied_message_context(message) -> str:
    """
    Extracts structured sender, text, caption, and media metadata from the replied-to message.
    Allows Prometheus to understand and process whatever message the user replied to.
    """
    reply_msg = getattr(message, "reply_to_message", None)
    if not reply_msg:
        return ""

    author_parts = []
    if getattr(reply_msg, "from_user", None) and reply_msg.from_user:
        name = reply_msg.from_user.first_name or "کاربر"
        if getattr(reply_msg.from_user, "last_name", None) and reply_msg.from_user.last_name:
            name += f" {reply_msg.from_user.last_name}"
        if getattr(reply_msg.from_user, "username", None) and reply_msg.from_user.username:
            name += f" (@{reply_msg.from_user.username})"
        author_parts.append(name)
    else:
        author_parts.append("کاربر")

    if getattr(reply_msg, "forward_from", None) and reply_msg.forward_from:
        f_name = reply_msg.forward_from.first_name or "کاربر"
        if getattr(reply_msg.forward_from, "username", None) and reply_msg.forward_from.username:
            f_name += f" (@{reply_msg.forward_from.username})"
        author_parts.append(f"فوروارد از {f_name}")
    elif getattr(reply_msg, "forward_from_chat", None) and reply_msg.forward_from_chat:
        title = getattr(reply_msg.forward_from_chat, "title", "") or ""
        author_parts.append(f"فوروارد از کانال/گروه {title}")

    author_desc = " | ".join(author_parts)
    content = getattr(reply_msg, "text", None) or getattr(reply_msg, "caption", None) or ""

    media_notes = []
    if getattr(reply_msg, "document", None) and reply_msg.document:
        doc_name = getattr(reply_msg.document, "file_name", None) or "سند"
        media_notes.append(f"فایل سند ({doc_name})")
    if getattr(reply_msg, "audio", None) and reply_msg.audio:
        title = getattr(reply_msg.audio, "title", None) or "موزیک"
        perf = getattr(reply_msg.audio, "performer", None) or ""
        media_notes.append(f"فایل صوتی ({perf} - {title})".strip())
    if getattr(reply_msg, "photo", None) and reply_msg.photo:
        media_notes.append("تصویر")
    if getattr(reply_msg, "video", None) and reply_msg.video:
        media_notes.append("ویدیو")
    if getattr(reply_msg, "poll", None) and reply_msg.poll:
        media_notes.append(f"نظرسنجی ({reply_msg.poll.question})")

    media_header = f" [نوع مدیا: {', '.join(media_notes)}]" if media_notes else ""
    if not content and not media_header:
        return ""

    body = content.strip() if content else "(بدون متن پیوست شده)"
    return f"📌 [پیام ریپلای‌شده از طرف {author_desc}{media_header}]:\n\"\"\"\n{body}\n\"\"\""


_WEATHER_EXCLUSIONS = (
    "منو داشته باش", "داشته باش", "جوش آب", "نقطه جوش", "دمای جوش", "اتاق", "بدن",
    "موتور", "روشن", "خاموش", "دلم", "سرم", "حالم", "کد", "پایتون", "برنامه"
)

def extract_weather_query(text: str) -> Optional[str]:
    """Matches natural Persian weather queries and extracts city name."""
    t = text.strip()
    if any(ex in t for ex in _WEATHER_EXCLUSIONS):
        return None

    # 1. Unambiguous weather pattern: "آب و هوای [شهر]", "وضعیت هوای [شهر]"
    m = re.search(
        r"(?:آب\s*و\s*هوای|وضعیت\s*(?:آب\s*و\s*)?هوای|آب\s*هوا[ی]?)\s+([آ-یa-zA-Z\s]+?)(?:\s+(?:چطوره|چطوریه|چگونه\s*است|چند\s*درجه\s*است|امروز|الان|\?|؟)|[\?؟]|$)",
        t
    )
    if m:
        city = m.group(1).strip()
        if len(city) >= 2 and city not in ("امروز", "فردا", "الان", "اینجا"):
            return city

    # 2. Pattern with "هوای [شهر]" or "دمای [شهر]" - require weather intent
    m2 = re.search(
        r"(?:هوای|دمای)\s+([آ-یa-zA-Z\s]+?)(?:\s+(?:چطوره|چطوریه|چگونه\s*است|چند\s*درجه\s*است|امروز|الان|بارونیه|برفیه|گرمه|سرده)|[\?؟]|$)",
        t
    )
    if m2:
        candidate = m2.group(1).strip()
        if len(candidate) >= 2 and candidate not in ("امروز", "فردا", "الان", "اینجا") and not any(v in candidate for v in ("من", "تو", "ما", "او", "کن", "باش", "شد", "رو")):
            return candidate

    return None


def is_math_query(text: str) -> bool:
    """Matches mathematical calculation requests."""
    t = text.strip()
    expr = re.sub(r"^(?:حساب کن|محاسبه کن|حساب|محاسبه)\s*", "", t, flags=re.IGNORECASE).strip()
    if not expr:
        return False
    if not re.search(r"\d", expr):
        return False
    has_op = any(op in expr for op in "+-*/^%") or bool(re.search(r"(?i)\b(?:sqrt|sin|cos|tan|log|abs|pow)\b", expr))
    if not has_op:
        return False
    cleaned = re.sub(r"(?i)\b(?:sqrt|sin|cos|tan|log|abs|pi|e|exp|pow)\b", "", expr)
    cleaned = re.sub(r"[0-9\.\+\-\*\/\(\)\^\%\s,،]", "", cleaned).strip()
    return len(cleaned) == 0


def extract_digikala_query(text: str) -> Optional[str]:
    """Matches requests to search or buy products from Digikala."""
    t = text.strip()
    m = re.search(r"(?:قیمت|خرید|جستجوی|سرچ)\s+(.+?)\s+(?:در|از|توی)\s+(?:دیجیکالا|دیجی کالا)", t, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"^(?:دیجیکالا|دیجی\s*کالا)\s*[:\s]\s*([آ-یa-zA-Z0-9\s]+)$", t, flags=re.IGNORECASE)
    if m2:
        candidate = m2.group(1).strip()
        if not any(candidate.startswith(w) for w in ("چطور", "چرا", "چیست", "کی", "کجا", "مال")):
            return candidate
    return None


# =========================================================================
# Command Handlers
# =========================================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command handler with Prometheus intro."""
    msg = update.effective_message
    user = update.effective_user
    u_name = user.first_name if user else "کاربر"

    text = (
        f"⚡ **درود {u_name}! به پرومته (Prometheus AI) خوش آمدید.**\n\n"
        "من **پرومته** هستم؛ دستیار هوش مصنوعی پیشرفته، پرسرعت و خودمختار شما که ادغام‌شده با **مغز پردازش غول‌آسای هرمس ایجنت**، دیتابیس ابری کلودفلر و ابزارهای تخصصی زنده است:\n\n"
        "• 🧠 **غول ایجنت خودمختار:** `/agent [پرسش یا موضوع تحقیق]` (اجرای تمام ابزارها، وب‌گردی، مرورگر و کدنویسی)\n"
        "• ⚡ **حالت فوق‌سریع:** `/fast [پرسش]` (پاسخ‌دهی زیر ۱ ثانیه با شبکه خصوصی)\n"
        "• ⚙️ **تنظیم حالت پاسخ‌دهی:** `/mode` (انتخاب بین هوشمند، غول ایجنت و فوق‌سریع)\n"
        "• 🆔 **استخراج آیدی عددی و مشخصات چت:** `/id` یا `/myid` (کپی فوری با یک لمس)\n"
        "• 📷 **درک تصویر، OCR و بازسازی بصری:** ارسال مستقیم عکس یا ریپلای روی عکس\n"
        "• 🏁 **ساخت بارکد و QR Code:** `/qr [متن]` یا `/barcode [کد]`\n"
        "• 📊 **نرخ لحظه‌ای دلار، تتر، طلا و سکه:** `/rates` یا `/dollar`\n"
        "• 🪙 **استعلام زنده رمزارزها:** `/crypto btc` یا `/crypto eth`\n"
        "• 🎵 **دانلود و آپلود مستقیم موزیک ۳۲۰:** `/music نام ترانه`\n"
        "• 📝 **انتشار فوری در تلگراف:** `/telegraph عنوان | متن`\n"
        "• 🛍 **استعلام و قیمت دیجی‌کالا:** `/digikala نام کالا`\n"
        "• 🌦 **پیش‌بینی آب و هوای زنده:** `/weather نام شهر`\n"
        "• 🕒 **ساعت رسمی و تقویم شمسی:** `/time`\n"
        "• 🧮 **ماشین حساب و ریاضی:** `/calc`\n"
        "• 🗑 **حذف پیام‌های ارسالی ربات:** `/del` یا گفتن «پاکش کن» با ریپلای روی پیام ربات\n"
        "• 📌 **درک هوشمند ریپلای:** روی هر پیامی ریپلای بزنید و سوال یا دستور خود را مطرح کنید تا ربات آن را تحلیل کند.\n\n"
        "💡 *در گروه‌ها، من تنها زمانی پاسخ می‌دهم که نام «پرومته» را بیاورید، مرا منشن (@) کنید یا روی پیامم ریپلای بزنید.*"
    )
    formatted = markdown_to_telegram_html(text)
    await msg.reply_text(formatted, parse_mode=ParseMode.HTML)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command handler."""
    msg = update.effective_message
    text = (
        "📖 **راهنمای جامع دستورات پرومته (Prometheus AI):**\n\n"
        "🧠 **هسته غول‌آسای هرمس ایجنت (Hermes Titan Brain):**\n"
        "• `/agent [پرسش]` یا `/research [موضوع]` - ارجاع مستقیم به غول هرمس ایجنت برای وب‌گردی خودکار با Chromium، پژوهش عمیق، تحلیل چندمرحله‌ای و اجرای کد sandbox\n"
        "• `/fast [پرسش]` - پاسخ‌دهی رعدآسا (زیر ۱ ثانیه) برای مکالمات و سوالات سریع\n"
        "• `/mode` - مشاهده و تغییر حالت کاری (هوشمند خودکار / غول ایجنت / فوق‌سریع)\n\n"
        "🛠 **ابزارهای اختصاصی و بلادرنگ:**\n"
        "• `/id` یا `/myid` - استخراج کامل آیدی عددی کاربر، چت، پیام، فرستنده فوروارد و فایل‌های مدیا به صورت کپی یک‌لمسی\n"
        "• `/qr [متن/لینک]` - ساخت کیوآر کد اختصاصی با کیفیت فوق‌العاده بالا\n"
        "• `/barcode [کد]` - ساخت بارکد میله‌ای استاندارد تجاری (Code128)\n"
        "• 📷 **بینایی ماشین (Vision):** ارسال هر تصویر یا ریپلای روی تصویر با سوال، استخراج متن (OCR)، تحلیل اشیاء یا درخواست «بازسازی تصویر»\n"
        "• `/rates` یا `/dollar` - قیمت زنده دلار، تتر، یورو، طلا و سکه در بازار ایران\n"
        "• `/crypto [نماد]` - نرخ لحظه‌ای رمزارزها به دلار و تومان (مثال: `/crypto btc`)\n"
        "• `/music [نام ترانه]` - جستجو و ارسال فایل کامل MP3 با کیفیت اصلی ۳۲۰\n"
        "• `/telegraph [عنوان | متن]` - انتشار فوری در تلگراف با Instant View\n"
        "• `/read [لینک]` - استخراج و خلاصه متن صفحات وب\n"
        "• `/weather [شهر]` - وضعیت آب و هوای زنده شهرها\n"
        "• `/digikala [کالا]` - استعلام قیمت و موجودی دیجی‌کالا\n"
        "• `/time` - ساعت رسمی تهران و تاریخ دقیق شمسی\n"
        "• `/calc [عبارت]` - محاسبات ریاضی و علمی\n"
        "• `/del` یا `/delete` - حذف پیام ارسال شده توسط پرومته (با ریپلای روی پیام یا گفتن «پاکش کن»)\n"
        "• `/clear` - پاکسازی حافظه نشست جاری\n"
        "• `/ping` - بررسی بیداری و سرعت پاسخ‌دهی سرور\n\n"
        "📌 **درک هوشمند ریپلای:** روی هر پیامی ریپلای بزنید و بپرسید «این رو ترجمه کن»، «نظرت چیه؟» یا «خلاصه‌اش کن» تا پرومته محتوای ریپلای‌شده را هوشمندانه بخواند و تحلیل کند.\n\n"
        "🗣 **مکالمه روان:** هر سوالی بپرسید، پرومته به صورت هوشمند و خودکار بهترین روش پاسخ را انتخاب می‌کند."
    )
    formatted = markdown_to_telegram_html(text)
    await msg.reply_text(formatted, parse_mode=ParseMode.HTML)


async def agent_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Directly invokes the autonomous Hermes Agent Titan Brain with all tools."""
    args = context.args or []
    if not args:
        guide = (
            "🧠 **موتور غول‌آسای هرمس ایجنت (Hermes Titan Brain):**\n\n"
            "برای پژوهش‌های عمیق وب، تحلیل‌های چندمرحله‌ای، اجرای ابزارهای خودکار و کدنویسی، پرسش خود را وارد کنید:\n\n"
            "مثال:\n"
            "• `/agent آخرین وضعیت و مشخصات فنی مدل Gemini 3 را به طور کامل تحلیل و گزارش کن`\n"
            "• `/agent یک اسکریپت پایتون بنویس برای تحلیل داده‌های مالی و نمودار شبیه‌سازی کن`"
        )
        await update.effective_message.reply_text(guide, parse_mode=ParseMode.MARKDOWN)
        return
    query = " ".join(args).strip()
    await _process_and_reply(update, context, query, force_agent=True)


async def fast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Directly invokes ultra low-latency fast engine (<800ms) for quick answers."""
    args = context.args or []
    if not args:
        await update.effective_message.reply_text(
            "⚡ **حالت فوق‌سریع پرومته:**\nلطفاً سوال یا پیام خود را بعد از دستور وارد کنید. مثال:\n`/fast پایتخت برزیل کجاست؟`",
            parse_mode=ParseMode.MARKDOWN
        )
        return
    query = " ".join(args).strip()
    await _process_and_reply(update, context, query, force_fast=True)


async def mode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Allows user to inspect or toggle their execution mode (smart, agent, fast)."""
    user = update.effective_user
    uid = user.id if user else 0
    current_mode = await get_user_mode(uid)

    mode_titles = {
        "smart": "🎯 حالت هوشمند (Smart Hybrid - خودکار)",
        "agent": "🧠 حالت غول ایجنت (Hermes Titan Brain)",
        "fast": "⚡ حالت فوق‌سریع (Ultra Fast <1s)",
    }

    text = (
        f"⚙️ **تنظیمات حالت اجرایی پرومته:**\n\n"
        f"وضعیت فعلی شما: **{mode_titles.get(current_mode, '🎯 حالت هوشمند')}**\n\n"
        "یکی از حالت‌های زیر را برای پردازش پیام‌های خود انتخاب نمایید:\n\n"
        "• 🎯 **حالت هوشمند (پیش‌فرض):** پاسخ‌های چت زیر ۱ ثانیه، و ارجاع خودکار سوالات پژوهشی و تخصصی به غول هرمس ایجنت.\n"
        "• 🧠 **حالت غول ایجنت:** اجرای تمام پیام‌ها توسط مغز خودمختار هرمس ایجنت با تمام ابزارهای وب، مرورگر و استدلال عمیق.\n"
        "• ⚡ **حالت فوق‌سریع:** پاسخ‌دهی رعدآسا (زیر ۱ ثانیه) برای تمام پیام‌ها از شبکه خصوصی داخلی."
    )

    keyboard = [
        [
            InlineKeyboardButton("🎯 حالت هوشمند", callback_data="setmode_smart"),
            InlineKeyboardButton("🧠 غول ایجنت", callback_data="setmode_agent"),
        ],
        [
            InlineKeyboardButton("⚡ فوق‌سریع", callback_data="setmode_fast"),
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.effective_message.reply_text(text, reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)


async def mode_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles inline keyboard selection for modes."""
    query = update.callback_query
    if not query:
        return
    await query.answer()

    data = query.data or ""
    if data.startswith("setmode_"):
        new_mode = data.replace("setmode_", "").strip()
        user = update.effective_user
        uid = user.id if user else 0
        await set_user_mode(uid, new_mode)

        mode_names = {
            "smart": "🎯 حالت هوشمند (Smart Hybrid)",
            "agent": "🧠 حالت غول ایجنت (Hermes Titan Brain)",
            "fast": "⚡ حالت فوق‌سریع (Ultra Fast)",
        }
        name = mode_names.get(new_mode, new_mode)
        await query.edit_message_text(
            f"✅ **حالت اجرایی شما با موفقیت به «{name}» تغییر یافت.**\nاز این پس پیام‌های شما با این الگو پردازش خواهند شد.",
            parse_mode=ParseMode.MARKDOWN
        )


async def clear_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Resets conversational session context in RAM and Cloudflare D1."""
    chat = update.effective_chat
    user = update.effective_user
    msg = update.effective_message

    if not chat or not msg:
        return

    if chat.type != ChatType.PRIVATE:
        if not user or not is_admin(user.id):
            await msg.reply_text("⛔ تنها مدیران مجاز به پاکسازی حافظه نشست پرومته در گروه‌ها هستند.")
            return

    clear_session(chat.id)
    await msg.reply_text("🧹 حافظه نشست جاری و تاریخچه دیتابیس با موفقیت پاکسازی شد.")


async def ping_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Heartbeat & live latency benchmark."""
    if update.effective_chat:
        await update.effective_chat.send_action(ChatAction.TYPING)
    t0 = time.perf_counter()
    res = await run_live_speed_test()
    if update.effective_chat:
        record_chat_latency(update.effective_chat.id, time.perf_counter() - t0, "تست زنده پینگ و تاخیر")
    await _deliver_reply(update.effective_message, res)


async def rates_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct fiat & gold rates lookup (supports /dollar or specific asset arguments)."""
    if update.effective_chat:
        await update.effective_chat.send_action(ChatAction.TYPING)
    msg = update.effective_message
    cmd = msg.text.split()[0].lower() if msg and msg.text else "/rates"
    target = None
    if "dollar" in cmd or "dolar" in cmd:
        target = "usd"
    elif context.args:
        target = extract_fiat_target(" ".join(context.args))
    t0 = time.perf_counter()
    res = await get_fiat_and_gold_rates(target=target)
    if update.effective_chat:
        record_chat_latency(update.effective_chat.id, time.perf_counter() - t0, f"دستور استعلام نرخ ({target or 'جامع'})")
    await _deliver_reply(msg, res)


async def crypto_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct crypto price lookup."""
    if update.effective_chat:
        await update.effective_chat.send_action(ChatAction.TYPING)
    args = context.args or []
    sym = args[0].strip().upper() if args else "BTC"
    res = await get_crypto_price(sym)
    await _deliver_reply(update.effective_message, res)


async def time_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Official time and Jalali calendar lookup."""
    if update.effective_chat:
        await update.effective_chat.send_action(ChatAction.TYPING)
    res = get_current_time()
    await _deliver_reply(update.effective_message, res)


async def weather_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct weather lookup."""
    if update.effective_chat:
        await update.effective_chat.send_action(ChatAction.TYPING)
    args = context.args or []
    city = " ".join(args).strip() if args else "تهران"
    res = await get_weather(city)
    await _deliver_reply(update.effective_message, res)


async def digikala_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Digikala product search command."""
    args = context.args or []
    if not args:
        await update.effective_message.reply_text("ℹ️ لطفاً نام محصول مورد نظر را وارد کنید. مثال: `/digikala آیفون 16`", parse_mode=ParseMode.MARKDOWN)
        return
    if update.effective_chat:
        await update.effective_chat.send_action(ChatAction.TYPING)
    query = " ".join(args).strip()
    res = await search_digikala(query)
    await _deliver_reply(update.effective_message, res)


async def calc_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Math calculator command."""
    args = context.args or []
    if not args:
        await update.effective_message.reply_text("ℹ️ لطفاً عبارت ریاضی مورد نظر را وارد کنید. مثال: `/calc 25 * 4 + 10`", parse_mode=ParseMode.MARKDOWN)
        return
    expr = " ".join(args).strip()
    res = calculate_math(expr)
    await _deliver_reply(update.effective_message, res)


async def read_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct webpage reader command."""
    args = context.args or []
    if not args:
        await update.effective_message.reply_text("ℹ️ لطفاً آدرس اینترنتی (URL) مورد نظر را وارد کنید. مثال: `/read https://example.com`", parse_mode=ParseMode.MARKDOWN)
        return
    url = args[0].strip()
    res = await fetch_webpage_text(url)
    await _deliver_reply(update.effective_message, res)


async def telegraph_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct Telegraph article publishing command."""
    msg = update.effective_message
    if not msg:
        return

    if update.effective_chat:
        await update.effective_chat.send_action(ChatAction.TYPING)

    # Check if this command is a reply to another message
    reply_msg = msg.reply_to_message
    args_text = " ".join(context.args or []).strip()

    if reply_msg and (reply_msg.text or reply_msg.caption):
        content = reply_msg.text or reply_msg.caption or ""
        title = args_text if args_text else "مستند تلگراف پرومته"
    elif args_text:
        title, content = extract_telegraph_args(args_text)
    else:
        guide = (
            "📝 **راهنمای انتشار در تلگراف (Telegra.ph):**\n\n"
            "برای انتشار فوری متن یا مقاله در تلگراف می‌توانید از روش‌های زیر استفاده کنید:\n\n"
            "۱. **فرمت مستقیم:**\n"
            "`/telegraph عنوان مقاله | متن کامل مقاله`\n\n"
            "۲. **ریپلای روی پیام:**\n"
            "روی هر پیام بلندی ریپلای بزنید و دستور `/telegraph [عنوان دلخواه]` را ارسال کنید.\n\n"
            "۳. **مکالمه با هوش مصنوعی:**\n"
            "به پرومته بگویید: *«یک مقاله درباره هوش مصنوعی بنویس و توی تلگراف منتشر کن»*"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.MARKDOWN)
        return

    res = await create_telegraph_article(title=title, content=content)
    await _deliver_reply(msg, res)


async def music_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct music search, download & upload command."""
    args = context.args or []
    query = " ".join(args).strip()
    await handle_music_request(update, context, query)


async def delete_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Deletes bot messages upon reply."""
    msg = update.effective_message
    if not msg:
        return
    bot_id = context.bot.id
    reply_to = msg.reply_to_message
    if reply_to and reply_to.from_user and reply_to.from_user.id == bot_id:
        try:
            await reply_to.delete()
        except Exception as e:
            logger.warning(f"Failed to delete bot message: {e}")
        try:
            await msg.delete()
        except Exception:
            pass
    elif reply_to:
        await msg.reply_text("⚠️ من فقط می‌توانم پیام‌هایی که خودم ارسال کرده‌ام را حذف کنم.")
    else:
        await msg.reply_text("ℹ️ برای حذف پیام پرومته، لطفاً روی پیام مورد نظر ریپلای کرده و /del یا «پاکش کن» را ارسال نمایید.")


async def id_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Extracts all Telegram IDs and metadata with 1-tap copyable code blocks."""
    msg = update.effective_message
    if not msg:
        return
    report = format_id_report(update)
    await msg.reply_text(report, parse_mode=ParseMode.HTML)


async def barcode_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Generates QR codes and barcodes directly in Telegram."""
    msg = update.effective_message
    if not msg:
        return

    cmd = (msg.text or "").split()[0].lower()
    args = context.args or []
    data_text = " ".join(args).strip()

    if not data_text:
        guide = (
            "🏁 **راهنمای ساخت بارکد و کد QR (پرومته):**\n\n"
            "• برای ساخت QR Code:\n"
            "`/qr [متن یا لینک یا شماره]`\n"
            "مثال: `/qr https://google.com`\n\n"
            "• برای ساخت بارکد میله‌ای استاندارد:\n"
            "`/barcode [اعداد یا حروف انگلیسی]`\n"
            "مثال: `/barcode 9789643110291`\n\n"
            "💡 همچنین می‌توانید در گفتگو بنویسید: *«برای شماره 09123456789 کیوآر کد بساز»*"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.MARKDOWN)
        return

    is_qr = ("qr" in cmd or "کیو" in cmd)
    if is_qr:
        buf = generate_qr_code(data_text)
        caption = f"🏁 <b>کیوآر کد اختصاصی پرومته</b>\n📄 محتوا: <code>{html.escape(data_text)}</code>"
    else:
        buf = generate_barcode(data_text)
        caption = f"🏁 <b>بارکد استاندارد پرومته (Code128)</b>\n📄 داده: <code>{html.escape(data_text)}</code>"

    await msg.reply_photo(photo=buf, caption=caption, parse_mode=ParseMode.HTML)


async def photo_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct multimodal vision handler for received photos."""
    msg = update.effective_message
    user = update.effective_user
    chat = update.effective_chat
    if not msg or not msg.photo or not chat or not user:
        return

    is_private = (chat.type == ChatType.PRIVATE)
    bot_id = context.bot.id
    bot_username = (context.bot.username or "").lower()
    caption = msg.caption or ""

    # Check group trigger
    if not is_private:
        is_triggered = False
        if msg.reply_to_message and msg.reply_to_message.from_user and msg.reply_to_message.from_user.id == bot_id:
            is_triggered = True
        elif bot_username and f"@{bot_username}" in caption.lower():
            is_triggered = True
        elif any(name in caption.lower() for name in ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس"]):
            is_triggered = True
        if not is_triggered:
            return

    # Rate limit check
    allowed, limit_msg = check_user_rate_limit(user.id)
    if not allowed:
        await msg.reply_text(limit_msg or "⚠️ لطفاً کمی شکیبا باشید.")
        return

    typing_task = asyncio.create_task(_send_typing_loop(context.bot, chat.id))
    t0 = time.perf_counter()
    try:
        largest_photo = msg.photo[-1]
        photo_file = await largest_photo.get_file()
        photo_bytes = await photo_file.download_as_bytearray()

        cleaned_caption = caption
        if bot_username:
            cleaned_caption = re.sub(rf"@{re.escape(bot_username)}", "", cleaned_caption, flags=re.IGNORECASE)
        for name in ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس", "پرومتيوس"]:
            cleaned_caption = re.sub(rf"(?<!\w){re.escape(name)}(?!\w)", "", cleaned_caption, flags=re.IGNORECASE)
        cleaned_caption = cleaned_caption.strip()

        analysis = await analyze_image_with_vision(
            image_bytes=bytes(photo_bytes),
            prompt=cleaned_caption if cleaned_caption else None,
            chat_id=chat.id,
        )

        if is_reconstruction_query(caption):
            reconstruct_prompt = cleaned_caption or "photorealistic detailed visual recreation"
            preview_url = build_reconstruction_image_url(reconstruct_prompt)
            analysis += f"\n\n🎨 <b>پیش‌نمایش شبیه‌سازی مجدد تصویر:</b>\n<a href=\"{preview_url}\">مشاهده پیش‌نمایش تصویر بازسازی‌شده</a>"

        elapsed = time.perf_counter() - t0
        record_chat_latency(chat.id, elapsed, "موتور بینایی چندوجهی پرومته (Vision)")
        await _deliver_reply(msg, analysis)
    except Exception as e:
        logger.error(f"Error processing photo vision: {e}")
        await msg.reply_text(f"❌ متأسفانه خطایی در پردازش تصویر رخ داد: {str(e)}")
    finally:
        typing_task.cancel()
        try:
            await typing_task
        except asyncio.CancelledError:
            pass


# =========================================================================
# Main Message Handler with Silence-By-Default Trigger Logic
# =========================================================================

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    user = update.effective_user
    chat = update.effective_chat

    if not message or not user or not chat:
        return

    raw_text = message.text or message.caption or ""
    if not raw_text.strip():
        return

    is_private = (chat.type == ChatType.PRIVATE)
    bot_id = context.bot.id
    bot_username = (context.bot.username or "").lower()

    # --- Trigger Policy (Silence By Default in Groups) ---
    is_triggered = False

    if is_private:
        # 1. Private Chat (DM) -> Always trigger
        is_triggered = True
    else:
        # 2. Group Chats: ONLY trigger if replied to bot, or explicitly mentioned
        # a) Direct reply to bot's message
        if message.reply_to_message and message.reply_to_message.from_user:
            if message.reply_to_message.from_user.id == bot_id:
                is_triggered = True

        # b) Mention via @username
        if bot_username and f"@{bot_username}" in raw_text.lower():
            is_triggered = True

        # c) Explicit trigger names (PROMETHEUS ONLY)
        trigger_names = ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس", "پرومتيوس", "پرومتـه"]
        if any(name in raw_text.lower() for name in trigger_names):
            is_triggered = True

    if not is_triggered:
        # Strictly remain silent in groups for all other messages
        return

    # Check Silence / Stop Triggers
    raw_lower = raw_text.lower().strip()
    silence_triggers = [
        "پرومته ساکت", "پرومته ساکت شو", "پرومته بسه", "پرومته بس کن",
        "سکوت پرومته", "پرومته خفه", "پرومته خفه شو", "ربات ساکت", "ربات ساکت شو"
    ]
    if any(st in raw_lower for st in silence_triggers):
        await message.reply_text(
            "🤐 *چشم، سکوت می‌کنم.* هر زمان نیاز به کمک داشتید، با صدا زدن نام «پرومته» یا ریپلای روی پیامم در خدمت شما هستم.",
            parse_mode=ParseMode.MARKDOWN
        )
        return

    allowed, limit_msg = check_user_rate_limit(user.id)
    if not allowed:
        await message.reply_text(limit_msg or "⚠️ لطفاً کمی شکیبا باشید و از ارسال رگباری پیام‌ها خودداری کنید.")
        return

    # Clean the trigger name from the prompt for cleaner matching
    cleaned_prompt = raw_text
    if bot_username:
        cleaned_prompt = re.sub(rf"@{re.escape(bot_username)}", "", cleaned_prompt, flags=re.IGNORECASE)
    for name in ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس", "پرومتيوس", "پرومتـه"]:
        cleaned_prompt = re.sub(rf"(?<!\w){re.escape(name)}(?!\w)", "", cleaned_prompt, flags=re.IGNORECASE)
    cleaned_prompt = cleaned_prompt.lstrip("،, :!-؟?").strip()

    if not cleaned_prompt:
        await message.reply_text("درود بر شما! در خدمتم. چه کمکی از دست پرومته ساخته است؟")
        return

    # Trigger immediate typing action for real-time visual feedback in Telegram
    try:
        await chat.send_action(ChatAction.TYPING)
    except Exception:
        pass

    cleaned_lower = cleaned_prompt.lower()

    # Fast-Path -2: Full Telegram Numeric ID & Diagnostics Extraction (<1ms)
    if is_id_request(cleaned_lower):
        report = format_id_report(update)
        await message.reply_text(report, parse_mode=ParseMode.HTML)
        return

    # Fast-Path -1: Bot Message Deletion (/del, /delete, /پاک, "پاکش کن", "حذف کن")
    if is_delete_request(cleaned_lower):
        reply_to = message.reply_to_message
        if reply_to and reply_to.from_user and reply_to.from_user.id == bot_id:
            try:
                await reply_to.delete()
            except Exception as e:
                logger.warning(f"Failed to delete bot message: {e}")
            try:
                await message.delete()
            except Exception:
                pass
            return
        elif reply_to:
            await message.reply_text("⚠️ من فقط می‌توانم پیام‌هایی که خودم ارسال کرده‌ام را حذف کنم.")
            return
        elif is_private:
            await message.reply_text("ℹ️ برای حذف پیام پرومته، لطفاً روی پیام مورد نظر ریپلای کرده و /del یا «پاکش کن» را ارسال نمایید.")
            return

    # Fast-Path 0: Response Time Tracking & Live Speed Benchmark
    latency_type = is_latency_query(cleaned_lower)
    if latency_type:
        t0 = time.perf_counter()
        if latency_type == "previous":
            res = format_last_latency_response(chat.id)
        else:
            res = await run_live_speed_test()
        elapsed = time.perf_counter() - t0
        record_chat_latency(chat.id, elapsed, "سنجشگر زنده سرعت و تاخیر پرومته")
        await _deliver_reply(message, res)
        return

    # Fast-Path 1: Heartbeat / Ping
    if any(k in cleaned_lower for k in ["بیداری", "پینگ", "بیدار"]):
        if len(cleaned_lower.split()) <= 3:
            t0 = time.perf_counter()
            res = await run_live_speed_test()
            record_chat_latency(chat.id, time.perf_counter() - t0, "تست زنده پینگ و تاخیر")
            await _deliver_reply(message, res)
            return

    # Fast-Path 2: Official Tehran Time & Solar Jalali Calendar (<1ms)
    if is_time_query(cleaned_lower):
        t0 = time.perf_counter()
        res = get_current_time()
        record_chat_latency(chat.id, time.perf_counter() - t0, "محاسبه‌گر ساعت و تقویم شمسی (<1ms)")
        await _deliver_reply(message, res)
        return

    # Fast-Path 3: Fiat & Gold Rates (<50ms)
    if is_fiat_or_gold_query(cleaned_lower):
        t0 = time.perf_counter()
        target = extract_fiat_target(cleaned_lower)
        res = await get_fiat_and_gold_rates(target=target)
        elapsed = time.perf_counter() - t0
        asset_label = f"استعلام لحظه‌ای {target.upper()}" if target else "جدول جامع نرخ ارز و طلا"
        record_chat_latency(chat.id, elapsed, f"ابزار اختصاصی {asset_label}")
        await _deliver_reply(message, res)
        return

    # Fast-Path 4: Crypto Rates (<100ms)
    crypto_sym = extract_crypto_query(cleaned_lower)
    if crypto_sym:
        t0 = time.perf_counter()
        res = await get_crypto_price(crypto_sym)
        record_chat_latency(chat.id, time.perf_counter() - t0, f"استعلام لحظه‌ای رمزارز {crypto_sym}")
        await _deliver_reply(message, res)
        return

    # Fast-Path 5: Weather (<150ms)
    weather_city = extract_weather_query(cleaned_prompt)
    if weather_city:
        t0 = time.perf_counter()
        res = await get_weather(weather_city)
        record_chat_latency(chat.id, time.perf_counter() - t0, f"هواشناسی زنده ({weather_city})")
        await _deliver_reply(message, res)
        return

    # Fast-Path 6: Digikala E-Commerce (<1s)
    dk_query = extract_digikala_query(cleaned_prompt)
    if dk_query:
        t0 = time.perf_counter()
        res = await search_digikala(dk_query)
        record_chat_latency(chat.id, time.perf_counter() - t0, f"جستجوی فروشگاهی دیجی‌کالا ({dk_query})")
        await _deliver_reply(message, res)
        return

    # Fast-Path 7: Safe Math Evaluation (<1ms)
    if is_math_query(cleaned_prompt):
        t0 = time.perf_counter()
        calc_expr = cleaned_prompt.replace("حساب کن", "").replace("محاسبه کن", "").strip()
        res = calculate_math(calc_expr)
        record_chat_latency(chat.id, time.perf_counter() - t0, "موتور محاسبات ریاضی پرومته (<1ms)")
        await _deliver_reply(message, res)
        return

    # Fast-Path 7.5: Barcode & QR Code Generator (<10ms)
    is_bc, bc_type, bc_content = parse_barcode_request(cleaned_prompt)
    if is_bc and bc_content:
        t0 = time.perf_counter()
        if bc_type == "qr":
            buf = generate_qr_code(bc_content)
            caption = f"🏁 <b>کیوآر کد اختصاصی پرومته</b>\n📄 محتوا: <code>{html.escape(bc_content)}</code>"
        else:
            buf = generate_barcode(bc_content)
            caption = f"🏁 <b>بارکد استاندارد پرومته (Code128)</b>\n📄 داده: <code>{html.escape(bc_content)}</code>"
        record_chat_latency(chat.id, time.perf_counter() - t0, f"تولید کننده {bc_type.upper()}")
        await message.reply_photo(photo=buf, caption=caption, parse_mode=ParseMode.HTML)
        return

    # Fast-Path 7.8: Multimodal Vision on Replied Photo
    if message.reply_to_message and message.reply_to_message.photo:
        reply_photo = message.reply_to_message.photo[-1]
        typing_task = asyncio.create_task(_send_typing_loop(context.bot, chat.id))
        t0 = time.perf_counter()
        try:
            photo_file = await reply_photo.get_file()
            photo_bytes = await photo_file.download_as_bytearray()
            analysis = await analyze_image_with_vision(
                image_bytes=bytes(photo_bytes),
                prompt=cleaned_prompt,
                chat_id=chat.id,
            )
            if is_reconstruction_query(cleaned_prompt):
                preview_url = build_reconstruction_image_url(cleaned_prompt)
                analysis += f"\n\n🎨 <b>پیش‌نمایش شبیه‌سازی مجدد تصویر:</b>\n<a href=\"{preview_url}\">مشاهده پیش‌نمایش تصویر بازسازی‌شده</a>"

            elapsed = time.perf_counter() - t0
            record_chat_latency(chat.id, elapsed, "موتور بینایی و درک تصویر پرومته (Vision)")
            await _deliver_reply(message, analysis)
            return
        except Exception as e:
            logger.error(f"Error processing replied photo vision: {e}")
        finally:
            typing_task.cancel()
            try:
                await typing_task
            except asyncio.CancelledError:
                pass

    # Fast-Path 8: Telegraph Article Publishing
    if any(k in cleaned_lower for k in ["تلگراف", "telegraph", "telegra.ph"]):
        # Case A: Reply to another message asking to publish to telegraph
        if message.reply_to_message and (message.reply_to_message.text or message.reply_to_message.caption):
            reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
            t_title = cleaned_prompt
            for rem in ["تلگرافش کن", "توی تلگراف بذار", "در تلگراف منتشر کن", "توی تلگراف منتشر کن", "تلگراف", "telegraph"]:
                t_title = t_title.replace(rem, "")
            t_title = t_title.strip() or "مستند تلگراف پرومته"
            res = await create_telegraph_article(title=t_title, content=reply_text)
            await _deliver_reply(message, res)
            return

        # Case B: Direct "تلگراف: عنوان | متن" or "عنوان | متن" with telegraph intent
        if "|" in cleaned_prompt and any(a in cleaned_lower for a in ["بساز", "منتشر", "صفحه", "پست", "publish", "create"]):
            t_title, t_content = extract_telegraph_args(cleaned_prompt)
            for rem in ["تلگراف:", "تلگراف", "telegraph:", "telegraph"]:
                t_title = t_title.replace(rem, "").strip()
            if t_content:
                res = await create_telegraph_article(title=t_title or "مستند تلگراف پرومته", content=t_content)
                await _deliver_reply(message, res)
                return

    # Fast-Path 9: Music Search, Download & Upload
    if is_music_request(cleaned_lower):
        music_q = extract_music_query(cleaned_prompt) or cleaned_prompt
        await handle_music_request(update, context, music_q)
        return

    # Process all queries through autonomous agent brain (zero typing animations)
    replied_context = extract_replied_message_context(message)
    if replied_context:
        agent_prompt = f"{replied_context}\n\nدستور یا پرسش کاربر درباره پیام بالا:\n{cleaned_prompt}"
    else:
        agent_prompt = cleaned_prompt

    await _process_and_reply(update, context, agent_prompt)


# =========================================================================
# Application Factory
# =========================================================================

def build_application():
    token = settings.TELEGRAM_BOT_TOKEN
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN is not set in environment or config.")

    request = HTTPXRequest(
        connection_pool_size=100,
        read_timeout=30.0,
        write_timeout=20.0,
        connect_timeout=15.0,
        pool_timeout=10.0,
    )

    app = ApplicationBuilder().token(token).request(request).concurrent_updates(True).build()

    # Commands & Aliases
    app.add_handler(CommandHandler(["start"], start_command))
    app.add_handler(CommandHandler(["help"], help_command))
    app.add_handler(CommandHandler(["agent", "research", "hermes"], agent_command))
    app.add_handler(CommandHandler(["fast", "speed"], fast_command))
    app.add_handler(CommandHandler(["mode", "setting", "settings"], mode_command))
    app.add_handler(CallbackQueryHandler(mode_callback, pattern=r"^setmode_"))
    app.add_handler(CommandHandler(["rates", "dollar", "arz", "gheymat"], rates_command))
    app.add_handler(CommandHandler(["crypto"], crypto_command))
    app.add_handler(CommandHandler(["time", "saat"], time_command))
    app.add_handler(CommandHandler(["weather", "hava"], weather_command))
    app.add_handler(CommandHandler(["digikala", "dk"], digikala_command))
    app.add_handler(CommandHandler(["music", "song", "ahang"], music_command))
    app.add_handler(CommandHandler(["read", "web", "url"], read_command))
    app.add_handler(CommandHandler(["telegraph", "telegra", "article"], telegraph_command))
    app.add_handler(CommandHandler(["calc", "hesab"], calc_command))
    app.add_handler(CommandHandler(["clear"], clear_command))
    app.add_handler(CommandHandler(["id", "myid", "info", "chatid", "whoami"], id_command))
    app.add_handler(CommandHandler(["qr", "qrcode"], barcode_command))
    app.add_handler(CommandHandler(["barcode", "bar"], barcode_command))
    app.add_handler(CommandHandler(["delete", "del", "pak"], delete_command))
    app.add_handler(CommandHandler(["ping"], ping_command))

    # Multimodal photo handler
    app.add_handler(MessageHandler(filters.PHOTO, photo_handler))

    # All text messages (with silence-by-default logic)
    app.add_handler(
        MessageHandler(
            filters.TEXT | filters.CAPTION,
            message_handler
        )
    )

    return app


if __name__ == "__main__":
    logger.info("Starting Prometheus Telegram Agent Bot...")
    app = build_application()
    app.run_polling(drop_pending_updates=False, allowed_updates=Update.ALL_TYPES)
