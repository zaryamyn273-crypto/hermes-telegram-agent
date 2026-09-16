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

from telegram import Update
from telegram.constants import ParseMode, ChatType, ChatAction
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)
from telegram.request import HTTPXRequest

from config import settings, is_admin
from agent_engine import execute_hermes_agent, clear_session, sanitize_identity
from tools.financial import get_fiat_and_gold_rates, get_crypto_price
from tools.system import get_current_time, calculate_math
from tools.weather import get_weather
from tools.ecommerce import search_digikala
from tools.web_reader import fetch_webpage_text
from tools.telegraph import create_telegraph_article, extract_telegraph_args
from utils.formatter import markdown_to_telegram_html, split_message, strip_thinking

# Setup Logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("HermesTelegramAgent")

# Microsecond In-Memory Rate Limiter (Per User)
_USER_LAST_REQ: dict = {}


def check_rate_limit(user_id: int) -> bool:
    """Microsecond in-memory rate limiter in RAM."""
    if is_admin(user_id):
        return True
    now = time.monotonic()
    last = _USER_LAST_REQ.get(user_id, 0.0)
    if now - last < 0.8:  # 0.8 second minimum between requests
        return False
    _USER_LAST_REQ[user_id] = now
    return True


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


async def _process_and_reply(update: Update, context: ContextTypes.DEFAULT_TYPE, prompt: str):
    """
    Dispatches query directly to autonomous agent engine with active Telegram typing indicator.
    """
    message = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    if not message or not chat:
        return

    typing_task = asyncio.create_task(_send_typing_loop(context.bot, chat.id))
    try:
        final_answer = await execute_hermes_agent(
            chat_id=chat.id,
            user_prompt=prompt,
            user_id=user.id if user else 0,
            username=user.username or "" if user else "",
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

    await _deliver_reply(message, final_answer)


# =========================================================================
# Fast-Path Intent Detectors
# =========================================================================

_FIAT_KEYWORDS = (
    "دلار", "dollar", "usd", "تتر", "usdt", "طلا", "سکه", "ارز", "یورو", "eur",
    "درهم", "aed", "مظنه", "انس"
)
_INTENT_KEYWORDS = (
    "قیمت", "نرخ", "چند", "چنده", "چقدر", "امروز", "لحظه", "بازار", "وضعیت",
    "بگو", "استعلام", "چند شد", "چند است", "چند شده"
)
_SPECIFIC_FIAT_PHRASES = (
    "سکه امامی", "بهار آزادی", "طلای ۱۸", "طلا ۱۸", "نیم سکه", "ربع سکه", "سکه گرمی",
    "قیمت دلار", "نرخ دلار", "دلار چنده", "قیمت تتر", "نرخ تتر", "قیمت طلا", "نرخ طلا",
    "قیمت سکه", "نرخ سکه", "نرخ ارز", "قیمت ارز", "وضعیت دلار", "وضعیت بازار ارز",
    "بازار ارز", "ارز و طلا", "طلا و ارز"
)

def is_fiat_or_gold_query(text: str) -> bool:
    """Matches any natural Persian query asking about dollar, euro, dirham, gold, or coin rates."""
    t = text.lower().strip()
    if t in ("دلار", "dollar", "usd", "تتر", "usdt", "طلا", "سکه", "ارز", "یورو", "eur", "درهم", "aed"):
        return True
    if any(sp in t for sp in _SPECIFIC_FIAT_PHRASES):
        return True
    has_curr = any(c in t for c in _FIAT_KEYWORDS)
    has_intent = any(i in t for i in _INTENT_KEYWORDS)
    return has_curr and has_intent


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
        if t == kw or t == f"قیمت {kw}" or t == f"نرخ {kw}":
            return sym
        if f"قیمت {kw}" in t or f"نرخ {kw}" in t or f"{kw} چنده" in t or f"{kw} چند است" in t or f"{kw} چند شد" in t or f"{kw} چند شده" in t:
            return sym
    return None


def is_time_query(text: str) -> bool:
    """Matches time and calendar queries."""
    t = text.lower().strip()
    time_keywords = [
        "ساعت چنده", "ساعت چند است", "ساعت رسمی", "ساعت چند شد", "ساعت تهران",
        "امروز چندمه", "تاریخ امروز", "امروز چه روزیه", "تاریخ شمسی", "تقویم",
        "زمان فعلی", "ساعت"
    ]
    if t in ("ساعت", "تاریخ", "تقویم", "زمان"):
        return True
    return any(k in t for k in time_keywords)


def extract_weather_query(text: str) -> Optional[str]:
    """Matches natural Persian weather queries and extracts city name."""
    t = text.strip()
    m = re.search(
        r"(?:آب\s*و\s*هوای|وضعیت\s*هوای|هوای|دمای|آب\s*هوا)\s+([آ-یa-zA-Z\s]+?)(?:\s+(?:چطوره|چطوریه|چگونه\s*است|چند\s*درجه\s*است|امروز|\?|؟)|[\?؟]|$)",
        t
    )
    if m:
        city = m.group(1).strip()
        if len(city) >= 2 and city not in ("امروز", "فردا", "الان"):
            return city
    return None


def is_math_query(text: str) -> bool:
    """Matches mathematical calculation requests."""
    t = text.strip()
    if t.startswith("حساب کن ") or t.startswith("محاسبه کن "):
        return True
    # Expression contains math symbols and numbers
    cleaned = re.sub(r"[0-9\.\+\-\*\/\(\)\^\%\s]", "", t)
    if not cleaned and len(t) >= 3 and any(op in t for op in "+-*/^"):
        return True
    return False


def extract_digikala_query(text: str) -> Optional[str]:
    """Matches requests to search or buy products from Digikala."""
    t = text.strip()
    m = re.search(r"(?:قیمت|خرید|جستجوی|سرچ)\s+(.+?)\s+(?:در|از)\s+(?:دیجیکالا|دیجی کالا)", t, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"(?:دیجیکالا|دیجی کالا)\s+(.+)", t, flags=re.IGNORECASE)
    if m2:
        return m2.group(1).strip()
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
        "من **پرومته** هستم؛ دستیار هوش مصنوعی پیشرفته، پرسرعت و خودمختار شما که مجهز به ابزارهای بلادرنگ، دیتابیس ابری کلودفلر و مغز استدلال ایجنتیک است:\n\n"
        "• 📊 **نرخ لحظه‌ای دلار، تتر، طلا و سکه** (`/rates`, `/dollar`)\n"
        "• 🪙 **استعلام زنده رمزارزها** (`/crypto btc` یا `/crypto eth`)\n"
        "• 🕒 **ساعت رسمی تهران و تقویم شمسی** (`/time`)\n"
        "• 🌦 **پیش‌بینی آب و هوای شهرها** (`/weather تهران`)\n"
        "• 🛍 **استعلام و قیمت کالا در دیجی‌کالا** (`/digikala آیفون 16`)\n"
        "• 📝 **انتشار فوری در تلگراف (Telegra.ph)** (`/telegraph عنوان | متن` یا ریپلای)\n"
        "• 🧮 **محاسبات ریاضی و علمی** (`/calc`)\n"
        "• 🔍 **تحلیل پیشرفته، استدلال و کدنویسی خودکار**\n\n"
        "💡 *در گروه‌ها، من تنها زمانی پاسخ می‌دهم که نام «پرومته» را بیاورید، مرا منشن (@) کنید یا روی پیامم ریپلای بزنید.*"
    )
    formatted = markdown_to_telegram_html(text)
    await msg.reply_text(formatted, parse_mode=ParseMode.HTML)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command handler."""
    msg = update.effective_message
    text = (
        "📖 **راهنمای جامع دستورات پرومته (Prometheus AI):**\n\n"
        "• `/rates` یا `/dollar` - قیمت زنده دلار، تتر، یورو، طلا و سکه در بازار ایران\n"
        "• `/crypto [نماد]` - نرخ لحظه‌ای رمزارزها به دلار و تومان (مثال: `/crypto btc`)\n"
        "• `/time` - ساعت رسمی تهران و تاریخ دقیق شمسی\n"
        "• `/weather [شهر]` - آب و هوای زنده شهرها (مثال: `/weather تهران`)\n"
        "• `/digikala [کالا]` - استعلام زنده قیمت، موجودی و لینک خرید دیجی‌کالا\n"
        "• `/telegraph [عنوان | متن]` - انتشار فوری مقالات و متن‌های بلند در تلگراف با قابلیت نمایش فوری (Instant View)\n"
        "• `/read [لینک]` - استخراج و مطالعه متن صفحات وب\n"
        "• `/calc [عبارت]` - محاسبات ریاضی و علمی (مثال: `/calc sqrt(144) + 10`)\n"
        "• `/clear` - پاکسازی حافظه نشست و دیتابیس گفتگو\n"
        "• `/ping` - تست بیداری و سرعت پاسخ‌دهی سرور\n\n"
        "🗣 **مکالمه طبیعی و هوشمند:**\n"
        "می‌توانید هر سوالی را به زبان ساده بپرسید؛ پرومته به صورت هوشمند و بدون نیاز به تایپ دستور پاسخ می‌دهد."
    )
    formatted = markdown_to_telegram_html(text)
    await msg.reply_text(formatted, parse_mode=ParseMode.HTML)


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
    """Heartbeat & latency ping."""
    t0 = time.perf_counter()
    msg = await update.effective_message.reply_text("🏓 پونگ...")
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    await msg.edit_text(
        f"🏓 **پونگ! پرومته کاملاً بیدار، هوشیار و آماده فرماندهی است.**\n⚡ تأخیر اتصال: `{elapsed_ms:.1f}ms`",
        parse_mode=ParseMode.MARKDOWN
    )


async def rates_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct fiat & gold rates lookup."""
    if update.effective_chat:
        await update.effective_chat.send_action(ChatAction.TYPING)
    res = await get_fiat_and_gold_rates()
    await _deliver_reply(update.effective_message, res)


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

    if not check_rate_limit(user.id):
        await message.reply_text("⚠️ لطفاً کمی شکیبا باشید و از ارسال رگباری پیام‌ها خودداری کنید.")
        return

    # Clean the trigger name from the prompt for cleaner matching
    cleaned_prompt = raw_text
    if bot_username:
        cleaned_prompt = re.sub(rf"@{re.escape(bot_username)}", "", cleaned_prompt, flags=re.IGNORECASE)
    for name in ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس", "پرومتيوس", "پرومتـه"]:
        cleaned_prompt = re.sub(rf"\b{re.escape(name)}\b", "", cleaned_prompt, flags=re.IGNORECASE)
    cleaned_prompt = cleaned_prompt.strip()

    if not cleaned_prompt:
        await message.reply_text("درود بر شما! در خدمتم. چه کمکی از دست پرومته ساخته است؟")
        return

    # Trigger immediate typing action for real-time visual feedback in Telegram
    try:
        await chat.send_action(ChatAction.TYPING)
    except Exception:
        pass

    cleaned_lower = cleaned_prompt.lower()

    # Fast-Path 1: Heartbeat / Ping
    if any(k in cleaned_lower for k in ["بیداری", "پینگ", "بیدار"]):
        if len(cleaned_lower.split()) <= 3:
            await message.reply_text(
                "🏓 **پونگ! پرومته کاملاً بیدار، هوشیار و آماده است.**",
                parse_mode=ParseMode.MARKDOWN
            )
            return

    # Fast-Path 2: Official Tehran Time & Solar Jalali Calendar (<1ms)
    if is_time_query(cleaned_lower):
        res = get_current_time()
        await _deliver_reply(message, res)
        return

    # Fast-Path 3: Fiat & Gold Rates (<50ms)
    if is_fiat_or_gold_query(cleaned_lower):
        res = await get_fiat_and_gold_rates()
        await _deliver_reply(message, res)
        return

    # Fast-Path 4: Crypto Rates (<100ms)
    crypto_sym = extract_crypto_query(cleaned_lower)
    if crypto_sym:
        res = await get_crypto_price(crypto_sym)
        await _deliver_reply(message, res)
        return

    # Fast-Path 5: Weather (<150ms)
    weather_city = extract_weather_query(cleaned_prompt)
    if weather_city:
        res = await get_weather(weather_city)
        await _deliver_reply(message, res)
        return

    # Fast-Path 6: Digikala E-Commerce (<1s)
    dk_query = extract_digikala_query(cleaned_prompt)
    if dk_query:
        res = await search_digikala(dk_query)
        await _deliver_reply(message, res)
        return

    # Fast-Path 7: Safe Math Evaluation (<1ms)
    if is_math_query(cleaned_prompt):
        calc_expr = cleaned_prompt.replace("حساب کن", "").replace("محاسبه کن", "").strip()
        res = calculate_math(calc_expr)
        await _deliver_reply(message, res)
        return

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

    # Process all queries through autonomous agent brain (zero typing animations)
    await _process_and_reply(update, context, cleaned_prompt)


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
    app.add_handler(CommandHandler(["rates", "dollar", "arz", "gheymat"], rates_command))
    app.add_handler(CommandHandler(["crypto"], crypto_command))
    app.add_handler(CommandHandler(["time", "saat"], time_command))
    app.add_handler(CommandHandler(["weather", "hava"], weather_command))
    app.add_handler(CommandHandler(["digikala", "dk"], digikala_command))
    app.add_handler(CommandHandler(["read", "web", "url"], read_command))
    app.add_handler(CommandHandler(["telegraph", "telegra", "article"], telegraph_command))
    app.add_handler(CommandHandler(["calc", "hesab"], calc_command))
    app.add_handler(CommandHandler(["clear"], clear_command))
    app.add_handler(CommandHandler(["ping"], ping_command))

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
