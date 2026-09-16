"""
Hermes Telegram Agent - Production Entrypoint (Prometheus AI)
Modern asynchronous architecture powered by python-telegram-bot v20+
Features Silence-by-default group trigger logic, Cloudflare D1 & KV storage,
direct delegation to Hermes Agent autonomous brain (3.8 low), and specialized Persian tools.
Zero typing animations or streaming artifacts to protect Prometheus identity.
"""

import re
import os
import html
import time
import logging
import asyncio
from typing import Optional

from telegram import Update
from telegram.constants import ParseMode, ChatType
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
# Common Response Delivery (No Typing Animations)
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


async def _process_and_reply(update: Update, context: ContextTypes.DEFAULT_TYPE, prompt: str):
    """
    Dispatches query directly to autonomous agent engine without showing typing animations.
    """
    message = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    if not message or not chat:
        return

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

    await _deliver_reply(message, final_answer)


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
        "• 🧮 **محاسبات ریاضی و علمی** (`/calc`)\n"
        "• 🔍 **جستجوی عمیق وب، تحلیل داده و کدنویسی خودکار**\n\n"
        "💡 *در گروه‌ها، من تنها زمانی فعال می‌شوم که نام «پرومته» را بیاورید، مرا منشن (@) کنید یا روی پیامم ریپلای بزنید.*"
    )
    formatted = markdown_to_telegram_html(text)
    await msg.reply_text(formatted, parse_mode=ParseMode.HTML)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command handler."""
    msg = update.effective_message
    text = (
        "📖 **راهنمای قابلیت‌ها و دستورات پرومته (Prometheus AI):**\n\n"
        "• `/start` - راه‌اندازی و معرفی پرومته\n"
        "• `/help` - راهنمای جامع دستورات\n"
        "• `/rates` یا `/dollar` - قیمت زنده دلار، تتر، یورو، طلا و سکه در بازار ایران\n"
        "• `/crypto [نماد]` - نرخ لحظه‌ای رمزارزها به دلار و تومان (مثال: `/crypto btc`)\n"
        "• `/time` - استعلام ساعت رسمی تهران و تاریخ دقیق شمسی\n"
        "• `/weather [شهر]` - آب و هوای زنده شهرها (مثال: `/weather تهران`)\n"
        "• `/calc [عبارت]` - محاسبه عبارات ریاضی و علمی (مثال: `/calc sqrt(144) + 10`)\n"
        "• `/clear` - پاکسازی حافظه نشست و دیتابیس گفتگو\n"
        "• `/ping` - بررسی بیداری و سرعت پاسخ‌دهی سرور\n\n"
        "🗣 **مکالمه آزاد در گروه و چت خصوصی:**\n"
        "می‌توانید هر سوال تحلیلی، برنامه‌نویسی، علمی یا عمومی را مطرح کنید. در گروه کافی است بگویید: «پرومته وضعیت بازار چطوره؟» یا روی پیام پرومته ریپلای کنید."
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

    # In groups, only authorized admins can clear bot conversation memory
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
        f"🏓 **پونگ! پرومته کاملاً بیدار، هوشیار و آماده است.**\n⚡ تأخیر اتصال: `{elapsed_ms:.1f}ms`",
        parse_mode=ParseMode.MARKDOWN
    )


async def rates_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct fiat & gold rates lookup."""
    res = await get_fiat_and_gold_rates()
    await _deliver_reply(update.effective_message, res)


async def crypto_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct crypto price lookup."""
    args = context.args or []
    sym = args[0].strip().upper() if args else "BTC"
    res = await get_crypto_price(sym)
    await _deliver_reply(update.effective_message, res)


async def time_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Official time and Jalali calendar lookup."""
    res = get_current_time()
    await _deliver_reply(update.effective_message, res)


async def weather_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct weather lookup."""
    args = context.args or []
    city = " ".join(args).strip() if args else "تهران"
    res = await get_weather(city)
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

    # --- Trigger Policy (Silence By Default) ---
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

    # Fast-Path 1: Heartbeat / Ping
    if any(k in raw_lower for k in ["پرومته بیداری", "بیداری پرومته", "پینگ پرومته", "پرومته بیدار"]):
        await message.reply_text(
            "🏓 **پونگ! پرومته کاملاً بیدار، هوشیار و آماده فرماندهی است.**",
            parse_mode=ParseMode.MARKDOWN
        )
        return

    # Fast-Path 2: Official Tehran Time & Calendar
    if any(k in raw_lower for k in ["ساعت چنده", "ساعت چند است", "ساعت رسمی", "امروز چندمه", "تاریخ امروز", "امروز چه روزیه"]):
        res = get_current_time()
        await _deliver_reply(message, res)
        return

    # Fast-Path 3: Fiat & Gold Rates
    fiat_keywords = [
        "قیمت دلار", "نرخ دلار", "دلار چنده", "دلار چند شده", "قیمت تتر", "نرخ تتر",
        "قیمت طلا", "نرخ طلا", "قیمت سکه", "نرخ سکه", "سکه امامی", "طلای ۱۸ عیار",
        "نرخ ارز", "قیمت یورو", "قیمت درهم"
    ]
    if any(k in raw_lower for k in fiat_keywords):
        res = await get_fiat_and_gold_rates()
        await _deliver_reply(message, res)
        return

    # Fast-Path 4: Crypto Rates
    crypto_kw_map = {
        "بیتکوین": "BTC", "بیت کوین": "BTC", "btc": "BTC",
        "اتریوم": "ETH", "eth": "ETH",
        "سولانا": "SOL", "sol": "SOL",
        "تون": "TON", "تون کوین": "TON", "ton": "TON",
        "دوج": "DOGE", "دوج کوین": "DOGE", "doge": "DOGE",
        "ریپل": "XRP", "xrp": "XRP",
    }
    for kw, sym in crypto_kw_map.items():
        if f"قیمت {kw}" in raw_lower or f"نرخ {kw}" in raw_lower or f"{kw} چنده" in raw_lower:
            res = await get_crypto_price(sym)
            await _deliver_reply(message, res)
            return

    # Clean the trigger from the prompt
    cleaned_prompt = raw_text
    if bot_username:
        cleaned_prompt = re.sub(rf"@{re.escape(bot_username)}", "", cleaned_prompt, flags=re.IGNORECASE)
    for name in ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس", "پرومتيوس", "پرومتـه"]:
        cleaned_prompt = re.sub(rf"\b{re.escape(name)}\b", "", cleaned_prompt, flags=re.IGNORECASE)
    cleaned_prompt = cleaned_prompt.strip()

    if not cleaned_prompt:
        await message.reply_text("درود بر شما! در خدمتم. چه کمکی از دست پرومته ساخته است؟")
        return

    # Process all queries through autonomous agent brain (without typing animations)
    await _process_and_reply(update, context, cleaned_prompt)


# =========================================================================
# Application Factory
# =========================================================================

def build_application():
    token = settings.TELEGRAM_BOT_TOKEN
    if not token:
        logger.warning("TELEGRAM_BOT_TOKEN is empty. Set it in environment variables or Railway.")

    extended_request = HTTPXRequest(
        connection_pool_size=100,
        connect_timeout=20.0,
        read_timeout=45.0,
        write_timeout=45.0,
        pool_timeout=10.0
    )

    app = (
        ApplicationBuilder()
        .token(token or "DUMMY_TOKEN")
        .request(extended_request)
        .concurrent_updates(16)
        .build()
    )

    # Command Handlers
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("clear", clear_command))
    app.add_handler(CommandHandler("ping", ping_command))
    app.add_handler(CommandHandler("time", time_command))
    app.add_handler(CommandHandler("weather", weather_command))
    app.add_handler(CommandHandler("crypto", crypto_command))
    app.add_handler(CommandHandler("rates", rates_command))
    app.add_handler(CommandHandler("gold", rates_command))
    app.add_handler(CommandHandler("dollar", rates_command))
    app.add_handler(CommandHandler("calc", calc_command))

    # General Message Handler (Supports text, captions, documents)
    app.add_handler(MessageHandler(filters.TEXT | filters.CAPTION, message_handler))

    return app


if __name__ == "__main__":
    logger.info("Starting Prometheus Telegram Agent...")
    if not settings.TELEGRAM_BOT_TOKEN:
        logger.error("CRITICAL: TELEGRAM_BOT_TOKEN is not configured.")
    app = build_application()
    app.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)
