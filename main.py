"""
Hermes Telegram Agent - Production Entrypoint
Modern asynchronous architecture powered by python-telegram-bot v20+
Features Silence-by-default group trigger logic, live response streaming, and Hermes Agent brain.
"""

import re
import os
import html
import time
import logging
import asyncio
from typing import Optional

from telegram import Update
from telegram.constants import ParseMode, ChatAction, ChatType
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)
from telegram.request import HTTPXRequest

from config import settings, is_admin
from agent_engine import execute_hermes_agent, clear_session
from tools.system import get_current_time, calculate_math
from tools.weather import get_weather
from tools.financial import get_crypto_price, get_fiat_and_gold_rates
from utils.formatter import markdown_to_telegram_html, split_message

# Setup Logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("HermesTelegramAgent")

# Rate Limiter (Per User)
_USER_LAST_REQ: dict = {}


def check_rate_limit(user_id: int) -> bool:
    """Microsecond in-memory rate limiter."""
    if is_admin(user_id):
        return True
    now = time.monotonic()
    last = _USER_LAST_REQ.get(user_id, 0.0)
    if now - last < 1.0:  # 1 second between requests minimum
        return False
    _USER_LAST_REQ[user_id] = now
    return True


# =========================================================================
# Fast-Path Direct Commands
# =========================================================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command handler with Hermes intro."""
    msg = update.effective_message
    user = update.effective_user
    u_name = user.first_name if user else "کاربر"

    text = (
        f"⚡ **درود {u_name}! به هرمس ایجنت (Hermes Agent) خوش آمدید.**\n\n"
        "من دستیار هوشمند و خودمختار شما هستم؛ مجهز به مدل‌های پیشرفته استدلال و ابزارهای بلادرنگ:\n"
        "• 📊 **نرخ زنده رمزارزها، دلار و طلا**\n"
        "• 🌦 **پیش‌بینی لحظه‌ای آب و هوا**\n"
        "• 🔍 **جستجوی وب و مطالعه لینک‌ها**\n"
        "• 🧮 **محاسبات ریاضی و علمی**\n"
        "• 🕒 **زمان رسمی و تقویم شمسی/میلادی**\n\n"
        "💡 *در گروه‌ها، تنها در صورتی پاسخ می‌دهم که من را منشن کنید یا روی پیامم ریپلای بزنید.*"
    )
    formatted = markdown_to_telegram_html(text)
    await msg.reply_text(formatted, parse_mode=ParseMode.HTML)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command handler."""
    msg = update.effective_message
    text = (
        "📖 **راهنمای استفاده از هرمس ایجنت:**\n\n"
        "• `/start` - راه‌اندازی و معرفی ربات\n"
        "• `/clear` - پاکسازی سابقه گفتگو و ریست نشست\n"
        "• `/ping` - استعلام وضعیت سلامت و اتصال سرور\n"
        "• `/time` - نمایش ساعت رسمی تهران و تاریخ خورشیدی\n"
        "• `/weather [شهر]` - استعلام وضعیت آب و هوا\n"
        "• `/crypto [نماد]` - نرخ لحظه‌ای رمزارزها (مثال: `/crypto btc`)\n\n"
        "✨ *همچنین می‌توانید هر سوال، مسئله برنامه‌نویسی یا متن تحلیلی را به زبان فارسی مطرح نمایید.*"
    )
    formatted = markdown_to_telegram_html(text)
    await msg.reply_text(formatted, parse_mode=ParseMode.HTML)


async def clear_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Resets conversational session context."""
    chat = update.effective_chat
    if chat:
        clear_session(chat.id)
    await update.effective_message.reply_text("🧹 حافظه نشست جاری با موفقیت پاکسازی و از نو مقداردهی شد.")


async def ping_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Heartbeat & latency ping."""
    t0 = time.perf_counter()
    msg = await update.effective_message.reply_text("🏓 پونگ...")
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    await msg.edit_text(f"🏓 **پونگ! هرمس ایجنت آنلاین و آماده است.**\n⚡ تأخیر اتصال: `{elapsed_ms:.1f}ms`", parse_mode=ParseMode.MARKDOWN)


async def time_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Official time fast-path."""
    res = get_current_time()
    await update.effective_message.reply_text(markdown_to_telegram_html(res), parse_mode=ParseMode.HTML)


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

        # c) Explicit trigger names
        trigger_names = ["hermes", "هرمس", "پرومته", "prometheus"]
        if any(name in raw_text.lower() for name in trigger_names):
            is_triggered = True

    if not is_triggered:
        # Strictly remain silent in groups for all other messages
        return

    if not check_rate_limit(user.id):
        await message.reply_text("⚠️ لطفاً کمی شکیبا باشید و از ارسال رگباری پیام‌ها خودداری کنید.")
        return

    # Clean the trigger from the prompt
    cleaned_prompt = raw_text
    if bot_username:
        cleaned_prompt = re.sub(rf"@{re.escape(bot_username)}", "", cleaned_prompt, flags=re.IGNORECASE)
    for name in ["hermes", "هرمس", "پرومته", "prometheus"]:
        cleaned_prompt = re.sub(rf"\b{re.escape(name)}\b", "", cleaned_prompt, flags=re.IGNORECASE)
    cleaned_prompt = cleaned_prompt.strip()

    if not cleaned_prompt:
        await message.reply_text("بفرمایید، در خدمتم. چه کمکی از دست من ساخته است؟")
        return

    # Send Initial Placeholder
    placeholder = await message.reply_text("✍️ *در حال تفکر و بررسی...*", parse_mode=ParseMode.MARKDOWN)

    # Streaming Update Throttler Callback
    last_edit_time = 0.0
    async def on_stream_delta(current_full_text: str):
        nonlocal last_edit_time
        now = time.monotonic()
        if now - last_edit_time < settings.STREAM_EDIT_INTERVAL:
            return
        last_edit_time = now

        try:
            preview = current_full_text[:3800]
            await placeholder.edit_text(f"{preview}\n\n▌", parse_mode=None)
        except Exception:
            pass

    # Execute Hermes Agent with streaming
    try:
        await context.bot.send_chat_action(chat_id=chat.id, action=ChatAction.TYPING)
        final_answer = await execute_hermes_agent(
            chat_id=chat.id,
            user_prompt=cleaned_prompt,
            on_stream_delta=on_stream_delta
        )
    except Exception as e:
        logger.error(f"Error executing Hermes Agent: {e}")
        final_answer = f"❌ متأسفانه خطایی در پردازش پاسخ رخ داد: {str(e)}"

    # Deliver final resolved response
    try:
        formatted = markdown_to_telegram_html(final_answer)
        if len(formatted) <= 3900:
            try:
                await placeholder.edit_text(formatted, parse_mode=ParseMode.HTML)
            except Exception:
                await placeholder.edit_text(final_answer[:3900])
        else:
            chunks = split_message(formatted, max_len=3900)
            await placeholder.edit_text(chunks[0], parse_mode=ParseMode.HTML)
            for ch in chunks[1:]:
                await message.reply_text(ch, parse_mode=ParseMode.HTML)
    except Exception as e:
        logger.error(f"Error finalizing message delivery: {e}")
        try:
            await placeholder.edit_text(final_answer[:3900])
        except Exception:
            pass


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

    # General Message Handler (Supports text, captions, documents)
    app.add_handler(MessageHandler(filters.TEXT | filters.CAPTION, message_handler))

    return app


if __name__ == "__main__":
    logger.info("Starting Hermes Telegram Agent...")
    if not settings.TELEGRAM_BOT_TOKEN:
        logger.error("CRITICAL: TELEGRAM_BOT_TOKEN is not configured.")
    app = build_application()
    app.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)
