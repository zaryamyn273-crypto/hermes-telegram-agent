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
from typing import Optional, Tuple, List, Dict, Any, Set, Union

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ChatPermissions
from telegram.constants import ParseMode, ChatType, ChatAction, ChatMemberStatus
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ChatMemberHandler,
    ContextTypes,
    filters
)
from telegram.request import HTTPXRequest

from config import settings, is_admin, _ADMIN_IDS
import database
from utils.formatter import split_message, markdown_to_telegram_html
from tools.moderation import (
    init_moderation_engine,
    is_user_banned,
    is_user_muted,
    is_group_banned,
    is_group_muted,
    is_group_approved,
    get_group_status,
    register_group_event,
    approve_group,
    reject_group,
    ban_user,
    unban_user,
    mute_user,
    unmute_user,
    ban_group,
    unban_group,
    mute_group,
    unmute_group,
    get_banned_users_list,
    get_muted_users_list,
    get_banned_groups_list,
    get_muted_groups_list,
    get_pending_groups_list,
    get_all_tracked_groups,
    get_unbanned_history,
    get_admin_commands_log,
    set_admin_setting,
    get_admin_setting,
    delete_admin_setting,
    get_all_admin_settings,
    get_cached_admin_directives,
    parse_duration_string,
    format_duration_persian,
    _MOD_LOCK,
    _BANNED_USERNAMES,
    _MUTED_USERNAMES,
)
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
from tools.twitter import (
    fetch_tweet_data,
    format_tweet_report,
    fetch_twitter_profile,
    format_profile_report,
    search_twitter_live,
    parse_twitter_request,
    extract_tweet_url_and_id,
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
# Moderation Gatekeeper & Group Workflow Helpers
# =========================================================================

async def _check_moderation_guard(update: Update, context: ContextTypes.DEFAULT_TYPE, is_admin_cmd: bool = False) -> bool:
    """
    Global Security & Moderation Gatekeeper:
    1. Banned Users: completely blocked and ignored.
    2. Muted Users: ignored until mute period expires.
    3. Groups:
       - If banned: bot is completely silent.
       - If muted: bot is silent.
       - If unapproved: bot remains inactive; if new, notifies admins with inline approval buttons.
    """
    user = update.effective_user
    chat = update.effective_chat
    if not user or not chat:
        return True

    uid = user.id
    uname = user.username

    # 1. User Ban Check
    if is_user_banned(uid, uname):
        logger.info(f"Gatekeeper: blocked banned user {uid} (@{uname})")
        return False

    # 2. User Mute Check
    muted, remaining = is_user_muted(uid, uname)
    if muted:
        logger.info(f"Gatekeeper: blocked muted user {uid} (@{uname}), remaining: {remaining:.1f}s")
        return False

    # 3. Group Chat Moderation
    if chat.type != ChatType.PRIVATE:
        # Group ban check
        if is_group_banned(chat.id):
            logger.info(f"Gatekeeper: blocked banned group {chat.id}")
            return False

        # Group bot mute check
        g_muted, _ = is_group_muted(chat.id)
        if g_muted and not (is_admin_cmd and is_admin(uid)):
            logger.info(f"Gatekeeper: bot is muted in group {chat.id}")
            return False

        # Group approval check
        status = get_group_status(chat.id)
        if status == "unknown":
            st, is_new = await register_group_event(
                chat_id=chat.id,
                title=chat.title or "گروه",
                chat_type=chat.type,
                added_by_id=uid if is_admin(uid) else 0,
                username=chat.username or ""
            )
            status = st
            if is_new and not is_admin(uid):
                await _notify_admin_group_request(context.bot, chat, user)
                try:
                    await chat.send_message(
                        "⏳ <b>درخواست فعال‌سازی پرومته در این گروه برای ادمین ارسال شد.</b>\n"
                        "پس از بررسی و تایید ادمین، ربات فعال خواهد شد.",
                        parse_mode=ParseMode.HTML
                    )
                except Exception:
                    pass

        if status != "approved":
            # If authorized admin is issuing an administrative command or interacting, permit through
            if is_admin(uid):
                return True
            logger.info(f"Gatekeeper: group {chat.id} status is '{status}'; bot remains inactive.")
            return False

    return True


async def _notify_admin_group_request(bot, chat, user):
    """Notifies authorized bot admins when the bot is placed in a new unapproved group."""
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ تایید فعال‌سازی", callback_data=f"grp_app:{chat.id}"),
            InlineKeyboardButton("❌ رد و ترک گروه", callback_data=f"grp_rej:{chat.id}"),
        ]
    ])

    user_name = (user.full_name or "کاربر") if user else "نامشخص"
    user_uname = f"@{user.username}" if (user and user.username) else "ندارد"
    user_id_str = str(user.id) if user else "0"
    chat_title = chat.title or "بدون نام"
    chat_uname = f"@{chat.username}" if chat.username else "گروه خصوصی (بدون لینک عمومی)"

    text = (
        "🚨 <b>درخواست فعال‌سازی پرومته در گروه جدید</b>\n\n"
        f"🏷 <b>نام گروه:</b> {html.escape(chat_title)}\n"
        f"🆔 <b>شناسه گروه:</b> <code>{chat.id}</code>\n"
        f"🔗 <b>لینک/یوزرنیم:</b> {chat_uname}\n"
        f"👤 <b>افزوده شده توسط:</b> {html.escape(user_name)} ({user_uname})\n"
        f"🔢 <b>شناسه کاربر:</b> <code>{user_id_str}</code>\n\n"
        "⚠️ <i>ربات تا زمان تایید شما در این گروه غیرفعال می‌ماند و به هیچ پیامی پاسخ نخواهد داد.</i>\n\n"
        f"⚡️ <b>دستورات سریع:</b>\n"
        f"• تایید: <code>/approvegroup {chat.id}</code>\n"
        f"• رد: <code>/rejectgroup {chat.id}</code>"
    )

    admin_targets = set()
    if settings.ADMIN_ID > 0:
        admin_targets.add(settings.ADMIN_ID)
    if hasattr(settings, "ADMIN_USER_IDS") and settings.ADMIN_USER_IDS:
        admin_targets.update(settings.ADMIN_USER_IDS)
    admin_targets.update(_ADMIN_IDS)

    for aid in admin_targets:
        if aid > 0:
            try:
                await bot.send_message(
                    chat_id=aid,
                    text=text,
                    parse_mode=ParseMode.HTML,
                    reply_markup=keyboard
                )
            except Exception as e:
                logger.warning(f"Could not send group approval notification to admin {aid}: {e}")


async def group_approval_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles admin click on approval/rejection inline buttons."""
    query = update.callback_query
    if not query:
        return
    user = update.effective_user
    if not user or not is_admin(user.id):
        await query.answer("⛔️ این اقدام فقط توسط ادمین مجاز ربات قابل انجام است.", show_alert=True)
        return

    data = query.data or ""
    parts = data.split(":")
    if len(parts) != 2:
        await query.answer("داده نامعتبر است.", show_alert=True)
        return

    action, chat_id_str = parts[0], parts[1]
    try:
        target_chat_id = int(chat_id_str)
    except ValueError:
        await query.answer("شناسه گروه نامعتبر است.", show_alert=True)
        return

    admin_display_name = html.escape(user.full_name or "ادمین")
    orig_text = ""
    if query.message:
        orig_text = query.message.text_html or (html.escape(query.message.text) if query.message.text else "")

    if action == "grp_app":
        await approve_group(target_chat_id, reviewed_by=user.id)
        await query.answer("✅ گروه تایید و فعال شد.", show_alert=True)
        new_text = (orig_text + f"\n\n<b>✅ وضعیت: توسط {admin_display_name} تایید و فعال گردید.</b>") if orig_text else f"✅ <b>گروه <code>{target_chat_id}</code> توسط {admin_display_name} تایید و فعال گردید.</b>"
        try:
            await query.edit_message_text(new_text, parse_mode=ParseMode.HTML, reply_markup=None)
        except Exception:
            try:
                await query.edit_message_reply_markup(reply_markup=None)
            except Exception:
                pass
        try:
            await context.bot.send_message(
                chat_id=target_chat_id,
                text="✅ <b>ربات توسط ادمین در این گروه تایید شد و هم‌اکنون فعال و آماده خدمت‌رسانی است.</b>",
                parse_mode=ParseMode.HTML
            )
        except Exception:
            pass

    elif action == "grp_rej":
        await reject_group(target_chat_id, reviewed_by=user.id)
        await query.answer("❌ گروه رد شد و ربات در حال خروج است.", show_alert=True)
        new_text = (orig_text + f"\n\n<b>❌ وضعیت: توسط {admin_display_name} رد شد و ربات خارج گردید.</b>") if orig_text else f"❌ <b>گروه <code>{target_chat_id}</code> توسط {admin_display_name} رد شد و ربات خارج گردید.</b>"
        try:
            await query.edit_message_text(new_text, parse_mode=ParseMode.HTML, reply_markup=None)
        except Exception:
            try:
                await query.edit_message_reply_markup(reply_markup=None)
            except Exception:
                pass
        try:
            await context.bot.send_message(
                chat_id=target_chat_id,
                text="❌ <b>درخواست فعال‌سازی پرومته در این گروه توسط ادمین تایید نشد. ربات از گروه خارج می‌شود.</b>",
                parse_mode=ParseMode.HTML
            )
        except Exception:
            pass
        try:
            await context.bot.leave_chat(chat_id=target_chat_id)
        except Exception as e:
            logger.warning(f"Could not leave chat {target_chat_id}: {e}")


async def chat_member_update_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Detects when the bot is added to or removed from groups."""
    result = update.my_chat_member
    if not result:
        return

    chat = update.effective_chat
    user = update.effective_user
    if not chat or chat.type == ChatType.PRIVATE:
        return

    new_status = result.new_chat_member.status
    if new_status in (ChatMemberStatus.MEMBER, ChatMemberStatus.ADMINISTRATOR):
        added_by_id = user.id if user else 0
        st, is_new = await register_group_event(
            chat_id=chat.id,
            title=chat.title or "گروه",
            chat_type=chat.type,
            added_by_id=added_by_id,
            username=chat.username or ""
        )

        if st == "approved":
            try:
                await chat.send_message(
                    "👋 <b>درود! پرومته در این گروه فعال شد.</b>\n"
                    "برای ارتباط، نام من را صدا بزنید یا روی پیام‌هایم ریپلای فرمایید.",
                    parse_mode=ParseMode.HTML
                )
            except Exception:
                pass
        elif is_new:
            await _notify_admin_group_request(context.bot, chat, user)
            try:
                await chat.send_message(
                    "⏳ <b>درود! پرومته به گروه افزوده شد.</b>\n"
                    "درخواست فعال‌سازی برای ادمین ربات ارسال شد. به محض تأیید ادمین، ربات فعال و پاسخگوی شما خواهد بود.",
                    parse_mode=ParseMode.HTML
                )
            except Exception:
                pass

    elif new_status in (ChatMemberStatus.LEFT, ChatMemberStatus.BANNED):
        await database.execute_d1_query(
            "UPDATE tracked_groups SET status = 'left' WHERE chat_id = ?", [chat.id]
        )


def extract_target_entity(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Tuple[Optional[int], Optional[str], Optional[str], List[str]]:
    """
    Extracts target user ID, username, and full name from reply or args.
    Returns: (target_id, target_username, target_name, remaining_args)
    """
    msg = update.effective_message
    if not msg:
        return None, None, None, []

    if msg.reply_to_message and msg.reply_to_message.from_user:
        tu = msg.reply_to_message.from_user
        args = list(context.args) if context.args else []
        return tu.id, tu.username, tu.full_name, args

    args = list(context.args) if context.args else []
    if args:
        first = args[0].strip()
        remaining = args[1:]
        if first.lstrip("-+").isdigit():
            return int(first), None, None, remaining
        if first.startswith("@") or not first.isdigit():
            uname = first.lstrip("@")
            return None, uname, None, remaining

    return None, None, None, []


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
        chunks = split_message(formatted, max_len=3900)
        for ch in chunks:
            try:
                await message.reply_text(ch, parse_mode=ParseMode.HTML)
            except Exception as html_err:
                logger.warning(f"HTML delivery failed for chunk ({html_err}), attempting sanitized fallback...")
                clean_ch = re.sub(r"<[^>]+>", "", ch).strip()
                if clean_ch:
                    await message.reply_text(clean_ch)
    except BadRequest as e:
        logger.warning(f"Telegram BadRequest in response delivery: {e}")
    except Exception as e:
        logger.error(f"Failed to deliver message: {e}")
        try:
            plain_fallback = re.sub(r"<[^>]+>", "", cleaned).strip()
            chunks = split_message(plain_fallback, max_len=3900)
            for ch in chunks:
                await message.reply_text(ch)
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
    "دلار چقدره", "دلار چند تومنه", "دلار چند تومن", "دلار آزاد", "دلار نقدی", "قیمت روز دلار", "نرخ روز دلار",
    "قیمت تتر", "نرخ تتر", "تتر چنده", "تتر چند است", "تتر چند شد", "تتر چقدره", "تتر چند تومنه",
    "قیمت طلا", "نرخ طلا", "طلا چنده", "طلا چند است", "طلا چند شد", "مظنه طلا", "انس طلا", "طلا چقدره",
    "قیمت سکه", "نرخ سکه", "سکه چنده", "سکه چند است", "سکه چند شد", "سکه چقدره",
    "نرخ ارز", "قیمت ارز", "قیمت ارزها", "قیمت روز ارز", "قیمت روز ارزها", "نرخ ارزها", "نرخ روز ارز",
    "ارز چنده", "ارزها چنده", "وضعیت دلار", "وضعیت بازار ارز", "بازار ارز", "ارز و طلا", "طلا و ارز",
    "قیمت دلار و ارز", "قیمت دلار و ارز ها", "قیمت دلار و ارزها", "قیمت ارز و دلار", "قیمت دلار و طلا",
    "ارز آزاد", "ارز دولتی",
    "قیمت یورو", "نرخ یورو", "یورو چنده", "قیمت درهم", "نرخ درهم", "درهم امارات"
)

_FIAT_PHRASE_REGEXES = [
    re.compile(rf"(?<!\w){re.escape(sp)}(?!\w)", re.IGNORECASE)
    for sp in _SPECIFIC_FIAT_PHRASES
]

_FIAT_ASSETS_PATTERN = re.compile(
    r"(?<!\w)(?:دلار|dollar|usd|تتر|usdt|طلا|طلای|سکه|مظنه|یورو|eur|درهم|aed|ارز|ارزها|ارزهای)(?!\w)",
    re.IGNORECASE
)

_FIAT_INTENT_PATTERN = re.compile(
    r"(?<!\w)(?:قیمت|نرخ|چند|چنده|چقدر|چقدره|امروز|روز|لحظه|لحظه‌ای|لحظه ای|بازار|وضعیت|استعلام|چند شد|چند است|چند تومنه|چند تومن|چند شده)(?!\w)",
    re.IGNORECASE
)

_FIAT_EXCLUDED_TOPICS_PATTERN = re.compile(
    r"(?<!\w)(?:اینترنت|هند|هندوستان|سیمکارت|شارژ|بسته|لپ\s*تاپ|لپتاپ|موبایل|گوشی|بلیت|بلیط|هواپیما|هتل|تور|ماشین|خودرو|پایتون|برنامه|کد|سهام|بورس|ارزان|ارزون|ارزش|انسان|آژانس|آرزو)(?!\w)",
    re.IGNORECASE
)


def is_fiat_or_gold_query(text: str) -> bool:
    """Matches natural Persian queries strictly asking about dollar, euro, dirham, gold, or coin rates."""
    t = text.lower().strip()
    if t in ("دلار", "dollar", "usd", "تتر", "usdt", "طلا", "سکه", "ارز", "ارزها", "یورو", "eur", "درهم", "aed", "مظنه", "درهم امارات"):
        return True

    # If general non-financial context is present, reject
    if _FIAT_EXCLUDED_TOPICS_PATTERN.search(t):
        return False

    # Check unambiguous specific phrases with strict boundary
    if any(p.search(t) for p in _FIAT_PHRASE_REGEXES):
        return True

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
    r"^/(?:del|delete|pak|hazf|حذف|پاک)(?:@\w+)?$",
    r"^(?:این\s*(?:رو|پیام\s*رو|پیامو)?\s*)?(?:حذف|پاک|دلیت|دیلیت|del|delete|remove)(?:\s*(?:کن|ش\s*کن|کنید|ش|کردن|پیام))?[!؟\.\s]*$",
    r"^(?:پاکش\s*کن|حذفش\s*کن|دلیتش\s*کن|دیلیتش\s*کن|اینم\s*پاک\s*کن|اینم\s*حذف\s*کن)[!؟\.\s]*$",
    r"^(?:حذف|پاک|دلیت|دیلیت|delete|del|remove)[!؟\.\s]*$",
]


def is_delete_request(text: str) -> bool:
    """Matches requests to delete the bot's own message."""
    t = text.lower().strip()
    return any(bool(re.search(p, t, re.IGNORECASE)) for p in _DELETE_PATTERNS)


_GROUP_LIST_REGEX = re.compile(
    r"^(?:/)?(?:groups|grouplist|listgroups|allgroups|all_groups|"
    r"(?:لیست|فهرست|نمایش|مشاهده)\s+(?:تمام\s+|همه\s+)?گروه(?:[\s\u200c]*(?:ها|های|هایی))?(?:\s+(?:که\s+)?(?:عضوی|توشونی|توشون\s+هستی|هستی|ثبت\s+شده))?(?:\s+(?:من|ربات|ما|شما|تون|ت))?(?:\s+(?:رو|را)?\s*(?:بده|بفرست|بیار|نشون\s+بده))?|"
    r"گروه(?:[\s\u200c]*(?:ها|های|هایی))?(?:\s+(?:که\s+)?(?:عضوی|توشونی|توشون\s+هستی|هستی|ثبت\s+شده))?(?:\s+(?:من|ربات|ما|شما|تون|ت))?(?:\s+(?:رو|را)?\s*(?:بده|بفرست|بیار|نشون\s+بده))?"
    r")$",
    re.IGNORECASE
)


def is_group_list_request(text: str) -> bool:
    """Matches requests asking for the list of Telegram groups."""
    if not text:
        return False
    t = text.strip()
    t = re.sub(r"[?!.؟!]+$", "", t).strip()
    if _GROUP_LIST_REGEX.match(t):
        return True
    t_clean = t.replace("\u200c", " ")
    has_list = any(k in t_clean for k in ["لیست", "فهرست", "نمایش", "مشاهده", "کدوم"])
    has_group = any(k in t_clean for k in ["گروه", "گروها", "groups"])
    if has_list and has_group:
        if not any(k in t_clean for k in ["بن", "بلاک", "میوت", "سکوت", "لاگ", "تنظیم"]):
            return True
    return False


_PROMETHEUS_TRIGGER_NAMES = ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس", "پرومتيوس", "پرومتـه"]


def is_direct_bot_request(update: Update, context: ContextTypes.DEFAULT_TYPE, raw_text: str) -> Tuple[bool, str]:
    """
    Determines if a message is a DIRECT request to Prometheus:
    - In Private Chat (DM): Always True.
    - In Group Chats: True ONLY if:
        1. It starts with a slash command ('/')
        2. It explicitly mentions the bot (@username)
        3. It explicitly calls the bot by name (پرومته, prometheus, ...)
        4. It is a direct reply to one of the bot's own messages.
    Returns: (is_direct: bool, cleaned_text: str)
    """
    chat = update.effective_chat
    message = update.effective_message
    if not chat or not raw_text:
        return False, ""

    text = raw_text.strip()
    if not text:
        return False, ""

    # 1. Private Chat (DM) is ALWAYS a direct interaction
    if chat.type == ChatType.PRIVATE:
        return True, text

    # 2. Group Chats: Strictly require direct invocation
    bot_id = context.bot.id if context and getattr(context, "bot", None) else None
    bot_username = (context.bot.username or "").lower() if context and getattr(context, "bot", None) else ""

    # a) Slash command
    if text.startswith("/"):
        if bot_username:
            text = re.sub(rf"^(/[a-zA-Z0-9_]+)@{re.escape(bot_username)}\b", r"\1", text, flags=re.IGNORECASE)
        return True, text

    # b) Mention via @bot_username
    if bot_username and f"@{bot_username}" in text.lower():
        cleaned = re.sub(rf"@{re.escape(bot_username)}", "", text, flags=re.IGNORECASE).strip()
        return True, cleaned

    # c) Explicit trigger names (PROMETHEUS)
    has_trigger_name = False
    cleaned = text
    for name in _PROMETHEUS_TRIGGER_NAMES:
        if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text, flags=re.IGNORECASE):
            has_trigger_name = True
            cleaned = re.sub(rf"(?<!\w){re.escape(name)}(?!\w)", "", cleaned, flags=re.IGNORECASE).strip()

    if has_trigger_name:
        cleaned = cleaned.lstrip("،, :!-؟?").rstrip("،, :!-؟?").strip()
        return True, cleaned

    # d) Direct reply to the bot's own message
    if message and message.reply_to_message and message.reply_to_message.from_user:
        rep_u = message.reply_to_message.from_user
        if (bot_id and rep_u.id == bot_id) or (bot_username and rep_u.username and rep_u.username.lower() == bot_username):
            return True, text

    return False, ""


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
    if not await _check_moderation_guard(update, context):
        return

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
        "• 🐦 **کاوشگر و خواننده X (توییتر):** `/twitter [اکانت یا جستجو]` یا ارسال لینک توییت\n"
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
    if not await _check_moderation_guard(update, context):
        return

    msg = update.effective_message
    user = update.effective_user

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
        "• `/tweet [لینک توییت]` - استخراج متن، آمار، رسانه‌ها و ترجمه توییت از X (توییتر)\n"
        "• `/twitter [یوزرنیم یا موضوع]` - مشاهده پروفایل، بیوگرافی و جستجوی زنده در X\n"
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

    if user and is_admin(user.id):
        text += (
            "\n\n👮‍♂️ **دستورات مدیریت و نظارت ادمین (Admin Governance):**\n"
            "• `/ban [کاربر/ریپلای] [علت]` - مسدودسازی دائم کاربر از ربات\n"
            "• `/unban [کاربر/ریپلای]` - رفع مسدودیت کاربر و ثبت در دیتابیس\n"
            "• `/mute [کاربر/ریپلای] [مدت] [علت]` - سکوت کاربر (مثال: `/mute 30m` یا `/mute 2h`)\n"
            "• `/unmute [کاربر/ریپلای]` - لغو سکوت کاربر\n"
            "• `/bangroup [شناسه گروه] [علت]` - مسدودسازی کامل ربات در گروه\n"
            "• `/unbangroup [شناسه گروه]` - رفع مسدودیت گروه\n"
            "• `/mutegroup [مدت]` - میوت کردن ربات در گروه\n"
            "• `/unmutegroup` - لغو سکوت ربات در گروه\n"
            "• `/banlist` - لیست دائم افراد و گروه‌های بن‌شده با یوزرنیم و آیدی عددی\n"
            "• `/mutelist` - لیست فعال افراد و گروه‌های میوت‌شده با زمان باقیمانده\n"
            "• `/groups` - فهرست تمامی گروه‌های ثبت‌شده، فعال، مسدود و وضعیت آن‌ها\n"
            "• `/pendinggroups` - لیست گروه‌های جدید در انتظار تایید ادمین\n"
            "• `/approvegroup [شناسه]` - تایید دستی فعال‌سازی ربات در گروه\n"
            "• `/rejectgroup [شناسه]` - رد فعال‌سازی و خروج ربات از گروه\n"
            "• `/set [کلید] [مقدار]` - ثبت دائم دستور و تنظیمات در دیتابیس\n"
            "• `/get [کلید]` - خواندن تنظیمات از دیتابیس\n"
            "• `/adminsettings` - مشاهده تمامی تنظیمات ذخیره‌شده\n"
            "• `/adminlogs` - تاریخچه و لاگ دائم تمامی دستورات ادمین‌ها"
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
    """Direct Telegraph article publishing command with AI generation support."""
    msg = update.effective_message
    if not msg:
        return

    chat = update.effective_chat
    user = update.effective_user

    # Check if this command is a reply to another message
    reply_msg = msg.reply_to_message
    args_text = " ".join(context.args or []).strip()

    if reply_msg and (reply_msg.text or reply_msg.caption):
        if chat:
            await chat.send_action(ChatAction.TYPING)
        content = reply_msg.text or reply_msg.caption or ""
        title = args_text if args_text else "مستند تلگراف پرومته"
    elif "|" in args_text:
        if chat:
            await chat.send_action(ChatAction.TYPING)
        title, content = extract_telegraph_args(args_text)
    elif "\n" in args_text or len(args_text) >= 120:
        if chat:
            await chat.send_action(ChatAction.TYPING)
        title, content = extract_telegraph_args(args_text)
    elif args_text:
        # User provided a topic to research, generate, and publish as an article
        topic = args_text.strip()
        status_msg = await msg.reply_text(
            f"✍️ <b>پرومته در حال نگارش مقاله تخصصی درباره «{html.escape(topic)}» و انتشار در تلگراف است...</b>",
            parse_mode=ParseMode.HTML
        )
        article_prompt = (
            f"یک مقاله تخصصی، عمیق و جامع به زبان فارسی با ساختار مارک‌داون حرفه‌ای، "
            f"تیتربندی استاندارد، چکیده اجرایی، جدول و نکات کلیدی درباره «{topic}» بنویس."
        )
        article_body = await execute_hermes_agent(
            chat_id=chat.id if chat else 0,
            user_prompt=article_prompt,
            user_id=user.id if user else 0,
            username=user.username or "" if user else "",
            force_agent=True
        )
        try:
            await status_msg.delete()
        except Exception:
            pass

        res = await create_telegraph_article(title=topic, content=article_body)
        await _deliver_reply(msg, res)
        return
    else:
        guide = (
            "📝 **راهنمای انتشار مقالات در تلگراف (Telegra.ph):**\n\n"
            "برای انتشار مقاله با نمایش فوری (Instant View) می‌توانید از روش‌های زیر استفاده کنید:\n\n"
            "۱. **تولید خودکار مقاله با هوش مصنوعی:**\n"
            "`/article هوش مصنوعی در سال 2026`\n"
            "`/telegraph ترندهای فناوری کوانتومی`\n\n"
            "۲. **فرمت مستقیم عنوان و متن:**\n"
            "`/telegraph عنوان مقاله | متن کامل مقاله`\n\n"
            "۳. **ریپلای روی پیام:**\n"
            "روی هر پیام بلندی ریپلای بزنید و دستور `/telegraph [عنوان اختیاری]` را ارسال کنید.\n\n"
            "۴. **گفتگوی آزاد با پرومته:**\n"
            "*«یک مقاله کامل در مورد بلاکچین بنویس و در تلگراف منتشر کن»*"
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
    bot_user = context.bot if (context and getattr(context, "bot", None)) else None
    bot_id = bot_user.id if bot_user else None
    bot_username = (bot_user.username or "").lower() if bot_user else ""
    reply_to = msg.reply_to_message
    if reply_to and reply_to.from_user:
        is_from_bot = (
            (bot_id and reply_to.from_user.id == bot_id)
            or (reply_to.from_user.is_bot and bot_username and (reply_to.from_user.username or "").lower() == bot_username)
        )
        if is_from_bot:
            try:
                await reply_to.delete()
            except Exception as e:
                logger.warning(f"Failed to delete bot message: {e}")
            try:
                await msg.delete()
            except Exception:
                pass
            return
        else:
            await msg.reply_text("⚠️ من فقط می‌توانم پیام‌هایی که خودم ارسال کرده‌ام را حذف کنم.")
            return
    else:
        await msg.reply_text("ℹ️ برای حذف پیام پرومته، لطفاً روی پیام مورد نظر ریپلای کرده و کلمه «حذف» یا /del را ارسال نمایید.")


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

    if not await _check_moderation_guard(update, context):
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


async def twitter_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles /twitter, /tweet, /x commands for reading tweets, profiles, or searching."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return

    args = context.args or []
    query = " ".join(args).strip()

    if not query:
        guide = (
            "🐦 **راهنمای کاوشگر و خواننده X (توییتر) پرومته:**\n\n"
            "• **خواندن و تحلیل کامل یک توییت:**\n"
            "`/tweet https://x.com/username/status/123456...`\n\n"
            "• **مشاهده پروفایل و آمار یک کاربر:**\n"
            "`/twitter @elonmusk`\n\n"
            "• **جستجو در جدیدترین توییت‌ها و مباحث:**\n"
            "`/twitter هوش مصنوعی جدید`\n\n"
            "💡 *همچنین می‌توانید لینک هر توییت را مستقیماً در چت بفرستید یا بپرسید «این توییت چی میگه؟»*"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.MARKDOWN)
        return

    await chat.send_action(ChatAction.TYPING)
    t0 = time.perf_counter()

    is_m, act, target = parse_twitter_request(query)
    if not is_m or not target:
        target = query
        act = "search"

    if act == "tweet":
        sn, tid = target.split(":", 1)
        tweet_data = await fetch_tweet_data(sn, tid)
        if tweet_data:
            report = format_tweet_report(tweet_data)
            record_chat_latency(chat.id, time.perf_counter() - t0, f"استخراج توییت (@{sn})")
            await _deliver_reply(msg, report)
            return
        else:
            await msg.reply_text("❌ متأسفانه دریافت اطلاعات این توییت میسر نشد (ممکن است توییت خصوصی، حذف‌شده یا آدرس نادرست باشد).")
            return

    elif act == "profile":
        profile_data = await fetch_twitter_profile(target)
        if profile_data:
            report = format_profile_report(profile_data)
            record_chat_latency(chat.id, time.perf_counter() - t0, f"پروفایل توییتر (@{target})")
            await _deliver_reply(msg, report)
            return
        else:
            await msg.reply_text(f"❌ پروفایل کاربری @{target} در توییتر/X یافت نشد یا در دسترس نیست.")
            return

    elif act == "search":
        search_res = await search_twitter_live(target, max_results=4)
        if search_res:
            record_chat_latency(chat.id, time.perf_counter() - t0, f"جستجوی زنده توییتر ({target})")
            await _deliver_reply(msg, search_res)
            return
        else:
            await msg.reply_text(f"🔍 نتیجه‌ای برای جستجوی «{query}» در شبکه X یافت نشد.")
            return


# =========================================================================
# Unified Admin Moderation Execution & Natural Language Interceptor
# =========================================================================

def extract_duration_and_reason(text: str, default_duration: float = 3600.0) -> Tuple[float, str]:
    """
    Extracts duration in seconds and remaining reason string from text.
    Handles English (10m, 2h, 1d) and Persian (۳۰ دقیقه, ۲ ساعت, ۱ روز).
    """
    if not text or not text.strip():
        return default_duration, ""

    t = text.strip()

    # Persian multi-word durations (e.g. "۲ ساعت", "۳۰ دقیقه", "۱ روز")
    fa_pat = r"^([۰-۹\d]+)\s*(ثانیه|دقیقه|ساعت|روز|هفته|ماه)(?:\s+(.*))?$"
    m_fa = re.match(fa_pat, t)
    if m_fa:
        dur_str = f"{m_fa.group(1)} {m_fa.group(2)}"
        dur = parse_duration_string(dur_str)
        reason = (m_fa.group(3) or "").strip()
        return (dur or default_duration), reason

    # English / short token (e.g. "10m", "2h", "1d", "60s")
    parts = t.split(maxsplit=1)
    dur = parse_duration_string(parts[0])
    if dur:
        reason = parts[1].strip() if len(parts) > 1 else ""
        return dur, reason

    return default_duration, t


async def execute_admin_ban(update: Update, context: ContextTypes.DEFAULT_TYPE, rem_text: str = "") -> bool:
    """Executes ban in database and attempts Telegram chat kick if in a group."""
    msg = update.effective_message
    user = update.effective_user
    chat = update.effective_chat
    if not user or not is_admin(user.id) or not msg:
        return False

    tid = None
    tuname = None
    tname = None
    reason = rem_text.strip()

    # 1. Target from reply
    if msg.reply_to_message:
        ru = msg.reply_to_message.from_user
        if ru:
            tid = ru.id
            tuname = ru.username or ""
            tname = ru.full_name or ""
        elif msg.reply_to_message.sender_chat:
            tid = msg.reply_to_message.sender_chat.id
            tname = msg.reply_to_message.sender_chat.title or ""
            tuname = msg.reply_to_message.sender_chat.username or ""
    elif rem_text:
        parts = rem_text.split(maxsplit=1)
        first_token = parts[0].strip()
        if first_token.lstrip("-+").isdigit():
            tid = int(first_token)
            reason = parts[1].strip() if len(parts) > 1 else ""
        elif first_token.startswith("@") or not first_token.isalnum():
            clean_first = first_token.lstrip("@")
            if re.match(r"^[a-zA-Z0-9_]{3,32}$", clean_first):
                tuname = clean_first
                reason = parts[1].strip() if len(parts) > 1 else ""

    if not tid and not tuname:
        await msg.reply_text(
            "⚠️ <b>راهنمای مسدودسازی (بن):</b>\n\n"
            "۱. <b>با ریپلای:</b> روی پیام کاربر ریپلای کنید و بفرستید: <code>بن</code> یا <code>/ban [علت]</code>\n"
            "۲. <b>با آیدی عددی:</b> <code>/ban 123456789 [علت]</code>\n"
            "۳. <b>با یوزرنیم:</b> <code>/ban @username [علت]</code>",
            parse_mode=ParseMode.HTML
        )
        return True

    if tid and is_admin(tid):
        await msg.reply_text("⛔️ خطا: امکان مسدود کردن ادمین ربات وجود ندارد.")
        return True

    if not reason:
        reason = "دستور مستقیم ادمین"

    target_id = tid or 0

    # 1. Database & Cache Ban
    await ban_user(
        user_id=target_id,
        username=tuname or "",
        name=tname or "",
        reason=reason,
        banned_by=user.id,
        chat_id=chat.id if chat else 0,
        chat_title=chat.title if chat else ""
    )

    # 2. Telegram Group Kick/Ban
    tg_status = ""
    if chat and chat.type != ChatType.PRIVATE and target_id > 0:
        try:
            await context.bot.ban_chat_member(chat_id=chat.id, user_id=target_id)
            tg_status = "\n⚡️ <i>کاربر همچنین از این گروه تلگرام اخراج (Ban) شد.</i>"
        except BadRequest as e:
            err_msg = str(e).lower()
            if "not enough rights" in err_msg or "chat_admin_required" in err_msg or "admin" in err_msg:
                tg_status = "\nℹ️ <i>توجه: کاربر از خدمات ربات مسدود شد. برای اخراج فیزیکی از گروه تلگرام، ربات را در این گروه ادمین کرده و دسترسی Ban Users بدهید.</i>"
            else:
                tg_status = f"\nℹ️ <i>وضعیت در تلگرام: {e}</i>"
        except Exception as e:
            logger.warning(f"Telegram ban_chat_member failed: {e}")
            tg_status = f"\nℹ️ <i>وضعیت در تلگرام: {e}</i>"

    disp = f"<code>{target_id}</code>" if target_id else ""
    if tuname:
        disp += f" (@{tuname})" if disp else f"@{tuname}"
    if tname:
        disp += f" ({html.escape(tname)})"

    confirm = (
        "🚫 <b>کاربر با موفقیت مسدود (Ban) شد:</b>\n\n"
        f"👤 <b>کاربر:</b> {disp}\n"
        f"📝 <b>علت:</b> {html.escape(reason)}\n"
        f"👮‍♂️ <b>ثبت‌کننده:</b> <code>{user.id}</code> ({html.escape(user.full_name)})\n"
        f"💾 <b>دیتابیس:</b> ثبت دائم در Cloudflare D1 و حافظه RAM.\n"
        f"🔒 <b>رفتار ربات:</b> عدم پاسخگویی و مسدودسازی کامل."
        f"{tg_status}"
    )
    await msg.reply_text(confirm, parse_mode=ParseMode.HTML)
    return True


async def execute_admin_unban(update: Update, context: ContextTypes.DEFAULT_TYPE, rem_text: str = "") -> bool:
    """Executes unban in database and attempts Telegram chat unban if in a group."""
    msg = update.effective_message
    user = update.effective_user
    chat = update.effective_chat
    if not user or not is_admin(user.id) or not msg:
        return False

    tid = None
    tuname = None
    reason = rem_text.strip()

    if msg.reply_to_message:
        ru = msg.reply_to_message.from_user
        if ru:
            tid = ru.id
            tuname = ru.username or ""
        elif msg.reply_to_message.sender_chat:
            tid = msg.reply_to_message.sender_chat.id
            tuname = msg.reply_to_message.sender_chat.username or ""
    elif rem_text:
        parts = rem_text.split(maxsplit=1)
        first_token = parts[0].strip()
        if first_token.lstrip("-+").isdigit():
            tid = int(first_token)
            reason = parts[1].strip() if len(parts) > 1 else ""
        elif first_token.startswith("@") or not first_token.isalnum():
            clean_first = first_token.lstrip("@")
            if re.match(r"^[a-zA-Z0-9_]{3,32}$", clean_first):
                tuname = clean_first
                reason = parts[1].strip() if len(parts) > 1 else ""

    if not tid and not tuname:
        await msg.reply_text(
            "⚠️ <b>راهنمای رفع مسدودیت (آنبن):</b>\n\n"
            "• ریپلای روی پیام: <code>آنبن</code> یا <code>/unban</code>\n"
            "• با آیدی عددی: <code>/unban 123456789</code>\n"
            "• با یوزرنیم: <code>/unban @username</code>",
            parse_mode=ParseMode.HTML
        )
        return True

    target_id = tid
    if not target_id and tuname:
        with _MOD_LOCK:
            rec = _BANNED_USERNAMES.get(tuname.lower())
            if rec:
                target_id = int(rec.get("user_id") or 0)

    if target_id is None:
        target_id = 0

    if not reason:
        reason = "رفع مسدودیت توسط ادمین"

    ok, prev_info = await unban_user(user_id=target_id, unbanned_by=user.id, reason=reason)

    tg_status = ""
    if chat and chat.type != ChatType.PRIVATE and target_id > 0:
        try:
            await context.bot.unban_chat_member(chat_id=chat.id, user_id=target_id, only_if_banned=True)
            tg_status = "\n⚡️ <i>کاربر در گروه تلگرام نیز رفع مسدودیت شد.</i>"
        except Exception as tg_err:
            logger.debug(f"Telegram unban_chat_member: {tg_err}")

    u_name = tuname or (prev_info.get("username") if prev_info else "")
    t_name = (prev_info.get("name") or prev_info.get("first_name")) if prev_info else ""
    disp = f"<code>{target_id}</code>" if target_id else ""
    if u_name:
        disp += f" (@{u_name})" if disp else f"@{u_name}"
    if t_name:
        disp += f" ({html.escape(t_name)})"

    await msg.reply_text(
        f"✅ <b>کاربر {disp} با موفقیت رفع مسدودیت (Unban) شد.</b>\n"
        f"📝 ثبت دائم در لاگ بازرسی دیتابیس (unbanned_log)."
        f"{tg_status}",
        parse_mode=ParseMode.HTML
    )
    return True


async def execute_admin_mute(update: Update, context: ContextTypes.DEFAULT_TYPE, rem_text: str = "") -> bool:
    """Executes mute in database and Telegram restrict if in a group."""
    msg = update.effective_message
    user = update.effective_user
    chat = update.effective_chat
    if not user or not is_admin(user.id) or not msg:
        return False

    tid = None
    tuname = None
    tname = None
    target_text = rem_text

    if msg.reply_to_message:
        ru = msg.reply_to_message.from_user
        if ru:
            tid = ru.id
            tuname = ru.username or ""
            tname = ru.full_name or ""
        elif msg.reply_to_message.sender_chat:
            tid = msg.reply_to_message.sender_chat.id
            tname = msg.reply_to_message.sender_chat.title or ""
            tuname = msg.reply_to_message.sender_chat.username or ""
    elif rem_text:
        parts = rem_text.split(maxsplit=1)
        first_token = parts[0].strip()
        if first_token.lstrip("-+").isdigit():
            tid = int(first_token)
            target_text = parts[1] if len(parts) > 1 else ""
        elif first_token.startswith("@") or not first_token.isalnum():
            clean_first = first_token.lstrip("@")
            if re.match(r"^[a-zA-Z0-9_]{3,32}$", clean_first):
                tuname = clean_first
                target_text = parts[1] if len(parts) > 1 else ""

    if not tid and not tuname:
        await msg.reply_text(
            "⚠️ <b>راهنمای بی‌صدا کردن (میوت):</b>\n\n"
            "• ریپلای روی پیام: <code>میوت 30m [علت]</code> یا <code>سکوت ۲ ساعت</code>\n"
            "• با آیدی عددی: <code>/mute 123456789 1h [علت]</code>\n"
            "• با یوزرنیم: <code>/mute @username 1d [علت]</code>\n\n"
            "💡 زمان‌ها: <code>10m</code>, <code>2h</code>, <code>1d</code> یا فارسی: <code>۳۰ دقیقه</code>, <code>۲ ساعت</code> (پیش‌فرض: ۶۰ دقیقه)",
            parse_mode=ParseMode.HTML
        )
        return True

    if tid and is_admin(tid):
        await msg.reply_text("⛔️ امکان میوت کردن ادمین ربات وجود ندارد.")
        return True

    duration_sec, reason = extract_duration_and_reason(target_text)
    if not reason:
        reason = "دستور مستقیم ادمین"

    target_id = tid or 0

    ok, until_ts = await mute_user(
        user_id=target_id,
        duration_sec=duration_sec,
        username=tuname or "",
        first_name=tname or "",
        reason=reason,
        muted_by=user.id,
        chat_id=chat.id if chat else 0,
        chat_title=chat.title if chat else ""
    )

    tg_status = ""
    if chat and chat.type != ChatType.PRIVATE and target_id > 0:
        try:
            until_dt = datetime.fromtimestamp(until_ts, tz=timezone.utc)
            await context.bot.restrict_chat_member(
                chat_id=chat.id,
                user_id=target_id,
                permissions=ChatPermissions(
                    can_send_messages=False,
                    can_send_audios=False,
                    can_send_documents=False,
                    can_send_photos=False,
                    can_send_videos=False,
                    can_send_video_notes=False,
                    can_send_voice_notes=False,
                    can_send_polls=False,
                    can_send_other_messages=False,
                    can_add_web_page_previews=False
                ),
                until_date=until_dt
            )
            tg_status = "\n⚡️ <i>کاربر در گروه تلگرام نیز تا پایان زمان بی‌صدا شد.</i>"
        except BadRequest as e:
            err_msg = str(e).lower()
            if "not enough rights" in err_msg or "chat_admin_required" in err_msg:
                tg_status = "\nℹ️ <i>توجه: کاربر از پاسخگویی ربات میوت شد. برای سلب دسترسی چت در گروه، ربات را ادمین کرده و دسترسی Restrict Members بدهید.</i>"
            else:
                tg_status = f"\nℹ️ <i>وضعیت در تلگرام: {e}</i>"
        except Exception as e:
            logger.warning(f"Telegram restrict_chat_member failed: {e}")
            tg_status = f"\nℹ️ <i>وضعیت در تلگرام: {e}</i>"

    dur_fa = format_duration_persian(duration_sec)
    disp = f"<code>{target_id}</code>" if target_id else ""
    if tuname:
        disp += f" (@{tuname})" if disp else f"@{tuname}"
    if tname:
        disp += f" ({html.escape(tname)})"

    confirm = (
        "🤐 <b>کاربر با موفقیت بی‌صدا (Mute) شد:</b>\n\n"
        f"👤 <b>کاربر:</b> {disp}\n"
        f"⏱ <b>مدت زمان:</b> {dur_fa}\n"
        f"📝 <b>علت:</b> {html.escape(reason)}\n"
        f"👮‍♂️ <b>ثبت‌کننده:</b> <code>{user.id}</code> ({html.escape(user.full_name)})\n"
        f"🔒 <b>رفتار ربات:</b> عدم پاسخگویی مطلق به این کاربر تا پایان زمان میوت.\n"
        f"💾 ذخیره در Cloudflare D1 با لغو خودکار پس از انقضا."
        f"{tg_status}"
    )
    await msg.reply_text(confirm, parse_mode=ParseMode.HTML)
    return True


async def execute_admin_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE, rem_text: str = "") -> bool:
    """Executes unmute in database and restores Telegram permissions."""
    msg = update.effective_message
    user = update.effective_user
    chat = update.effective_chat
    if not user or not is_admin(user.id) or not msg:
        return False

    tid = None
    tuname = None

    if msg.reply_to_message:
        ru = msg.reply_to_message.from_user
        if ru:
            tid = ru.id
            tuname = ru.username or ""
        elif msg.reply_to_message.sender_chat:
            tid = msg.reply_to_message.sender_chat.id
            tuname = msg.reply_to_message.sender_chat.username or ""
    elif rem_text:
        parts = rem_text.split()
        first_token = parts[0].strip()
        if first_token.lstrip("-+").isdigit():
            tid = int(first_token)
        elif first_token.startswith("@") or not first_token.isalnum():
            clean_first = first_token.lstrip("@")
            if re.match(r"^[a-zA-Z0-9_]{3,32}$", clean_first):
                tuname = clean_first

    if not tid and not tuname:
        await msg.reply_text(
            "⚠️ <b>راهنمای رفع سکوت (آنمیوت):</b>\n\n"
            "• ریپلای روی پیام: <code>آنمیوت</code> یا <code>/unmute</code>\n"
            "• با آیدی: <code>/unmute 123456789</code>\n"
            "• با یوزرنیم: <code>/unmute @username</code>",
            parse_mode=ParseMode.HTML
        )
        return True

    target_id = tid
    if not target_id and tuname:
        with _MOD_LOCK:
            rec = _MUTED_USERNAMES.get(tuname.lower())
            if rec:
                target_id = int(rec.get("user_id") or 0)

    if target_id is None:
        target_id = 0

    await unmute_user(user_id=target_id, unmuted_by=user.id)

    tg_status = ""
    if chat and chat.type != ChatType.PRIVATE and target_id > 0:
        try:
            await context.bot.restrict_chat_member(
                chat_id=chat.id,
                user_id=target_id,
                permissions=ChatPermissions(
                    can_send_messages=True,
                    can_send_audios=True,
                    can_send_documents=True,
                    can_send_photos=True,
                    can_send_videos=True,
                    can_send_video_notes=True,
                    can_send_voice_notes=True,
                    can_send_polls=True,
                    can_send_other_messages=True,
                    can_add_web_page_previews=True
                )
            )
            tg_status = "\n⚡️ <i>محدودیت چت کاربر در گروه تلگرام نیز لغو شد.</i>"
        except Exception as tg_err:
            logger.debug(f"Telegram restrict_chat_member unmute: {tg_err}")

    disp = f"<code>{target_id}</code>" if target_id else ""
    if tuname:
        disp += f" (@{tuname})" if disp else f"@{tuname}"

    await msg.reply_text(
        f"🔊 <b>سکوت کاربر {disp} لغو شد (Unmuted).</b>\n"
        f"🤖 ربات مجدداً به پیام‌های این کاربر پاسخ خواهد داد."
        f"{tg_status}",
        parse_mode=ParseMode.HTML
    )
    return True


async def execute_admin_bangroup(update: Update, context: ContextTypes.DEFAULT_TYPE, rem_text: str = "") -> bool:
    """Bans a group from using the bot."""
    user = update.effective_user
    msg = update.effective_message
    chat = update.effective_chat
    if not user or not is_admin(user.id) or not msg:
        return False

    parts = rem_text.split()
    target_chat_id = None
    reason_parts = []
    if parts and parts[0].lstrip("-+").isdigit():
        target_chat_id = int(parts[0])
        reason_parts = parts[1:]
    elif chat and chat.type != ChatType.PRIVATE:
        target_chat_id = chat.id
        reason_parts = parts

    if not target_chat_id:
        await msg.reply_text(
            "⚠️ دستور را در گروه مربوطه اجرا کرده یا شناسه چت را وارد نمایید:\n<code>/bangroup -100xxxxxxxxxx [علت]</code>",
            parse_mode=ParseMode.HTML
        )
        return True

    reason = " ".join(reason_parts).strip() or "مسدودسازی گروه به دستور ادمین"
    title = chat.title if (chat and chat.id == target_chat_id) else f"گروه {target_chat_id}"
    await ban_group(chat_id=target_chat_id, title=title, reason=reason, banned_by=user.id)

    await msg.reply_text(
        f"🚫 <b>گروه <code>{target_chat_id}</code> ({html.escape(title)}) مسدود شد.</b>\n"
        f"ربات در این گروه به صورت کامل غیرفعال و خاموش خواهد بود.",
        parse_mode=ParseMode.HTML
    )
    return True


async def execute_admin_unbangroup(update: Update, context: ContextTypes.DEFAULT_TYPE, rem_text: str = "") -> bool:
    """Unbans a group."""
    user = update.effective_user
    msg = update.effective_message
    chat = update.effective_chat
    if not user or not is_admin(user.id) or not msg:
        return False

    parts = rem_text.split()
    target_chat_id = None
    if parts and parts[0].lstrip("-+").isdigit():
        target_chat_id = int(parts[0])
    elif chat and chat.type != ChatType.PRIVATE:
        target_chat_id = chat.id

    if not target_chat_id:
        await msg.reply_text("⚠️ لطفاً شناسه گروه را قید فرمایید:\n<code>/unbangroup -100xxxxxxxxxx</code>", parse_mode=ParseMode.HTML)
        return True

    reason = " ".join(parts[1:]).strip() if (parts and len(parts) > 1) else "رفع مسدودیت توسط ادمین"
    await unban_group(chat_id=target_chat_id, unbanned_by=user.id, reason=reason)

    await msg.reply_text(
        f"✅ <b>مسدودیت گروه <code>{target_chat_id}</code> رفع شد و در لاگ دیتابیس ثبت گردید.</b>",
        parse_mode=ParseMode.HTML
    )
    return True


async def execute_admin_mutegroup(update: Update, context: ContextTypes.DEFAULT_TYPE, rem_text: str = "") -> bool:
    """Mutes the bot in a group."""
    user = update.effective_user
    msg = update.effective_message
    chat = update.effective_chat
    if not user or not is_admin(user.id) or not msg:
        return False

    parts = rem_text.split()
    target_chat_id = None
    dur_text = rem_text
    if parts and parts[0].lstrip("-+").isdigit() and (parts[0].startswith("-100") or len(parts[0]) > 8):
        target_chat_id = int(parts[0])
        dur_text = " ".join(parts[1:])
    elif chat and chat.type != ChatType.PRIVATE:
        target_chat_id = chat.id

    if not target_chat_id:
        await msg.reply_text("⚠️ دستور را در گروه مربوطه اجرا نمایید یا شناسه گروه را قید فرمایید.", parse_mode=ParseMode.HTML)
        return True

    duration_sec = 0.0
    if dur_text:
        d = parse_duration_string(dur_text)
        if d:
            duration_sec = d

    title = chat.title if (chat and chat.id == target_chat_id) else f"گروه {target_chat_id}"
    await mute_group(chat_id=target_chat_id, duration_sec=duration_sec, title=title, muted_by=user.id)

    dur_msg = format_duration_persian(duration_sec) if duration_sec > 0 else "تا زمان لغو دستی توسط ادمین"
    await msg.reply_text(
        f"🤐 <b>ربات در گروه <code>{target_chat_id}</code> ({html.escape(title)}) میوت شد:</b>\n\n"
        f"⏱ <b>مدت زمان:</b> {dur_msg}\n"
        f"ربات در این گروه به پیام‌های کاربران پاسخی ارسال نخواهد کرد.",
        parse_mode=ParseMode.HTML
    )
    return True


async def execute_admin_unmutegroup(update: Update, context: ContextTypes.DEFAULT_TYPE, rem_text: str = "") -> bool:
    """Unmutes the bot in a group."""
    user = update.effective_user
    msg = update.effective_message
    chat = update.effective_chat
    if not user or not is_admin(user.id) or not msg:
        return False

    parts = rem_text.split()
    target_chat_id = None
    if parts and parts[0].lstrip("-+").isdigit():
        target_chat_id = int(parts[0])
    elif chat and chat.type != ChatType.PRIVATE:
        target_chat_id = chat.id

    if not target_chat_id:
        await msg.reply_text("⚠️ لطفاً در گروه مورد نظر ارسال فرمایید یا شناسه گروه را قید کنید.", parse_mode=ParseMode.HTML)
        return True

    await unmute_group(chat_id=target_chat_id, unmuted_by=user.id)
    await msg.reply_text(
        f"🔊 <b>سکوت ربات در گروه <code>{target_chat_id}</code> لغو شد.</b>\nربات طبق روال عادی پاسخگو خواهد بود.",
        parse_mode=ParseMode.HTML
    )
    return True


async def handle_admin_text_command(update: Update, context: ContextTypes.DEFAULT_TYPE, raw_text: str) -> bool:
    """
    Directly intercepts admin commands (Persian natural language and slash commands)
    and executes them immediately without ever sending them to the AI LLM.
    Strictly requires that the bot is DIRECTLY addressed when in group chats.
    """
    user = update.effective_user
    chat = update.effective_chat
    if not user or not is_admin(user.id):
        return False

    # In group chats, strictly require that the bot was directly requested
    if chat and chat.type != ChatType.PRIVATE:
        is_direct, t = is_direct_bot_request(update, context, raw_text)
        if not is_direct or not t:
            return False
    else:
        t = (raw_text or "").strip()

    if not t:
        return False

    bot_username = (context.bot.username or "").lower() if context and getattr(context, "bot", None) else ""
    if bot_username:
        t = re.sub(rf"@{re.escape(bot_username)}", "", t, flags=re.IGNORECASE).strip()

    for name in _PROMETHEUS_TRIGGER_NAMES:
        t = re.sub(rf"^(?:{re.escape(name)}[\s,:،-]*)+", "", t, flags=re.IGNORECASE).strip()
        t = re.sub(rf"[\s,:،-]+(?:{re.escape(name)})+$", "", t, flags=re.IGNORECASE).strip()

    if not t:
        return False

    # 1. Ban List
    if re.match(r"^(?:/)?(?:banlist|bans|لیست\s+بن(?:‌ها)?|لیست\s+مسدود(?:ها|ین)?)$", t, re.IGNORECASE):
        await banlist_command(update, context)
        return True

    # 2. Mute List
    if re.match(r"^(?:/)?(?:mutelist|mutes|لیست\s+میوت(?:‌ها)?|لیست\s+سکوت)$", t, re.IGNORECASE):
        await mutelist_command(update, context)
        return True

    # 3. All Groups List
    if is_group_list_request(t):
        await grouplist_command(update, context)
        return True

    # 3.1 Pending Groups Specifically
    if re.match(r"^(?:/)?(?:pendinggroups|pending_groups|(?:لیست|فهرست)?\s*گروه(?:[\s\u200c]*(?:ها|های))?\s+در\s+انتظار(?:\s+تایید)?)$", t, re.IGNORECASE):
        await pendinggroups_command(update, context)
        return True

    # 4. Admin Settings & Directives List
    if re.match(r"^(?:/)?(?:directives|adminrules|rules|adminsettings|customdata|(?:لیست|فهرست|مشاهده|نمایش)?\s*(?:دستورات|تنظیمات|قوانین)\s*(?:ادمین|دائمی)?)$", t, re.IGNORECASE):
        await settings_command(update, context)
        return True

    # 5. Admin Logs
    if re.match(r"^(?:/)?(?:adminlogs|audit|لاگ\s+ادمین|لاگ(?:‌ها)?)$", t, re.IGNORECASE):
        await adminlogs_command(update, context)
        return True

    # 6. Group Unban
    unbangroup_m = re.match(r"^(?:/)?(?:unbangroup|unban_group|(?:آنبن|انبن|نبن|آن\s+بن|رفع\s+بن|لغو\s+بن)\s+گروه)(?:\s+(.*))?$", t, re.IGNORECASE)
    if unbangroup_m:
        return await execute_admin_unbangroup(update, context, unbangroup_m.group(1) or "")

    # 7. Group Ban
    bangroup_m = re.match(r"^(?:/)?(?:bangroup|ban_group|(?:بن|بلاک|مسدود)\s+گروه)(?:\s+(.*))?$", t, re.IGNORECASE)
    if bangroup_m:
        return await execute_admin_bangroup(update, context, bangroup_m.group(1) or "")

    # 8. Group Unmute
    unmutegroup_m = re.match(r"^(?:/)?(?:unmutegroup|unmute_group|unmutebot|(?:آنمیوت|انمیوت|نمیوت|آن\s+میوت|لغو\s+سکوت|رفع\s+سکوت|لغو\s+میوت|رفع\s+میوت)\s+گروه)(?:\s+(.*))?$", t, re.IGNORECASE)
    if unmutegroup_m:
        return await execute_admin_unmutegroup(update, context, unmutegroup_m.group(1) or "")

    # 9. Group Mute
    mutegroup_m = re.match(r"^(?:/)?(?:mutegroup|mute_group|mutebot|(?:میوت|سکوت)\s+گروه)(?:\s+(.*))?$", t, re.IGNORECASE)
    if mutegroup_m:
        return await execute_admin_mutegroup(update, context, mutegroup_m.group(1) or "")

    # 10. User Unban
    unban_m = re.match(r"^(?:/)?(?:unban|unblock|آنبن|انبن|نبن|آن\s+بن|رفع\s+بن|لغو\s+بن|حذف\s+بن|انبلاک|آنبلاک|رفع\s+بلاک|لغو\s+بلاک|رفع\s+مسدودیت|لغو\s+مسدودیت)(?:\s+(?:کن|ش\s+کن|ش))?(?:\s+(.*))?$", t, re.IGNORECASE)
    if unban_m:
        return await execute_admin_unban(update, context, unban_m.group(1) or "")

    # 11. User Ban
    ban_m = re.match(r"^(?:/)?(?:ban|block|بن|بلاک|اخراج|سیکتیر|دیپورت|مسدود)(?:\s+(?:کن|ش\s+کن|ش))?(?:\s+(.*))?$", t, re.IGNORECASE)
    if ban_m:
        return await execute_admin_ban(update, context, ban_m.group(1) or "")

    # 12. User Unmute
    unmute_m = re.match(r"^(?:/)?(?:unmute|unsilence|آنمیوت|انمیوت|نمیوت|آن\s+میوت|رفع\s+میوت|لغو\s+میوت|رفع\s+سکوت|لغو\s+سکوت)(?:\s+(?:کن|ش\s+کن|ش))?(?:\s+(.*))?$", t, re.IGNORECASE)
    if unmute_m:
        return await execute_admin_unmute(update, context, unmute_m.group(1) or "")

    # 13. User Mute
    mute_m = re.match(r"^(?:/)?(?:mute|silence|میوت|سکوت|ساکت|خاموش|ببند)(?:\s+(?:کن|ش\s+کن|ش))?(?:\s+(.*))?$", t, re.IGNORECASE)
    if mute_m:
        return await execute_admin_mute(update, context, mute_m.group(1) or "")

    # 14. Register Permanent Admin Directive / Rule
    dir_m = re.match(
        r"^(?:/)?(?:ثبت\s+دستور|دستور\s+دائمی|دستور\s+جدید|دستور\s+ادمین|directive|addrule|rule)\s*(?::|-)?\s*(?:([a-zA-Z0-9_\-\u0600-\u06FF]+)\s*[:=]\s*)?(.*)$",
        t,
        re.IGNORECASE | re.DOTALL
    )
    if dir_m:
        k = (dir_m.group(1) or "").strip()
        v = (dir_m.group(2) or "").strip()
        if not k and v:
            parts = v.split(maxsplit=1)
            if len(parts) == 2 and parts[0].lower() in ("add", "set", "ثبت", "ایجاد"):
                sub = parts[1].split(maxsplit=1)
                if len(sub) == 2:
                    k, v = sub[0], sub[1]
        if not k:
            all_s = await get_all_admin_settings()
            existing = [s.get("key_name", "") for s in all_s if s.get("key_name", "").startswith("rule_")]
            k = f"rule_{len(existing) + 1}"

        if v:
            await set_admin_setting(k, v, category="directive", admin_id=user.id)
            await update.effective_message.reply_text(
                f"💾 <b>دستور دائمی ادمین با موفقیت در دیتابیس ثبت شد:</b>\n\n"
                f"🔑 <b>عنوان:</b> <code>{html.escape(k)}</code>\n"
                f"📄 <b>دستور:</b> <code>{html.escape(v)}</code>\n\n"
                f"🌐 <i>این دستور بلافاصله در حافظه زنده (L1 RAM)، دیتابیس Cloudflare D1 و KV ذخیره گردید و به طور دائم بر تمام پاسخ‌های پرومته اعمال می‌شود.</i>",
                parse_mode=ParseMode.HTML
            )
            return True

    # 14.1 Delete Directive / Setting
    del_m = re.match(
        r"^(?:/)?(?:delsetting|del_setting|delrule|del_rule|deldirective|del_directive|(?:حذف|پاک\s*کردن)\s+(?:دستور|تنظیم|قانون))\s+([a-zA-Z0-9_\-\u0600-\u06FF]+)$",
        t,
        re.IGNORECASE
    )
    if del_m:
        k = del_m.group(1).strip()
        await delete_admin_setting(k, admin_id=user.id)
        await update.effective_message.reply_text(
            f"🗑 <b>دستور/تنظیم <code>{html.escape(k)}</code> با موفقیت از دیتابیس و حافظه پرومته حذف گردید.</b>",
            parse_mode=ParseMode.HTML
        )
        return True

    # 14.2 Dynamic Setting Set
    set_m = re.match(r"^(?:/)?(?:set|set_setting|تنظیم)\s+([a-zA-Z0-9_\-\.]+)\s+(.*)$", t, re.DOTALL)
    if set_m:
        k = set_m.group(1).strip()
        v = set_m.group(2).strip()
        ok = await set_admin_setting(k, v, category="custom", admin_id=user.id)
        if ok:
            await update.effective_message.reply_text(
                f"💾 <b>تنظیم با موفقیت ثبت شد:</b>\n<code>{k}</code> = <code>{html.escape(v)}</code>",
                parse_mode=ParseMode.HTML
            )
        else:
            await update.effective_message.reply_text("❌ خطا در ذخیره‌سازی در دیتابیس.")
        return True

    # 15. Dynamic Setting Get
    get_m = re.match(r"^(?:/)?(?:get|get_setting|دریافت)\s+([a-zA-Z0-9_\-\.]+)$", t)
    if get_m:
        k = get_m.group(1).strip()
        val = await get_admin_setting(k)
        if val is not None:
            await update.effective_message.reply_text(
                f"📖 <b>مقدار تنظیم <code>{k}</code>:</b>\n<pre>{html.escape(val)}</pre>",
                parse_mode=ParseMode.HTML
            )
        else:
            await update.effective_message.reply_text(f"⚠️ کلیدی با عنوان <code>{k}</code> یافت نشد.", parse_mode=ParseMode.HTML)
        return True

    return False


# =========================================================================
# Main Message Handler with Silence-By-Default Trigger Logic
# =========================================================================

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    user = update.effective_user
    chat = update.effective_chat

    if not message or not user or not chat:
        return

    bot_user = context.bot if (context and getattr(context, "bot", None)) else None
    bot_id = bot_user.id if bot_user else None
    bot_username = (bot_user.username or "").lower() if bot_user else ""
    is_private = (chat.type == ChatType.PRIVATE)

    if not await _check_moderation_guard(update, context):
        return

    raw_text = message.text or message.caption or ""
    if not raw_text.strip():
        return

    # 1. Enforce Direct Bot Request Policy:
    # In groups, the bot strictly ignores any message that does not directly call or address it.
    is_direct, cleaned_prompt = is_direct_bot_request(update, context, raw_text)
    if not is_direct:
        # Strictly remain silent in groups for all other messages
        return

    # 2. Direct Interception of Admin Commands (Persian & Slash)
    if is_admin(user.id):
        if await handle_admin_text_command(update, context, raw_text):
            return

    # 3. Check Silence / Stop Triggers
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

    if not cleaned_prompt:
        await message.reply_text("درود بر شما! در خدمتم. چه کمکی از دست پرومته ساخته است؟")
        return

    # Trigger immediate typing action for real-time visual feedback in Telegram
    try:
        await chat.send_action(ChatAction.TYPING)
    except Exception:
        pass

    cleaned_lower = cleaned_prompt.lower()

    # Fast-Path -3: Group List Request Interception (<1ms)
    if is_group_list_request(cleaned_lower):
        if is_admin(user.id):
            await grouplist_command(update, context)
        else:
            await message.reply_text(
                "⛔️ مشاهده فهرست گروه‌های فعال و متصل به پرومته صرفاً در اختیار مدیر (ادمین) ربات می‌باشد.",
                parse_mode=ParseMode.HTML
            )
        return

    # Fast-Path -2: Full Telegram Numeric ID & Diagnostics Extraction (<1ms)
    if is_id_request(cleaned_lower):
        report = format_id_report(update)
        await message.reply_text(report, parse_mode=ParseMode.HTML)
        return

    # Fast-Path -1: Bot Message Deletion (/del, /delete, /پاک, "پاکش کن", "حذف کن", "حذف", "پاک")
    if is_delete_request(cleaned_lower):
        reply_to = message.reply_to_message
        if reply_to:
            is_from_bot = (
                (bot_id and reply_to.from_user and reply_to.from_user.id == bot_id)
                or (reply_to.from_user and reply_to.from_user.is_bot and bot_username and (reply_to.from_user.username or "").lower() == bot_username)
            )
            if is_from_bot:
                try:
                    await reply_to.delete()
                except Exception as e:
                    logger.warning(f"Failed to delete replied bot message: {e}")
                try:
                    await message.delete()
                except Exception:
                    pass
                return
            else:
                await message.reply_text("⚠️ من فقط می‌توانم پیام‌هایی که خودم ارسال کرده‌ام را حذف کنم.")
                return
        else:
            await message.reply_text("ℹ️ برای حذف پیام پرومته، لطفاً روی پیام مورد نظر ریپلای کرده و کلمه «حذف» یا /del را ارسال نمایید.")
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

    # Fast-Path 7.9: Twitter / X Explorer & Tweet Reader (<500ms)
    is_tw, tw_act, tw_target = parse_twitter_request(cleaned_prompt)
    if is_tw and tw_target:
        t0 = time.perf_counter()
        if tw_act == "tweet":
            sn, tid = tw_target.split(":", 1)
            tweet_data = await fetch_tweet_data(sn, tid)
            if tweet_data:
                # If user asked for translation / summary / analysis
                if any(k in cleaned_lower for k in ["ترجمه", "خلاصه", "تحلیل", "نظرت", "معنی"]):
                    agent_prompt = f"این توییت از طرف @{sn} در شبکه X (توییتر) منتشر شده است:\n\"\"\"\n{tweet_data.get('text')}\n\"\"\"\n\nدستور کاربر: {cleaned_prompt}"
                    await _process_and_reply(update, context, agent_prompt)
                    return
                report = format_tweet_report(tweet_data)
                record_chat_latency(chat.id, time.perf_counter() - t0, f"استخراج توییت (@{sn})")
                await _deliver_reply(message, report)
                return
        elif tw_act == "profile":
            profile_data = await fetch_twitter_profile(tw_target)
            if profile_data:
                report = format_profile_report(profile_data)
                record_chat_latency(chat.id, time.perf_counter() - t0, f"پروفایل توییتر (@{tw_target})")
                await _deliver_reply(message, report)
                return
        elif tw_act == "search":
            search_res = await search_twitter_live(tw_target, max_results=4)
            if search_res:
                record_chat_latency(chat.id, time.perf_counter() - t0, f"جستجوی زنده توییتر ({tw_target})")
                await _deliver_reply(message, search_res)
                return

    # Fast-Path 7.95: Check if user replied to a message containing a Tweet link
    if message.reply_to_message and (message.reply_to_message.text or message.reply_to_message.caption):
        reply_raw = message.reply_to_message.text or message.reply_to_message.caption or ""
        r_sn, r_tid = extract_tweet_url_and_id(reply_raw)
        if r_sn and r_tid and any(k in cleaned_lower for k in ["توییت", "چی میگه", "بخون", "ترجمه", "خلاصه", "tweet", "تحلیل", "معنی"]):
            t0 = time.perf_counter()
            tweet_data = await fetch_tweet_data(r_sn, r_tid)
            if tweet_data:
                if any(k in cleaned_lower for k in ["ترجمه", "خلاصه", "تحلیل", "نظرت", "معنی"]):
                    agent_prompt = f"این توییت از طرف @{r_sn} در شبکه X (توییتر) منتشر شده است:\n\"\"\"\n{tweet_data.get('text')}\n\"\"\"\n\nدستور کاربر: {cleaned_prompt}"
                    await _process_and_reply(update, context, agent_prompt)
                    return
                report = format_tweet_report(tweet_data)
                record_chat_latency(chat.id, time.perf_counter() - t0, f"استخراج توییت ریپلای‌شده (@{r_sn})")
                await _deliver_reply(message, report)
                return

    # Fast-Path 8: Telegraph Article Publishing
    if any(k in cleaned_lower for k in ["تلگراف", "telegraph", "telegra.ph"]):
        # Case A: Reply to another message asking to publish to telegraph
        if message.reply_to_message and (message.reply_to_message.text or message.reply_to_message.caption):
            reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
            t_title = cleaned_prompt
            for rem in [
                "تلگرافش کن", "توی تلگراف بذار", "توی تلگراف بزار", "در تلگراف منتشر کن",
                "توی تلگراف منتشر کن", "تلگراف کن", "تلگراف بفرست", "تلگراف", "telegraph"
            ]:
                t_title = t_title.replace(rem, "")
            t_title = t_title.strip() or "مستند تلگراف پرومته"
            res = await create_telegraph_article(title=t_title, content=reply_text)
            await _deliver_reply(message, res)
            return

        # Case B: Direct "تلگراف: عنوان | متن" or "عنوان | متن" with telegraph intent
        if "|" in cleaned_prompt and any(a in cleaned_lower for a in ["بساز", "منتشر", "صفحه", "پست", "publish", "create", "بذار", "بزار", "کن"]):
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
# Admin Governance & Moderation Commands
# =========================================================================

async def ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bans a user from using the bot (via reply, numeric ID, or username)."""
    rem = " ".join(context.args) if context.args else ""
    await execute_admin_ban(update, context, rem)


async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Unbans a user and logs to unbanned_log in D1."""
    rem = " ".join(context.args) if context.args else ""
    await execute_admin_unban(update, context, rem)


async def mute_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Mutes a user for a specified duration."""
    rem = " ".join(context.args) if context.args else ""
    await execute_admin_mute(update, context, rem)


async def unmute_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Unmutes a user immediately."""
    rem = " ".join(context.args) if context.args else ""
    await execute_admin_unmute(update, context, rem)


async def bangroup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bans a group from using the bot."""
    rem = " ".join(context.args) if context.args else ""
    await execute_admin_bangroup(update, context, rem)


async def unbangroup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Unbans a group."""
    rem = " ".join(context.args) if context.args else ""
    await execute_admin_unbangroup(update, context, rem)


async def mutegroup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Mutes the bot in a group."""
    rem = " ".join(context.args) if context.args else ""
    await execute_admin_mutegroup(update, context, rem)


async def unmutegroup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Unmutes the bot in a group."""
    rem = " ".join(context.args) if context.args else ""
    await execute_admin_unmutegroup(update, context, rem)


async def banlist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Displays permanently stored banned users and groups with username and numeric ID."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز.")
        return

    users = await get_banned_users_list()
    groups = await get_banned_groups_list()

    lines = ["📋 <b>لیست دائم کاربران و گروه‌های مسدودشده (Banned):</b>\n"]

    if not users and not groups:
        lines.append("<i>هیچ موردی در دیتابیس ثبت نشده است.</i>")
    else:
        if users:
            lines.append(f"👤 <b>کاربران مسدودشده ({len(users)} نفر):</b>")
            for idx, u in enumerate(users[:35], 1):
                uid = u.get("user_id")
                uname = f"@{u.get('username')}" if u.get("username") else "بدون یوزرنیم"
                name = u.get("name") or u.get("first_name") or ""
                reason = u.get("reason") or "بدون علت"
                date = u.get("banned_at") or ""
                lines.append(f"{idx}. <code>{uid}</code> | {html.escape(uname)} {html.escape(name)}\n   └ علت: {html.escape(reason)} ({date})")

        if groups:
            lines.append(f"\n👥 <b>گروه‌های مسدودشده ({len(groups)} گروه):</b>")
            for idx, g in enumerate(groups[:25], 1):
                cid = g.get("chat_id")
                title = g.get("title") or "گروه"
                reason = g.get("reason") or ""
                lines.append(f"{idx}. <code>{cid}</code> | <b>{html.escape(title)}</b>\n   └ علت: {html.escape(reason)}")

    text = "\n".join(lines)
    for chunk in split_message(text, max_len=3800):
        await msg.reply_text(chunk, parse_mode=ParseMode.HTML)


async def mutelist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Displays actively muted users and groups with remaining time."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز.")
        return

    m_users = await get_muted_users_list()
    m_groups = await get_muted_groups_list()

    lines = ["🤐 <b>لیست فعال افراد و گروه‌های میوت‌شده (Muted):</b>\n"]

    if not m_users and not m_groups:
        lines.append("<i>در حال حاضر هیچ کاربر یا گروهی میوت نیست.</i>")
    else:
        if m_users:
            lines.append(f"👤 <b>کاربران میوت‌شده ({len(m_users)} نفر):</b>")
            for idx, u in enumerate(m_users[:35], 1):
                uid = u.get("user_id")
                uname = f"@{u.get('username')}" if u.get("username") else "بدون یوزرنیم"
                rem_sec = u.get("remaining_seconds", 0)
                rem_str = format_duration_persian(rem_sec)
                reason = u.get("reason") or ""
                lines.append(f"{idx}. <code>{uid}</code> | {html.escape(uname)}\n   └ مانده: <b>{rem_str}</b> | علت: {html.escape(reason)}")

        if m_groups:
            lines.append(f"\n👥 <b>سکوت در گروه‌ها ({len(m_groups)} مورد):</b>")
            for idx, g in enumerate(m_groups[:25], 1):
                cid = g.get("chat_id")
                title = g.get("title") or "گروه"
                rem_sec = g.get("remaining_seconds", 0)
                rem_str = format_duration_persian(rem_sec) if rem_sec > 0 else "نامحدود"
                lines.append(f"{idx}. <code>{cid}</code> | <b>{html.escape(title)}</b> (مانده: {rem_str})")

    text = "\n".join(lines)
    for chunk in split_message(text, max_len=3800):
        await msg.reply_text(chunk, parse_mode=ParseMode.HTML)


async def grouplist_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Displays all tracked groups with their status (approved, pending, banned, muted)."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز. این دستور فقط مخصوص مدیران ربات است.")
        return

    groups = await get_all_tracked_groups()
    banned_groups = {int(g["chat_id"]): g for g in await get_banned_groups_list() if g.get("chat_id")}
    muted_groups = {int(g["chat_id"]): g for g in await get_muted_groups_list() if g.get("chat_id")}

    # Also merge any banned groups that might not be in tracked_groups table
    known_cids = {int(g["chat_id"]) for g in groups if g.get("chat_id")}
    for bg_cid, bg_data in banned_groups.items():
        if bg_cid not in known_cids:
            groups.append({
                "chat_id": bg_cid,
                "title": bg_data.get("title") or "گروه مسدود",
                "chat_type": "supergroup",
                "member_count": 0,
                "status": "banned",
                "added_at": bg_data.get("banned_at", "")
            })
            known_cids.add(bg_cid)

    if not groups:
        await msg.reply_text(
            "📋 <b>فهرست گروه‌های پرومته:</b>\n\n"
            "<i>در حال حاضر هیچ گروهی در دیتابیس ثبت نشده است.</i>\n"
            "💡 به محض اضافه شدن ربات به گروه یا دریافت پیام، گروه به صورت خودکار شناسایی و ذخیره می‌شود.",
            parse_mode=ParseMode.HTML
        )
        return

    lines = [f"👥 <b>فهرست گروه‌های ثبت‌شده در پرومته ({len(groups)} گروه):</b>\n"]

    for idx, g in enumerate(groups, 1):
        cid = int(g.get("chat_id") or 0)
        title = g.get("title") or "گروه بدون نام"
        uname = f"@{g.get('username')}" if g.get("username") else ""
        m_count = g.get("member_count") or 0
        st = g.get("status", "unknown")
        added_at = g.get("added_at") or ""

        # Moderation badge & management commands
        if cid in banned_groups or st == "banned":
            st_text = "🚫 مسدود (Banned)"
            quick_act = f"دستور رفع بن: <code>/unbangroup {cid}</code>"
        elif cid in muted_groups:
            rem = muted_groups[cid].get("remaining_seconds", 0)
            st_text = f"🔇 میوت ({format_duration_persian(rem)})" if rem > 0 else "🔇 میوت نامحدود"
            quick_act = f"دستور رفع سکوت: <code>/unmutegroup {cid}</code>"
        elif st in ("approved", "active"):
            st_text = "✅ تایید شده و فعال (Active)"
            quick_act = f"بن: <code>بن گروه {cid}</code> | میوت: <code>میوت گروه {cid} 1h</code>"
        elif st == "pending":
            st_text = "⏳ در انتظار تایید ادمین (Pending)"
            quick_act = f"تایید: <code>/approvegroup {cid}</code> | رد: <code>/rejectgroup {cid}</code>"
        elif st == "rejected":
            st_text = "❌ رد شده (Rejected)"
            quick_act = f"تایید مجدد: <code>/approvegroup {cid}</code>"
        elif st == "left":
            st_text = "🚪 خارج شده (Left)"
            quick_act = f"تایید مجدد: <code>/approvegroup {cid}</code>"
        else:
            st_text = f"ℹ️ {st}"
            quick_act = f"تایید: <code>/approvegroup {cid}</code>"

        members_info = f" | 👥 {m_count} عضو" if m_count > 0 else ""
        uname_info = f" ({html.escape(uname)})" if uname else ""
        date_info = f" | 📅 {added_at}" if added_at else ""

        lines.append(
            f"{idx}. <b>{html.escape(title)}</b>{uname_info}{members_info}\n"
            f"   🆔 شناسه: <code>{cid}</code>{date_info}\n"
            f"   📊 وضعیت: {st_text}\n"
            f"   ⚙️ {quick_act}\n"
        )

    text = "\n".join(lines)
    for chunk in split_message(text, max_len=3800):
        await msg.reply_text(chunk, parse_mode=ParseMode.HTML)


async def pendinggroups_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Lists all groups awaiting admin approval."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز.")
        return

    pending = await get_pending_groups_list()
    if not pending:
        await msg.reply_text("✅ در حال حاضر هیچ گروهی در انتظار تایید نیست.", parse_mode=ParseMode.HTML)
        return

    lines = [f"⏳ <b>گروه‌های در انتظار تایید ادمین ({len(pending)} گروه):</b>\n"]
    for idx, g in enumerate(pending[:15], 1):
        cid = g.get("chat_id")
        title = g.get("title") or "بدون عنوان"
        added_by = g.get("added_by") or 0
        date = g.get("added_at") or ""
        lines.append(
            f"{idx}. <b>{html.escape(title)}</b>\n"
            f"   🆔 شناسه: <code>{cid}</code>\n"
            f"   👤 افزوده شده توسط: <code>{added_by}</code> ({date})\n"
            f"   دستور تایید: <code>/approvegroup {cid}</code>\n"
            f"   دستور رد: <code>/rejectgroup {cid}</code>\n"
        )

    await msg.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def approvegroup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Manually approves a group for bot activation."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز.")
        return

    args = context.args or []
    if not args or not args[0].lstrip("-+").isdigit():
        await msg.reply_text("⚠️ نحوه استفاده: <code>/approvegroup -100xxxxxxxxxx [عنوان اختیاری]</code>", parse_mode=ParseMode.HTML)
        return

    cid = int(args[0])
    custom_title = " ".join(args[1:]).strip() if len(args) > 1 else ""
    await approve_group(cid, reviewed_by=user.id, title=custom_title)
    await msg.reply_text(f"✅ گروه <code>{cid}</code> با موفقیت تایید و فعال شد.", parse_mode=ParseMode.HTML)
    try:
        await context.bot.send_message(
            chat_id=cid,
            text="✅ <b>ربات توسط ادمین در این گروه تایید شد و هم‌اکنون فعال و آماده خدمت‌رسانی است.</b>",
            parse_mode=ParseMode.HTML
        )
    except Exception:
        pass


async def rejectgroup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Rejects a group request and leaves."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز.")
        return

    args = context.args or []
    if not args or not args[0].lstrip("-+").isdigit():
        await msg.reply_text("⚠️ نحوه استفاده: <code>/rejectgroup -100xxxxxxxxxx</code>", parse_mode=ParseMode.HTML)
        return

    cid = int(args[0])
    await reject_group(cid, reviewed_by=user.id)
    await msg.reply_text(f"❌ گروه <code>{cid}</code> رد شد و ربات در حال خروج است.", parse_mode=ParseMode.HTML)
    try:
        await context.bot.leave_chat(chat_id=cid)
    except Exception as e:
        logger.warning(f"Could not leave chat {cid}: {e}")


async def set_setting_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Persists an admin setting in Cloudflare D1 permanently."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز.")
        return

    args = context.args or []
    if len(args) < 2:
        await msg.reply_text("⚠️ نحوه استفاده:\n<code>/set [کلید_تنظیمات] [مقدار]</code>\nمثال:\n<code>/set default_mute_time 30m</code>", parse_mode=ParseMode.HTML)
        return

    key = args[0].strip()
    val = " ".join(args[1:]).strip()
    await set_admin_setting(key, val, admin_id=user.id)
    await msg.reply_text(
        f"💾 <b>تنظیمات با موفقیت در دیتابیس ثبت شد:</b>\n\n"
        f"🔑 <b>کلید:</b> <code>{html.escape(key)}</code>\n"
        f"📄 <b>مقدار:</b> <code>{html.escape(val)}</code>\n"
        f"ثبت دائمی در Cloudflare D1 و در دسترس در تمام زمان‌ها.",
        parse_mode=ParseMode.HTML
    )


async def get_setting_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Reads a setting from Cloudflare D1."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز.")
        return

    args = context.args or []
    if not args:
        await msg.reply_text("⚠️ نحوه استفاده: <code>/get [کلید]</code>", parse_mode=ParseMode.HTML)
        return

    key = args[0].strip()
    val = await get_admin_setting(key)
    if val is None:
        await msg.reply_text(f"❓ کلید <code>{html.escape(key)}</code> در دیتابیس یافت نشد.", parse_mode=ParseMode.HTML)
    else:
        await msg.reply_text(f"🔑 <code>{html.escape(key)}</code>:\n<code>{html.escape(val)}</code>", parse_mode=ParseMode.HTML)


async def del_setting_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Deletes an admin setting or permanent directive from D1, KV, and RAM."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز.")
        return

    args = context.args or []
    if not args:
        await msg.reply_text("⚠️ نحوه استفاده: <code>/delsetting [کلید]</code> یا <code>حذف دستور [کلید]</code>", parse_mode=ParseMode.HTML)
        return

    key = args[0].strip()
    await delete_admin_setting(key, admin_id=user.id)
    await msg.reply_text(
        f"🗑 <b>دستور/تنظیم <code>{html.escape(key)}</code> با موفقیت از دیتابیس و حافظه پرومته حذف گردید.</b>",
        parse_mode=ParseMode.HTML
    )


async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Lists all custom settings and permanent directives stored in Cloudflare D1 and RAM."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز.")
        return

    all_settings = await get_all_admin_settings()
    if not all_settings:
        await msg.reply_text(
            "ℹ️ <b>هنوز هیچ دستور یا تنظیماتی در دیتابیس ثبت نشده است.</b>\n\n"
            "💡 <b>برای ثبت دستور دائمی جدید:</b>\n"
            "• <code>ثبت دستور [عنوان]: [متن دستور]</code>\n"
            "• <code>/set [کلید] [مقدار]</code>",
            parse_mode=ParseMode.HTML
        )
        return

    directives = [s for s in all_settings if s.get("category") in ("directive", "rule", "instruction", "system")]
    others = [s for s in all_settings if s.get("category") not in ("directive", "rule", "instruction", "system")]

    lines = [f"⚙️ <b>پایگاه فرامین و تنظیمات دائمی ادمین ({len(all_settings)} مورد فعال):</b>\n"]

    if directives:
        lines.append("📜 <b>فرامین و دستورات دائمی اعمال‌شده بر رفتار هوش مصنوعی:</b>")
        for d in directives:
            k = d.get("key_name") or ""
            v = d.get("data_value") or ""
            lines.append(f"• 🔑 <code>{html.escape(k)}</code>:\n  └ {html.escape(v)}")
        lines.append("")

    if others:
        lines.append("🔧 <b>سایر متغیرها و تنظیمات ذخیره‌شده:</b>")
        for s in others:
            k = s.get("key_name") or ""
            v = s.get("data_value") or ""
            cat = s.get("category") or "custom"
            lines.append(f"• <b>[{html.escape(cat)}]</b> <code>{html.escape(k)}</code>: <code>{html.escape(v)}</code>")
        lines.append("")

    lines.append("⚡️ <b>راهنمای مدیریت فرامین دائم:</b>\n• ثبت دستور جدید: <code>ثبت دستور [عنوان]: [متن]</code>\n• حذف دستور: <code>حذف دستور [عنوان]</code> یا <code>/delsetting [عنوان]</code>")

    text = "\n".join(lines)
    for chunk in split_message(text, max_len=3800):
        await msg.reply_text(chunk, parse_mode=ParseMode.HTML)


async def adminlogs_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Lists recent admin commands and unbans from D1."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز.")
        return

    logs = await get_admin_commands_log(limit=25)
    unbans = await get_unbanned_history(limit=10)

    lines = ["📜 <b>تاریخچه و لاگ دائم اقدامات ادمین‌ها:</b>\n"]
    if logs:
        lines.append("👮‍♂️ <b>آخرین دستورات ثبت‌شده در دیتابیس:</b>")
        for l in logs[:15]:
            cmd = l.get("command")
            aid = l.get("admin_id")
            tid = l.get("target_id")
            tname = l.get("target_username")
            dt = l.get("created_at")
            details = l.get("details") or ""
            target_str = f"کاربر {tid}" if tid else ""
            if tname:
                target_str += f" (@{tname})"
            lines.append(f"• <code>{dt}</code> | <b>{html.escape(cmd or '')}</b> توسط <code>{aid}</code>\n  └ {html.escape(target_str)} {html.escape(details)}")

    if unbans:
        lines.append("\n🔓 <b>آخرین رفع مسدودیت‌ها (Unbans):</b>")
        for ub in unbans[:10]:
            et = ub.get("entity_type")
            eid = ub.get("entity_id")
            uname = ub.get("username")
            dt = ub.get("unbanned_at")
            lines.append(f"• <code>{dt}</code> | {et} <code>{eid}</code> (@{html.escape(uname or '')}) توسط <code>{ub.get('unbanned_by')}</code>")

    text = "\n".join(lines)
    for chunk in split_message(text, max_len=3800):
        await msg.reply_text(chunk, parse_mode=ParseMode.HTML)


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

    async def post_init(application: Application):
        await init_moderation_engine()
        logger.info("Prometheus moderation engine loaded in post_init.")

    app = (
        ApplicationBuilder()
        .token(token)
        .request(request)
        .post_init(post_init)
        .concurrent_updates(True)
        .build()
    )

    def guard(handler_func, is_admin_cmd: bool = False):
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not await _check_moderation_guard(update, context, is_admin_cmd=is_admin_cmd):
                return
            return await handler_func(update, context)
        return wrapper

    # Core Commands & Aliases
    app.add_handler(CommandHandler(["start"], guard(start_command)))
    app.add_handler(CommandHandler(["help"], guard(help_command)))
    app.add_handler(CommandHandler(["agent", "research", "hermes"], guard(agent_command)))
    app.add_handler(CommandHandler(["fast", "speed"], guard(fast_command)))
    app.add_handler(CommandHandler(["mode", "setting", "settings"], guard(mode_command)))
    app.add_handler(CallbackQueryHandler(guard(mode_callback), pattern=r"^setmode_"))
    app.add_handler(CommandHandler(["rates", "dollar", "arz", "gheymat"], guard(rates_command)))
    app.add_handler(CommandHandler(["crypto"], guard(crypto_command)))
    app.add_handler(CommandHandler(["time", "saat"], guard(time_command)))
    app.add_handler(CommandHandler(["weather", "hava"], guard(weather_command)))
    app.add_handler(CommandHandler(["digikala", "dk"], guard(digikala_command)))
    app.add_handler(CommandHandler(["music", "song", "ahang"], guard(music_command)))
    app.add_handler(CommandHandler(["read", "web", "url"], guard(read_command)))
    app.add_handler(CommandHandler(["telegraph", "telegra", "article"], guard(telegraph_command)))
    app.add_handler(CommandHandler(["calc", "hesab"], guard(calc_command)))
    app.add_handler(CommandHandler(["clear"], guard(clear_command)))
    app.add_handler(CommandHandler(["id", "myid", "info", "chatid", "whoami"], guard(id_command)))
    app.add_handler(CommandHandler(["qr", "qrcode"], guard(barcode_command)))
    app.add_handler(CommandHandler(["barcode", "bar"], guard(barcode_command)))
    app.add_handler(CommandHandler(["twitter", "tweet", "x"], guard(twitter_command)))
    app.add_handler(CommandHandler(["delete", "del", "pak", "hazf", "remove"], guard(delete_command)))
    app.add_handler(CommandHandler(["ping"], guard(ping_command)))

    # Admin Governance & Moderation Commands
    app.add_handler(CommandHandler(["ban", "block"], guard(ban_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["unban", "unblock"], guard(unban_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["mute", "silence"], guard(mute_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["unmute", "unsilence"], guard(unmute_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["bangroup", "ban_group"], guard(bangroup_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["unbangroup", "unban_group"], guard(unbangroup_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["mutegroup", "mutebot"], guard(mutegroup_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["unmutegroup", "unmutebot"], guard(unmutegroup_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["banlist", "bans"], guard(banlist_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["mutelist", "mutes"], guard(mutelist_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["groups", "grouplist", "listgroups", "allgroups"], guard(grouplist_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["pendinggroups", "pending_groups"], guard(pendinggroups_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["approvegroup", "approve_group", "addgroup", "add_group"], guard(approvegroup_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["rejectgroup", "reject_group"], guard(rejectgroup_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["set", "set_setting"], guard(set_setting_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["get", "get_setting"], guard(get_setting_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["delsetting", "del_setting", "delrule", "del_rule", "deldirective"], guard(del_setting_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["adminsettings", "customdata", "directives", "rules"], guard(settings_command, is_admin_cmd=True)))
    app.add_handler(CommandHandler(["adminlogs", "audit"], guard(adminlogs_command, is_admin_cmd=True)))

    # Callback Query Handlers for Group Approvals
    app.add_handler(CallbackQueryHandler(group_approval_callback, pattern=r"^grp_(app|rej):"))

    # Chat Member Updates (Bot added/removed in groups)
    app.add_handler(ChatMemberHandler(chat_member_update_handler, ChatMemberHandler.MY_CHAT_MEMBER))

    # Multimodal photo handler
    app.add_handler(MessageHandler(filters.PHOTO, guard(photo_handler)))

    # All text messages (with silence-by-default logic)
    app.add_handler(
        MessageHandler(
            filters.TEXT | filters.CAPTION,
            guard(message_handler)
        )
    )

    return app


if __name__ == "__main__":
    logger.info("Starting Prometheus Telegram Agent Bot...")
    app = build_application()
    app.run_polling(drop_pending_updates=False, allowed_updates=Update.ALL_TYPES)
