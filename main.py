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

import io
import re
import os
import html
import time
import logging
import asyncio
from typing import Optional, Tuple, List, Dict, Any, Set, Union
from datetime import datetime, timezone

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
from utils.formatter import split_message, markdown_to_telegram_html, apply_expandable_containers, wrap_in_expandable_blockquote

from tools.summary_tool import parse_summary_request, summarize_group_messages
from tools.search_tool import parse_search_request, search_group_messages
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
    get_live_telegram_groups,
    update_group_live_metadata,
    get_unbanned_history,
    get_admin_commands_log,
    set_admin_setting,
    get_admin_setting,
    delete_admin_setting,
    get_all_admin_settings,
    get_cached_admin_directives,
    parse_duration_string,
    format_duration_persian,
    detect_mute_scope,
    match_mute_command,
    is_user_chat_admin,
    can_bot_restrict_members,
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
    detect_jailbreak_attempt,
    is_architecture_query,
)
from tools.system import (
    get_current_time,
    calculate_math,
    record_chat_latency,
    format_last_latency_response,
    run_live_speed_test,
)
from tools.rate_limiter import check_user_rate_limit, get_user_quota_info
from tools.id_tool import is_id_request, format_id_report
from tools.vision import (
    analyze_image_with_vision,
    is_reconstruction_query,
    build_reconstruction_image_url,
)
from tools.media_group import (
    record_media_group_photo,
    get_media_group_photos,
    resolve_media_group_id,
    debounce_incoming_album,
)
from tools.file_tool import (
    extract_file_content,
    create_document_file,
    detect_file_creation_intent,
)
from tools.virustotal import (
    scan_file_hash,
    upload_and_scan_file,
    scan_url_or_domain,
    format_virustotal_report,
    is_virustotal_request,
)
from tools.permissions import (
    init_permissions_engine,
    has_tool_permission,
    grant_tool_command,
    revoke_tool_command,
    user_tools_command,
    granted_tools_command,
)
from tools.osint_search import search_web_osint, crawl_webpage_layers
from tools.osint_dork import generate_smart_dorks, execute_smart_dork
from tools.osint_linkedin import search_linkedin_profile, search_linkedin_company
from tools.osint_github import investigate_github_user, search_github
from tools.osint_username import search_username_across_platforms
from tools.osint_network import resolve_dns_records, enumerate_subdomains_crtsh, lookup_ip_intel
from tools.osint_email_phone import investigate_email, analyze_phone_number
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

# In-memory cooldown cache for PV restriction notices: uid -> float timestamp
_PV_RESTRICT_WARN_CACHE: Dict[int, float] = {}


async def _check_moderation_guard(update: Update, context: ContextTypes.DEFAULT_TYPE, is_admin_cmd: bool = False) -> bool:
    """
    Global Security & Moderation Gatekeeper:
    1. Banned Users: completely blocked and ignored.
    2. Muted Users: ignored until mute period expires.
    3. Private Chats (PV): Strictly restricted to bot admins only. Non-admins receive an informative restricted notice.
    4. Groups:
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

    # 3. Private Chat (PV / Direct Message) Restriction:
    # Strictly restricted: nobody except authorized bot administrators can message the bot in private.
    if chat.type == ChatType.PRIVATE:
        if not is_admin(uid):
            logger.info(f"Gatekeeper: blocked non-admin user {uid} (@{uname}) in private chat (PV).")
            now = time.monotonic()
            if now - _PV_RESTRICT_WARN_CACHE.get(uid, 0.0) >= 10.0:
                _PV_RESTRICT_WARN_CACHE[uid] = now
                msg = update.effective_message
                if msg:
                    try:
                        await msg.reply_text(
                            "⛔️ <b>دسترسی به گفتگوی خصوصی محدود است.</b>\n\n"
                            "ارسال پیام در پیوی (گفتگوی خصوصی) با پرومته، صرفاً برای <b>مدیر (ادمین) ربات</b> مجاز می‌باشد.\n"
                            "جهت استفاده از خدمات پرومته، می‌توانید ربات را به گروه‌های مجاز اضافه فرمایید.",
                            parse_mode=ParseMode.HTML
                        )
                    except Exception as e:
                        logger.debug(f"Failed to send PV restriction notice: {e}")
            return False
        return True

    # 4. Group Chat Moderation
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

        # Keep live group title and username synchronized in RAM/DB
        update_group_live_metadata(
            chat_id=chat.id,
            title=chat.title or "",
            username=chat.username or ""
        )

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
                text=(
                    "⚡️ <b>پرومته فعال شد!</b>\n\n"
                    "با دستور مستقیم ادمین ارشد، سیستم شناسایی و هوش مصنوعی پرومته در این گروه رسماً تایید و فعال گردید.\n"
                    "هم‌اکنون تمامی قابلیت‌های OSINT، کاوش عمیق وب، تحلیل لایه‌ها و پاسخگویی هوشمند در دسترس شماست.\n\n"
                    "▫️ جهت مشاهده راهنما: <code>/phelp</code> یا منشن نام ربات"
                ),
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

    elif new_status in (ChatMemberStatus.LEFT, ChatMemberStatus.BANNED):
        from tools.moderation import _TRACKED_GROUPS
        with _MOD_LOCK:
            if chat.id in _TRACKED_GROUPS:
                _TRACKED_GROUPS[chat.id]["status"] = "left"
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
    Applies Telegram-native Expandable Blockquotes (<blockquote expandable>) for long answers,
    and persists bot assistant messages to the database for full conversation memory.
    """
    cleaned = sanitize_identity(final_text).strip()
    if not cleaned:
        cleaned = "درود بر شما! پاسخی برای این پرسش دریافت نشد. لطفاً مجدداً سوال خود را بفرمایید."

    try:
        formatted = markdown_to_telegram_html(cleaned)
        # Apply collapsible expandable container if response is long
        formatted = apply_expandable_containers(formatted, char_threshold=550)
        chunks = split_message(formatted, max_len=3900)
        for ch in chunks:
            try:
                sent = await message.reply_text(ch, parse_mode=ParseMode.HTML)
                if sent and message.chat:
                    bot_user = sent.from_user
                    asyncio.create_task(
                        database.persist_message(
                            chat_id=message.chat.id,
                            message_id=sent.message_id,
                            user_id=bot_user.id if bot_user else 0,
                            username=bot_user.username or "" if bot_user else "",
                            full_name=bot_user.full_name or "Prometheus" if bot_user else "Prometheus",
                            role="assistant",
                            content=cleaned,
                            reply_to_message_id=message.message_id,
                            media_type="text",
                            is_bot=1
                        )
                    )
            except Exception as html_err:
                logger.warning(f"HTML delivery failed for chunk ({html_err}), attempting sanitized fallback...")
                clean_ch = re.sub(r"<[^>]+>", "", ch).strip()
                if clean_ch:
                    sent = await message.reply_text(clean_ch)
                    if sent and message.chat:
                        bot_user = sent.from_user
                        asyncio.create_task(
                            database.persist_message(
                                chat_id=message.chat.id,
                                message_id=sent.message_id,
                                user_id=bot_user.id if bot_user else 0,
                                username=bot_user.username or "" if bot_user else "",
                                full_name=bot_user.full_name or "Prometheus" if bot_user else "Prometheus",
                                role="assistant",
                                content=cleaned,
                                reply_to_message_id=message.message_id,
                                media_type="text",
                                is_bot=1
                            )
                        )
    except BadRequest as e:
        logger.warning(f"Telegram BadRequest in response delivery: {e}")

    except Exception as e:
        logger.error(f"Failed to deliver message: {e}")
        try:
            plain_fallback = re.sub(r"<[^>]+>", "", cleaned).strip()
            chunks = split_message(plain_fallback, max_len=3900)
            for ch in chunks:
                sent = await message.reply_text(ch)
                if sent and message.chat:
                    bot_user = sent.from_user
                    asyncio.create_task(
                        database.persist_message(
                            chat_id=message.chat.id,
                            message_id=sent.message_id,
                            user_id=bot_user.id if bot_user else 0,
                            username=bot_user.username or "" if bot_user else "",
                            full_name=bot_user.full_name or "Prometheus" if bot_user else "Prometheus",
                            role="assistant",
                            content=cleaned,
                            reply_to_message_id=message.message_id,
                            media_type="text",
                            is_bot=1
                        )
                    )
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

    # Check if user explicitly requested a file attachment / download
    p_lower = prompt.lower()
    if any(k in p_lower for k in ["فایل بده", "به صورت فایل", "توی فایل", "داخل فایل", "فایل پایتون", "فایل متنی", "فایل اسکریپت", "download file", "as a file"]):
        code_blocks = re.findall(r"```([a-zA-Z0-9_+\-]+)?\n([\s\S]*?)```", final_answer)
        if code_blocks:
            c_lang, c_code = code_blocks[0]
            ext = (c_lang.lower().strip() if c_lang else "txt")
            if ext in ("python", "py"):
                ext = "py"
            elif ext in ("javascript", "js"):
                ext = "js"
            elif ext in ("html", "htm"):
                ext = "html"
            elif ext in ("json",):
                ext = "json"
            elif ext in ("shell", "bash", "sh"):
                ext = "sh"
            else:
                ext = "py" if "پایتون" in p_lower else (ext or "txt")

            try:
                buf, final_fn = create_document_file(f"script.{ext}", c_code)
                await message.reply_document(
                    document=buf,
                    filename=final_fn,
                    caption=f"📁 <b>فایل کد استخراج‌شده:</b> <code>{final_fn}</code>",
                    parse_mode=ParseMode.HTML
                )
            except Exception as fe:
                logger.warning(f"Could not deliver code block as file: {fe}")




# =========================================================================
# Fast-Path Intent Detectors
# =========================================================================

_SPECIFIC_FIAT_PHRASES = (
    "سکه امامی", "بهار آزادی", "طلای ۱۸", "طلا ۱۸", "طلای ۱۸ عیار", "نیم سکه", "ربع سکه", "سکه گرمی",
    "قیمت دلار", "نرخ دلار", "دلار چنده", "دلار چند است", "دلار چند شد", "دلار چند شده", "دلار امروز", "دلار الان",
    "دلار چقدره", "دلار چند تومنه", "دلار چند تومن", "دلار آزاد", "دلار نقدی", "قیمت روز دلار", "نرخ روز دلار",
    "دلار رو بگو", "دلار بگو", "قیمت دلار رو بگو", "قیمت دلار بگو", "دلار بده", "دلار رو بده", "استعلام دلار", "استعلام طلا", "استعلام ارز",
    "ارز و دلار", "دلار و ارز", "دلار ارز", "ارز دلار",
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
    r"(?<!\w)(?:قیمت|نرخ|چند|چنده|چقدر|چقدره|امروز|روز|لحظه|لحظه‌ای|لحظه ای|بازار|وضعیت|استعلام|چند شد|چند است|چند تومنه|چند تومن|چند شده|بگو|بده|اعلام|اعلام کن|بفرمایید|چند هست|ارزش)(?!\w)",
    re.IGNORECASE
)

_FIAT_EXCLUDED_TOPICS_PATTERN = re.compile(
    r"(?<!\w)(?:اینترنت|هند|هندوستان|سیمکارت|شارژ|بسته|لپ\s*تاپ|لپتاپ|موبایل|گوشی|بلیت|بلیط|هواپیما|هتل|تور|ماشین|خودرو|پایتون|برنامه|کد|سهام|بورس|ارزان|ارزون|ارزش\s*افزوده|ارزش\s*غذایی|انسان|آژانس|آرزو|دیجی[\s\u200c]*کالا|دیجیکالا|digikala)(?!\w)",
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


# Crypto fast paths removed for OSINT engine


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
    r"^/(?:p|p_|pro|pro_|prom_|prometheus_)?(?:del|delete|pak|hazf|remove|حذف|پاک)(?:@\w+)?$",
    r"^(?:حذف|پاک|دلیت|دیلیت|delete|del|remove)[!؟\.\s]*$",
    r"^(?:لطف[ااً]|میشه|بی‌زحمت|بی\s*زحمت)?\s*(?:این\s*|اینو\s*|اینم\s*)?(?:پیام(?:ت|تون|ت رو|تو|تون رو|ت رو هم| خودت| خودتو| خودت رو|\s*رو)?|رو|پیامو)?\s*(?:هم\s*)?(?:حذف|پاک|دلیت|دیلیت|del|delete|remove)(?:ش)?(?:\s*(?:کن|کنید|کنی|کنین|کردن))?(?:\s*(?:پیام|لطف[ااً]|بی‌زحمت|بی\s*زحمت))?[!؟\.\s]*$",
    r"^(?:لطف[ااً]|میشه|بی‌زحمت|بی\s*زحمت)?\s*(?:پاک|حذف|دلیت|دیلیت)(?:ش)?\s*(?:کن|کنید|کنی|کنین)?\s*(?:این\s*)?(?:پیام(?:ت|تون|ت رو|تو|تون رو| خودت| خودتو|\s*رو)?|اینو|این رو|اینم)?[!؟\.\s]*$",
    r"^(?:حذف|پاک|دلیت|دیلیت)\s*(?:کردن\s*)?(?:این\s*)?پیام[!؟\.\s]*$",
    r"^(?:del|delete|remove)\s*(?:kon|konid|کن|کنید)[!؟\.\s]*$",
    r"^(?:اینم|اینو)\s*(?:هم\s*)?(?:پاک|حذف|دلیت|دیلیت)(?:ش)?(?:\s*(?:کن|کنید|کنی))?[!؟\.\s]*$",
]


def is_delete_request(text: str) -> bool:
    """Matches requests to delete the bot's own message."""
    t = text.lower().strip()
    return any(bool(re.search(p, t, re.IGNORECASE)) for p in _DELETE_PATTERNS)


_GROUP_LIST_REGEX = re.compile(
    r"^(?:/)?(?:(?:p_|pro_|p|pro)?groups|grouplist|listgroups|allgroups|all_groups|"
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

# Base commands registered in Prometheus
PROMETHEUS_BASE_COMMANDS: Set[str] = {
    "start", "help",
    "agent", "research", "hermes",
    "fast", "speed",
    "mode", "setting", "settings",
    "osint", "search", "web", "find", "jostojoo",
    "crawl", "scrape", "layers", "read", "url",
    "dork", "dorks", "googledork",
    "github", "git", "gh",
    "linkedin", "in",
    "usercheck", "username", "user",
    "dns", "ns", "mx",
    "subdomains", "subdomain", "subs", "crtsh",
    "ip", "geo", "asn",
    "email", "mail",
    "phone", "tel", "mobile",
    "time", "saat",
    "clear", "clean",
    "id", "myid", "info", "chatid", "whoami",
    "delete", "del", "pak", "hazf", "remove",
    "ping", "status",
    "summarize", "recap", "summary", "kholase",
    "file", "createfile", "makefile",
    "scan", "vt", "virustotal", "antivirus",
    # Admin commands
    "ban", "block",
    "unban", "unblock",
    "mute", "silence",
    "unmute", "unsilence",
    "bangroup", "ban_group",
    "unbangroup", "unban_group",
    "mutegroup", "mutebot",
    "unmutegroup", "unmutebot",
    "banlist", "bans",
    "mutelist", "mutes",
    "groups", "grouplist", "listgroups", "allgroups",
    "pendinggroups", "pending_groups",
    "approvegroup", "approve_group", "addgroup", "add_group",
    "rejectgroup", "reject_group",
    "set", "set_setting",
    "get", "get_setting",
    "delsetting", "del_setting", "delrule", "del_rule", "deldirective",
    "adminsettings", "customdata", "directives", "rules",
    "adminlogs", "audit",
}

# Supported short prefixes derived from Prometheus (پرومته)
PROMETHEUS_COMMAND_PREFIXES = ["p", "p_", "pro", "pro_"]


def is_prometheus_prefixed_command(cmd_name: str) -> bool:
    """
    Checks whether a command string matches a Prometheus-specific prefixed command.
    Matches:
    - 'p' + command (e.g. 'pinfo', 'pid', 'phelp', 'pstart', 'pping', 'pstatus', 'prates', 'pfast', 'pagent', ...)
    - 'p_' + command or arbitrary name (e.g. 'p_info', 'p_id', 'p_help', 'p_ping', ...)
    - 'pro' + command (e.g. 'proinfo', 'prohelp', 'proping', ...)
    - 'pro_' + command (e.g. 'pro_info', 'pro_help', ...)
    - 'prom_' / 'prometheus_' + command
    """
    cmd = (cmd_name or "").lower().strip()
    if not cmd:
        return False
    if cmd in ("p", "pro"):
        return True
    if cmd.startswith(("p_", "pro_", "prom_", "prometheus_")):
        suffix = cmd.split("_", 1)[1]
        return suffix in PROMETHEUS_BASE_COMMANDS or bool(suffix)
    for prefix in ("pro", "p"):
        if cmd.startswith(prefix):
            remainder = cmd[len(prefix):]
            if remainder in PROMETHEUS_BASE_COMMANDS:
                return True
    return False


def make_bot_commands(base_commands: List[str]) -> List[str]:
    """
    Expands base commands with Prometheus-specific prefixes:
    ['info', 'id'] -> ['info', 'id', 'pinfo', 'p_info', 'proinfo', 'pro_info', 'pid', 'p_id', 'proid', 'pro_id']
    """
    res = list(base_commands)
    for cmd in base_commands:
        for pref in PROMETHEUS_COMMAND_PREFIXES:
            alias = f"{pref}{cmd}"
            if alias not in res:
                res.append(alias)
    return res


def is_command_addressed_to_bot(update: Update, context: ContextTypes.DEFAULT_TYPE, is_admin_cmd: bool = False) -> bool:
    """
    Determines if a slash command is specifically intended for Prometheus:
    - In Private Chat (DM): Always True (both prefixed and standard commands are accepted).
    - In Group Chats:
      1. Explicitly mentions bot username (@AMZprometheusopenbot)
      2. Uses personalized Prometheus prefix (e.g. /p..., /p_..., /pro..., /pro_..., /prom_..., /prometheus_...)
      3. Is a direct reply to Prometheus's own message
      4. Explicitly mentions Prometheus by name in text ('پرومته', 'prometheus', ...)
      5. Is an authorized bot administrator executing an administrative command
      Otherwise in groups: returns False to prevent command collision with other bots!
    """
    chat = update.effective_chat
    message = update.effective_message
    user = update.effective_user
    if not chat or not message:
        return True

    if chat.type == ChatType.PRIVATE:
        return True

    # Authorized bot administrator issuing an admin command
    if is_admin_cmd and user and is_admin(user.id):
        return True

    raw_text = (message.text or message.caption or "").strip()
    if not raw_text:
        return False

    bot_user = context.bot if (context and getattr(context, "bot", None)) else None
    bot_id = bot_user.id if bot_user else None
    bot_username = (bot_user.username or "").lower() if bot_user else ""

    # 1. Reply to bot's own message
    if message.reply_to_message and message.reply_to_message.from_user:
        rep_u = message.reply_to_message.from_user
        if (bot_id and rep_u.id == bot_id) or (bot_username and rep_u.username and rep_u.username.lower() == bot_username):
            return True

    # 2. Contains Prometheus trigger names in the text
    for name in _PROMETHEUS_TRIGGER_NAMES:
        if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", raw_text, flags=re.IGNORECASE):
            return True

    # 3. Check the command word itself
    first_token = raw_text.split()[0] if raw_text else ""
    if not first_token.startswith("/"):
        return False

    cmd_part = first_token[1:]  # remove leading '/'
    cmd_name = cmd_part.split("@")[0].lower()
    target_bot = cmd_part.split("@")[1].lower() if "@" in cmd_part else ""

    # Targeted explicitly to this bot: /cmd@bot_username
    if target_bot:
        if bot_username and target_bot == bot_username:
            return True
        else:
            return False

    # Starts with Prometheus personalized prefixes:
    if cmd_name.startswith(("p_", "pro_", "prom_", "prometheus_")):
        return True

    # Starts with 'p' or 'pro' followed by a valid command suffix
    if is_prometheus_prefixed_command(cmd_name):
        return True

    # Unique Prometheus AI commands that never collide with moderation bots
    if cmd_name in ("summarize", "recap", "summary", "kholase"):
        return True

    # Otherwise in group chats, generic bare commands (like bare /info, /help, /id, /ping) are ignored
    # to avoid collisions with other bots in the same group!
    logger.info(f"Command collision guard: ignoring generic un-prefixed command '/{cmd_name}' in group {chat.id}")
    return False


def is_direct_bot_request(update: Update, context: ContextTypes.DEFAULT_TYPE, raw_text: str) -> Tuple[bool, str]:
    """
    Determines if a message is a DIRECT request to Prometheus:
    - In Private Chat (DM): Always True.
    - In Group Chats: True ONLY if:
        1. It is a slash command targeted to Prometheus (@username) or prefixed with Prometheus abbreviations (p / p_ / pro)
        2. It explicitly mentions the bot (@username)
        3. It explicitly calls the bot by name (پرومته, prometheus, ...)
        4. It is a direct reply to one of the bot's own messages.
        5. It is an authorized bot administrator issuing a known bot command
    Returns: (is_direct: bool, cleaned_text: str)
    """
    chat = update.effective_chat
    message = update.effective_message
    user = update.effective_user
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

    # a) Direct reply to the bot's own message
    if message and message.reply_to_message and message.reply_to_message.from_user:
        rep_u = message.reply_to_message.from_user
        if (bot_id and rep_u.id == bot_id) or (bot_username and rep_u.username and rep_u.username.lower() == bot_username):
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

    # d) Slash command in groups: MUST be addressed or personalized to Prometheus!
    if text.startswith("/"):
        first_token = text.split()[0]
        cmd_part = first_token[1:]  # remove leading '/'
        cmd_name = cmd_part.split("@")[0].lower()
        target_bot = cmd_part.split("@")[1].lower() if "@" in cmd_part else ""

        # Explicit target @bot_username
        if target_bot:
            if bot_username and target_bot == bot_username:
                cleaned = re.sub(rf"^(/[a-zA-Z0-9_]+)@{re.escape(bot_username)}\b", r"\1", text, flags=re.IGNORECASE)
                return True, cleaned
            else:
                return False, ""

        # Personalized prefix: /p, /p_..., /pro_..., /prom_..., /prometheus_...
        if cmd_name in ("p", "pro") or cmd_name.startswith(("p_", "pro_", "prom_", "prometheus_")):
            return True, text

        # Prefixed command name: p[command] or pro[command]
        if is_prometheus_prefixed_command(cmd_name):
            return True, text

        # Unique Prometheus AI commands that never collide with moderation bots
        if cmd_name in ("summarize", "recap", "summary", "kholase"):
            return True, text

        # Authorized bot administrator issuing a known bot command
        if user and is_admin(user.id) and (cmd_name in PROMETHEUS_BASE_COMMANDS or is_prometheus_prefixed_command(cmd_name)):
            return True, text

        # Bare slash commands in group chats (e.g. /warn, /kick, /info, /help, /pin)
        # without bot mention or prefix are NOT for Prometheus!
        return False, ""

    return False, ""


def extract_replied_message_context(message) -> str:
    """
    Extracts structured sender, text, caption, and media metadata from the replied-to message.
    Guarantees that Telegram Numeric User IDs, Usernames, Forward Origins, and Message IDs
    are directly injected into the prompt context for 100% accurate AI understanding.
    """
    reply_msg = getattr(message, "reply_to_message", None)
    if not reply_msg:
        return ""

    author_parts = []
    if getattr(reply_msg, "from_user", None) and reply_msg.from_user:
        ru = reply_msg.from_user
        name = ru.first_name or "کاربر"
        if ru.last_name:
            name += f" {ru.last_name}"
        if ru.username:
            name += f" (@{ru.username})"
        author_parts.append(f"{name} [شناسه عددی (User ID): {ru.id}]")
    elif getattr(reply_msg, "sender_chat", None) and reply_msg.sender_chat:
        sc = reply_msg.sender_chat
        sc_title = sc.title or "کانال/گروه"
        if sc.username:
            sc_title += f" (@{sc.username})"
        author_parts.append(f"{sc_title} [شناسه عددی (Chat ID): {sc.id}]")
    else:
        author_parts.append("کاربر")

    # Check Modern Telegram Bot API 7.0+ Forward Origins
    fo = getattr(reply_msg, "forward_origin", None)
    if fo:
        fo_type = getattr(fo, "type", "")
        if fo_type == "user" and getattr(fo, "sender_user", None):
            fu = fo.sender_user
            fu_name = fu.first_name or "کاربر"
            if fu.last_name:
                fu_name += f" {fu.last_name}"
            if fu.username:
                fu_name += f" (@{fu.username})"
            author_parts.append(f"فوروارد از کاربر اصلی: {fu_name} [شناسه عددی فرستنده اصلی: {fu.id}]")
        elif fo_type in ("chat", "channel"):
            fc = getattr(fo, "chat", None) or getattr(fo, "sender_chat", None)
            if fc:
                fc_title = getattr(fc, "title", "") or "کانال/گروه"
                fc_user = f" (@{fc.username})" if getattr(fc, "username", None) else ""
                author_parts.append(f"فوروارد از کانال/گروه: {fc_title}{fc_user} [شناسه عددی: {fc.id}]")
        elif fo_type == "hidden_user":
            h_name = getattr(fo, "sender_user_name", "کاربر ناشناس")
            author_parts.append(f"فوروارد از کاربر با حساب مخفی: {h_name} [حریم خصوصی تلگرام]")
    else:
        # Legacy forward attributes fallback
        if getattr(reply_msg, "forward_from", None) and reply_msg.forward_from:
            ff = reply_msg.forward_from
            f_name = ff.first_name or "کاربر"
            if ff.last_name:
                f_name += f" {ff.last_name}"
            if ff.username:
                f_name += f" (@{ff.username})"
            author_parts.append(f"فوروارد از کاربر: {f_name} [شناسه عددی فرستنده اصلی: {ff.id}]")
        elif getattr(reply_msg, "forward_from_chat", None) and reply_msg.forward_from_chat:
            fc = reply_msg.forward_from_chat
            title = getattr(fc, "title", "") or ""
            f_user = f" (@{fc.username})" if getattr(fc, "username", None) else ""
            author_parts.append(f"فوروارد از کانال/گروه: {title}{f_user} [شناسه عددی: {fc.id}]")

    author_parts.append(f"[شماره پیام: {reply_msg.message_id}]")
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


def extract_forward_message_context(message) -> str:
    """
    Extracts structured sender metadata when the incoming message itself is forwarded.
    Allows Prometheus to identify the original author and their Telegram User ID.
    """
    if not message:
        return ""
    fo = getattr(message, "forward_origin", None)
    ff = getattr(message, "forward_from", None)
    fc = getattr(message, "forward_from_chat", None)
    if not fo and not ff and not fc:
        return ""

    origin_parts = []
    if fo:
        fo_type = getattr(fo, "type", "")
        if fo_type == "user" and getattr(fo, "sender_user", None):
            fu = fo.sender_user
            fu_name = fu.first_name or "کاربر"
            if fu.last_name:
                fu_name += f" {fu.last_name}"
            if fu.username:
                fu_name += f" (@{fu.username})"
            origin_parts.append(f"کاربر فرستنده اصلی: {fu_name} [شناسه عددی/User ID: {fu.id}]")
        elif fo_type in ("chat", "channel"):
            c = getattr(fo, "chat", None) or getattr(fo, "sender_chat", None)
            if c:
                c_title = getattr(c, "title", "") or "کانال/گروه"
                c_user = f" (@{c.username})" if getattr(c, "username", None) else ""
                origin_parts.append(f"کانال/گروه مبدا: {c_title}{c_user} [شناسه عددی: {c.id}]")
        elif fo_type == "hidden_user":
            h_name = getattr(fo, "sender_user_name", "کاربر ناشناس")
            origin_parts.append(f"کاربر فرستنده اصلی با حساب مخفی: {h_name} [حریم خصوصی تلگرام]")
    elif ff:
        f_name = ff.first_name or "کاربر"
        if ff.last_name:
            f_name += f" {ff.last_name}"
        if ff.username:
            f_name += f" (@{ff.username})"
        origin_parts.append(f"کاربر فرستنده اصلی: {f_name} [شناسه عددی/User ID: {ff.id}]")
    elif fc:
        c_title = getattr(fc, "title", "") or "کانال/گروه"
        c_user = f" (@{fc.username})" if getattr(fc, "username", None) else ""
        origin_parts.append(f"کانال/گروه مبدا: {c_title}{c_user} [شناسه عددی: {fc.id}]")

    origin_desc = " | ".join(origin_parts) if origin_parts else "پیام فوروارد شده"
    content = getattr(message, "text", None) or getattr(message, "caption", None) or ""
    body = content.strip() if content else "(بدون متن پیوست شده)"
    return f"📌 [پیام فوروارد شده از طرف {origin_desc}]:\n\"\"\"\n{body}\n\"\"\""


# Weather helper removed for OSINT engine


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


# Digikala helper removed for OSINT engine


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
        f"⚡️ <b>درود {html.escape(u_name)}! به سامانه پرومته OSINT خوش آمدید.</b>\n\n"
        "من <b>پرومته</b> هستم؛ دستیار پیشرفته و خودمختار هوش مصنوعی برای <b>پژوهش‌های عمیق، تحلیل اطلاعات وب و هوش سایبری (OSINT)</b>:\n\n"
        "🔍 <b>مهم‌ترین قابلیت‌های تخصصی پرومته OSINT:</b>\n"
        "• 🌐 <b>جستجوی چندموتوره وب:</b> <code>/osint [عبارت]</code> یا <code>/search</code>\n"
        "• 🕷 <b>کاوشگر لایه‌های وب و متاداده:</b> <code>/crawl [لینک]</code> یا <code>/scrape</code> یا <code>/read</code>\n"
        "• 🔎 <b>دورک‌های هوشمند گوگل:</b> <code>/dork [هدف]</code> (اسناد محرمانه، دایرکتوری باز، لاگین)\n"
        "• 🐙 <b>کاوشگر امنیتی گیت‌هاب:</b> <code>/github [یوزر/مخزن]</code> (استخراج ایمیل نویسندگان از کامیت‌ها، کلیدهای SSH)\n"
        "• 💼 <b>هوش سازمانی لینکدین:</b> <code>/linkedin [شخص/شرکت]</code>\n"
        "• 👤 <b>ردیابی نام‌کاربری:</b> <code>/usercheck [یوزرنیم]</code> در ۲۵+ پلتفرم\n"
        "• 📡 <b>رکوردهای کامل DNS:</b> <code>/dns [دامنه]</code> (A, AAAA, MX, NS, TXT, SOA)\n"
        "• 🌐 <b>کشف ساب‌دامین‌ها:</b> <code>/subdomains [دامنه]</code> با Certificate Transparency\n"
        "• 🌍 <b>شناسایی و مکان‌یابی IP:</b> <code>/ip [آدرس IP یا دامنه]</code>\n"
        "• 📧 <b>تحلیل ایمیل:</b> <code>/email [ایمیل]</code> (بررسی MX و Gravatar)\n"
        "• 📞 <b>تحلیل شماره تلفن:</b> <code>/phone [شماره]</code> (تشخیص اپراتور و کشور)\n"
        "• 🛡️ <b>اسکنر امنیتی VirusTotal:</b> <code>/scan [فایل/لینک/هش]</code> با ۷۰ آنتی‌ویروس\n"
        "• 🧠 <b>مغز خودمختار OSINT پرومته:</b> <code>/agent [پرسش]</code> یا گفتگوی مستقیم\n\n"
        "💡 <i>در گروه‌ها کلیه دستورات با پیشوند p یا p_ (مانند <code>/phelp</code>، <code>/posint</code>، <code>/pdork</code>) یا با منشن نام ربات فعال می‌شوند.</i>"
    )
    await msg.reply_text(text, parse_mode=ParseMode.HTML)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command handler."""
    if not await _check_moderation_guard(update, context):
        return

    msg = update.effective_message
    user = update.effective_user

    text = (
        "📖 <b>راهنمای جامع دستورات سامانه پرومته OSINT:</b>\n\n"
        "💡 <b>پیشوند اختصاصی در گروه‌ها (p / p_):</b>\n"
        "جهت جلوگیری از تداخل با سایر ربات‌ها، در گروه‌ها دستورات با پیشوند اختصاصی (مانند <code>/phelp</code>، <code>/posint</code>، <code>/pdork</code>، <code>/pgithub</code>) یا منشن نام ربات عمل می‌کنند.\n\n"
        "🔍 <b>ابزارهای تخصصی اوسینت و وب:</b>\n"
        "• <code>/osint [عبارت]</code> یا <code>/search</code> - جستجوی همزمان چندموتوره در وب\n"
        "• <code>/crawl [لینک]</code> یا <code>/scrape</code> یا <code>/read</code> - کاوش لایه‌های صفحه، کشف ایمیل‌ها، شماره‌ها، ولت‌ها و تکنولوژی‌های وب‌سایت\n"
        "• <code>/dork [هدف]</code> - تولید و اجرای دورک‌های هدفمند گوگل برای نفوذ، دایرکتوری باز و اسناد\n"
        "• <code>/github [کاربر]</code> - تحلیل اکانت گیت‌هاب، استخراج ایمیل از کامیت‌ها و کلیدهای SSH\n"
        "• <code>/linkedin [نام/شرکت]</code> - کشف سوابق و پروفایل‌های لینکدین\n"
        "• <code>/usercheck [نام کاربری]</code> - استعلام فوری یوزرنیم در ۲۵+ پلتفرم مطرح جهانی\n"
        "• <code>/dns [دامنه]</code> - تفکیک کلیه رکوردهای DNS دامنه\n"
        "• <code>/subdomains [دامنه]</code> - استخراج تمامی ساب‌دامین‌ها از لاگ‌های گواهی امنیتی\n"
        "• <code>/ip [IP/دامنه]</code> - موقعیت جغرافیایی، کشور، شهر، ISP و شماره AS\n"
        "• <code>/email [ایمیل]</code> - بررسی صحت، رکوردهای میل‌سرور و پروفایل Gravatar\n"
        "• <code>/phone [شماره]</code> - اعتبارسنجی شماره و تشخیص اپراتور تلفن همراه\n"
        "• <code>/scan [فایل/لینک/هش]</code> - اسکن امنیتی و تحلیل بدافزار با VirusTotal\n\n"
        "⚙️ <b>دستورات عمومی:</b>\n"
        "• <code>/agent [پرسش]</code> - ارجاع به موتور خودمختار پرومته برای تحلیل و پژوهش‌های چندمرحله‌ای\n"
        "• <code>/fast [پرسش]</code> - پاسخ‌دهی رعدآسا برای گفتگوهای سریع\n"
        "• <code>/id</code> یا <code>/pinfo</code> - استخراج آیدی عددی و مشخصات چت\n"
        "• <code>/ping</code> - تست زنده زمان پاسخگویی سرور\n"
        "• <code>/clear</code> - پاکسازی حافظه نشست جاری\n"
        "• <code>/del</code> - حذف پیام ربات (با ریپلای روی پیام ربات)"
    )

    if user and is_admin(user.id):
        text += (
            "\n\n👮‍♂️ <b>دستورات مدیریت و نظارت ادمین (Admin Governance):</b>\n"
            "• <code>/ban [کاربر/ریپلای]</code> - مسدودسازی دائم کاربر\n"
            "• <code>/unban [کاربر/ریپلای]</code> - رفع مسدودیت کاربر\n"
            "• <code>/mute [کاربر/ریپلای] [مدت]</code> - سکوت موقت کاربر\n"
            "• <code>/unmute [کاربر/ریپلای]</code> - لغو سکوت کاربر\n"
            "• <code>/bangroup [شناسه گروه]</code> - مسدودسازی گروه\n"
            "• <code>/unbangroup [شناسه گروه]</code> - رفع مسدودیت گروه\n"
            "• <code>/mutegroup [مدت]</code> - میوت کردن ربات در گروه\n"
            "• <code>/unmutegroup</code> - لغو سکوت ربات در گروه\n"
            "• <code>/banlist</code> - لیست کاربران و گروه‌های بن‌شده\n"
            "• <code>/mutelist</code> - لیست افراد و گروه‌های میوت‌شده\n"
            "• <code>/groups</code> - فهرست گروه‌های ثبت‌شده و وضعیت آن‌ها\n"
            "• <code>/pendinggroups</code> - لیست گروه‌های در انتظار تایید\n"
            "• <code>/approvegroup [شناسه]</code> - تایید دستی گروه و فعال‌سازی ربات\n"
            "• <code>/rejectgroup [شناسه]</code> - رد درخواست گروه و خروج ربات\n"
            "• <code>/adminlogs</code> - مشاهده لاگ دستورات مدیریتی"
        )

    await msg.reply_text(text, parse_mode=ParseMode.HTML)


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


async def osint_search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Multi-engine OSINT web intelligence search command (/osint or /search)."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return
    args = context.args or []
    query = " ".join(args).strip()
    if not query:
        guide = (
            "🔍 <b>راهنمای موتور جستجوی پیشرفته اوسینت (OSINT Web Intelligence):</b>\n\n"
            "جستجوی همزمان در چند موتور جستجوگر و تار عنکبوتی وب با اولویت Tavily و DuckDuckGo.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/osint [عبارت جستجو]</code>\n"
            "• <code>/search [عبارت جستجو]</code>\n\n"
            "مثال: <code>/osint شرکت فناوری امنیتی تهران</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    await chat.send_action(ChatAction.TYPING)
    t0 = time.perf_counter()
    results = await search_web_osint(query, max_results=5)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, f"جستجوی وب OSINT ({query[:15]})")

    if not results:
        await msg.reply_text(f"🔍 هیچ نتیجه‌ای برای «{html.escape(query)}» یافت نشد.", parse_mode=ParseMode.HTML)
        return

    lines = [f"🌐 <b>نتایج کاوش وب برای:</b> <code>{html.escape(query)}</code>\n"]
    for i, r in enumerate(results, 1):
        title = html.escape(r.get("title") or "بدون عنوان")
        url = r.get("url") or "#"
        snippet = html.escape(r.get("snippet") or "")
        lines.append(f"<b>{i}. <a href=\"{url}\">{title}</a></b>\n{snippet}\n")

    report = "\n".join(lines)
    await _deliver_reply(msg, report)


async def crawl_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Deep webpage layer analyzer: metadata, tech stack, email, phone, crypto wallet, subdomain extraction."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return

    url = ""
    args = context.args or []
    if args:
        url = args[0].strip()
    elif msg.reply_to_message:
        r_txt = msg.reply_to_message.text or msg.reply_to_message.caption or ""
        u_match = re.search(r"https?://\S+", r_txt)
        if u_match:
            url = u_match.group(0).strip()

    if not url:
        guide = (
            "🕷 <b>کاوشگر لایه‌های وب و تحلیل عمیق صفحه (Deep Web Crawler):</b>\n\n"
            "تحلیل متاداده، فناوری‌های مورد استفاده (CMS، CDN، فریم‌ورک)، استخراج ایمیل‌ها، شماره‌ها، کیف‌پول‌های کریپتو، ساب‌دامین‌ها و لینک‌های صفحه.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/crawl https://example.com</code>\n"
            "• <code>/layers https://example.com</code>\n"
            "• <code>/scrape https://example.com</code>\n"
            "• <code>/read https://example.com</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    await chat.send_action(ChatAction.TYPING)
    status_msg = await msg.reply_text("🕷 <b>در حال کاوش و استخراج لایه‌های صفحه وب...</b>", parse_mode=ParseMode.HTML)
    t0 = time.perf_counter()
    data = await crawl_webpage_layers(url)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, "کاوشگر لایه‌های وب")

    if data.get("error"):
        await status_msg.edit_text(f"❌ خطا در تحلیل صفحه: <code>{html.escape(str(data.get('error')))}</code>", parse_mode=ParseMode.HTML)
        return

    title = html.escape(data.get("title") or "بدون عنوان")
    status_code = data.get("status_code", 0)
    tech = data.get("technologies") or []
    emails = data.get("emails") or data.get("extracted_emails") or []
    phones = data.get("phones") or data.get("extracted_phones") or []
    wallets = data.get("crypto") or data.get("extracted_crypto_wallets") or {}
    subdomains = data.get("subdomains") or data.get("extracted_subdomains") or []
    internal_links = data.get("internal_links") or []
    external_links = data.get("external_links") or []

    lines = [
        f"🎯 <b>گزارش کاوش عمیق وب (Webpage Layer Analysis)</b>\n",
        f"🔗 <b>آدرس:</b> <code>{html.escape(data.get('final_url', url))}</code>",
        f"📄 <b>عنوان:</b> {title}",
        f"📡 <b>کد وضعیت:</b> <code>{status_code}</code> | ⏱ <b>زمان پاسخ:</b> <code>{data.get('response_time_ms', 0)}ms</code>",
    ]

    if tech:
        lines.append(f"\n⚙️ <b>فناوری‌های شناسایی‌شده:</b> {html.escape(', '.join(tech))}")

    if emails:
        lines.append(f"\n📧 <b>ایمیل‌های کشف‌شده ({len(emails)}):</b>")
        for em in emails[:8]:
            lines.append(f"  • <code>{html.escape(em)}</code>")

    if phones:
        lines.append(f"\n📞 <b>شماره‌های تماس ({len(phones)}):</b>")
        for ph in phones[:8]:
            lines.append(f"  • <code>{html.escape(ph)}</code>")

    active_wallets = {k: v for k, v in wallets.items() if v}
    if active_wallets:
        lines.append("\n💰 <b>آدرس‌های کیف‌پول رمزارز:</b>")
        for wtype, wlist in active_wallets.items():
            for w in wlist[:3]:
                lines.append(f"  • {wtype.upper()}: <code>{html.escape(w)}</code>")

    if subdomains:
        lines.append(f"\n🌐 <b>ساب‌دامین‌های استخراج‌شده ({len(subdomains)}):</b>")
        for s in subdomains[:6]:
            lines.append(f"  • <code>{html.escape(s)}</code>")

    lines.append(f"\n🔗 <b>آمار لینک‌ها:</b> داخلی: <code>{len(internal_links)}</code> | خارجی: <code>{len(external_links)}</code>")

    text = "\n".join(lines)
    try:
        await status_msg.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception:
        await _deliver_reply(msg, text)


async def dork_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Google Dorking intelligence suite: generates targeted dorks and executes live queries."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return
    args = context.args or []
    target = " ".join(args).strip()
    if not target:
        guide = (
            "🔎 <b>موتور تخصصی دورک‌های گوگل (Smart Google Dorking Engine):</b>\n\n"
            "تولید و اجرای دورک‌های نفوذ و اوسینت برای کشف فایل‌های حساس، اطلاعات محرمانه، پورتال‌های ورود و دایرکتوری‌های باز.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/dork example.com</code> (دورک‌های جامع دامنه)\n"
            "• <code>/dork admin example.com</code> (پورتال‌های ورود و پنل مدیریت)\n"
            "• <code>/dork files example.com</code> (دایرکتوری‌های باز و ایندکس‌ها)\n"
            "• <code>/dork docs example.com</code> (اسناد محرمانه PDF, XLSX, DOCX)\n"
            "• <code>/dork creds example.com</code> (فایل‌های کانفیگ، پسورد و .env)"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    await chat.send_action(ChatAction.TYPING)
    status_msg = await msg.reply_text(f"🔎 <b>در حال تولید و تحلیل دورک‌های هوشمند برای:</b> <code>{html.escape(target)}</code>...", parse_mode=ParseMode.HTML)
    t0 = time.perf_counter()

    category = None
    target_clean = target
    parts = target.split(None, 1)
    if len(parts) == 2 and parts[0].lower() in ("sensitive", "admin", "dirs", "files", "docs", "creds", "subdomains", "cloud"):
        category = parts[0].lower()
        target_clean = parts[1]

    dorks = generate_smart_dorks(target_clean, category=category)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, "تولید دورک گوگل")

    lines = [
        f"🎯 <b>دورک‌های هوشمند گوگل برای هدف:</b> <code>{html.escape(target_clean)}</code>\n"
    ]
    for i, d in enumerate(dorks[:6], 1):
        name = html.escape(d.get("category_title", ""))
        dork_query = html.escape(d.get("query", ""))
        google_url = d.get("google_url", "")
        lines.append(f"<b>{i}. {name}</b>\n▫️ <code>{dork_query}</code>\n▫️ <a href=\"{google_url}\">جستجوی مستقیم در Google</a>\n")

    text = "\n".join(lines)
    try:
        await status_msg.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception:
        await _deliver_reply(msg, text)


async def github_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """GitHub OSINT investigator: scans public & commit history for hidden author emails, SSH keys, top repos."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return
    args = context.args or []
    target = " ".join(args).strip()
    if not target:
        guide = (
            "🐙 <b>کاوشگر امنیتی گیت‌هاب (GitHub OSINT Suite):</b>\n\n"
            "شناسایی دقیق هویت توسعه‌دهندگان، تحلیل تاریخچه کامیت‌ها برای **استخراج ایمیل‌های مخفی نویسنده**، کلیدهای عمومی SSH، مخازن برتر و سازمان‌ها.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/github [نام کاربری]</code> (پروفایل و استخراج ایمیل از کامیت‌ها)\n"
            "• <code>/github search [عبارت]</code> (جستجوی سورس‌کد و مخازن)\n\n"
            "مثال: <code>/github torvalds</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    await chat.send_action(ChatAction.TYPING)
    status_msg = await msg.reply_text(f"🐙 <b>در حال استخراج اطلاعات OSINT از گیت‌هاب برای «{html.escape(target)}»...</b>", parse_mode=ParseMode.HTML)
    t0 = time.perf_counter()

    if target.startswith("search "):
        q = target[7:].strip()
        data = await search_github(q)
        elapsed = time.perf_counter() - t0
        record_chat_latency(chat.id, elapsed, "جستجوی گیت‌هاب")
        repos = data.get("repositories", [])
        if not repos:
            await status_msg.edit_text(f"🔍 نتیجه‌ای در مخازن گیت‌هاب برای «{html.escape(q)}» یافت نشد.", parse_mode=ParseMode.HTML)
            return
        lines = [f"🐙 <b>مخازن یافت شده برای:</b> <code>{html.escape(q)}</code>\n"]
        for r in repos[:5]:
            lines.append(f"• <b><a href=\"{r.get('url')}\">{html.escape(r.get('name', ''))}</a></b> (⭐ {r.get('stars')} | {r.get('language') or 'N/A'})\n  {html.escape(r.get('description') or '')}\n")
        await status_msg.edit_text("\n".join(lines), parse_mode=ParseMode.HTML, disable_web_page_preview=True)
        return

    username = target.replace("https://github.com/", "").strip("/").split()[0]
    data = await investigate_github_user(username)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, f"بررسی OSINT گیت‌هاب (@{username})")

    if not data.get("success"):
        await status_msg.edit_text(f"❌ کاربر «{html.escape(username)}» در گیت‌هاب یافت نشد.", parse_mode=ParseMode.HTML)
        return

    name = html.escape(data.get("name") or username)
    bio = html.escape(data.get("bio") or "ندارد")
    company = html.escape(data.get("company") or "ندارد")
    location = html.escape(data.get("location") or "ندارد")
    created = (data.get("created_at") or "")[:10]
    followers = data.get("followers", 0)
    public_repos = data.get("public_repos_count", 0)
    html_url = data.get("profile_url", f"https://github.com/{username}")

    lines = [
        f"🐙 <b>اطلاعات OSINT کاربر گیت‌هاب:</b> <a href=\"{html_url}\">@{html.escape(username)}</a>",
        f"👤 <b>نام:</b> {name}",
        f"📝 <b>بیو:</b> {bio}",
        f"🏢 <b>سازمان/شرکت:</b> {company} | 📍 <b>موقعیت:</b> {location}",
        f"👥 <b>دنبال‌کنندگان:</b> <code>{followers}</code> | 📁 <b>مخازن عمومی:</b> <code>{public_repos}</code>",
        f"📅 <b>تاریخ عضویت:</b> <code>{created}</code>",
    ]

    emails = data.get("discovered_emails") or []
    if emails:
        lines.append(f"\n📧 <b>ایمیل‌های استخراج‌شده از تاریخچه کامیت‌ها ({len(emails)}):</b>")
        for em in emails:
            lines.append(f"  • <code>{html.escape(em)}</code>")
    else:
        lines.append("\n📧 <b>ایمیل کامیت:</b> <i>هیچ ایمیل عمومی در کامیت‌های اخیر یافت نشد.</i>")

    top_repos = data.get("top_repos") or []
    if top_repos:
        lines.append("\n⭐ <b>مخازن برتر:</b>")
        for r in top_repos[:4]:
            lines.append(f"  • <a href=\"{r.get('url')}\">{html.escape(r.get('name'))}</a> (⭐ {r.get('stars')} | {r.get('language') or 'N/A'})")

    text = "\n".join(lines)
    try:
        await status_msg.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception:
        await _deliver_reply(msg, text)


async def linkedin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """LinkedIn OSINT reconnaissance: profiles, companies, and roles."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return
    args = context.args or []
    target = " ".join(args).strip()
    if not target:
        guide = (
            "💼 <b>کاوشگر اطلاعات لینکدین (LinkedIn OSINT Recon):</b>\n\n"
            "شناسایی موقعیت‌های شغلی، سوابق حرفه‌ای، پروفایل‌های اشخاص و اطلاعات سازمانی شرکت‌ها بدون نیاز به لاگین.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/linkedin [نام شخص] [عنوان شغلی اختیاری]</code>\n"
            "• <code>/linkedin company [نام شرکت]</code>\n\n"
            "مثال:\n"
            "• <code>/linkedin مهرداد فلاحی امنیت شبکه</code>\n"
            "• <code>/linkedin company دیجی کالا</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    await chat.send_action(ChatAction.TYPING)
    status_msg = await msg.reply_text(f"💼 <b>در حال جستجوی اطلاعات در لینکدین برای «{html.escape(target)}»...</b>", parse_mode=ParseMode.HTML)
    t0 = time.perf_counter()

    if target.lower().startswith("company ") or target.lower().startswith("شرکت "):
        cname = re.sub(r"^(?:company|شرکت)\s+", "", target, flags=re.IGNORECASE).strip()
        data = await search_linkedin_company(cname)
        elapsed = time.perf_counter() - t0
        record_chat_latency(chat.id, elapsed, f"جستجوی شرکت لینکدین ({cname[:15]})")

        companies = data.get("companies", [])
        if not companies:
            await status_msg.edit_text(f"❌ اطلاعات شرکتی برای «{html.escape(cname)}» در لینکدین یافت نشد.", parse_mode=ParseMode.HTML)
            return

        lines = [f"🏢 <b>اطلاعات سازمان در لینکدین برای:</b> <code>{html.escape(cname)}</code>\n"]
        for c in companies[:4]:
            lines.append(f"• <b><a href=\"{c.get('url')}\">{html.escape(c.get('name', ''))}</a></b>\n  {html.escape(c.get('snippet', ''))}\n")
        await status_msg.edit_text("\n".join(lines), parse_mode=ParseMode.HTML, disable_web_page_preview=True)
        return

    data = await search_linkedin_profile(target)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, f"جستجوی پروفایل لینکدین ({target[:15]})")

    profiles = data.get("profiles", [])
    if not profiles:
        await status_msg.edit_text(f"❌ پروفایلی مطابق با «{html.escape(target)}» در لینکدین یافت نشد.", parse_mode=ParseMode.HTML)
        return

    lines = [f"💼 <b>پروفایل‌های یافت‌شده در لینکدین برای:</b> <code>{html.escape(target)}</code>\n"]
    for p in profiles[:5]:
        lines.append(f"• <b><a href=\"{p.get('url')}\">{html.escape(p.get('title', ''))}</a></b>\n  {html.escape(p.get('snippet', ''))}\n")

    text = "\n".join(lines)
    try:
        await status_msg.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception:
        await _deliver_reply(msg, text)


async def usercheck_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Asynchronous 25+ platform username reconnaissance checker."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return
    args = context.args or []
    username = (args[0] if args else "").lstrip("@").strip()
    if not username:
        guide = (
            "👤 <b>ردیابی نام‌کاربری در ۲۵+ پلتفرم جهان (Username OSINT):</b>\n\n"
            "پویش موازی و لحظه‌ای نام‌کاربری در شبکه‌های اجتماعی، پلتفرم‌های توسعه‌دهندگان، هاستینگ کد، پایگاه‌های رمزنگاری و گیمینگ.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/usercheck [نام کاربری]</code>\n"
            "• <code>/username [نام کاربری]</code>\n\n"
            "مثال: <code>/usercheck SatoshiNakamoto</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    await chat.send_action(ChatAction.TYPING)
    status_msg = await msg.reply_text(f"👤 <b>در حال ردیابی نام‌کاربری @{html.escape(username)} در ۲۵+ پلتفرم...</b>", parse_mode=ParseMode.HTML)
    t0 = time.perf_counter()
    data = await search_username_across_platforms(username)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, f"ردیابی نام‌کاربری (@{username})")

    found_count = data.get("total_found", data.get("found_count", 0))
    total_checked = data.get("total_scanned", data.get("total_checked", 0))
    found_profiles = data.get("profiles", data.get("found", []))

    lines = [
        f"🎯 <b>نتایج ردیابی نام‌کاربری:</b> <code>@{html.escape(username)}</code>",
        f"📊 <b>وضعیت:</b> کشف‌شده در <b>{found_count}</b> از <b>{total_checked}</b> پلتفرم بررسی‌شده (در <code>{elapsed:.2f}s</code>)\n"
    ]

    if not found_profiles:
        lines.append("<i>این نام کاربری در پلتفرم‌های اصلی عمومی یافت نشد یا ثبت نگردیده است.</i>")
    else:
        for p in found_profiles:
            pname = html.escape(p.get("platform", ""))
            cat = html.escape(p.get("category", ""))
            url = p.get("url", "#")
            cat_str = f" ({cat})" if cat else ""
            lines.append(f"  ✅ <b>{pname}</b>{cat_str}: <a href=\"{url}\">مشاهده پروفایل</a>")

    text = "\n".join(lines)
    try:
        await status_msg.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception:
        await _deliver_reply(msg, text)


async def dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """DNS intelligence command: resolves A, AAAA, MX, NS, TXT, SOA records."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return
    args = context.args or []
    domain = (args[0] if args else "").strip()
    if not domain:
        guide = (
            "📡 <b>تحلیل رکوردهای DNS دامنه (DNS Records Intelligence):</b>\n\n"
            "استخراج جامع رکوردهای DNS از جمله A، AAAA، MX، NS، TXT و SOA دامنه.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/dns [دامنه]</code>\n\n"
            "مثال: <code>/dns google.com</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    await chat.send_action(ChatAction.TYPING)
    t0 = time.perf_counter()
    data = await resolve_dns_records(domain)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, f"بررسی DNS ({domain})")

    lines = [f"📡 <b>گزارش رکوردهای DNS برای:</b> <code>{html.escape(domain)}</code>\n"]
    records = data.get("records", {})
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        vals = records.get(rtype, [])
        if vals:
            lines.append(f"<b>📌 رکوردهای {rtype}:</b>")
            for v in vals[:6]:
                lines.append(f"  • <code>{html.escape(str(v))}</code>")
            lines.append("")

    if not any(records.values()):
        lines.append("<i>هیچ رکورد DNS فعالی برای این دامنه دریافت نشد.</i>")

    await _deliver_reply(msg, "\n".join(lines))


async def subdomains_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Certificate Transparency subdomain discovery via crt.sh."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return
    args = context.args or []
    domain = (args[0] if args else "").strip()
    if not domain:
        guide = (
            "🌐 <b>کشف ساب‌دامین‌های فعال با Certificate Transparency (crt.sh):</b>\n\n"
            "پویش لاگ‌های شفافیت گواهی SSL/TLS برای کشف تمامی ساب‌دامین‌های ثبت‌شده دامنه.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/subdomains [دامنه]</code>\n"
            "• <code>/subs [دامنه]</code>\n\n"
            "مثال: <code>/subdomains github.com</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    await chat.send_action(ChatAction.TYPING)
    status_msg = await msg.reply_text(f"🌐 <b>در حال استخراج ساب‌دامین‌های <code>{html.escape(domain)}</code> از crt.sh...</b>", parse_mode=ParseMode.HTML)
    t0 = time.perf_counter()
    data = await enumerate_subdomains_crtsh(domain)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, f"استخراج ساب‌دامین ({domain})")

    subs = data.get("subdomains", [])
    count = data.get("count", 0)

    lines = [
        f"🌐 <b>ساب‌دامین‌های کشف‌شده برای:</b> <code>{html.escape(domain)}</code>",
        f"📊 <b>تعداد کل:</b> <code>{count}</code> ساب‌دامین یکتا\n"
    ]

    if not subs:
        lines.append("<i>هیچ ساب‌دامینی در لاگ‌های گواهی یافت نشد.</i>")
    else:
        for s in subs[:25]:
            lines.append(f"  • <code>{html.escape(s)}</code>")
        if count > 25:
            lines.append(f"\n<i>... و {count - 25} ساب‌دامین دیگر</i>")

    text = "\n".join(lines)
    try:
        await status_msg.edit_text(text, parse_mode=ParseMode.HTML)
    except Exception:
        await _deliver_reply(msg, text)


async def ip_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """IP / Hostname Geolocation, ASN, and network intelligence lookup."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return
    args = context.args or []
    target = (args[0] if args else "").strip()
    if not target:
        guide = (
            "🌍 <b>اطلاعات شبکه و موقعیت جغرافیایی IP (IP Intel & Geo):</b>\n\n"
            "تحلیل آدرس IP یا دامنه، موقعیت مکانی، کشور، شهر، رساننده خدمات (ISP)، سازمان و شماره AS.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/ip [آدرس IP یا دامنه]</code>\n\n"
            "مثال: <code>/ip 1.1.1.1</code> یا <code>/ip telegram.org</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    target_clean = re.sub(r"^https?://", "", target).split("/")[0]
    await chat.send_action(ChatAction.TYPING)
    t0 = time.perf_counter()
    data = await lookup_ip_intel(target_clean)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, f"تحلیل IP ({target_clean})")

    if data.get("error"):
        await msg.reply_text(f"❌ خطا در استعلام IP: <code>{html.escape(str(data.get('error')))}</code>", parse_mode=ParseMode.HTML)
        return

    ip = html.escape(data.get("ip") or target_clean)
    country = html.escape(data.get("country") or "نامشخص")
    region = html.escape(data.get("region") or "نامشخص")
    city = html.escape(data.get("city") or "نامشخص")
    isp = html.escape(data.get("isp") or "نامشخص")
    org = html.escape(data.get("org") or "نامشخص")
    asn = html.escape(data.get("asn") or "نامشخص")
    coords = html.escape(data.get("coordinates") or "نامشخص")
    timezone = html.escape(data.get("timezone") or "نامشخص")

    lines = [
        f"🌍 <b>اطلاعات شبکه و موقعیت IP:</b> <code>{ip}</code>\n",
        f"📍 <b>موقعیت:</b> {country}، {region}، {city}",
        f"🏢 <b>ارائه‌دهنده (ISP):</b> {isp}",
        f"🏛 <b>سازمان:</b> {org}",
        f"🔢 <b>سیستم خودمختار (ASN):</b> <code>{asn}</code>",
        f"🌐 <b>مختصات جغرافیایی:</b> <code>{coords}</code>",
        f"⏰ <b>منطقه زمانی:</b> <code>{timezone}</code>",
    ]

    await _deliver_reply(msg, "\n".join(lines))


async def email_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Email validation, domain MX records, and Gravatar profile investigator."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return
    args = context.args or []
    email = (args[0] if args else "").strip()
    if not email:
        guide = (
            "📧 <b>بررسی هویت و اعتبار ایمیل (Email OSINT Suite):</b>\n\n"
            "صحت‌سنجی ساختار، بررسی رکوردهای MX سرور ایمیل و کشف پروفایل‌های متصل در Gravatar.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/email user@example.com</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    await chat.send_action(ChatAction.TYPING)
    t0 = time.perf_counter()
    data = await investigate_email(email)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, "بررسی ایمیل OSINT")

    is_valid = data.get("syntax_valid", False)
    domain = html.escape(data.get("domain", ""))
    mx_records = data.get("mx_records", [])
    gravatar = data.get("gravatar", {})

    lines = [
        f"📧 <b>گزارش OSINT ایمیل:</b> <code>{html.escape(email)}</code>\n",
        f"✔️ <b>فرمت معتبر:</b> {'بله ✅' if is_valid else 'خیر ❌'}",
        f"🌐 <b>دامنه:</b> <code>{domain}</code>",
    ]

    if mx_records:
        lines.append(f"📬 <b>سرورهای میل (MX):</b> <code>{html.escape(', '.join(str(m) for m in mx_records[:3]))}</code>")
    else:
        lines.append("📬 <b>سرور میل (MX):</b> <i>رکوردی یافت نشد (احتمالاً دامنه فاقد میل‌سرور است).</i>")

    if gravatar.get("has_gravatar"):
        lines.append(f"🖼 <b>پروفایل Gravatar:</b> <a href=\"{gravatar.get('profile_url')}\">مشاهده پروفایل</a>")
        gname = gravatar.get("display_name")
        if gname:
            lines.append(f"👤 <b>نام نمایشی:</b> {html.escape(gname)}")

    await _deliver_reply(msg, "\n".join(lines))


async def phone_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Phone number intelligence: carrier detection, country, and valid format."""
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return
    args = context.args or []
    number = (args[0] if args else "").strip()
    if not number:
        guide = (
            "📞 <b>شناسایی و تحلیل شماره تلفن (Phone OSINT):</b>\n\n"
            "تحلیل فرمت شماره، تشخیص اپراتور (همراه اول، ایرانسل، رایتل، شاتل و...)، کشور و اعتبارسنجی ساختاری.\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/phone 09121234567</code>\n"
            "• <code>/phone +14155552671</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    await chat.send_action(ChatAction.TYPING)
    t0 = time.perf_counter()
    data = await analyze_phone_number(number)
    elapsed = time.perf_counter() - t0
    record_chat_latency(chat.id, elapsed, "تحلیل شماره تلفن")

    lines = [
        f"📞 <b>اطلاعات شماره تلفن:</b> <code>{html.escape(number)}</code>\n",
        f"✔️ <b>وضعیت اعتبار:</b> {'معتبر ✅' if data.get('valid') else 'نامعتبر ❌'}",
        f"🌍 <b>کشور:</b> {html.escape(data.get('country', 'نامشخص'))}",
        f"📡 <b>اپراتور شناسایی‌شده:</b> {html.escape(data.get('carrier', 'نامشخص'))}",
        f"🔢 <b>فرمت استاندارد بین‌المللی:</b> <code>{html.escape(data.get('international_format', 'N/A'))}</code>",
        f"📱 <b>فرمت ملی:</b> <code>{html.escape(data.get('national_format', 'N/A'))}</code>",
    ]

    await _deliver_reply(msg, "\n".join(lines))


async def time_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Official time and Jalali calendar lookup."""
    if update.effective_chat:
        await update.effective_chat.send_action(ChatAction.TYPING)
    res = get_current_time()
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


async def delete_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Deletes bot messages upon reply silently without sending any follow-up replies."""
    msg = update.effective_message
    if not msg:
        return
    user = update.effective_user
    chat = update.effective_chat
    bot_user = context.bot if (context and getattr(context, "bot", None)) else None
    bot_id = bot_user.id if bot_user else None
    bot_username = (bot_user.username or "").lower() if bot_user else ""
    reply_to = msg.reply_to_message

    is_bot_adm = is_admin(user.id) if user else False
    is_grp_adm = False
    if chat and chat.type != ChatType.PRIVATE and user and context and getattr(context, "bot", None):
        is_grp_adm = await is_user_chat_admin(context.bot, chat.id, user.id)

    if reply_to:
        is_from_bot = (
            (bot_id and reply_to.from_user and reply_to.from_user.id == bot_id)
            or (reply_to.from_user and reply_to.from_user.is_bot and bot_username and (reply_to.from_user.username or "").lower() == bot_username)
            or (reply_to.from_user and reply_to.from_user.is_bot and not bot_username)
        )
        if is_from_bot or ((is_bot_adm or is_grp_adm) and chat and chat.type != ChatType.PRIVATE):
            try:
                await reply_to.delete()
            except Exception as e:
                logger.warning(f"Failed to delete message: {e}")
            try:
                await msg.delete()
            except Exception:
                pass
            return
        else:
            return
    else:
        if not (is_bot_adm or is_grp_adm) and chat and chat.type == ChatType.PRIVATE:
            await msg.reply_text("ℹ️ برای حذف پیام پرومته، لطفاً روی پیام مورد نظر ریپلای کرده و کلمه «حذف» یا /del را ارسال نمایید.")
        return


async def id_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Extracts all Telegram IDs and metadata with 1-tap copyable code blocks."""
    msg = update.effective_message
    if not msg:
        return
    report = format_id_report(update)
    await msg.reply_text(report, parse_mode=ParseMode.HTML)


async def summarize_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Summarizes recent chat messages (up to 3000) using lightweight sub-agents."""
    chat = update.effective_chat
    message = update.effective_message
    if not chat or not message:
        return

    count = 100
    if context.args:
        try:
            val = int(context.args[0])
            count = min(3000, max(10, val))
        except ValueError:
            pass

    t0 = time.perf_counter()
    report = await summarize_group_messages(
        chat_id=chat.id,
        count=count,
        chat_title=chat.title or ""
    )
    record_chat_latency(chat.id, time.perf_counter() - t0, f"ساب‌اجنت‌های خلاصه‌ساز گفتگو ({count} پیام)")
    await message.reply_text(report, parse_mode=ParseMode.HTML)


async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Searches past messages in the chat using SQLite FTS5 BM25 full-text search."""
    chat = update.effective_chat
    message = update.effective_message
    if not chat or not message:
        return

    query = " ".join(context.args).strip() if context.args else ""
    if not query:
        await message.reply_text(
            "ℹ️ لطفاً عبارت مورد نظر جهت جستجو را پس از دستور بنویسید:\nمثال: <code>/search هوش مصنوعی</code>",
            parse_mode=ParseMode.HTML
        )
        return

    t0 = time.perf_counter()
    report = await search_group_messages(
        chat_id=chat.id,
        query=query,
        limit=10,
        chat_title=chat.title or ""
    )
    record_chat_latency(chat.id, time.perf_counter() - t0, "جستجوی FTS5 در دیتابیس")
    await message.reply_text(report, parse_mode=ParseMode.HTML)






async def photo_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Direct multimodal vision handler for received photos and albums."""
    msg = update.effective_message
    user = update.effective_user
    chat = update.effective_chat
    if not msg or not msg.photo or not chat or not user:
        return

    # Always record media_group_id so all album photos are permanently tracked
    if msg.media_group_id and msg.photo:
        await record_media_group_photo(
            chat_id=chat.id,
            media_group_id=str(msg.media_group_id),
            message_id=msg.message_id,
            file_id=msg.photo[-1].file_id
        )

    if not await _check_moderation_guard(update, context):
        return

    # Ingest photo message into database
    asyncio.create_task(
        database.persist_message(
            chat_id=chat.id,
            user_id=user.id,
            role="user",
            content=caption or "[Photo]",
            username=user.username or "",
            full_name=user.full_name or "",
            message_id=msg.message_id,
            reply_to_message_id=msg.reply_to_message.message_id if msg.reply_to_message else 0,
            media_type="photo",
            is_bot=1 if user.is_bot else 0
        )
    )

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

    # Check photo caption for jailbreak attempts
    if caption:
        attack_name = detect_jailbreak_attempt(caption)
        if attack_name:
            if is_admin(user.id):
                logger.warning(f"Admin {user.id} triggered jailbreak pattern in photo caption; skipping auto-ban.")
            else:
                logger.warning(f"Security Alert: Auto-banning user {user.id} for photo jailbreak attack: {attack_name}")
                await ban_user(
                    user_id=user.id,
                    username=user.username or "",
                    name=user.full_name or "",
                    reason=f"تلاش خودکار برای نفوذ/جیل‌بریک در کپشن تصویر: {attack_name}",
                    banned_by=0,
                    chat_id=chat.id,
                    chat_title=chat.title or "",
                )
                if chat.type != ChatType.PRIVATE:
                    try:
                        await context.bot.ban_chat_member(chat_id=chat.id, user_id=user.id)
                    except Exception as be:
                        logger.debug(f"Could not ban member from Telegram chat: {be}")

                user_mention = f"@{user.username}" if user.username else (user.full_name or f"کاربر {user.id}")
                ban_notice = (
                    f"⛔️ <b>کاربر {html.escape(user_mention)} به دلیل تلاش برای نفوذ یا جیل‌بریک مسدود (Ban) شد.</b>\n\n"
                    f"⚠️ <b>نوع اقدام:</b> {html.escape(attack_name)}\n"
                    f"🚫 <i>دسترسی این کاربر به کلیه خدمات پرومته به صورت دائمی مسدود گردید.</i>"
                )
                await msg.reply_text(ban_notice, parse_mode=ParseMode.HTML)
                return

    if caption and is_id_request(caption):
        report = format_id_report(update)
        await msg.reply_text(report, parse_mode=ParseMode.HTML)
        return

    # Rate limit check
    allowed, limit_msg = check_user_rate_limit(user.id)
    if not allowed:
        await msg.reply_text(limit_msg or "⚠️ لطفاً کمی شکیبا باشید.")
        return

    # Check if this photo is part of an incoming album (Media Group)
    if msg.media_group_id:
        async def _on_album_ready(mg_id: str, fids: List[str], album_caption: str):
            typing_task = asyncio.create_task(_send_typing_loop(context.bot, chat.id))
            t0 = time.perf_counter()
            try:
                cleaned_c = album_caption or ""
                if bot_username:
                    cleaned_c = re.sub(rf"@{re.escape(bot_username)}", "", cleaned_c, flags=re.IGNORECASE)
                for name in ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس", "پرومتيوس"]:
                    cleaned_c = re.sub(rf"(?<!\w){re.escape(name)}(?!\w)", "", cleaned_c, flags=re.IGNORECASE)
                cleaned_c = cleaned_c.strip()

                async def _dl_album_photo(fid):
                    try:
                        f = await context.bot.get_file(fid)
                        return bytes(await f.download_as_bytearray())
                    except Exception as de:
                        logger.warning(f"Error downloading album photo {fid}: {de}")
                        return None

                downloaded_bytes = await asyncio.gather(*[_dl_album_photo(fid) for fid in fids])
                photos_bytes_list = [b for b in downloaded_bytes if b]
                if not photos_bytes_list:
                    largest_photo = msg.photo[-1]
                    photo_file = await largest_photo.get_file()
                    photos_bytes_list = [bytes(await photo_file.download_as_bytearray())]

                analysis = await analyze_image_with_vision(
                    images=photos_bytes_list,
                    prompt=cleaned_c if cleaned_c else None,
                    chat_id=chat.id,
                )

                if is_reconstruction_query(album_caption):
                    reconstruct_prompt = cleaned_c or "photorealistic detailed visual recreation"
                    preview_url = build_reconstruction_image_url(reconstruct_prompt)
                    analysis += f"\n\n🎨 <b>پیش‌نمایش شبیه‌سازی مجدد تصویر:</b>\n<a href=\"{preview_url}\">مشاهده پیش‌نمایش تصویر بازسازی‌شده</a>"

                elapsed = time.perf_counter() - t0
                engine_label = f"موتور بینایی چندوجهی پرومته ({len(photos_bytes_list)} تصویر آلبوم)"
                record_chat_latency(chat.id, elapsed, engine_label)
                header = f"📸 <b>تحلیل چندوجهی آلبوم تصاویر ({len(photos_bytes_list)} تصویر):</b>\n\n" if len(photos_bytes_list) > 1 else ""
                await _deliver_reply(msg, header + analysis)
            except Exception as e:
                logger.error(f"Error processing album vision: {e}")
                await msg.reply_text(f"❌ متأسفانه خطایی در پردازش آلبوم تصاویر رخ داد: {str(e)}")
            finally:
                typing_task.cancel()
                try:
                    await typing_task
                except asyncio.CancelledError:
                    pass

        # Check if this photo or album was addressed to the bot
        is_trig = is_private
        if not is_trig:
            if msg.reply_to_message and msg.reply_to_message.from_user and msg.reply_to_message.from_user.id == bot_id:
                is_trig = True
            elif bot_username and f"@{bot_username}" in caption.lower():
                is_trig = True
            elif any(name in caption.lower() for name in ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس"]):
                is_trig = True

        await debounce_incoming_album(
            chat_id=chat.id,
            media_group_id=str(msg.media_group_id),
            message_id=msg.message_id,
            file_id=msg.photo[-1].file_id,
            caption=caption if is_trig else None,
            on_ready_callback=_on_album_ready if is_trig else (lambda *args: None),
            delay=1.0
        )
        return

    typing_task = asyncio.create_task(_send_typing_loop(context.bot, chat.id))
    t0 = time.perf_counter()
    try:
        cleaned_caption = caption
        if bot_username:
            cleaned_caption = re.sub(rf"@{re.escape(bot_username)}", "", cleaned_caption, flags=re.IGNORECASE)
        for name in ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس", "پرومتيوس"]:
            cleaned_caption = re.sub(rf"(?<!\w){re.escape(name)}(?!\w)", "", cleaned_caption, flags=re.IGNORECASE)
        cleaned_caption = cleaned_caption.strip()

        largest_photo = msg.photo[-1]
        photo_file = await largest_photo.get_file()
        photos_bytes_list = [bytes(await photo_file.download_as_bytearray())]

        analysis = await analyze_image_with_vision(
            images=photos_bytes_list,
            prompt=cleaned_caption if cleaned_caption else None,
            chat_id=chat.id,
        )

        if is_reconstruction_query(caption):
            reconstruct_prompt = cleaned_caption or "photorealistic detailed visual recreation"
            preview_url = build_reconstruction_image_url(reconstruct_prompt)
            analysis += f"\n\n🎨 <b>پیش‌نمایش شبیه‌سازی مجدد تصویر:</b>\n<a href=\"{preview_url}\">مشاهده پیش‌نمایش تصویر بازسازی‌شده</a>"

        elapsed = time.perf_counter() - t0
        engine_label = f"موتور بینایی چندوجهی پرومته (1 تصویر)"
        record_chat_latency(chat.id, elapsed, engine_label)
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
# File Management & VirusTotal Threat Intelligence Engine
# =========================================================================

async def file_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles /file, /createfile, /makefile commands.
    Generates and sends downloadable files (.py, .txt, .json, .csv, .docx, .xlsx, .pdf, etc.).
    Usage:
      - /file script.py print("Hello World")
      - Or reply to any code/text message with: /file bot.py
      - Or /file report.pdf [text...]
    """
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return

    args = context.args or []
    target_filename = args[0] if args else ""
    content = " ".join(args[1:]).strip() if len(args) > 1 else ""

    # If replied to a message, extract content from replied message if not supplied in args
    if not content and msg.reply_to_message:
        reply_raw = msg.reply_to_message.text or msg.reply_to_message.caption or ""
        code_blocks = re.findall(r"```(?:[a-zA-Z0-9_+\-]+)?\n([\s\S]*?)```", reply_raw)
        if code_blocks:
            content = code_blocks[0].strip()
        else:
            content = reply_raw.strip()

    if not target_filename and not content:
        guide = (
            "📁 <b>راهنمای تولید و ساخت انواع فایل در پرومته:</b>\n\n"
            "پرومته توانایی ساخت و ارسال انواع فایل‌ها با فرمت‌های مختلف را دارد:\n"
            "• 🐍 <b>اسکریپت و کد:</b> <code>.py</code>, <code>.js</code>, <code>.html</code>, <code>.sh</code>, <code>.json</code>, <code>.sql</code>\n"
            "• 📊 <b>جداول و داده:</b> اکسل (<code>.xlsx</code>), <code>.csv</code>\n"
            "• 📝 <b>اسناد اداری:</b> ورد (<code>.docx</code>), پی‌دی‌اف (<code>.pdf</code>), متن (<code>.txt</code>, <code>.md</code>)\n\n"
            "<b>روش‌های استفاده:</b>\n"
            "۱. ارسال دستور مستقیم:\n"
            "<code>/file script.py print('Hello World')</code>\n\n"
            "۲. ریپلای روی کد یا متن در چت:\n"
            "<code>/file main.py</code>\n\n"
            "۳. درخواست مستقیم به زبان محاوره‌ای:\n"
            "<i>«یک فایل پایتون به نام bot.py بساز با کد...»</i>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    if not target_filename:
        target_filename = "document.txt"

    if not content:
        await msg.reply_text(
            "⚠️ محتوایی برای قرارگیری در فایل مشخص نشده است.\n"
            "لطفاً روی یک پیام حاوی متن ریپلای کنید یا محتوا را پس از نام فایل وارد نمایید:\n"
            f"<code>/file {target_filename} [محتوای مورد نظر]</code>",
            parse_mode=ParseMode.HTML
        )
        return

    await chat.send_action(ChatAction.UPLOAD_DOCUMENT)
    t0 = time.perf_counter()
    try:
        buf, final_name = create_document_file(target_filename, content)
        elapsed = time.perf_counter() - t0
        record_chat_latency(chat.id, elapsed, f"تولید فایل ({final_name})")
        size_kb = len(buf.getvalue()) / 1024
        caption = (
            f"📄 <b>فایل تولید شده توسط پرومته:</b> <code>{html.escape(final_name)}</code>\n"
            f"💾 حجم: <code>{size_kb:.1f} KB</code>\n"
            f"⏱ زمان تولید: <code>{elapsed*1000:.1f}ms</code>"
        )
        await msg.reply_document(
            document=buf,
            filename=final_name,
            caption=caption,
            parse_mode=ParseMode.HTML
        )
    except Exception as e:
        logger.error(f"Error creating file {target_filename}: {e}")
        await msg.reply_text(f"❌ متأسفانه در ایجاد فایل خطایی رخ داد: {e}")


async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles /scan, /vt, /virustotal, /antivirus commands.
    Scans files, hashes, URLs, and domains against 70+ antivirus engines via VirusTotal.
    """
    msg = update.effective_message
    chat = update.effective_chat
    if not msg or not chat:
        return

    args = context.args or []
    target = " ".join(args).strip() if args else ""

    # Case 1: Replied to a document
    if msg.reply_to_message and msg.reply_to_message.document:
        doc = msg.reply_to_message.document
        if doc.file_size and doc.file_size > 32 * 1024 * 1024:
            await msg.reply_text("⚠️ حجم فایل بیش از ۳۲ مگابایت است و امکان ارسال به VirusTotal برای اسکن لایو وجود ندارد.")
            return

        status_msg = await msg.reply_text("🔍 در حال دریافت فایل و ارسال به VirusTotal جهت اسکن امنیتی...")
        await chat.send_action(ChatAction.TYPING)
        t0 = time.perf_counter()
        try:
            tg_file = await doc.get_file()
            f_bytes = await tg_file.download_as_bytearray()
            res = await upload_and_scan_file(bytes(f_bytes), doc.file_name or "file.bin")
            elapsed = time.perf_counter() - t0
            record_chat_latency(chat.id, elapsed, "اسکن امنیتی فایل با VirusTotal")
            report = format_virustotal_report(res)
            await status_msg.edit_text(report, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
            return
        except Exception as e:
            logger.error(f"Error scanning replied document: {e}")
            await status_msg.edit_text(f"❌ خطا در اسکن فایل با VirusTotal: {e}")
            return

    # Case 2: Replied to a text message containing URL / Hash
    if not target and msg.reply_to_message:
        reply_raw = msg.reply_to_message.text or msg.reply_to_message.caption or ""
        is_req, extracted = is_virustotal_request(reply_raw)
        if extracted:
            target = extracted
        else:
            hash_or_url = re.search(r"([a-fA-F0-9]{64}|[a-fA-F0-9]{32}|https?://\S+|[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/\S*)?)", reply_raw)
            if hash_or_url:
                target = hash_or_url.group(1)

    # Case 3: Target supplied directly (URL, Domain, Hash)
    if target:
        await chat.send_action(ChatAction.TYPING)
        t0 = time.perf_counter()
        clean_target = target.strip()
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", clean_target):
            res = await scan_file_hash(clean_target)
            elapsed = time.perf_counter() - t0
            record_chat_latency(chat.id, elapsed, f"استعلام هش VirusTotal ({clean_target[:8]})")
            report = format_virustotal_report(res)
            await _deliver_reply(msg, report)
            return
        else:
            res = await scan_url_or_domain(clean_target)
            elapsed = time.perf_counter() - t0
            record_chat_latency(chat.id, elapsed, f"اسکن آدرس در VirusTotal ({clean_target[:20]})")
            report = format_virustotal_report(res)
            await _deliver_reply(msg, report)
            return

    # Case 4: No argument and no reply - Show guide
    guide = (
        "🛡️ <b>راهنمای پویشگر و آنتی‌ویروس جامع VirusTotal پرومته:</b>\n\n"
        "این سیستم امنیتی به بیش از <b>۷۰ موتور آنتی‌ویروس مطرح جهان</b> (کسپرسکی، مایکروسافت، بیت‌دیفندر، نود۳۲ و...) متصل است.\n\n"
        "<b>قابلیت‌ها و نحوه استفاده:</b>\n"
        "• <b>اسکن فایل:</b> روی هر فایل ارسال‌شده در چت ریپلای کنید و دستور <code>/scan</code> یا <code>/vt</code> را بفرستید.\n"
        "• <b>بررسی امنیت لینک/سایت:</b>\n"
        "<code>/scan https://suspicious-site.com</code>\n"
        "• <b>استعلام هش فایل (SHA-256 یا MD5):</b>\n"
        "<code>/scan 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f</code>\n"
        "• <b>درخواست محاوره‌ای:</b> <i>«این لینک رو اسکن کن...»</i> یا <i>«آیا این سایت ویروسیه؟»</i>"
    )
    await msg.reply_text(guide, parse_mode=ParseMode.HTML)


async def virustotal_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles inline button clicks for VirusTotal scanning on documents."""
    query = update.callback_query
    if not query or not query.data:
        return

    await query.answer("🔍 در حال اتصال به VirusTotal و آغاز تحلیل امنیتی...")

    file_id = query.data.split(":", 1)[1] if ":" in query.data else ""
    if not file_id:
        await query.edit_message_text("❌ شناسه فایل نامعتبر است.")
        return

    try:
        tg_file = await context.bot.get_file(file_id)
        if tg_file.file_size and tg_file.file_size > 32 * 1024 * 1024:
            await query.edit_message_text("⚠️ حجم این فایل بیش از ۳۲ مگابایت است و امکان ارسال به VirusTotal برای اسکن لایو وجود ندارد.")
            return

        f_bytes = await tg_file.download_as_bytearray()
        res = await upload_and_scan_file(bytes(f_bytes), "file.bin")
        report = format_virustotal_report(res)
        await query.edit_message_text(report, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except Exception as e:
        logger.error(f"Error in virustotal_callback: {e}")
        await query.edit_message_text(f"❌ خطا در انجام اسکن امنیتی: {e}")


async def document_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles all incoming document files (PDF, Word, Excel, CSV, Code, Text, Archives, etc.).
    Extracts text/data, offers smart actions, and supports 1-tap VirusTotal scanning.
    """
    msg = update.effective_message
    user = update.effective_user
    chat = update.effective_chat
    if not msg or not user or not chat or not msg.document:
        return

    doc = msg.document
    caption = (msg.caption or "").strip()

    # 1. Moderation / Banned check
    if not await _check_moderation_guard(update, context):
        return

    # Ingest document message into database
    asyncio.create_task(
        database.persist_message(
            chat_id=chat.id,
            user_id=user.id,
            role="user",
            content=f"[Document: {doc.file_name or 'file'}] {caption}".strip(),
            username=user.username or "",
            full_name=user.full_name or "",
            message_id=msg.message_id,
            reply_to_message_id=msg.reply_to_message.message_id if msg.reply_to_message else 0,
            media_type="document",
            is_bot=1 if user.is_bot else 0
        )
    )

    # 2. Check caption for jailbreak attempt
    if caption:
        attack_name = detect_jailbreak_attempt(caption)
        if attack_name:
            if is_admin(user.id):
                logger.warning(f"Admin {user.id} triggered jailbreak in document caption; skipping auto-ban.")
            else:
                logger.warning(f"Security Alert: Auto-banning user {user.id} for document jailbreak attack: {attack_name}")
                await ban_user(
                    user_id=user.id,
                    username=user.username or "",
                    name=user.full_name or "",
                    reason=f"تلاش خودکار برای نفوذ/جیل‌بریک در کپشن فایل: {attack_name}",
                    banned_by=0,
                    chat_id=chat.id,
                    chat_title=chat.title or "",
                )
                if chat.type != ChatType.PRIVATE:
                    try:
                        await context.bot.ban_chat_member(chat_id=chat.id, user_id=user.id)
                    except Exception as be:
                        logger.debug(f"Could not ban member from Telegram chat: {be}")

                user_mention = f"@{user.username}" if user.username else (user.full_name or f"کاربر {user.id}")
                ban_notice = (
                    f"⛔️ <b>کاربر {html.escape(user_mention)} به دلیل تلاش برای نفوذ یا جیل‌بریک مسدود (Ban) شد.</b>\n\n"
                    f"⚠️ <b>نوع اقدام:</b> {html.escape(attack_name)}\n"
                    f"🚫 <i>دسترسی این کاربر به کلیه خدمات پرومته به صورت دائمی مسدود گردید.</i>"
                )
                await msg.reply_text(ban_notice, parse_mode=ParseMode.HTML)
                return

    # In groups: Enforce direct address policy (caption mentions bot, or replies to bot)
    is_private = (chat.type == ChatType.PRIVATE)
    if not is_private:
        is_direct, _ = is_direct_bot_request(update, context, caption)
        if not is_direct and not any(caption.startswith(f"/{c}") for c in ["scan", "vt", "file", "createfile", "makefile", "pscan", "pfile"]):
            return

    # Rate limit check
    allowed, limit_msg = check_user_rate_limit(user.id)
    if not allowed:
        await msg.reply_text(limit_msg or "⚠️ لطفاً کمی شکیبا باشید.")
        return

    # File size check (Telegram Bot API downloads limited to 20MB)
    if doc.file_size and doc.file_size > 20 * 1024 * 1024:
        await msg.reply_text(
            f"⚠️ <b>محدودیت حجم دانلود تلگرام:</b>\n"
            f"حجم فایل ارسالی ({doc.file_size / (1024*1024):.1f} MB) بیش از سقف مجاز دانلود برای ربات‌های تلگرام (۲۰ مگابایت) است.\n"
            f"💡 برای اسکن امنیتی یا بررسی، می‌توانید هش فایل را استعلام نمایید:\n"
            f"<code>/scan [هش SHA-256 یا MD5]</code>",
            parse_mode=ParseMode.HTML
        )
        return

    # Check if user explicitly asked for VirusTotal scan in caption
    is_scan_req, _ = is_virustotal_request(caption)

    typing_task = asyncio.create_task(_send_typing_loop(context.bot, chat.id))
    t0 = time.perf_counter()
    try:
        tg_file = await doc.get_file()
        file_bytes = await tg_file.download_as_bytearray()
        f_name = doc.file_name or "document.bin"
        f_mime = doc.mime_type or ""

        if is_scan_req:
            vt_res = await upload_and_scan_file(bytes(file_bytes), f_name)
            elapsed = time.perf_counter() - t0
            record_chat_latency(chat.id, elapsed, f"اسکن VirusTotal فایل ({f_name})")
            report = format_virustotal_report(vt_res)
            await _deliver_reply(msg, report)
            return

        # Read & parse the file content
        parsed = extract_file_content(bytes(file_bytes), f_name, mime_type=f_mime)
        elapsed = time.perf_counter() - t0
        record_chat_latency(chat.id, elapsed, f"استخراج و تحلیل محتوای فایل ({f_name})")

        # Clean caption of bot mentions
        cleaned_caption = caption
        bot_user = context.bot if (context and getattr(context, "bot", None)) else None
        bot_username = (bot_user.username or "").lower() if bot_user else ""
        if bot_username:
            cleaned_caption = re.sub(rf"@{re.escape(bot_username)}", "", cleaned_caption, flags=re.IGNORECASE)
        for name in ["پرومته", "prometheus", "پرومتئوس", "پرومتیوس", "پرومتيوس"]:
            cleaned_caption = re.sub(rf"(?<!\w){re.escape(name)}(?!\w)", "", cleaned_caption, flags=re.IGNORECASE)
        cleaned_caption = cleaned_caption.strip()

        # If user asked a specific instruction/question about this file
        if cleaned_caption and len(cleaned_caption) > 2:
            agent_prompt = (
                f"فایلی با نام «{f_name}» (فرمت: {parsed['file_type']}) توسط کاربر ارسال شده است.\n"
                f"محتوای استخراج شده از فایل:\n"
                f"\"\"\"\n{parsed['content']}\n\"\"\"\n\n"
                f"دستور و خواسته کاربر درباره این فایل:\n{cleaned_caption}"
            )
            await _process_and_reply(update, context, agent_prompt)
            return

        # Otherwise deliver rich extracted summary with 1-tap VirusTotal scan button
        size_kb = (doc.file_size or len(file_bytes)) / 1024
        header = (
            f"📄 <b>اطلاعات و محتوای فایل دریافت شده:</b>\n"
            f"• نام فایل: <code>{html.escape(f_name)}</code>\n"
            f"• نوع: <code>{html.escape(parsed['file_type'])}</code>\n"
            f"• حجم: <code>{size_kb:.1f} KB</code>\n"
        )
        if parsed.get("page_count"):
            header += f"• تعداد صفحات: <code>{parsed['page_count']}</code>\n"
        if parsed.get("line_count"):
            header += f"• تعداد خطوط: <code>{parsed['line_count']}</code>\n"

        preview_text = parsed.get("preview") or parsed.get("content") or ""
        if preview_text:
            body = (
                f"\n👁 <b>پیش‌نمایش محتوا:</b>\n"
                f"<blockquote>{html.escape(preview_text[:1200])}</blockquote>\n"
            )
        else:
            body = "\n⚠️ محتوای متنی قابل پیش‌نمایش در این فایل یافت نشد.\n"

        footer = "\n💡 <i>می‌توانید روی این پیام ریپلای کنید و بپرسید: «این فایل رو خلاصه کن»، «به پایتون تبدیل کن»، «اشکالات کد رو بگو» و...</i>"

        full_rep = header + body + footer
        keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("🛡️ اسکن امنیتی با VirusTotal", callback_data=f"vt_scan:{doc.file_id}")]
        ])

        chunks = split_message(full_rep, max_len=3900)
        for i, ch in enumerate(chunks):
            if i == len(chunks) - 1:
                await msg.reply_text(ch, parse_mode=ParseMode.HTML, reply_markup=keyboard)
            else:
                await msg.reply_text(ch, parse_mode=ParseMode.HTML)

    except Exception as e:
        logger.error(f"Error handling document {doc.file_name}: {e}")
        await msg.reply_text(f"❌ متأسفانه خطایی در پردازش فایل ارسالی رخ داد: {e}")
    finally:
        typing_task.cancel()
        try:
            await typing_task
        except asyncio.CancelledError:
            pass


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


def make_mute_keyboard(target_id: int, duration_sec: int, active_scope: str) -> InlineKeyboardMarkup:
    """Creates inline keyboard allowing admins to easily switch mute mode or unmute."""
    chk_grp = "🔘 " if active_scope == "group" else ""
    chk_bot = "🔘 " if active_scope == "bot" else ""
    chk_both = "🔘 " if active_scope == "both" else ""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(f"{chk_grp}🔇 فقط در گروه", callback_data=f"mod:mute:group:{target_id}:{duration_sec}"),
            InlineKeyboardButton(f"{chk_bot}🤖 فقط از ربات", callback_data=f"mod:mute:bot:{target_id}:{duration_sec}"),
        ],
        [
            InlineKeyboardButton(f"{chk_both}⚡️ میوت کامل (هردو)", callback_data=f"mod:mute:both:{target_id}:{duration_sec}"),
            InlineKeyboardButton("🔊 لغو سکوت (آنمیوت)", callback_data=f"mod:unmute:all:{target_id}:0"),
        ]
    ])


async def execute_admin_mute(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    rem_text: str = "",
    requested_scope: str = "auto"
) -> bool:
    """
    Intelligently executes mute in database (Bot Mute) and/or Telegram group restriction (Group Mute).
    Understands:
    - 'group': Telegram group restrict only (cannot chat in group)
    - 'bot': Prometheus bot mute only (bot ignores user)
    - 'both': Full mute (both group and bot)
    - 'auto': Resolves from text or defaults to 'both' in groups and 'bot' in private chats.
    """
    msg = update.effective_message
    user = update.effective_user
    chat = update.effective_chat
    if not user or not msg or not chat:
        return False

    is_bot_adm = is_admin(user.id)
    is_grp_adm = False
    if chat.type != ChatType.PRIVATE and context and getattr(context, "bot", None):
        is_grp_adm = await is_user_chat_admin(context.bot, chat.id, user.id)

    if not is_bot_adm and not is_grp_adm:
        await msg.reply_text(
            "⛔️ <b>عدم دسترسی:</b> دستورات مدیریت و میوت کاربران صرفاً در اختیار مدیران این گروه و ادمین‌های پرومته می‌باشد.",
            parse_mode=ParseMode.HTML
        )
        return True

    tid = None
    tuname = None
    tname = None
    target_text = rem_text

    # Extract target from replied message
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

    # Extract target from text if not in reply
    if not tid and not tuname and target_text:
        parts = target_text.split(maxsplit=1)
        first_token = parts[0].strip()
        if first_token.lstrip("-+").isdigit():
            tid = int(first_token)
            target_text = parts[1] if len(parts) > 1 else ""
        elif first_token.startswith("@"):
            clean_first = first_token.lstrip("@")
            if re.match(r"^[a-zA-Z0-9_]{3,32}$", clean_first):
                tuname = clean_first
                target_text = parts[1] if len(parts) > 1 else ""
        else:
            m_user = re.search(r"@([a-zA-Z0-9_]{3,32})", target_text)
            if m_user:
                tuname = m_user.group(1)
                target_text = target_text.replace(m_user.group(0), " ").strip()
            else:
                m_num = re.search(r"\b(\d{5,15})\b", target_text)
                if m_num:
                    tid = int(m_num.group(1))
                    target_text = target_text.replace(m_num.group(0), " ").strip()

    if not tid and not tuname:
        guide = (
            "⚠️ <b>سامانه هوشمند مدیریت و بی‌صدا کردن (Mute):</b>\n\n"
            "پرومته از ۲ حالت کاربردی برای میوت کاربران پشتیبانی می‌کند:\n\n"
            "۱. 🔇 <b>میوت در گروه (Telegram Group Restrict):</b>\n"
            "سلب دسترسی ارسال هرگونه پیام، مدیا، استیکر و چت در سوپرگروه تلگرام.\n"
            "• <i>دستور:</i> ریپلای و ارسال <code>میوت در گروه 30m [علت]</code>\n"
            "• <i>نیازمندی:</i> ربات باید ادمین گروه با دسترسی Restrict Members باشد.\n\n"
            "۲. 🤖 <b>میوت از ربات (Prometheus Bot Mute):</b>\n"
            "عدم پاسخگویی مطلق ربات پرومته به پیام‌ها و پرسش‌های کاربر در همه جا.\n"
            "• <i>دستور:</i> ریپلای و ارسال <code>میوت از ربات 2h [علت]</code>\n\n"
            "⚡️ <b>میوت دوگانه / کامل (پیش‌فرض در گروه):</b>\n"
            "با ریپلای و ارسال <code>میوت 1h [علت]</code> یا <code>/mute 1h</code>، کاربر هم در گروه تلگرام و هم از پاسخگویی ربات بی‌صدا می‌شود.\n\n"
            "💡 <b>مدت زمان‌ها:</b> <code>10m</code>, <code>2h</code>, <code>1d</code> یا فارسی: <code>۳۰ دقیقه</code>, <code>۲ ساعت</code> (پیش‌فرض: ۶۰ دقیقه)"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return True

    if tid and is_admin(tid):
        await msg.reply_text("⛔️ امکان میوت کردن ادمین ارشد پرومته وجود ندارد.")
        return True

    if chat.type != ChatType.PRIVATE and tid and context and getattr(context, "bot", None):
        if await is_user_chat_admin(context.bot, chat.id, tid):
            await msg.reply_text("⛔️ امکان میوت کردن مدیران (ادمین‌های) این گروه وجود ندارد.")
            return True

    if tid and context and getattr(context, "bot", None) and tid == context.bot.id:
        await msg.reply_text(
            "⛔️ امکان میوت کردن خود ربات با این دستور وجود ندارد. برای بی‌صدا کردن فعالیت ربات در گروه از <code>/mutegroup</code> استفاده فرمایید.",
            parse_mode=ParseMode.HTML
        )
        return True

    # Detect scope from text if requested_scope is 'auto'
    scope_detected, target_text = detect_mute_scope(target_text)
    effective_scope = requested_scope if requested_scope != "auto" else scope_detected
    if effective_scope == "auto":
        effective_scope = "bot" if chat.type == ChatType.PRIVATE else "both"

    duration_sec, reason = extract_duration_and_reason(target_text)
    if not reason:
        reason = "دستور مستقیم ادمین"

    target_id = tid or 0
    bot_muted = False
    tg_restricted = False
    tg_notice = ""
    until_ts = time.time() + duration_sec

    # 1. Execute Bot Mute (if scope is 'bot' or 'both')
    if effective_scope in ("bot", "both"):
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
        bot_muted = True

    # 2. Execute Telegram Group Restrict (if scope is 'group' or 'both')
    if effective_scope in ("group", "both") and chat.type != ChatType.PRIVATE and target_id > 0:
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
            tg_restricted = True
            tg_notice = "\n⚡️ <i>دسترسی چت کاربر در گروه تلگرام مسدود شد.</i>"
        except BadRequest as e:
            err_msg = str(e).lower()
            if "not enough rights" in err_msg or "chat_admin_required" in err_msg or "can't restrict" in err_msg:
                tg_notice = "\nℹ️ <i>توجه: پرومته در این گروه دسترسی ادمین برای سلب ارسال پیام (Restrict Members) ندارد. برای میوت در گروه، ربات را ادمین کرده و دسترسی سلب دسترسی کاربران بدهید.</i>"
            else:
                tg_notice = f"\nℹ️ <i>وضعیت در تلگرام: {html.escape(str(e))}</i>"
        except Exception as e:
            logger.warning(f"Telegram restrict_chat_member failed: {e}")
            tg_notice = f"\nℹ️ <i>وضعیت در تلگرام: {html.escape(str(e))}</i>"

    dur_fa = format_duration_persian(duration_sec)
    disp = f"<code>{target_id}</code>" if target_id else ""
    if tuname:
        disp += f" (@{tuname})" if disp else f"@{tuname}"
    if tname:
        disp += f" ({html.escape(tname)})"

    if effective_scope == "group":
        title_hdr = "🔇 <b>کاربر در گروه تلگرام بی‌صدا شد:</b>"
        scope_desc = "فقط در گروه تلگرام (ارسال پیام مسدود شد)"
    elif effective_scope == "bot":
        title_hdr = "🤖 <b>کاربر از تعامل با ربات پرومته میوت شد:</b>"
        scope_desc = "فقط از ربات (عدم پاسخگویی ربات پرومته)"
    else:
        title_hdr = "🤐 <b>کاربر با موفقیت بی‌صدا (Mute کامل) شد:</b>"
        scope_desc = "میوت دوگانه (هم در گروه تلگرام و هم از پاسخگویی ربات)"

    confirm = (
        f"{title_hdr}\n\n"
        f"👤 <b>کاربر:</b> {disp}\n"
        f"🎯 <b>نوع میوت:</b> {scope_desc}\n"
        f"⏱ <b>مدت زمان:</b> {dur_fa}\n"
        f"📝 <b>علت:</b> {html.escape(reason)}\n"
        f"👮‍♂️ <b>ثبت‌کننده:</b> <code>{user.id}</code> ({html.escape(user.full_name)})\n"
        f"💾 <i>ذخیره در پایگاه داده با لغو خودکار پس از پایان زمان.</i>"
        f"{tg_notice}"
    )

    reply_markup = None
    if chat.type != ChatType.PRIVATE and target_id > 0:
        reply_markup = make_mute_keyboard(target_id, int(duration_sec), effective_scope)

    await msg.reply_text(confirm, parse_mode=ParseMode.HTML, reply_markup=reply_markup)
    return True


async def execute_admin_unmute(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    rem_text: str = "",
    requested_scope: str = "auto"
) -> bool:
    """Executes unmute in database (Bot Mute) and restores Telegram permissions."""
    msg = update.effective_message
    user = update.effective_user
    chat = update.effective_chat
    if not user or not msg or not chat:
        return False

    is_bot_adm = is_admin(user.id)
    is_grp_adm = False
    if chat.type != ChatType.PRIVATE and context and getattr(context, "bot", None):
        is_grp_adm = await is_user_chat_admin(context.bot, chat.id, user.id)

    if not is_bot_adm and not is_grp_adm:
        await msg.reply_text(
            "⛔️ <b>عدم دسترسی:</b> دستورات رفع سکوت (آنمیوت) صرفاً در اختیار مدیران این گروه و ادمین‌های پرومته می‌باشد.",
            parse_mode=ParseMode.HTML
        )
        return True

    tid = None
    tuname = None
    target_text = rem_text

    if msg.reply_to_message:
        ru = msg.reply_to_message.from_user
        if ru:
            tid = ru.id
            tuname = ru.username or ""
        elif msg.reply_to_message.sender_chat:
            tid = msg.reply_to_message.sender_chat.id
            tuname = msg.reply_to_message.sender_chat.username or ""
    elif target_text:
        parts = target_text.split()
        first_token = parts[0].strip()
        if first_token.lstrip("-+").isdigit():
            tid = int(first_token)
        elif first_token.startswith("@"):
            clean_first = first_token.lstrip("@")
            if re.match(r"^[a-zA-Z0-9_]{3,32}$", clean_first):
                tuname = clean_first
        else:
            m_user = re.search(r"@([a-zA-Z0-9_]{3,32})", target_text)
            if m_user:
                tuname = m_user.group(1)
            else:
                m_num = re.search(r"\b(\d{5,15})\b", target_text)
                if m_num:
                    tid = int(m_num.group(1))

    if not tid and not tuname:
        await msg.reply_text(
            "⚠️ <b>راهنمای رفع سکوت (آنمیوت):</b>\n\n"
            "• ریپلای روی پیام: <code>آنمیوت</code> یا <code>/unmute</code>\n"
            "• در گروه: <code>آنمیوت در گروه</code>\n"
            "• از ربات: <code>آنمیوت از ربات</code>\n"
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

    scope_detected, _ = detect_mute_scope(target_text)
    effective_scope = requested_scope if requested_scope != "auto" else scope_detected
    if effective_scope == "auto":
        effective_scope = "both"

    tg_status = ""
    # 1. Unmute in Telegram group (if requested)
    if effective_scope in ("group", "both") and chat.type != ChatType.PRIVATE and target_id > 0:
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
            tg_status = "\n⚡️ <i>محدودیت ارسال پیام در گروه تلگرام لغو گردید.</i>"
        except Exception as tg_err:
            logger.debug(f"Telegram restrict_chat_member unmute: {tg_err}")

    # 2. Unmute from Bot (if requested)
    if effective_scope in ("bot", "both"):
        await unmute_user(user_id=target_id, unmuted_by=user.id)

    disp = f"<code>{target_id}</code>" if target_id else ""
    if tuname:
        disp += f" (@{tuname})" if disp else f"@{tuname}"

    await msg.reply_text(
        f"🔊 <b>سکوت کاربر {disp} با موفقیت لغو شد (Unmuted).</b>\n"
        f"🤖 دسترسی و پاسخگویی ربات پرومته مجدداً برقرار گردید."
        f"{tg_status}",
        parse_mode=ParseMode.HTML
    )
    return True


async def moderation_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles inline button clicks for adjusting mute scope or unmuting."""
    query = update.callback_query
    if not query or not query.data:
        return
    user = query.from_user
    chat = query.message.chat if query.message else None
    if not user or not chat:
        return

    is_auth = is_admin(user.id) or await is_user_chat_admin(context.bot, chat.id, user.id)
    if not is_auth:
        await query.answer("⛔️ این تنظیمات صرفاً مخصوص مدیران گروه و ادمین‌های پرومته است.", show_alert=True)
        return

    parts = query.data.split(":")
    # mod:mute:scope:target_id:duration_sec OR mod:unmute:scope:target_id:duration_sec
    if len(parts) < 4:
        return

    action = parts[1]
    scope = parts[2]
    try:
        target_id = int(parts[3])
    except ValueError:
        return
    duration_sec = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 3600

    if action == "unmute":
        await unmute_user(user_id=target_id, unmuted_by=user.id)
        if chat.type != ChatType.PRIVATE and target_id > 0:
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
            except Exception as e:
                logger.debug(f"Unmute callback Telegram restrict error: {e}")

        await query.answer("✅ سکوت کاربر با موفقیت لغو شد.", show_alert=False)
        try:
            await query.edit_message_text(
                f"🔊 <b>سکوت کاربر <code>{target_id}</code> توسط {html.escape(user.full_name)} به طور کامل لغو شد (Unmuted).</b>\n\n"
                f"✅ هم دسترسی در گروه تلگرام فعال شد و هم پاسخگویی ربات پرومته برقرار گردید.",
                parse_mode=ParseMode.HTML
            )
        except Exception:
            pass
        return

    if action == "mute":
        until_ts = time.time() + duration_sec
        until_dt = datetime.fromtimestamp(until_ts, tz=timezone.utc)
        dur_fa = format_duration_persian(duration_sec)

        if scope == "group":
            # Lift bot mute, enforce group restrict
            await unmute_user(user_id=target_id, unmuted_by=user.id)
            try:
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
            except Exception as e:
                logger.warning(f"Callback group restrict failed: {e}")

            await query.answer("✅ وضعیت به «فقط میوت در گروه» تغییر یافت.", show_alert=False)
            new_kb = make_mute_keyboard(target_id, duration_sec, "group")
            try:
                msg_text = (
                    f"🔇 <b>وضعیت میوت کاربر <code>{target_id}</code>:</b>\n\n"
                    f"🎯 <b>نوع:</b> فقط در گروه تلگرام (ارسال پیام مسدود)\n"
                    f"🤖 <b>ربات پرومته:</b> آزاد (کاربر می‌تواند با پرومته گفتگو کند)\n"
                    f"⏱ <b>مدت زمان:</b> {dur_fa}\n"
                    f"👮‍♂️ <b>تنظیم‌کننده:</b> {html.escape(user.full_name)}"
                )
                await query.edit_message_text(msg_text, parse_mode=ParseMode.HTML, reply_markup=new_kb)
            except Exception:
                pass

        elif scope == "bot":
            # Enforce bot mute, restore group chat
            await mute_user(
                user_id=target_id,
                duration_sec=duration_sec,
                username="",
                first_name="",
                reason="تنظیم شده از طریق دکمه‌های شیشه‌ای ادمین",
                muted_by=user.id,
                chat_id=chat.id,
                chat_title=chat.title or ""
            )
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
            except Exception:
                pass

            await query.answer("✅ وضعیت به «فقط میوت از ربات» تغییر یافت.", show_alert=False)
            new_kb = make_mute_keyboard(target_id, duration_sec, "bot")
            try:
                msg_text = (
                    f"🤖 <b>وضعیت میوت کاربر <code>{target_id}</code>:</b>\n\n"
                    f"🎯 <b>نوع:</b> فقط از ربات پرومته (عدم پاسخگویی ربات)\n"
                    f"👥 <b>گروه تلگرام:</b> آزاد (کاربر می‌تواند در گروه پیام بدهد)\n"
                    f"⏱ <b>مدت زمان:</b> {dur_fa}\n"
                    f"👮‍♂️ <b>تنظیم‌کننده:</b> {html.escape(user.full_name)}"
                )
                await query.edit_message_text(msg_text, parse_mode=ParseMode.HTML, reply_markup=new_kb)
            except Exception:
                pass

        elif scope == "both":
            # Enforce both
            await mute_user(
                user_id=target_id,
                duration_sec=duration_sec,
                username="",
                first_name="",
                reason="تنظیم شده از طریق دکمه‌های شیشه‌ای ادمین",
                muted_by=user.id,
                chat_id=chat.id,
                chat_title=chat.title or ""
            )
            try:
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
            except Exception:
                pass

            await query.answer("✅ وضعیت به «میوت کامل (هردو)» تغییر یافت.", show_alert=False)
            new_kb = make_mute_keyboard(target_id, duration_sec, "both")
            try:
                msg_text = (
                    f"⚡️ <b>وضعیت میوت کاربر <code>{target_id}</code>:</b>\n\n"
                    f"🎯 <b>نوع:</b> میوت کامل (هم در گروه تلگرام و هم از پاسخگویی ربات)\n"
                    f"⏱ <b>مدت زمان:</b> {dur_fa}\n"
                    f"👮‍♂️ <b>تنظیم‌کننده:</b> {html.escape(user.full_name)}"
                )
                await query.edit_message_text(msg_text, parse_mode=ParseMode.HTML, reply_markup=new_kb)
            except Exception:
                pass



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
    if not user:
        return False

    is_bot_adm = is_admin(user.id)
    is_grp_adm = False
    if chat and chat.type != ChatType.PRIVATE and context and getattr(context, "bot", None):
        is_grp_adm = await is_user_chat_admin(context.bot, chat.id, user.id)

    if not is_bot_adm and not is_grp_adm:
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

    raw_bname = getattr(context.bot, "username", None) if context and getattr(context, "bot", None) else ""
    bot_username = str(raw_bname).lower() if isinstance(raw_bname, str) else ""
    if bot_username:
        t = re.sub(rf"@{re.escape(bot_username)}", "", t, flags=re.IGNORECASE).strip()

    for name in _PROMETHEUS_TRIGGER_NAMES:
        t = re.sub(rf"^(?:{re.escape(name)}[\s,:،-]*)+", "", t, flags=re.IGNORECASE).strip()
        t = re.sub(rf"[\s,:،-]+(?:{re.escape(name)})+$", "", t, flags=re.IGNORECASE).strip()

    # Normalize Prometheus command prefixes: /p_ban -> /ban, /pban -> /ban, etc.
    t = re.sub(r"^/(?:p_|pro_|prom_|prometheus_)", "/", t, flags=re.IGNORECASE)
    t = re.sub(r"^/(?:p|pro)(?=(?:ban|mute|groups|pending|approve|reject|set|get|del|admin|directives|rules))", "/", t, flags=re.IGNORECASE)

    if not t:
        return False

    # 0. Admin deletion command interception (Silent execution: 0 messages sent)
    if is_delete_request(t):
        msg = update.effective_message
        reply_to = msg.reply_to_message if msg else None
        if reply_to:
            try:
                await reply_to.delete()
            except Exception as e:
                logger.warning(f"Failed to delete replied message on admin command: {e}")
            try:
                await msg.delete()
            except Exception:
                pass
        return True

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

    # 12 & 13. User Mute & Unmute (Universal Natural Language, Slash Commands & Scope Detection)
    m_act, m_scope, m_rem = match_mute_command(t)
    if m_act == "unmute":
        return await execute_admin_unmute(update, context, m_rem, requested_scope=m_scope)
    elif m_act == "mute":
        return await execute_admin_mute(update, context, m_rem, requested_scope=m_scope)

    # Legacy regex fallbacks
    unmute_m = re.match(r"^(?:/)?(?:unmute|unsilence|آنمیوت|انمیوت|نمیوت|آن\s+میوت|رفع\s+میوت|لغو\s+میوت|رفع\s+سکوت|لغو\s+سکوت)(?:\s+(?:کن|ش\s+کن|ش))?(?:\s+(.*))?$", t, re.IGNORECASE)
    if unmute_m:
        return await execute_admin_unmute(update, context, unmute_m.group(1) or "")

    mute_m = re.match(r"^(?:/)?(?:mute|silence|میوت|سکوت|ساکت|خاموش|ببند)(?:\s+(?:کن|ش\s+کن|ش))?(?:\s+(.*))?$", t, re.IGNORECASE)
    if mute_m:
        return await execute_admin_mute(update, context, mute_m.group(1) or "")

    # Commands below (Directives, Custom Rules, Settings, Audit) require Bot Master Admin
    if not is_bot_adm:
        return False

    # 14. Register Permanent Admin Directive / Rule (Universal Natural Language & Slash Commands)
    dir_prefix = re.match(
        r"^(?:/)?(?:ثبت\s+(?:دستورات\s+ادمین|دستورات|دستور|قوانین\s+ادمین|قوانین|قانون)|دستور\s+(?:دائمی|جدید|ادمین)|قانون\s+(?:دائمی|جدید|ادمین)|directive|addrule|rule)\b(?:\s*[:=-])?\s*(.*)$",
        t,
        re.IGNORECASE | re.DOTALL
    )
    if dir_prefix:
        rest = (dir_prefix.group(1) or "").strip()
        if not rest:
            # Bare command sent without arguments: show helpful guide and active directives
            active_dirs = get_cached_admin_directives()
            guide_text = (
                "ℹ️ <b>راهنمای ثبت دستورات دائمی و قوانین ادمین:</b>\n\n"
                "برای ثبت دستور دائمی که رفتار پرومته را برای همیشه تغییر دهد، به یکی از روش‌های زیر عمل کنید:\n"
                "• <code>ثبت دستور: همیشه پاسخ‌ها کوتاه و خلاصه باشد</code>\n"
                "• <code>دستور دائمی style: پاسخ‌ها بسیار رسمی باشد</code>\n"
                "• <code>ثبت دستورات ادمین: اولویت با پاسخ‌های علمی است</code>\n"
                "• <code>/addrule format: markdown</code>\n\n"
                "🗑 برای حذف: <code>حذف دستور [عنوان/کلید]</code> یا <code>/delrule [key]</code>\n"
                "📋 برای مشاهده تمام دستورات: <code>دستورات ادمین</code> یا <code>/directives</code>"
            )
            if active_dirs:
                guide_text += f"\n\n📌 <b>دستورات فعال فعلی ({len(active_dirs)} مورد):</b>\n"
                for d in active_dirs:
                    guide_text += f"• <b>{html.escape(d.get('key_name', ''))}:</b> <code>{html.escape(d.get('data_value', ''))}</code>\n"
            await update.effective_message.reply_text(guide_text, parse_mode=ParseMode.HTML)
            return True

        # Check if there is an explicit key: value structure (e.g. "style: بسیار رسمی باشد")
        kv_match = re.match(r"^([a-zA-Z0-9_\-\u0600-\u06FF]{2,30})\s*[:=]\s*(.+)$", rest, re.DOTALL)
        if kv_match:
            k = kv_match.group(1).strip()
            v = kv_match.group(2).strip()
        else:
            k = ""
            v = rest

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

    # 14.1 Delete Directive / Setting (Singular & Plural Support)
    del_m = re.match(
        r"^(?:/)?(?:delsetting|del_setting|delrule|del_rule|deldirective|del_directive|(?:حذف|پاک\s*کردن)\s+(?:دستورات|دستور|تنظیمات|تنظیم|قوانین|قانون))\s+([a-zA-Z0-9_\-\u0600-\u06FF]+)$",
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

async def edited_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Synchronizes edited messages in Telegram directly into the persistent database.
    Performs UPSERT in-place via UNIQUE(chat_id, message_id) to update content and search index.
    """
    msg = update.edited_message
    chat = update.effective_chat
    user = update.effective_user
    if not msg or not chat or not user:
        return

    raw_text = msg.text or msg.caption or ""
    if not raw_text.strip():
        return

    media_type = "text"
    if msg.photo:
        media_type = "photo"
    elif msg.document:
        media_type = "document"
    elif msg.video:
        media_type = "video"
    elif msg.audio:
        media_type = "audio"
    elif msg.voice:
        media_type = "voice"
    elif msg.sticker:
        media_type = "sticker"

    reply_id = msg.reply_to_message.message_id if msg.reply_to_message else 0
    await database.persist_message(
        chat_id=chat.id,
        user_id=user.id,
        role="user",
        content=raw_text,
        username=user.username or "",
        full_name=user.full_name or "",
        message_id=msg.message_id,
        reply_to_message_id=reply_id,
        media_type=media_type,
        is_bot=1 if user.is_bot else 0
    )


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

    # Ingest ALL incoming messages asynchronously into database for rich search & summarization
    media_type = "text"
    if message.photo:
        media_type = "photo"
    elif message.document:
        media_type = "document"
    elif message.video:
        media_type = "video"
    elif message.audio:
        media_type = "audio"
    elif message.voice:
        media_type = "voice"
    elif message.sticker:
        media_type = "sticker"

    reply_id = message.reply_to_message.message_id if message.reply_to_message else 0
    asyncio.create_task(
        database.persist_message(
            chat_id=chat.id,
            user_id=user.id,
            role="user",
            content=raw_text,
            username=user.username or "",
            full_name=user.full_name or "",
            message_id=message.message_id,
            reply_to_message_id=reply_id,
            media_type=media_type,
            is_bot=1 if user.is_bot else 0
        )
    )

    # 1. Automated Anti-Jailbreak Defense & Immediate User Auto-Ban (Global check across all incoming text)
    # Evaluated immediately so attacks even without explicit bot mentions in groups are neutralized,
    # while educational questions about jailbreak are explicitly exempted and never banned.
    attack_name = detect_jailbreak_attempt(raw_text)
    if attack_name:
        if is_admin(user.id):
            logger.warning(f"Admin {user.id} triggered jailbreak pattern '{attack_name}'; skipping auto-ban.")
        else:
            logger.warning(
                f"Security Alert: Auto-banning user {user.id} (@{user.username}) for jailbreak attack: {attack_name}"
            )
            # 1. Permanently ban user in internal database & RAM cache
            await ban_user(
                user_id=user.id,
                username=user.username or "",
                name=user.full_name or "",
                reason=f"تلاش خودکار برای نفوذ/جیل‌بریک: {attack_name}",
                banned_by=0,
                chat_id=chat.id,
                chat_title=chat.title or "",
            )
            # 2. If in group, attempt to ban member from Telegram group
            if chat.type != ChatType.PRIVATE:
                try:
                    await context.bot.ban_chat_member(chat_id=chat.id, user_id=user.id)
                except Exception as be:
                    logger.debug(f"Could not ban member from Telegram chat: {be}")

            # 3. Delete the malicious attack message to sanitize the chat room
            try:
                await message.delete()
            except Exception as de:
                logger.debug(f"Could not delete malicious attack message: {de}")

            # 3. Notify chat
            user_mention = f"@{user.username}" if user.username else (user.full_name or f"کاربر {user.id}")
            ban_notice = (
                f"⛔️ <b>کاربر {html.escape(user_mention)} به دلیل تلاش برای نفوذ، تزریق پرامپت یا جیل‌بریک مسدود (Ban) شد.</b>\n\n"
                f"⚠️ <b>نوع اقدام:</b> {html.escape(attack_name)}\n"
                f"🚫 <i>دسترسی این کاربر به کلیه خدمات پرومته به صورت دائمی مسدود گردید.</i>"
            )
            await message.reply_text(ban_notice, parse_mode=ParseMode.HTML)

            # 4. Security Alert to Bot Administrators
            admin_alert = (
                "🚨 <b>هشدار امنیتی پرومته: انسداد خودکار (Auto-Ban)</b>\n\n"
                f"👤 <b>کاربر:</b> {html.escape(user.full_name or '')} ({user_mention})\n"
                f"🆔 <b>شناسه عددی:</b> <code>{user.id}</code>\n"
                f"💬 <b>محیط چت:</b> {html.escape(chat.title or 'خصوصی (PV)')} (<code>{chat.id}</code>)\n"
                f"⚠️ <b>نوع اقدام:</b> {html.escape(attack_name)}\n"
                f"📝 <b>متن پیام:</b>\n<code>{html.escape(raw_text[:300])}</code>\n\n"
                "🛡️ <i>کاربر بلافاصله در پایگاه داده و حافظه موقت مسدود گردید.</i>"
            )
            for aid in _ADMIN_IDS:
                try:
                    await context.bot.send_message(chat_id=aid, text=admin_alert, parse_mode=ParseMode.HTML)
                except Exception:
                    pass
            return

    # 2. Enforce Direct Bot Request Policy:
    # In groups, the bot strictly ignores any message that does not directly call or address it.
    is_direct, cleaned_prompt = is_direct_bot_request(update, context, raw_text)
    if not is_direct:
        # Strictly remain silent in groups for all other messages
        return

    # 2. Direct Interception of Admin & Moderation Commands (Persian & Slash)
    is_bot_adm = is_admin(user.id)
    is_grp_adm = False
    if chat.type != ChatType.PRIVATE and context and getattr(context, "bot", None):
        is_grp_adm = await is_user_chat_admin(context.bot, chat.id, user.id)

    if is_bot_adm or is_grp_adm:
        if await handle_admin_text_command(update, context, raw_text):
            return
    else:
        # Intercept unauthorized moderation attempts (mute, unmute, ban)
        m_act, _, _ = match_mute_command(cleaned_prompt)
        is_ban_cmd = bool(re.search(r"^(?:/)?(?:ban|block|بن|بلاک|اخراج|سیکتیر|دیپورت|مسدود|آنبن|انبن|unban)", cleaned_prompt, re.IGNORECASE))
        if m_act or is_ban_cmd:
            await message.reply_text(
                "⛔️ <b>عدم دسترسی:</b> دستورات مدیریت، مسدودسازی و میوت کاربران صرفاً در اختیار مدیران این گروه و ادمین‌های پرومته می‌باشد.",
                parse_mode=ParseMode.HTML
            )
            return

    # Fast-Path -1: Bot Message Deletion (Silent execution, <1ms, before typing animation, rate limit and LLM)
    raw_clean = (cleaned_prompt or raw_text).strip()
    if is_delete_request(raw_clean) or is_delete_request(raw_text.strip()):
        reply_to = message.reply_to_message
        if reply_to:
            is_from_bot = (
                (bot_id and reply_to.from_user and reply_to.from_user.id == bot_id)
                or (reply_to.from_user and reply_to.from_user.is_bot and bot_username and (reply_to.from_user.username or "").lower() == bot_username)
                or (reply_to.from_user and reply_to.from_user.is_bot and not bot_username)
            )
            if is_from_bot or (is_bot_adm or is_grp_adm):
                try:
                    await reply_to.delete()
                except Exception as e:
                    logger.warning(f"Failed to delete replied message: {e}")
                try:
                    await message.delete()
                except Exception:
                    pass
                return
            else:
                return
        else:
            if is_private and not (is_bot_adm or is_grp_adm):
                await message.reply_text("ℹ️ برای حذف پیام پرومته، لطفاً روی پیام مورد نظر ریپلای کرده و کلمه «حذف» یا /del را ارسال نمایید.")
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
    is_direct_fwd = bool(
        getattr(message, "forward_origin", None)
        or getattr(message, "forward_from", None)
        or getattr(message, "forward_from_chat", None)
    )
    if is_id_request(cleaned_lower) or (is_private and is_direct_fwd and (not cleaned_prompt or cleaned_lower in ["", "این کیه", "کیه", "کیه این", "who is this", "id", "info", "آیدی", "ایدی", "شناسه"])):
        report = format_id_report(update)
        await message.reply_text(report, parse_mode=ParseMode.HTML)
        return

    # Fast-Path -2.5: Group Message Search in Database (FTS5 BM25) (<5ms)
    is_search, search_q = parse_search_request(cleaned_prompt)
    if is_search and search_q:
        t0 = time.perf_counter()
        search_res = await search_group_messages(
            chat_id=chat.id,
            query=search_q,
            limit=10,
            chat_title=chat.title or ""
        )
        record_chat_latency(chat.id, time.perf_counter() - t0, "جستجوی پیشرفته در دیتابیس FTS5")
        await message.reply_text(search_res, parse_mode=ParseMode.HTML)
        return

    # Fast-Path -2.2: Multi-Subagent Conversation Summarization (Up to 3,000 Messages)
    is_sum, sum_count = parse_summary_request(cleaned_lower)
    if is_sum:
        t0 = time.perf_counter()
        summary_rep = await summarize_group_messages(
            chat_id=chat.id,
            count=sum_count,
            chat_title=chat.title or ""
        )
        record_chat_latency(chat.id, time.perf_counter() - t0, f"ساب‌اجنت‌های خلاصه‌ساز گفتگو ({sum_count} پیام)")
        await message.reply_text(summary_rep, parse_mode=ParseMode.HTML)
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



    # Fast-Path 7: Safe Math Evaluation (<1ms)
    if is_math_query(cleaned_prompt):
        t0 = time.perf_counter()
        calc_expr = cleaned_prompt.replace("حساب کن", "").replace("محاسبه کن", "").strip()
        res = calculate_math(calc_expr)
        record_chat_latency(chat.id, time.perf_counter() - t0, "موتور محاسبات ریاضی پرومته (<1ms)")
        await _deliver_reply(message, res)
        return



    # Fast-Path 7.8: Multimodal Vision on Replied Photo or Album (Media Group)
    if message.reply_to_message and message.reply_to_message.photo:
        reply_mg = getattr(message.reply_to_message, "media_group_id", None)
        if not reply_mg:
            reply_mg = await resolve_media_group_id(
                chat_id=chat.id,
                message_id=message.reply_to_message.message_id,
                file_id=message.reply_to_message.photo[-1].file_id if message.reply_to_message.photo else None
            )

        typing_task = asyncio.create_task(_send_typing_loop(context.bot, chat.id))
        t0 = time.perf_counter()
        try:
            fids: List[str] = []
            if reply_mg:
                fids = await get_media_group_photos(chat.id, str(reply_mg))

            if not fids:
                fids = [message.reply_to_message.photo[-1].file_id]

            async def _dl_replied_photo(fid: str):
                try:
                    f = await context.bot.get_file(fid)
                    return bytes(await f.download_as_bytearray())
                except Exception as de:
                    logger.warning(f"Error downloading replied album photo {fid}: {de}")
                    return None

            downloaded = await asyncio.gather(*[_dl_replied_photo(fid) for fid in fids])
            photos_bytes_list = [b for b in downloaded if b]
            if not photos_bytes_list:
                reply_photo = message.reply_to_message.photo[-1]
                photo_file = await reply_photo.get_file()
                photos_bytes_list = [bytes(await photo_file.download_as_bytearray())]

            analysis = await analyze_image_with_vision(
                images=photos_bytes_list,
                prompt=cleaned_prompt,
                chat_id=chat.id,
            )
            if is_reconstruction_query(cleaned_prompt):
                preview_url = build_reconstruction_image_url(cleaned_prompt)
                analysis += f"\n\n🎨 <b>پیش‌نمایش شبیه‌سازی مجدد تصویر:</b>\n<a href=\"{preview_url}\">مشاهده پیش‌نمایش تصویر بازسازی‌شده</a>"

            elapsed = time.perf_counter() - t0
            engine_label = f"موتور بینایی چندوجهی پرومته ({len(photos_bytes_list)} تصویر)"
            record_chat_latency(chat.id, elapsed, engine_label)
            header = f"📸 <b>تحلیل جامع آلبوم تصاویر ({len(photos_bytes_list)} تصویر):</b>\n\n" if len(photos_bytes_list) > 1 else ""
            await _deliver_reply(message, header + analysis)
            return
        except Exception as e:
            logger.error(f"Error processing replied photo vision: {e}")
        finally:
            typing_task.cancel()
            try:
                await typing_task
            except asyncio.CancelledError:
                pass

    # Fast-Path 7.85: VirusTotal Threat Scan Query (<500ms)
    is_vt, vt_target = is_virustotal_request(cleaned_prompt)
    if is_vt:
        t0 = time.perf_counter()
        if message.reply_to_message and message.reply_to_message.document:
            r_doc = message.reply_to_message.document
            status_m = await message.reply_text("🔍 در حال دریافت فایل و ارسال به VirusTotal...")
            try:
                tg_f = await r_doc.get_file()
                b = await tg_f.download_as_bytearray()
                vt_res = await upload_and_scan_file(bytes(b), r_doc.file_name or "file.bin")
                record_chat_latency(chat.id, time.perf_counter() - t0, "اسکن فایل در VirusTotal")
                rep = format_virustotal_report(vt_res)
                await status_m.edit_text(rep, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
                return
            except Exception as e:
                await status_m.edit_text(f"❌ خطا در اسکن فایل: {e}")
                return

        if not vt_target and message.reply_to_message:
            r_txt = message.reply_to_message.text or message.reply_to_message.caption or ""
            h_or_u = re.search(r"([a-fA-F0-9]{64}|[a-fA-F0-9]{32}|https?://\S+|[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/\S*)?)", r_txt)
            if h_or_u:
                vt_target = h_or_u.group(1)

        if vt_target:
            clean_tgt = vt_target.strip()
            if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", clean_tgt):
                res = await scan_file_hash(clean_tgt)
                record_chat_latency(chat.id, time.perf_counter() - t0, f"استعلام هش VirusTotal ({clean_tgt[:8]})")
            else:
                res = await scan_url_or_domain(clean_tgt)
                record_chat_latency(chat.id, time.perf_counter() - t0, f"اسکن آدرس در VirusTotal ({clean_tgt[:20]})")
            rep = format_virustotal_report(res)
            await _deliver_reply(message, rep)
            return

    # Fast-Path 7.86: Direct File Generation Request (<100ms)
    reply_text_for_file = (
        (message.reply_to_message.text or message.reply_to_message.caption or "")
        if message.reply_to_message else None
    )
    file_intent = detect_file_creation_intent(cleaned_prompt, reply_text=reply_text_for_file)
    if file_intent:
        fname, fcontent = file_intent
        t0 = time.perf_counter()
        try:
            buf, final_name = create_document_file(fname, fcontent)
            elapsed = time.perf_counter() - t0
            record_chat_latency(chat.id, elapsed, f"تولید فایل درخواستی ({final_name})")
            size_kb = len(buf.getvalue()) / 1024
            caption = (
                f"📄 <b>فایل تولید شده توسط پرومته:</b> <code>{html.escape(final_name)}</code>\n"
                f"💾 حجم: <code>{size_kb:.1f} KB</code>"
            )
            await message.reply_document(
                document=buf,
                filename=final_name,
                caption=caption,
                parse_mode=ParseMode.HTML
            )
            return
        except Exception as e:
            logger.error(f"Error in file creation fast-path: {e}")



    # Process all queries through autonomous agent brain (zero typing animations)
    replied_context = extract_replied_message_context(message)
    if replied_context:
        agent_prompt = f"{replied_context}\n\nدستور یا پرسش کاربر درباره پیام بالا:\n{cleaned_prompt}"
    else:
        forward_context = extract_forward_message_context(message)
        if forward_context:
            agent_prompt = f"{forward_context}\n\nدستور یا پرسش کاربر درباره پیام فوروارد شده:\n{cleaned_prompt}"
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
    """Displays all live, active groups verified in real time directly from Telegram."""
    user = update.effective_user
    msg = update.effective_message
    if not user or not is_admin(user.id):
        if msg:
            await msg.reply_text("⛔️ دسترسی غیرمجاز. این دستور فقط مخصوص مدیران ربات است.")
        return

    # Send temporary progress notice
    status_msg = None
    if msg:
        try:
            status_msg = await msg.reply_text(
                "🔄 <i>در حال استعلام زنده وضعیت گروه‌ها از سرورهای تلگرام...</i>",
                parse_mode=ParseMode.HTML
            )
        except Exception:
            pass

    live_groups = await get_live_telegram_groups(context.bot)
    banned_groups = {int(g["chat_id"]): g for g in await get_banned_groups_list() if g.get("chat_id")}
    muted_groups = {int(g["chat_id"]): g for g in await get_muted_groups_list() if g.get("chat_id")}

    if not live_groups:
        no_groups_text = (
            "📋 <b>فهرست گروه‌های زنده پرومته:</b>\n\n"
            "<i>در حال حاضر پرومته در هیچ گروه تلگرامی زنده‌ای عضو نیست یا ربات از گروه‌ها خارج شده است.</i>\n\n"
            "💡 <b>راهنمای اتصال به گروه جدید:</b>\n"
            "۱. پرومته (@AMZprometheusopenbot) را به گروه تلگرامی خود اضافه فرمایید.\n"
            "۲. جهت عملکرد بهینه و مدیریت کامل، به ربات دسترسی ادمین بدهید.\n"
            "۳. به محض ورود یا ارسال اولین پیام، گروه به صورت خودکار شناسایی شده و در این لیست قرار می‌گیرد."
        )
        if status_msg:
            await status_msg.edit_text(no_groups_text, parse_mode=ParseMode.HTML)
        elif msg:
            await msg.reply_text(no_groups_text, parse_mode=ParseMode.HTML)
        return

    lines = [f"👥 <b>فهرست گروه‌های زنده و فعال پرومته ({len(live_groups)} گروه):</b>\n"]

    for idx, g in enumerate(live_groups, 1):
        cid = int(g.get("chat_id") or 0)
        title = g.get("title") or "گروه بدون نام"
        uname = f"@{g.get('username')}" if g.get("username") else ""
        m_count = g.get("member_count") or 0
        is_admin_in_group = g.get("is_admin", False)
        st = g.get("status", "approved")

        role_badge = "⭐️ مدیر (Admin)" if is_admin_in_group else "🟢 عضو عادی (Member)"

        if cid in banned_groups or st == "banned":
            st_text = "🚫 مسدود (Banned)"
            quick_act = f"دستور رفع بن: <code>/unbangroup {cid}</code>"
        elif cid in muted_groups:
            rem = muted_groups[cid].get("remaining_seconds", 0)
            st_text = f"🔇 میوت ({format_duration_persian(rem)})" if rem > 0 else "🔇 میوت نامحدود"
            quick_act = f"دستور رفع سکوت: <code>/unmutegroup {cid}</code>"
        elif st in ("approved", "active"):
            st_text = "✅ تایید شده و فعال (Active)"
            quick_act = f"بن: <code>/bangroup {cid}</code> | میوت: <code>/mutegroup {cid} 1h</code>"
        elif st == "pending":
            st_text = "⏳ در انتظار تایید ادمین (Pending)"
            quick_act = f"تایید: <code>/approvegroup {cid}</code> | رد: <code>/rejectgroup {cid}</code>"
        else:
            st_text = f"ℹ️ {st}"
            quick_act = f"مدیریت: <code>/bangroup {cid}</code>"

        members_info = f" | 👥 {m_count:,} عضو" if m_count > 0 else ""
        uname_info = f" ({html.escape(uname)})" if uname else ""

        lines.append(
            f"{idx}. <b>{html.escape(title)}</b>{uname_info}{members_info}\n"
            f"   🆔 شناسه عددی: <code>{cid}</code>\n"
            f"   🤖 وضعیت ربات: {role_badge}\n"
            f"   📊 وضعیت پرومته: {st_text}\n"
            f"   ⚙️ {quick_act}\n"
        )

    lines.append("⚡ <i>استعلام زنده وضعیت ربات از سرورهای تلگرام</i>")
    text = "\n".join(lines)

    chunks = split_message(text, max_len=3800)
    if status_msg:
        await status_msg.edit_text(chunks[0], parse_mode=ParseMode.HTML)
        for ch in chunks[1:]:
            if msg:
                await msg.reply_text(ch, parse_mode=ParseMode.HTML)
    elif msg:
        for ch in chunks:
            await msg.reply_text(ch, parse_mode=ParseMode.HTML)


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
            text=(
                "⚡️ <b>پرومته فعال شد!</b>\n\n"
                "با دستور مستقیم ادمین ارشد، سیستم شناسایی و هوش مصنوعی پرومته در این گروه رسماً تایید و فعال گردید.\n"
                "هم‌اکنون تمامی قابلیت‌های OSINT، کاوش عمیق وب، تحلیل لایه‌ها و پاسخگویی هوشمند در دسترس شماست.\n\n"
                "▫️ جهت مشاهده راهنما: <code>/phelp</code> یا منشن نام ربات"
            ),
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
        await database.init_database()
        logger.info("Prometheus storage & SQLite FTS5 database initialized in post_init.")
        await init_moderation_engine()
        logger.info("Prometheus moderation engine loaded in post_init.")
        await init_permissions_engine()
        logger.info("Prometheus granular permissions engine loaded in post_init.")

    app = (
        ApplicationBuilder()
        .token(token)
        .request(request)
        .post_init(post_init)
        .concurrent_updates(True)
        .build()
    )

    def guard(handler_func, is_admin_cmd: bool = False, is_cmd: bool = True):
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
            if not await _check_moderation_guard(update, context, is_admin_cmd=is_admin_cmd):
                return
            if is_cmd and not is_command_addressed_to_bot(update, context, is_admin_cmd=is_admin_cmd):
                return
            return await handler_func(update, context)
        return wrapper

    # Core OSINT Commands & Aliases (Personalized with p / p_ / pro / pro_ prefixes)
    app.add_handler(CommandHandler(make_bot_commands(["start"]), guard(start_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["help"]), guard(help_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["agent", "research", "hermes", "osintagent"]), guard(agent_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["fast", "speed"]), guard(fast_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["mode", "setting", "settings"]), guard(mode_command, is_cmd=True)))
    app.add_handler(CallbackQueryHandler(guard(mode_callback, is_cmd=False), pattern=r"^setmode_"))

    # OSINT Reconnaissance Suite
    app.add_handler(CommandHandler(make_bot_commands(["osint", "search", "web", "find", "jostojoo"]), guard(osint_search_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["crawl", "scrape", "layers", "read", "url"]), guard(crawl_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["dork", "dorks", "googledork"]), guard(dork_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["github", "git", "gh"]), guard(github_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["linkedin", "in"]), guard(linkedin_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["usercheck", "username", "user"]), guard(usercheck_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["dns", "ns", "mx"]), guard(dns_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["subdomains", "subdomain", "subs", "crtsh"]), guard(subdomains_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["ip", "geo", "asn"]), guard(ip_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["email", "mail"]), guard(email_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["phone", "tel", "mobile"]), guard(phone_command, is_cmd=True)))

    # Threat Intelligence & Utilities
    app.add_handler(CommandHandler(make_bot_commands(["scan", "vt", "virustotal", "antivirus"]), guard(scan_command, is_cmd=True)))
    app.add_handler(CallbackQueryHandler(virustotal_callback, pattern=r"^vt_scan:"))
    app.add_handler(CommandHandler(make_bot_commands(["time", "saat"]), guard(time_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["calc", "hesab"]), guard(calc_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["clear", "clean"]), guard(clear_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["id", "myid", "info", "chatid", "whoami"]), guard(id_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["delete", "del", "pak", "hazf", "remove"]), guard(delete_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["ping", "status"]), guard(ping_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["summarize", "recap", "summary", "kholase"]), guard(summarize_command, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["file", "createfile", "makefile"]), guard(file_command, is_cmd=True)))


    # Admin Governance & Moderation Commands (Personalized with p / p_ / pro / pro_ prefixes)
    app.add_handler(CommandHandler(make_bot_commands(["ban", "block"]), guard(ban_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["unban", "unblock"]), guard(unban_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["mute", "silence"]), guard(mute_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["unmute", "unsilence"]), guard(unmute_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["bangroup", "ban_group"]), guard(bangroup_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["unbangroup", "unban_group"]), guard(unbangroup_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["mutegroup", "mutebot"]), guard(mutegroup_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["unmutegroup", "unmutebot"]), guard(unmutegroup_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["banlist", "bans"]), guard(banlist_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["mutelist", "mutes"]), guard(mutelist_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["groups", "grouplist", "listgroups", "allgroups"]), guard(grouplist_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["pendinggroups", "pending_groups"]), guard(pendinggroups_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["approvegroup", "approve_group", "addgroup", "add_group"]), guard(approvegroup_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["rejectgroup", "reject_group"]), guard(rejectgroup_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["set", "set_setting"]), guard(set_setting_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["get", "get_setting"]), guard(get_setting_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["delsetting", "del_setting", "delrule", "del_rule", "deldirective"]), guard(del_setting_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["adminsettings", "customdata", "directives", "rules"]), guard(settings_command, is_admin_cmd=True, is_cmd=True)))
    app.add_handler(CommandHandler(make_bot_commands(["adminlogs", "audit"]), guard(adminlogs_command, is_admin_cmd=True, is_cmd=True)))

    # Callback Query Handlers for Group Approvals
    app.add_handler(CallbackQueryHandler(group_approval_callback, pattern=r"^grp_(app|rej):"))

    # Callback Query Handlers for Moderation Mute/Unmute Scope Toggling
    app.add_handler(CallbackQueryHandler(moderation_callback_handler, pattern=r"^mod:"))

    # Chat Member Updates (Bot added/removed in groups)
    app.add_handler(ChatMemberHandler(chat_member_update_handler, ChatMemberHandler.MY_CHAT_MEMBER))

    # Multimodal photo handler
    app.add_handler(MessageHandler(filters.PHOTO, guard(photo_handler, is_cmd=False)))

    # Incoming document / file handler (PDF, Word, Excel, CSV, Code, Text, Archives)
    app.add_handler(MessageHandler(filters.Document.ALL, guard(document_handler, is_cmd=False)))

    # Synchronize edited messages into database
    app.add_handler(
        MessageHandler(
            filters.UpdateType.EDITED_MESSAGE,
            guard(edited_message_handler, is_cmd=False)
        )
    )

    # All text messages (with silence-by-default logic)
    app.add_handler(
        MessageHandler(
            filters.TEXT | filters.CAPTION,
            guard(message_handler, is_cmd=False)
        )
    )

    return app


if __name__ == "__main__":
    logger.info("Starting Prometheus Telegram Agent Bot...")
    app = build_application()
    app.run_polling(drop_pending_updates=False, allowed_updates=Update.ALL_TYPES)
