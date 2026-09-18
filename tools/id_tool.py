"""
Supercharged Telegram Numeric ID & Diagnostics Extraction Tool:
Extracts user ID, chat ID, message ID, replied message ID, forward origins,
and media File IDs with 1-tap copyable HTML code blocks.
Fully supports Telegram Bot API 7.0+ MessageOrigin types and legacy attributes.
"""

import re
import html
from typing import Optional, Dict, Any
from telegram import Update, Message, User, Chat
from telegram.constants import ChatType

_ID_EXCLUSIONS = (
    # E-commerce and shopping
    "کالا", "محصول", "دیجیکالا", "دیجی کالا", "سفارش", "تراکنش", "خرید",
    # External social platforms / sites
    "اینستاگرام", "توییتر", "یوتیوب", "فیسبوک", "تیک‌تاک", "گیت‌هاب", "github", "instagram", "twitter",
    # Conversational & analytical question keywords (should be routed to AI reasoning / search)
    "چرا باید", "چرا", "هدف چیه", "هدف از", "دلیل", "علت",
    "سرچ بکن", "سرچ کن", "سرچ", "جستجو بکن", "جستجو کن", "جستجو", "google", "search",
    "تحلیل", "بررسی", "توضیح", "مقایسه", "نظرت", "دیدگاه", "فکر می‌کنی",
    "لو بده", "لو بره", "لو دادن", "افشا", "نشت",
    "امنیت", "آسیب‌پذیری", "باگ", "نفوذ", "هک",
    "میرور بات", "میرور", "ربات تلگرامی", "اسکریپت", "پایتون",
    "دیتایی", "دیتا", "پایگاه داده", "دیتابیس"
)


def is_id_request(text: str) -> bool:
    """
    Matches natural Persian and English queries asking for Telegram numeric IDs,
    user/chat info, whois diagnostics, or sender identification.
    Strictly prevents false positives on conversational, analytical, or search inquiries.
    """
    if not text:
        return False
    t = text.lower().strip()
    t = t.replace("ي", "ی").replace("ك", "ک")

    # 1. Exact command or short keyword triggers
    exact_triggers = {
        "/id", "/myid", "/info", "/chatid", "/whoami", "/whois", "/userinfo",
        "id", "whoami", "whois", "userinfo",
        "آیدی", "ایدی", "شناسه", "آیدی؟", "ایدی؟", "شناسه؟",
        "آیدی من", "ایدی من", "شناسه من", "آیدی عددی", "شناسه عددی",
        "آیدی این", "ایدی این", "آیدی طرف", "ایدی طرف", "آیدیش", "ایدیش",
        "آیدی فرستنده", "ایدی فرستنده", "شناسه فرستنده", "آیدی کاربر", "ایدی کاربر",
        "این کیه", "کیه این", "کیه؟", "این کیه؟", "who is this"
    }
    if t in exact_triggers:
        return True

    # 2. Slash command with optional bot username or args (e.g. /id@bot, /info)
    if re.match(r"^/(?:id|myid|info|chatid|whoami|whois|userinfo)(?:@\w+)?(?:\s+.*)?$", t):
        return True

    # Guard: Natural conversational ID requests are never long paragraphs or complex essays.
    # Telegram ID commands are concise (<= 12 words and <= 85 characters).
    words = t.split()
    if len(words) > 12 or len(t) > 85:
        return False

    # Exclude e-commerce, external sites, and analytical questions
    if any(ex in t for ex in _ID_EXCLUSIONS):
        return False

    # 3. Intent match: contains explicit Telegram ID / identity keyword
    # Note: "اطلاعات" is generic Persian for information/data and must NOT match Telegram IDs.
    id_root = r"(?:\b(?:آیدی|ایدی|user\s*id|\bid\b|whois|userinfo)\b|شناسه\s*عددی|آیدی\s*عددی|مشخصات\s+(?:من|کاربر|کاربری|اکانت|حساب|فرستنده|چت|گروه|کانال|این|طرف))"
    if not re.search(id_root, t):
        # Also check compound "شناسه" with target or action
        if not (re.search(r"\bشناسه\b", t) and re.search(r"(?:عددی|این|طرف|کاربر|فرستنده|پیام|چت|من)", t)):
            return False

    # Action / Extraction verbs
    actions = r"(?:استخراج|بده|بگو|چیه|چند\s*است|چنده|درار|پیدا\s*کن|نمایش|بفرست|کپی|اعلام\s*کن|ارسال\s*کن)"
    # Target entities
    targets = r"(?:عددی|این|اون|طرف|یک\s*نفر|کاربر|فرستنده|ایشون|پیام|چت|گروه|کانال|من|ما|اکانت|حساب)"

    if re.search(actions, t) or re.search(targets, t):
        return True

    return False


def _format_user_name(u: Any) -> str:
    """Safely extracts and formats a user's full name, handling MagicMock objects in tests."""
    if not u:
        return "کاربر"
    fn = getattr(u, "first_name", "") or ""
    ln = getattr(u, "last_name", "") or ""
    if u.__class__.__name__ == "MagicMock":
        fn_str = str(fn) if isinstance(fn, str) else ""
        ln_str = str(ln) if isinstance(ln, str) else ""
        full = f"{fn_str} {ln_str}".strip()
        return full or "کاربر"
    if isinstance(getattr(u, "full_name", None), str) and u.full_name:
        return u.full_name
    full = f"{fn} {ln}".strip()
    return full or "کاربر"


def _extract_origin_info(origin: Any, forward_from: Optional[User] = None, forward_from_chat: Optional[Chat] = None) -> Optional[Dict[str, Any]]:
    """
    Normalizes Telegram Bot API 7.0+ MessageOrigin objects and legacy forward attributes.
    """
    if origin:
        otype = getattr(origin, "type", None)
        if otype == "user" and getattr(origin, "sender_user", None):
            u = origin.sender_user
            if isinstance(getattr(u, "id", None), int):
                name = _format_user_name(u)
                uname = getattr(u, "username", None)
                return {
                    "type": "user",
                    "id": u.id,
                    "name": name,
                    "username": f"@{uname}" if isinstance(uname, str) and uname else "ندارد",
                    "is_bot": bool(getattr(u, "is_bot", False))
                }
        elif otype in ("chat", "channel"):
            c = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
            if c and isinstance(getattr(c, "id", None), int):
                title = getattr(c, "title", None) or ("کانال" if otype == "channel" else "گروه")
                uname = getattr(c, "username", None)
                return {
                    "type": otype,
                    "id": c.id,
                    "title": str(title),
                    "username": f"@{uname}" if isinstance(uname, str) and uname else "ندارد"
                }
        elif otype == "hidden_user":
            hname = getattr(origin, "sender_user_name", None)
            if isinstance(hname, str):
                return {
                    "type": "hidden_user",
                    "name": str(hname)
                }

    if forward_from and isinstance(getattr(forward_from, "id", None), int):
        u = forward_from
        name = _format_user_name(u)
        uname = getattr(u, "username", None)
        return {
            "type": "user",
            "id": u.id,
            "name": name,
            "username": f"@{uname}" if isinstance(uname, str) and uname else "ندارد",
            "is_bot": bool(getattr(u, "is_bot", False))
        }

    if forward_from_chat and isinstance(getattr(forward_from_chat, "id", None), int):
        c = forward_from_chat
        title = getattr(c, "title", None) or "کانال/گروه"
        uname = getattr(c, "username", None)
        return {
            "type": "channel",
            "id": c.id,
            "title": str(title),
            "username": f"@{uname}" if isinstance(uname, str) and uname else "ندارد"
        }

    return None


def format_id_report(update: Update) -> str:
    """Generates a comprehensive diagnostic report of all available Telegram IDs."""
    message = update.effective_message
    user = update.effective_user
    chat = update.effective_chat

    sections = []
    reply = message.reply_to_message if (message and getattr(message, "reply_to_message", None)) else None

    # Priority 1: Replied Target Details (Target User / Channel / Forward / Media)
    reply_user = getattr(reply, "from_user", None) if reply else None
    reply_user_has_id = bool(reply_user and isinstance(getattr(reply_user, "id", None), int))
    reply_chat = getattr(reply, "sender_chat", None) if reply else None
    reply_chat_has_id = bool(reply_chat and isinstance(getattr(reply_chat, "id", None), int))
    reply_has_msg_id = bool(reply and isinstance(getattr(reply, "message_id", None), int))

    has_target = reply and (reply_user_has_id or reply_chat_has_id or reply_has_msg_id)

    if has_target:
        r_parts = ["🎯 <b>مشخصات کاربر و پیام هدف (Target Info):</b>"]
        r_user = getattr(reply, "from_user", None)
        if r_user and isinstance(getattr(r_user, "id", None), int):
            rn = _format_user_name(r_user)
            ru_handle = f"@{r_user.username}" if isinstance(getattr(r_user, "username", None), str) and r_user.username else "ندارد"
            r_bot = "🤖 ربات" if getattr(r_user, "is_bot", False) else "👤 کاربر حقیقی"
            r_parts.append(f"• 🆔 <b>آیدی عددی کاربر (User ID):</b> <code>{r_user.id}</code>")
            r_parts.append(f"• 🏷 <b>نام نمایشی:</b> {html.escape(rn)} ({r_bot})")
            r_parts.append(f"• 🔗 <b>نام کاربری:</b> {ru_handle}")
        elif getattr(reply, "sender_chat", None) and isinstance(getattr(reply.sender_chat, "id", None), int):
            sc = reply.sender_chat
            sc_type = "📢 کانال" if getattr(sc, "type", None) == ChatType.CHANNEL else "👥 گروه"
            r_parts.append(f"• 🆔 <b>آیدی عددی مبدا ({sc_type}):</b> <code>{sc.id}</code>")
            r_parts.append(f"• 🏷 <b>عنوان:</b> {html.escape(str(getattr(sc, 'title', '') or ''))}")
            if getattr(sc, "username", None):
                r_parts.append(f"• 🔗 <b>نام کاربری:</b> @{sc.username}")

        if getattr(reply, "message_id", None) and isinstance(reply.message_id, int):
            r_parts.append(f"• ✉️ <b>شماره پیام هدف:</b> <code>{reply.message_id}</code>")

        # Check Forward Origin of replied message
        finfo = _extract_origin_info(
            getattr(reply, "forward_origin", None),
            getattr(reply, "forward_from", None),
            getattr(reply, "forward_from_chat", None)
        )
        if finfo:
            if finfo["type"] == "user":
                r_parts.append(f"• ↪️ <b>فوروارد شده از کاربر اصلی:</b> {html.escape(finfo['name'])} ({finfo['username']})")
                r_parts.append(f"• 🆔 <b>آیدی عددی فرستنده اصلی:</b> <code>{finfo['id']}</code>")
            elif finfo["type"] in ("chat", "channel"):
                ctype = "کانال" if finfo["type"] == "channel" else "گروه"
                r_parts.append(f"• 📢 <b>فوروارد شده از {ctype} مبدا:</b> {html.escape(finfo.get('title', ''))} ({finfo['username']})")
                r_parts.append(f"• 🆔 <b>آیدی عددی مبدا فوروارد:</b> <code>{finfo['id']}</code>")
            elif finfo["type"] == "hidden_user":
                r_parts.append(f"• 🔒 <b>حریم خصوصی فوروارد:</b> کاربر ({html.escape(finfo['name'])}) در تنظیمات تلگرام لینک حساب خود را مخفی کرده است.")

        # Check Media File IDs
        file_id = None
        file_uid = None
        m_type_label = None

        reply_photo = getattr(reply, "photo", None)
        if isinstance(reply_photo, (list, tuple)) and len(reply_photo) > 0 and hasattr(reply_photo[-1], "file_id"):
            file_id = reply_photo[-1].file_id
            file_uid = getattr(reply_photo[-1], "file_unique_id", None)
            m_type_label = "تصویر (Photo)"
        elif getattr(reply, "document", None) and isinstance(getattr(reply.document, "file_id", None), str):
            file_id = reply.document.file_id
            file_uid = getattr(reply.document, "file_unique_id", None)
            m_type_label = f"سند ({reply.document.file_name or 'Document'})"
        elif getattr(reply, "video", None) and isinstance(getattr(reply.video, "file_id", None), str):
            file_id = reply.video.file_id
            file_uid = getattr(reply.video, "file_unique_id", None)
            m_type_label = "ویدیو (Video)"
        elif getattr(reply, "audio", None) and isinstance(getattr(reply.audio, "file_id", None), str):
            file_id = reply.audio.file_id
            file_uid = getattr(reply.audio, "file_unique_id", None)
            m_type_label = f"صوت ({reply.audio.title or 'Audio'})"
        elif getattr(reply, "voice", None) and isinstance(getattr(reply.voice, "file_id", None), str):
            file_id = reply.voice.file_id
            file_uid = getattr(reply.voice, "file_unique_id", None)
            m_type_label = "ویس (Voice)"
        elif getattr(reply, "sticker", None) and isinstance(getattr(reply.sticker, "file_id", None), str):
            file_id = reply.sticker.file_id
            file_uid = getattr(reply.sticker, "file_unique_id", None)
            m_type_label = f"استیکر ({reply.sticker.emoji or 'Sticker'})"

        if file_id and isinstance(file_id, str):
            r_parts.append(f"• 📦 <b>نوع فایل پیوست:</b> {m_type_label}")
            r_parts.append(f"• 🔑 <b>شناسه فایل (File ID):</b>\n<code>{file_id}</code>")
            if file_uid:
                r_parts.append(f"• 🔒 <b>شناسه یکتا (Unique ID):</b> <code>{file_uid}</code>")

        sections.append("\n".join(r_parts))

    # Priority 2: Direct Forward Info (if message itself was forwarded directly to bot)
    elif message:
        finfo = _extract_origin_info(
            getattr(message, "forward_origin", None),
            getattr(message, "forward_from", None),
            getattr(message, "forward_from_chat", None)
        )
        if finfo:
            f_parts = ["↪️ <b>مشخصات پیام فوروارد شده (Forward Source):</b>"]
            if finfo["type"] == "user":
                f_parts.append(f"• 🆔 <b>آیدی عددی فرستنده اصلی (User ID):</b> <code>{finfo['id']}</code>")
                f_parts.append(f"• 🏷 <b>نام فرستنده:</b> {html.escape(finfo['name'])}")
                f_parts.append(f"• 🔗 <b>نام کاربری:</b> {finfo['username']}")
            elif finfo["type"] in ("chat", "channel"):
                ctype = "کانال" if finfo["type"] == "channel" else "گروه"
                f_parts.append(f"• 🆔 <b>آیدی عددی {ctype} مبدا:</b> <code>{finfo['id']}</code>")
                f_parts.append(f"• 🏷 <b>عنوان {ctype}:</b> {html.escape(finfo.get('title', ''))}")
                f_parts.append(f"• 🔗 <b>نام کاربری:</b> {finfo['username']}")
            elif finfo["type"] == "hidden_user":
                f_parts.append(f"• 🔒 <b>حریم خصوصی فوروارد:</b> کاربر ({html.escape(finfo['name'])}) در تنظیمات تلگرام لینک حساب کاربری خود را در فورواردها مخفی کرده است.")
            if getattr(message, "message_id", None) and isinstance(message.message_id, int):
                f_parts.append(f"• ✉️ <b>شماره پیام:</b> <code>{message.message_id}</code>")
            sections.append("\n".join(f_parts))

    # Priority 3: Requester User & Chat Details
    ctx_parts = []
    if user and isinstance(getattr(user, "id", None), int):
        u_name = _format_user_name(user)
        uname = getattr(user, "username", None)
        u_handle = f"@{uname}" if isinstance(uname, str) and uname else "ندارد"
        is_prem = "✅" if getattr(user, "is_premium", False) is True else "❌"
        ctx_parts.append(
            "👤 <b>مشخصات شما (Your Info):</b>\n"
            f"• 🆔 <b>آیدی عددی شما:</b> <code>{user.id}</code>\n"
            f"• 🏷 <b>نام:</b> {html.escape(u_name)} | 🔗 <b>یوزرنیم:</b> {u_handle} | ⭐ <b>پرمیوم:</b> {is_prem}"
        )

    if chat and isinstance(getattr(chat, "id", None), int):
        type_names = {
            ChatType.PRIVATE: "خصوصی (DM)",
            ChatType.GROUP: "گروه (Group)",
            ChatType.SUPERGROUP: "سوپرگروه (Supergroup)",
            ChatType.CHANNEL: "کانال (Channel)",
        }
        ch_type = type_names.get(getattr(chat, "type", None), str(getattr(chat, "type", "")))
        title = getattr(chat, "title", None)
        ch_title = f" ({html.escape(str(title))})" if isinstance(title, str) and title else ""
        ctx_parts.append(
            f"💬 <b>مشخصات چت:</b> <code>{chat.id}</code> - {ch_type}{ch_title}"
        )

    if message and isinstance(getattr(message, "message_id", None), int):
        ctx_parts.append(f"• ✉️ <b>شماره پیام (Message ID):</b> <code>{message.message_id}</code>")

    if ctx_parts:
        sections.append("\n".join(ctx_parts))

    footer = "\n💡 <i>برای کپی کردن سریع هر آیدی، کافیست روی کد مونو‌اسپیس آن ضربه بزنید.</i>"
    return "\n\n───────────────\n\n".join(sections) + footer
