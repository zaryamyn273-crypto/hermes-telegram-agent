"""
Supercharged Telegram Numeric ID & Diagnostics Extraction Tool:
Extracts user ID, chat ID, message ID, replied message ID, forward origins,
and media File IDs with 1-tap copyable HTML code blocks.
"""

import re
from typing import Optional
from telegram import Update, Message, User, Chat
from telegram.constants import ChatType


def is_id_request(text: str) -> bool:
    """Matches natural Persian and English queries asking for IDs or user info."""
    t = text.lower().strip()
    if t in ("/id", "/myid", "/info", "/chatid", "/whoami", "id", "آیدی", "ایدی", "شناسه", "آیدی من", "ایدی من", "آیدی عددی", "شناسه من", "whoami"):
        return True
    patterns = [
        r"^(?:/id|/myid|/info|/chatid|/whoami)(?:@\w+)?$",
        r"^(?:آیدی|ایدی|شناسه)\s*(?:عددی|من|ما|این\s*چت|گروه|کانال|این\s*پیام|این\s*کاربر|کاربری)?[\?؟]?$",
        r"^(?:آیدی|ایدی|شناسه)\s*(?:عددی|من|ما|این\s*چت|گروه|کانال|این\s*پیام|این\s*رو|ایشون|این\s*کاربر|کاربری|رو)?\s*(?:بده|بگو|چیه|چند است|چنده|رو\s*بده|رو\s*بگو)[\?؟]?$",
    ]
    return any(bool(re.search(p, t, re.IGNORECASE)) for p in patterns)


def format_id_report(update: Update) -> str:
    """Generates a comprehensive diagnostic report of all available Telegram IDs."""
    message = update.effective_message
    user = update.effective_user
    chat = update.effective_chat

    sections = []

    # 1. Requester User Details
    if user:
        u_name = user.first_name or "نامشخص"
        if user.last_name:
            u_name += f" {user.last_name}"
        u_handle = f"@{user.username}" if user.username else "ندارد"
        is_prem = "✅ دارد" if getattr(user, "is_premium", False) else "❌ ندارد"
        lang = getattr(user, "language_code", "fa") or "fa"

        u_section = (
            "👤 **مشخصات شما (User Info):**\n"
            f"• 🆔 **آیدی عددی کاربر:** <code>{user.id}</code>\n"
            f"• 🏷 **نام:** {u_name}\n"
            f"• 🔗 **یوزرنیم:** {u_handle}\n"
            f"• ⭐ **پرمیوم تلگرام:** {is_prem}\n"
            f"• 🌐 **زبان:** <code>{lang}</code>"
        )
        sections.append(u_section)

    # 2. Chat / Group Details
    if chat:
        type_names = {
            ChatType.PRIVATE: "چت خصوصی (DM)",
            ChatType.GROUP: "گروه معمولی (Group)",
            ChatType.SUPERGROUP: "سوپرگروه (Supergroup)",
            ChatType.CHANNEL: "کانال (Channel)",
        }
        ch_type = type_names.get(chat.type, str(chat.type))
        ch_title = f"\n• 🏷 **عنوان چت:** {chat.title}" if chat.title else ""
        ch_user = f"\n• 🔗 **یوزرنیم چت:** @{chat.username}" if getattr(chat, "username", None) else ""

        c_section = (
            "💬 **مشخصات این چت (Chat Info):**\n"
            f"• 🆔 **آیدی عددی چت:** <code>{chat.id}</code>\n"
            f"• 📂 **نوع گفتگو:** {ch_type}"
            f"{ch_title}{ch_user}"
        )
        sections.append(c_section)

    # 3. Message Details
    if message:
        m_section = (
            "✉️ **مشخصات این پیام (Message Info):**\n"
            f"• 🆔 **شماره پیام (Message ID):** <code>{message.message_id}</code>"
        )
        sections.append(m_section)

    # 4. Replied Message Details (Target / Target User / Media)
    reply = message.reply_to_message if message else None
    if reply:
        r_user = reply.from_user
        r_parts = ["🎯 **مشخصات پیام ریپلای‌شده (Target Info):**"]
        r_parts.append(f"• 🆔 **شماره پیام هدف:** <code>{reply.message_id}</code>")

        if r_user:
            rn = r_user.first_name or "کاربر"
            if r_user.last_name:
                rn += f" {r_user.last_name}"
            ru_handle = f"@{r_user.username}" if r_user.username else "ندارد"
            r_bot = "🤖 ربات" if r_user.is_bot else "👤 کاربر حقیقی"
            r_parts.append(f"• 🆔 **آیدی عددی نویسنده:** <code>{r_user.id}</code>")
            r_parts.append(f"• 🏷 **نام نویسنده:** {rn} ({r_bot})")
            r_parts.append(f"• 🔗 **یوزرنیم:** {ru_handle}")

        # Check Forward Origin
        if getattr(reply, "forward_from", None) and reply.forward_from:
            ff = reply.forward_from
            ff_name = ff.first_name or ""
            if ff.last_name:
                ff_name += f" {ff.last_name}"
            ff_user = f" (@{ff.username})" if ff.username else ""
            r_parts.append(f"• ↪️ **فوروارد شده از کاربر:** {ff_name}{ff_user}")
            r_parts.append(f"• 🆔 **آیدی عددی فرستنده اصلی:** <code>{ff.id}</code>")

        elif getattr(reply, "forward_from_chat", None) and reply.forward_from_chat:
            fc = reply.forward_from_chat
            fc_user = f" (@{fc.username})" if getattr(fc, "username", None) else ""
            r_parts.append(f"• 📢 **فوروارد شده از کانال/گروه:** {fc.title or ''}{fc_user}")
            r_parts.append(f"• 🆔 **آیدی عددی کانال مبدا:** <code>{fc.id}</code>")

        # Check Media File IDs
        file_id = None
        file_uid = None
        m_type_label = None

        if reply.photo:
            file_id = reply.photo[-1].file_id
            file_uid = reply.photo[-1].file_unique_id
            m_type_label = "تصویر (Photo)"
        elif reply.document:
            file_id = reply.document.file_id
            file_uid = reply.document.file_unique_id
            m_type_label = f"سند ({reply.document.file_name or 'Document'})"
        elif reply.video:
            file_id = reply.video.file_id
            file_uid = reply.video.file_unique_id
            m_type_label = "ویدیو (Video)"
        elif reply.audio:
            file_id = reply.audio.file_id
            file_uid = reply.audio.file_unique_id
            m_type_label = f"صوت ({reply.audio.title or 'Audio'})"
        elif reply.voice:
            file_id = reply.voice.file_id
            file_uid = reply.voice.file_unique_id
            m_type_label = "ویس (Voice)"
        elif reply.sticker:
            file_id = reply.sticker.file_id
            file_uid = reply.sticker.file_unique_id
            m_type_label = f"استیکر ({reply.sticker.emoji or 'Sticker'})"

        if file_id:
            r_parts.append(f"• 📦 **نوع فایل پیوست:** {m_type_label}")
            r_parts.append(f"• 🔑 **شناسه فایل (File ID):**\n<code>{file_id}</code>")
            r_parts.append(f"• 🔒 **شناسه یکتا (Unique ID):** <code>{file_uid}</code>")

        sections.append("\n".join(r_parts))

    # 5. Direct Forward Info (if user forwarded a message directly to bot)
    elif message and getattr(message, "forward_from", None):
        ff = message.forward_from
        f_name = ff.first_name or ""
        if ff.last_name:
            f_name += f" {ff.last_name}"
        f_user = f" (@{ff.username})" if ff.username else ""
        f_sec = (
            "↪️ **مشخصات پیام فوروارد شده (Forward Source):**\n"
            f"• 🆔 **آیدی عددی فرستنده اصلی:** <code>{ff.id}</code>\n"
            f"• 🏷 **نام:** {f_name}{f_user}"
        )
        sections.append(f_sec)

    elif message and getattr(message, "forward_from_chat", None):
        fc = message.forward_from_chat
        fc_user = f" (@{fc.username})" if getattr(fc, "username", None) else ""
        f_sec = (
            "📢 **مشخصات کانال/گروه مبدا فوروارد:**\n"
            f"• 🆔 **آیدی عددی کانال/گروه:** <code>{fc.id}</code>\n"
            f"• 🏷 **عنوان:** {fc.title or ''}{fc_user}"
        )
        sections.append(f_sec)

    footer = "\n\n💡 *برای کپی کردن سریع هر آیدی، کافیست روی کد مونو‌اسپیس آن ضربه بزنید.*"
    return "\n\n" + "\n\n───────────────\n\n".join(sections) + footer
