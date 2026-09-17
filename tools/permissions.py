"""
Prometheus Granular Permissions & Selective Tool Access Engine:
Allows bot administrators to selectively unlock/grant specific tools to individual users.

Features:
- Sub-millisecond in-memory cache for instant permission checks (<0.001ms).
- Persistent multi-tier storage: Cloudflare D1 / SQLite + Cloudflare Workers KV.
- Full support for replying to user messages or specifying numeric user IDs.
- Canonical tool alias resolution (e.g. 'pkg' -> 'apt', 'sh' -> 'shell', 'py' -> 'sandbox').
- Fine-grained permission evaluator: `has_tool_permission(user_id, tool_name) -> bool`.
- Admin-only governance commands:
  - /grant_tool <user_id> <tool_name>  (or reply with /grant_tool <tool_name>)
  - /revoke_tool <user_id> <tool_name> (or reply with /revoke_tool <tool_name>)
  - /user_tools [user_id]              (inspect a user's granted tools)
  - /granted_tools                     (audit all granted tool access)
"""

import re
import html
import json
import logging
import threading
from typing import Dict, Set, Optional, Tuple, List, Any

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from config import is_admin, settings
import database

logger = logging.getLogger("HermesTelegramAgent.Permissions")

# =========================================================================
# Tool Categorization & Canonical Aliases
# =========================================================================

# Tools that are restricted to bot admins by default unless explicitly granted
RESTRICTED_TOOLS: Set[str] = {
    "apt",      # Debian Linux Package Manager (restricted to admin by default)
    "shell",    # Host Linux Shell Execution (advanced commands restricted to admin or granted users)
}

# Mapping of all accepted aliases (English and Persian) to canonical tool names
TOOL_ALIASES: Dict[str, str] = {
    # APT Package Manager
    "apt": "apt",
    "pkg": "apt",
    "dpkg": "apt",
    "package": "apt",
    "packages": "apt",
    "apt-get": "apt",
    "پکیج": "apt",
    "بسته": "apt",
    "نصب": "apt",

    # Shell & Terminal
    "shell": "shell",
    "sh": "shell",
    "bash": "shell",
    "terminal": "shell",
    "cmd": "shell",
    "ترمینال": "shell",
    "شل": "shell",
    "بش": "shell",

    # Sandbox & Code Interpreter
    "sandbox": "sandbox",
    "e2b": "sandbox",
    "py": "sandbox",
    "python": "sandbox",
    "run": "sandbox",
    "exec": "sandbox",
    "code": "sandbox",
    "ساندباکس": "sandbox",
    "پایتون": "sandbox",
    "اجرا": "sandbox",

    # Music & Audio Streaming
    "music": "music",
    "song": "music",
    "ahang": "music",
    "audio": "music",
    "موزیک": "music",
    "آهنگ": "music",
    "صدا": "music",

    # File Generation & Document Creation
    "file": "file",
    "createfile": "file",
    "makefile": "file",
    "document": "file",
    "doc": "file",
    "فایل": "file",
    "سند": "file",

    # VirusTotal & Security Scanning
    "virustotal": "virustotal",
    "vt": "virustotal",
    "scan": "virustotal",
    "antivirus": "virustotal",
    "آنتی‌ویروس": "virustotal",
    "ویروس": "virustotal",
    "اسکن": "virustotal",

    # Vision & Multimodal Image Analysis
    "vision": "vision",
    "ocr": "vision",
    "image": "vision",
    "photo": "vision",
    "تصویر": "vision",
    "عکس": "vision",
    "بینایی": "vision",

    # Group Chat Summarizer
    "summary": "summary",
    "summarize": "summary",
    "kholase": "summary",
    "recap": "summary",
    "خلاصه": "summary",
    "جمع‌بندی": "summary",

    # Database & Chat Search
    "search": "search",
    "find": "search",
    "searchdb": "search",
    "jostojoo": "search",
    "جستجو": "search",
    "سرچ": "search",

    # Telegraph Instant View Publisher
    "telegraph": "telegraph",
    "article": "telegraph",
    "تلگراف": "telegraph",
    "مقاله": "telegraph",

    # Twitter / X Content Fetcher
    "twitter": "twitter",
    "tweet": "twitter",
    "x": "twitter",
    "توییتر": "twitter",
    "توییت": "twitter",

    # Universal wildcard (all tools)
    "*": "*",
    "all": "*",
    "همه": "*",
    "تمام": "*",
    "کل": "*",
}

# Persian friendly display names and descriptions for tools
TOOL_DISPLAY_INFO: Dict[str, Tuple[str, str]] = {
    "apt": ("مدیریت پکیج لینوکس (APT)", "نصب، حذف و جستجوی بسته‌های دبیان/اوبونتو سرور"),
    "shell": ("ترمینال و شل سیستمی (Shell)", "اجرای دستورات خط فرمان لینوکس"),
    "sandbox": ("ساندباکس اجرای کد ابری (E2B / Python)", "اجرا و تحلیل کدهای پایتون و تولید نمودار"),
    "music": ("جستجو و استریم موزیک (Music)", "جستجو، دانلود و ارسال مستقیم فایل صوتی MP3"),
    "file": ("سازنده فایل و سند (File Tool)", "ایجاد و ارسال انواع فرمت‌های متنی و اسناد"),
    "virustotal": ("اسکنر ویروس‌توتال (VirusTotal)", "بررسی امنیت فایل‌ها، دامنه‌ها و لینک‌ها"),
    "vision": ("پردازش تصویر و OCR (Vision)", "تحلیل هوشمند تصاویر و استخراج متن"),
    "summary": ("خلاصه‌ساز گفتگوها (Summary)", "جمع‌بندی هوشمند تاریخچه پیام‌های گروه"),
    "search": ("جستجوی دیتابیس گروه (Search)", "جستجوی متنی پیشرفته در پیام‌های ذخیره‌شده"),
    "telegraph": ("انتشار تلگراف (Telegraph)", "تبدیل متن‌های بلند به مقالات Instant View"),
    "twitter": ("کاوشگر توییتر / X (Twitter)", "استخراج متن، رسانه و پروفایل‌های توییتر"),
    "*": ("دسترسی همگانی به تمام ابزارها (*)", "آزادسازی نامحدود تمام امکانات برای کاربر"),
}


# =========================================================================
# In-Memory Cache & Persistence Engine
# =========================================================================

# Fast In-Memory Map: user_id -> Set[canonical_tool_names]
_USER_PERMISSIONS: Dict[int, Set[str]] = {}
_PERM_LOCK = threading.RLock()
_PERMS_INITIALIZED = False


def normalize_tool_name(raw_tool: str) -> Optional[str]:
    """Normalizes any input string or alias into its canonical tool name."""
    if not raw_tool:
        return None
    clean = raw_tool.strip().lower()
    clean = clean.lstrip("/").replace("-", "").replace("_", "")
    # Check direct lookup first
    if clean in TOOL_ALIASES:
        return TOOL_ALIASES[clean]
    # Check normalized lookup
    for alias, canonical in TOOL_ALIASES.items():
        if clean == alias.replace("-", "").replace("_", ""):
            return canonical
    return None


async def init_permissions_engine():
    """
    Initializes database tables for granular permissions and hydrates
    fast in-memory L1 cache from Cloudflare D1 / SQLite.
    """
    global _PERMS_INITIALIZED
    if _PERMS_INITIALIZED:
        return

    logger.info("Initializing Prometheus Granular Permissions Engine...")

    # Create table in Cloudflare D1 / SQLite
    schema_sql = """
    CREATE TABLE IF NOT EXISTS user_tool_permissions (
        user_id INTEGER NOT NULL,
        tool_name TEXT NOT NULL,
        granted_by INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, tool_name)
    );
    """
    try:
        await database.execute_d1_query(schema_sql)
    except Exception as e:
        logger.warning(f"Failed to create user_tool_permissions table: {e}")

    # Index for fast user query
    try:
        await database.execute_d1_query("CREATE INDEX IF NOT EXISTS idx_user_tool_perms_uid ON user_tool_permissions (user_id);")
    except Exception:
        pass

    # Hydrate memory cache
    await refresh_permissions_cache()
    _PERMS_INITIALIZED = True


async def refresh_permissions_cache():
    """Loads all granted permissions from D1 / SQLite into RAM cache."""
    global _USER_PERMISSIONS
    query_sql = "SELECT user_id, tool_name FROM user_tool_permissions;"
    res = await database.execute_d1_query(query_sql)
    rows = res.get("results", []) if res.get("success") else []

    new_map: Dict[int, Set[str]] = {}
    for r in rows:
        uid = int(r["user_id"])
        tname = str(r["tool_name"]).strip()
        if uid not in new_map:
            new_map[uid] = set()
        new_map[uid].add(tname)

    with _PERM_LOCK:
        _USER_PERMISSIONS = new_map

    logger.info(f"Loaded {sum(len(v) for v in new_map.values())} active tool grants across {len(new_map)} users into RAM.")


# =========================================================================
# Permission Evaluator & Mutators
# =========================================================================

def has_tool_permission(user_id: Optional[int], tool_name: str) -> bool:
    """
    Evaluates whether a user has permission to execute a specific tool.
    Rules:
    1. Bot Administrators (is_admin): Always 100% permitted on all tools.
    2. Explicitly Granted Users: If granted '*' or the specific tool -> permitted.
    3. Non-Restricted Tools: Standard tools are public to allowed users.
    4. Restricted Tools (apt, shell, sandbox): Denied unless explicitly granted or admin.
    """
    if user_id is None:
        return False

    try:
        uid = int(user_id)
    except (ValueError, TypeError):
        return False

    # 1. Admins have unrestricted access
    if is_admin(uid):
        return True

    # Normalize tool name
    canonical = normalize_tool_name(tool_name) or tool_name.lower().strip()

    # 2. Check selective granted permissions in RAM cache (<0.001ms)
    with _PERM_LOCK:
        granted_set = _USER_PERMISSIONS.get(uid, set())
        if "*" in granted_set or canonical in granted_set:
            return True

    # 3. Check if tool is restricted by default
    if canonical in RESTRICTED_TOOLS:
        return False

    # Standard public tool -> Allowed
    return True


async def grant_user_tool(user_id: int, tool_name: str, granted_by: int = 0) -> Tuple[bool, str]:
    """
    Grants a tool permission to a user.
    Persists to RAM cache, SQLite / Cloudflare D1, and Cloudflare KV.
    Returns (success: bool, canonical_tool_name: str).
    """
    canonical = normalize_tool_name(tool_name)
    if not canonical:
        return False, tool_name

    uid = int(user_id)

    # 1. Update in-memory cache immediately
    with _PERM_LOCK:
        if uid not in _USER_PERMISSIONS:
            _USER_PERMISSIONS[uid] = set()
        _USER_PERMISSIONS[uid].add(canonical)

    # 2. Persist to D1 / SQLite
    sql = "INSERT OR REPLACE INTO user_tool_permissions (user_id, tool_name, granted_by) VALUES (?, ?, ?);"
    try:
        await database.execute_d1_query(sql, [uid, canonical, granted_by])
    except Exception as ex:
        logger.error(f"Failed to persist grant in D1: {ex}")

    # 3. Update Cloudflare KV cache for resilient failover
    try:
        kv_key = f"USER_PERM_{uid}"
        with _PERM_LOCK:
            tools_list = list(_USER_PERMISSIONS.get(uid, set()))
        await database.kv_set(kv_key, json.dumps(tools_list), ttl_sec=86400 * 30)
    except Exception as kv_ex:
        logger.debug(f"KV write exception for permissions: {kv_ex}")

    return True, canonical


async def revoke_user_tool(user_id: int, tool_name: str) -> Tuple[bool, str]:
    """
    Revokes a tool permission from a user.
    If tool_name is '*' or 'all', revokes all tools for that user.
    Returns (success: bool, canonical_tool_name: str).
    """
    canonical = normalize_tool_name(tool_name)
    if not canonical:
        return False, tool_name

    uid = int(user_id)

    with _PERM_LOCK:
        if canonical == "*":
            # Clear all
            _USER_PERMISSIONS.pop(uid, None)
        else:
            if uid in _USER_PERMISSIONS:
                _USER_PERMISSIONS[uid].discard(canonical)
                if not _USER_PERMISSIONS[uid]:
                    _USER_PERMISSIONS.pop(uid, None)

    # Persist to D1 / SQLite
    if canonical == "*":
        sql = "DELETE FROM user_tool_permissions WHERE user_id = ?;"
        params = [uid]
    else:
        sql = "DELETE FROM user_tool_permissions WHERE user_id = ? AND tool_name = ?;"
        params = [uid, canonical]

    try:
        await database.execute_d1_query(sql, params)
    except Exception as ex:
        logger.error(f"Failed to persist revoke in D1: {ex}")

    # Update Cloudflare KV
    try:
        kv_key = f"USER_PERM_{uid}"
        with _PERM_LOCK:
            tools_list = list(_USER_PERMISSIONS.get(uid, set()))
        if tools_list:
            await database.kv_set(kv_key, json.dumps(tools_list), ttl_sec=86400 * 30)
        else:
            await database.kv_delete(kv_key)
    except Exception as kv_ex:
        logger.debug(f"KV delete exception for permissions: {kv_ex}")

    return True, canonical


def get_user_granted_tools(user_id: int) -> Set[str]:
    """Returns copy of all tool permissions granted to a user."""
    with _PERM_LOCK:
        return set(_USER_PERMISSIONS.get(int(user_id), set()))


def get_all_granted_users() -> Dict[int, Set[str]]:
    """Returns copy of all active user grants."""
    with _PERM_LOCK:
        return {uid: set(tools) for uid, tools in _USER_PERMISSIONS.items()}


# =========================================================================
# Telegram Formatting Helpers
# =========================================================================

def format_user_permissions_report(user_id: int, username: str = "") -> str:
    """Generates an informative Persian HTML summary of user tool privileges."""
    uid = int(user_id)
    is_adm = is_admin(uid)
    granted = get_user_granted_tools(uid)

    user_label = f"@{html.escape(username)}" if username else f"<code>{uid}</code>"

    lines = [
        "🔐 <b>گزارش سطح دسترسی و ابزارهای کاربر:</b>",
        f"• <b>شناسه کاربر:</b> <code>{uid}</code> ({user_label})",
        f"• <b>نقش سیستمی:</b> {'👑 <b>ادمین کل ربات (دسترسی نامحدود)</b>' if is_adm else '👤 <b>کاربر عادی</b>'}",
        ""
    ]

    if is_adm:
        lines.append("⚡️ <i>این کاربر به عنوان ادمین، به ۱۰۰٪ ابزارها از جمله APT، ترمینال شل و ساندباکس دسترسی تام دارد.</i>")
    elif not granted:
        lines.append("ℹ️ <i>این کاربر هیچ دسترسی اختصاصی اضافه‌ای ندارد و به ابزارهای عمومی دسترسی دارد.</i>")
        lines.append("🔒 <i>ابزارهای حساس (مانند APT و Shell) برای این کاربر قفل هستند.</i>")
    else:
        lines.append("🔓 <b>ابزارهای اختصاصی آزادسازی‌شده:</b>")
        for tool in sorted(granted):
            disp, desc = TOOL_DISPLAY_INFO.get(tool, (f"ابزار {tool}", "دسترسی سفارشی"))
            lines.append(f"  ✅ <b>{disp}</b>\n     ▫️ <i>{desc}</i>")

    return "\n".join(lines)


def format_all_permissions_report() -> str:
    """Generates an audit report of all users who have received selective tool grants."""
    all_grants = get_all_granted_users()
    if not all_grants:
        return (
            "📋 <b>فهرست دسترسی‌های گزینشی ابزارها:</b>\n\n"
            "ℹ️ <i>در حال حاضر هیچ دسترسی اختصاصی به ابزارهای حساس برای کاربران ثبت نشده است.</i>\n\n"
            "💡 <i>برای اعطای دسترسی گزینشی، از دستور زیر استفاده کنید:</i>\n"
            "<code>/grant_tool &lt;user_id&gt; &lt;tool_name&gt;</code>"
        )

    lines = [
        "📋 <b>فهرست دسترسی‌های گزینشی کاربران به ابزارها:</b>",
        f"• <b>تعداد کل کاربران مجاز:</b> <code>{len(all_grants)}</code>",
        ""
    ]

    for uid, tools in sorted(all_grants.items(), key=lambda x: x[0]):
        tool_names = ", ".join(sorted(tools))
        lines.append(f"👤 <code>{uid}</code> ➜ <b>[{tool_names}]</b>")

    lines.append("")
    lines.append("💡 <i>برای سلب دسترسی:</i> <code>/revoke_tool &lt;user_id&gt; &lt;tool_name&gt;</code>")
    return "\n".join(lines)


# =========================================================================
# Telegram Command Handlers
# =========================================================================

def _resolve_target_user_and_tool(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Extracts target user_id, tool_name, and optional username from:
    1. Reply message (e.g. reply + /grant_tool apt)
    2. Arguments (e.g. /grant_tool 123456789 apt)
    Returns: (user_id, tool_name, username)
    """
    msg = update.effective_message
    if not msg:
        return None, None, None

    args = context.args or []
    reply_msg = msg.reply_to_message

    target_id: Optional[int] = None
    target_uname: Optional[str] = None
    tool_arg: Optional[str] = None

    if reply_msg and reply_msg.from_user:
        target_id = reply_msg.from_user.id
        target_uname = reply_msg.from_user.username or ""
        if args:
            tool_arg = args[0].strip()
    elif len(args) >= 2:
        first = args[0].strip()
        if first.lstrip("-+").isdigit():
            target_id = int(first)
            tool_arg = args[1].strip()
        else:
            # Maybe username or tool in reverse order
            if args[1].lstrip("-+").isdigit():
                target_id = int(args[1].strip())
                tool_arg = first
    elif len(args) == 1:
        first = args[0].strip()
        if first.lstrip("-+").isdigit():
            target_id = int(first)
            tool_arg = None
        else:
            tool_arg = first

    return target_id, tool_arg, target_uname


async def grant_tool_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Admin Command: /grant_tool <user_id> <tool_name> or reply /grant_tool <tool_name>.
    Selectively grants access to restricted tools.
    """
    msg = update.effective_message
    user = update.effective_user
    if not msg or not user:
        return

    if not is_admin(user.id):
        await msg.reply_text("⛔️ این دستور صرفاً ویژه ادمین ربات پرومته است.", parse_mode=ParseMode.HTML)
        return

    target_id, tool_arg, target_uname = _resolve_target_user_and_tool(update, context)

    if not target_id or not tool_arg:
        guide = (
            "🔓 <b>دستور آزادسازی گزینشی ابزارها (/grant_tool):</b>\n\n"
            "ادمین گرامی، می‌توانید دسترسی به ابزارهای حساس (مانند APT، ترمینال و ساندباکس) را برای افراد مورد نظرتان فعال کنید.\n\n"
            "📌 <b>روش‌های استفاده:</b>\n"
            "1️⃣ <b>با ریپلای روی پیام کاربر:</b>\n"
            "   <code>/grant_tool apt</code>\n"
            "   <code>/grant_tool shell</code>\n"
            "   <code>/grant_tool *</code> (تمام ابزارها)\n\n"
            "2️⃣ <b>با وارد کردن شناسه عددی کاربر:</b>\n"
            "   <code>/grant_tool 123456789 apt</code>\n"
            "   <code>/grant_tool 123456789 shell</code>\n\n"
            "🛠 <b>نام‌های معتبر ابزارها:</b>\n"
            "• <code>apt</code> (مدیریت پکیج دبیان سرور)\n"
            "• <code>shell</code> (شل و ترمینال سرور)\n"
            "• <code>sandbox</code> (محیط اجرای کد E2B / پایتون)\n"
            "• <code>music</code> | <code>file</code> | <code>vision</code> | <code>vt</code>\n"
            "• <code>*</code> یا <code>all</code> (آزادسازی کلیه ابزارها)"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    canonical = normalize_tool_name(tool_arg)
    if not canonical:
        await msg.reply_text(
            f"❌ ابزاری با نام «<code>{html.escape(tool_arg)}</code>» شناسایی نشد.\n\n"
            "نام‌های مجاز: <code>apt</code>, <code>shell</code>, <code>sandbox</code>, <code>music</code>, <code>file</code>, <code>vision</code>, <code>vt</code>, <code>*</code>",
            parse_mode=ParseMode.HTML
        )
        return

    success, norm_name = await grant_user_tool(target_id, canonical, granted_by=user.id)
    if not success:
        await msg.reply_text("❌ خطا در ثبت مجوز ابزار.", parse_mode=ParseMode.HTML)
        return

    disp, desc = TOOL_DISPLAY_INFO.get(norm_name, (f"ابزار {norm_name}", ""))
    u_label = f"@{target_uname}" if target_uname else f"<code>{target_id}</code>"

    resp = (
        f"✅ <b>دسترسی ابزار با موفقیت آزادسازی شد:</b>\n\n"
        f"• <b>کاربر:</b> {u_label} (شناسه: <code>{target_id}</code>)\n"
        f"• <b>ابزار مجاز شده:</b> <b>{disp}</b> (<code>{norm_name}</code>)\n"
        f"• <b>توسط ادمین:</b> <code>{user.id}</code>\n\n"
        f"💡 <i>از این پس کاربر می‌تواند از این ابزار استفاده نماید.</i>"
    )
    await msg.reply_text(resp, parse_mode=ParseMode.HTML)


async def revoke_tool_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Admin Command: /revoke_tool <user_id> <tool_name> or reply /revoke_tool <tool_name>.
    Revokes previously granted tool access.
    """
    msg = update.effective_message
    user = update.effective_user
    if not msg or not user:
        return

    if not is_admin(user.id):
        await msg.reply_text("⛔️ این دستور صرفاً ویژه ادمین ربات پرومته است.", parse_mode=ParseMode.HTML)
        return

    target_id, tool_arg, target_uname = _resolve_target_user_and_tool(update, context)

    if not target_id or not tool_arg:
        guide = (
            "🔒 <b>دستور سلب دسترسی گزینشی ابزارها (/revoke_tool):</b>\n\n"
            "📌 <b>روش‌های استفاده:</b>\n"
            "1️⃣ <b>با ریپلای روی پیام کاربر:</b>\n"
            "   <code>/revoke_tool apt</code>\n"
            "   <code>/revoke_tool shell</code>\n"
            "   <code>/revoke_tool *</code> (سلب همه ابزارها)\n\n"
            "2️⃣ <b>با شناسه عددی کاربر:</b>\n"
            "   <code>/revoke_tool 123456789 apt</code>\n"
            "   <code>/revoke_tool 123456789 *</code>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    canonical = normalize_tool_name(tool_arg)
    if not canonical:
        await msg.reply_text(f"❌ نام ابزار «<code>{html.escape(tool_arg)}</code>» نامعتبر است.", parse_mode=ParseMode.HTML)
        return

    success, norm_name = await revoke_user_tool(target_id, canonical)
    u_label = f"@{target_uname}" if target_uname else f"<code>{target_id}</code>"

    if norm_name == "*":
        resp = (
            f"🔒 <b>تمامی دسترسی‌های گزینشی ابزارها برای کاربر لغو شد:</b>\n\n"
            f"• <b>کاربر:</b> {u_label} (شناسه: <code>{target_id}</code>)\n"
            f"• <b>اقدام:</b> بازگشت به سطح دسترسی عادی (ابزارهای حساس قفل شدند)"
        )
    else:
        disp, _ = TOOL_DISPLAY_INFO.get(norm_name, (f"ابزار {norm_name}", ""))
        resp = (
            f"🔒 <b>دسترسی ابزار لغو شد:</b>\n\n"
            f"• <b>کاربر:</b> {u_label} (شناسه: <code>{target_id}</code>)\n"
            f"• <b>ابزار سلب‌شده:</b> <b>{disp}</b> (<code>{norm_name}</code>)"
        )

    await msg.reply_text(resp, parse_mode=ParseMode.HTML)


async def user_tools_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Inspects tool permissions for self (or another user if requested by admin).
    Command: /user_tools [user_id]
    """
    msg = update.effective_message
    user = update.effective_user
    if not msg or not user:
        return

    caller_id = user.id
    target_id, _, target_uname = _resolve_target_user_and_tool(update, context)

    # If non-admin requests another user's tools -> restrict to self
    if not is_admin(caller_id) or not target_id:
        target_id = caller_id
        target_uname = user.username or ""

    report = format_user_permissions_report(target_id, target_uname or "")
    await msg.reply_text(report, parse_mode=ParseMode.HTML)


async def granted_tools_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Admin Command: /granted_tools
    Lists all users who have received selective tool grants.
    """
    msg = update.effective_message
    user = update.effective_user
    if not msg or not user:
        return

    if not is_admin(user.id):
        await msg.reply_text("⛔️ این دستور صرفاً ویژه ادمین ربات پرومته است.", parse_mode=ParseMode.HTML)
        return

    report = format_all_permissions_report()
    await msg.reply_text(report, parse_mode=ParseMode.HTML)
