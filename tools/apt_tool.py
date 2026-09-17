"""
Prometheus APT Package Management Tool (ابزار مدیریت پکیج لینوکس):
Provides high-performance, secure management of Debian/Ubuntu system packages directly from Telegram.

Features:
- Two-tier security with granular permission enforcement (`has_tool_permission(user_id, 'apt')`).
- Default Access: Restricted to Bot Administrators (can be selectively unlocked via /grant_tool).
- Safe Inspection Operations (search, show, list, version):
  Executes immediately with zero delay.
- Modifying Operations (install, remove, purge, update, upgrade, autoremove):
  Interactive Telegram confirmation (Inline Keyboard) with 2-minute token TTL.
- Non-Interactive Execution:
  Enforces `DEBIAN_FRONTEND=noninteractive` and `-y` to prevent subprocess hangs.
- Sanitized environment preventing secret/token leakage.
- Clean Telegram HTML formatting with execution timing and exit codes.
"""

import re
import html
import time
import secrets
import asyncio
import logging
from typing import Dict, Any, Optional, Tuple, List

from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from config import is_admin
from tools.permissions import has_tool_permission
from tools.sandbox import _get_sanitized_env

logger = logging.getLogger("HermesTelegramAgent.APT")

_MAX_APT_OUTPUT_CHARS = 3800
_PENDING_TTL_SECONDS = 120.0

# Active pending confirmation cache: token -> {cmd, action, user_id, chat_id, created_at}
_PENDING_APT_COMMANDS: Dict[str, Dict[str, Any]] = {}


def _clean_expired_pending_apt():
    """Purges expired pending confirmation tokens."""
    now = time.time()
    expired = [t for t, data in _PENDING_APT_COMMANDS.items() if now - data.get("created_at", 0) > _PENDING_TTL_SECONDS]
    for t in expired:
        _PENDING_APT_COMMANDS.pop(t, None)


# =========================================================================
# Command Classifier
# =========================================================================

_SAFE_APT_SUBCOMMANDS = {
    "search", "show", "list", "policy", "source",
    "version", "--version", "-v", "help", "--help"
}

_MODIFYING_APT_SUBCOMMANDS = {
    "install", "remove", "purge", "update", "upgrade",
    "dist-upgrade", "full-upgrade", "autoremove", "clean",
    "autoclean", "reinstall", "build-dep", "download"
}


def classify_apt_command(args_str: str) -> Tuple[bool, str, str]:
    """
    Analyzes APT command arguments and determines safety.
    Returns:
        (is_safe: bool, action: str, description: str)
    """
    cleaned = args_str.strip()
    if not cleaned:
        return True, "help", "نمایش راهنمای ابزار APT"

    tokens = cleaned.split()
    first_sub = tokens[0].lower()

    # Handle if user typed "apt install ..." or "apt-get install ..."
    if first_sub in ("apt", "apt-get", "apt-cache", "dpkg"):
        tokens = tokens[1:]
        first_sub = tokens[0].lower() if tokens else "help"

    if first_sub in _SAFE_APT_SUBCOMMANDS:
        target = " ".join(tokens[1:]) if len(tokens) > 1 else ""
        if first_sub == "search":
            desc = f"جستجوی بسته «{target}» در مخازن" if target else "جستجوی بسته‌ها"
        elif first_sub == "show":
            desc = f"مشاهده مشخصات بسته «{target}»"
        elif first_sub == "list":
            desc = f"مشاهده فهرست بسته‌ها ({target})" if target else "مشاهده فهرست بسته‌ها"
        else:
            desc = f"بررسی اطلاعات سیستم ({first_sub})"
        return True, first_sub, desc

    if first_sub in _MODIFYING_APT_SUBCOMMANDS:
        targets = " ".join(tokens[1:]) if len(tokens) > 1 else ""
        if first_sub == "install":
            desc = f"نصب بسته(ها): {targets}" if targets else "نصب بسته"
        elif first_sub in ("remove", "purge"):
            desc = f"حذف بسته(ها): {targets}" if targets else "حذف بسته"
        elif first_sub == "update":
            desc = "به‌روزرسانی لیست مخازن apt (apt update)"
        elif first_sub in ("upgrade", "dist-upgrade", "full-upgrade"):
            desc = "ارتقای بسته‌های سیستم‌عامل (apt upgrade)"
        elif first_sub == "autoremove":
            desc = "پاکسازی بسته‌های اضافه و بی‌استفاده (autoremove)"
        else:
            desc = f"تغییر پکیج‌های سیستم ({first_sub} {targets})"
        return False, first_sub, desc

    # Default to modifying for safety if unknown
    return False, first_sub, f"دستور سیستمی apt ({cleaned})"


# =========================================================================
# APT Command Execution Engine
# =========================================================================

def _build_apt_cli(subcommand: str, args_list: List[str]) -> str:
    """Builds a secure, non-interactive apt command string."""
    sub = subcommand.lower()

    if sub in ("search", "show", "policy"):
        # apt-cache is fastest and standard on Debian/Ubuntu
        return f"apt-cache {sub} {' '.join(args_list)}"

    if sub == "list":
        return f"apt list {' '.join(args_list)}"

    if sub in ("--version", "-v", "version"):
        return "apt --version"

    # Modifying commands: Use apt-get with non-interactive flags
    opts = [
        "-o Dpkg::Options::=\"--force-confdef\"",
        "-o Dpkg::Options::=\"--force-confold\"",
        "-y",
        "--assume-yes"
    ]
    opts_str = " ".join(opts)

    if sub == "update":
        return f"apt-get update"
    elif sub == "install":
        return f"apt-get install {opts_str} {' '.join(args_list)}"
    elif sub == "remove":
        return f"apt-get remove {opts_str} {' '.join(args_list)}"
    elif sub == "purge":
        return f"apt-get purge {opts_str} {' '.join(args_list)}"
    elif sub in ("upgrade", "dist-upgrade", "full-upgrade"):
        return f"apt-get upgrade {opts_str} {' '.join(args_list)}"
    elif sub == "autoremove":
        return f"apt-get autoremove {opts_str}"
    elif sub in ("clean", "autoclean"):
        return f"apt-get {sub}"

    # Generic fallback
    return f"apt-get {opts_str} {sub} {' '.join(args_list)}"


async def execute_apt_command(args_str: str, timeout_sec: float = 120.0) -> Dict[str, Any]:
    """
    Executes an APT package manager command with sanitized environment and timeout.
    Returns:
      {
        "success": bool,
        "stdout": str,
        "stderr": str,
        "exit_code": int,
        "duration_ms": float,
        "timed_out": bool,
        "cli_command": str,
        "error": Optional[str]
      }
    """
    cleaned = args_str.strip()
    if not cleaned:
        return {
            "success": False,
            "stdout": "",
            "stderr": "دستوری برای APT وارد نشده است.",
            "exit_code": 1,
            "duration_ms": 0.0,
            "timed_out": False,
            "cli_command": "",
            "error": "Empty command"
        }

    tokens = cleaned.split()
    first_sub = tokens[0].lower()
    if first_sub in ("apt", "apt-get", "apt-cache", "dpkg"):
        tokens = tokens[1:]
        first_sub = tokens[0].lower() if tokens else "help"

    subcmd = first_sub
    args_list = tokens[1:]

    cli_cmd = _build_apt_cli(subcmd, args_list)

    t0 = time.perf_counter()
    env = _get_sanitized_env()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["APT_LISTCHANGES_FRONTEND"] = "none"

    try:
        proc = await asyncio.create_subprocess_shell(
            cli_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd="/root"
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            dur = (time.perf_counter() - t0) * 1000

            stdout_str = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()

            if len(stdout_str) > _MAX_APT_OUTPUT_CHARS:
                stdout_str = stdout_str[:_MAX_APT_OUTPUT_CHARS] + "\n... [خروجی به دلیل حجم بالا کوتاه شد]"

            if len(stderr_str) > _MAX_APT_OUTPUT_CHARS:
                stderr_str = stderr_str[:_MAX_APT_OUTPUT_CHARS] + "\n... [پیام‌های سیستمی کوتاه شد]"

            return {
                "success": proc.returncode == 0,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "exit_code": proc.returncode or 0,
                "duration_ms": round(dur, 2),
                "timed_out": False,
                "cli_command": cli_cmd,
                "error": None if proc.returncode == 0 else f"Exit code {proc.returncode}"
            }

        except asyncio.TimeoutError:
            dur = (time.perf_counter() - t0) * 1000
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return {
                "success": False,
                "stdout": "",
                "stderr": f"⏱ زمان اجرای دستور APT از {timeout_sec:.1f} ثانیه فراتر رفت و متوقف شد.",
                "exit_code": -1,
                "duration_ms": round(dur, 2),
                "timed_out": True,
                "cli_command": cli_cmd,
                "error": "APT command timed out"
            }

    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        logger.error(f"Failed to execute APT command '{cli_cmd}': {e}")
        return {
            "success": False,
            "stdout": "",
            "stderr": f"خطا در اجرای فرآیند APT: {str(e)}",
            "exit_code": 1,
            "duration_ms": round(dur, 2),
            "timed_out": False,
            "cli_command": cli_cmd,
            "error": str(e)
        }


def format_apt_result(res: Dict[str, Any], user_input: str) -> str:
    """Formats APT execution results into an elegant Persian Telegram HTML message."""
    success = res.get("success", False)
    timed_out = res.get("timed_out", False)
    dur_ms = res.get("duration_ms", 0.0)
    stdout = res.get("stdout", "").strip()
    stderr = res.get("stderr", "").strip()
    exit_code = res.get("exit_code", 0)
    cli_cmd = res.get("cli_command", user_input)

    if timed_out:
        status_emoji = "⏱"
        status_text = "تایم‌اوت (Timeout)"
    elif success:
        status_emoji = "✅"
        status_text = "موفقیت‌آمیز (Exit 0)"
    else:
        status_emoji = "❌"
        status_text = f"خطا در اجرا (Exit {exit_code})"

    dur_str = f"{dur_ms / 1000:.2f}s" if dur_ms >= 1000 else f"{dur_ms:.0f}ms"

    lines = [
        "📦 <b>مدیریت بسته‌های لینوکس (Prometheus APT):</b>",
        f"• <b>وضعیت:</b> {status_emoji} <code>{status_text}</code>",
        f"• <b>زمان پردازش:</b> <code>{dur_str}</code>",
        "",
        f"<blockquote expandable>⌨️ <b>دستور اجرا شده:</b>\n<pre><code class=\"language-bash\">{html.escape(cli_cmd)}</code></pre></blockquote>",
        ""
    ]

    if stdout:
        lines.append("📤 <b>خروجی عملیات (stdout):</b>")
        lines.append(f"<pre>{html.escape(stdout)}</pre>")
    elif success and not stderr:
        lines.append("ℹ️ <i>دستور پکیج منیجر با موفقیت بدون خروجی متنی انجام شد.</i>")

    if stderr:
        lines.append("")
        lines.append("⚠️ <b>پیام‌های سیستمی / هشدارها (stderr):</b>")
        lines.append(f"<pre>{html.escape(stderr)}</pre>")

    return "\n".join(lines)


# =========================================================================
# Intent Detection & Natural Language Extraction
# =========================================================================

_APT_COMMAND_PREFIXES = (
    "/apt", "/pkg", "/dpkg", "/package",
    "/papt", "/p_apt", "/pro_apt", "/propkg",
    "/pro_pkg", "/p_pkg", "/aptget", "/apt_get"
)

_APT_TRIGGER_PATTERNS = [
    re.compile(r"^(?:لطف[ااً]|میشه|بی‌زحمت|بی\s*زحمت)?\s*(?:با\s+)?(?:apt|پکیج\s*منیجر|مدیریت\s*بسته)\s*(?:رو|را|زیر\s*رو)?\s*(?:اجرا\s*کن|بزن)", re.IGNORECASE),
    re.compile(r"^(?:دستور|کامند)\s*apt\s*[:\n]", re.IGNORECASE),
    re.compile(r"\b(?:پکیج|بسته)\s+([a-zA-Z0-9_\-\.]+)\s+(?:رو|را)?\s*(?:با\s+apt\s+)?(?:نصب|اینستال|install|حذف|remove|پاک|سرچ|search|پیدا)\s*کن", re.IGNORECASE),
    re.compile(r"\b(?:با\s+)?apt\s+(?:install|search|show|list|update|upgrade|remove|purge|autoremove)\b", re.IGNORECASE),
]


def is_apt_request(text: str) -> bool:
    """Matches commands and natural Persian queries requesting APT operations."""
    if not text:
        return False
    t = text.strip()
    first_token = t.split()[0].lower() if t.split() else ""
    if any(first_token == cmd or first_token.startswith(f"{cmd}@") for cmd in _APT_COMMAND_PREFIXES):
        return True
    if any(p.search(t) for p in _APT_TRIGGER_PATTERNS):
        return True
    return False


def extract_apt_command(text: str) -> Optional[str]:
    """Extracts the APT arguments string from markdown code blocks or natural queries."""
    if not text:
        return None

    # Check for fenced code block ```bash apt ... ``` or ```apt ... ```
    code_blocks = re.findall(r"```(?:bash|sh|apt)?\n([\s\S]*?)```", text, re.IGNORECASE)
    if code_blocks:
        extracted = code_blocks[0].strip()
        # Clean leading apt or apt-get
        extracted = re.sub(r"^(?:apt|apt-get|apt-cache)\s+", "", extracted, flags=re.IGNORECASE)
        return extracted

    # Check for inline backtick `apt ...`
    inline_blocks = re.findall(r"`([^`\n]+)`", text)
    if inline_blocks and len(inline_blocks[0].strip()) >= 2:
        extracted = inline_blocks[0].strip()
        extracted = re.sub(r"^(?:apt|apt-get|apt-cache)\s+", "", extracted, flags=re.IGNORECASE)
        return extracted

    t = text.strip()
    # Strip slash command prefix
    t = re.sub(r"^/(?:p|pro|prom|prometheus)?_?(?:apt|pkg|dpkg|aptget|apt_get)(?:@\w+)?\s*", "", t, flags=re.IGNORECASE)

    # Check natural Persian pattern for package installation / removal
    install_match = re.search(r"(?:پکیج|بسته)\s+([a-zA-Z0-9_\-\.]+)\s+(?:رو|را)?\s*(?:با\s+apt\s+)?(?:نصب|اینستال|install)\s*کن", t, re.IGNORECASE)
    if install_match:
        return f"install {install_match.group(1)}"

    remove_match = re.search(r"(?:پکیج|بسته)\s+([a-zA-Z0-9_\-\.]+)\s+(?:رو|را)?\s*(?:با\s+apt\s+)?(?:حذف|remove|پاک)\s*کن", t, re.IGNORECASE)
    if remove_match:
        return f"remove {remove_match.group(1)}"

    search_match = re.search(r"(?:پکیج|بسته)?\s*([a-zA-Z0-9_\-\.]+)\s+(?:رو|را)?\s*(?:با\s+apt\s+)?(?:سرچ|search|پیدا)\s*کن", t, re.IGNORECASE)
    if search_match and not t.lower().startswith("install"):
        return f"search {search_match.group(1)}"

    update_match = re.search(r"(?:مخازن|apt)\s+(?:رو|را)?\s+(?:آپدیت|بروزرسانی|update)\s*کن", t, re.IGNORECASE)
    if update_match:
        return "update"

    # Strip natural language trigger prefix
    for p in _APT_TRIGGER_PATTERNS:
        t = p.sub("", t).strip()

    t = re.sub(r"^(?:apt|apt-get|apt-cache)\s+", "", t, flags=re.IGNORECASE).strip()
    return t if len(t) >= 1 else None


# =========================================================================
# Telegram Command and Callback Handlers
# =========================================================================

async def apt_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles /apt and /pkg commands.
    Enforces selective access control:
    - Default: Restricted to Bot Admins.
    - Selectively granted users: Allowed.
    - Safe query commands: Execute immediately.
    - Modifying commands: Interactive Inline Keyboard confirmation.
    """
    msg = update.effective_message
    user = update.effective_user
    if not msg or not user:
        return

    user_id = user.id

    # 1. Enforce granular permissions check
    if not has_tool_permission(user_id, "apt"):
        err_text = (
            "⛔️ <b>دسترسی غیرمجاز به ابزار مدیریت پکیج (APT):</b>\n\n"
            "ابزار مدیریت پکیج‌های سیستم‌عامل سرور (APT) به صورت پیش‌فرض ویژه <b>ادمین کل ربات</b> است.\n\n"
            "💡 <i>ادمین ربات می‌تواند با دستور زیر دسترسی اختصاصی این ابزار را برای شما آزاد کند:</i>\n"
            f"<code>/grant_tool {user_id} apt</code>"
        )
        await msg.reply_text(err_text, parse_mode=ParseMode.HTML)
        return

    raw_text = msg.text or msg.caption or ""
    args = context.args or []
    cmd_args = " ".join(args).strip()

    if not cmd_args:
        reply_msg = msg.reply_to_message
        if reply_msg and (reply_msg.text or reply_msg.caption):
            cmd_args = extract_apt_command(reply_msg.text or reply_msg.caption or "") or ""
        else:
            cmd_args = extract_apt_command(raw_text) or ""

    if not cmd_args:
        guide = (
            "📦 <b>راهنمای ابزار مدیریت پکیج لینوکس (Prometheus APT):</b>\n\n"
            "این ابزار امکان مدیریت بسته‌های نرم‌افزاری سرور لینوکس (Debian/Ubuntu) را فراهم می‌کند:\n\n"
            "🔍 <b>دستورات جستجو و مشاهده (اجرای فوری):</b>\n"
            "• <code>/apt search &lt;نام بسته&gt;</code> (جستجو در مخازن)\n"
            "• <code>/apt show &lt;نام بسته&gt;</code> (مشخصات و توضیحات بسته)\n"
            "• <code>/apt list --installed</code> (فهرست بسته‌های نصب‌شده)\n"
            "• <code>/apt --version</code>\n\n"
            "⚙️ <b>دستورات تغییردهنده (نیازمند تایید دکمه‌ای):</b>\n"
            "• <code>/apt update</code> (به‌روزرسانی مخازن)\n"
            "• <code>/apt install &lt;نام بسته&gt;</code> (نصب بسته)\n"
            "• <code>/apt remove &lt;نام بسته&gt;</code> (حذف بسته)\n"
            "• <code>/apt upgrade</code> (ارتقای پکیج‌ها)\n"
            "• <code>/apt autoremove</code> (پاکسازی بسته‌های بی‌استفاده)\n\n"
            "🔒 <i>تمامی دستورات تغییردهنده با فلگ <code>noninteractive</code> و تاییدیه اجرا می‌شوند.</i>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    is_safe, action, action_desc = classify_apt_command(cmd_args)

    # 2. Safe read-only inspection -> Execute immediately
    if is_safe:
        res = await execute_apt_command(cmd_args, timeout_sec=45.0)
        formatted = format_apt_result(res, cmd_args)
        await msg.reply_text(formatted, parse_mode=ParseMode.HTML)
        return

    # 3. Modifying command -> Prompt interactive confirmation
    _clean_expired_pending_apt()
    token = secrets.token_hex(6)
    _PENDING_APT_COMMANDS[token] = {
        "cmd": cmd_args,
        "action": action,
        "action_desc": action_desc,
        "user_id": user_id,
        "chat_id": update.effective_chat.id if update.effective_chat else 0,
        "created_at": time.time(),
    }

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ بله، دستور APT اجرا شود", callback_data=f"apt_exec:{token}"),
            InlineKeyboardButton("❌ انصراف", callback_data=f"apt_cancel:{token}")
        ]
    ])

    confirm_text = (
        f"⚠️ <b>هشدار امنیتی: تایید اجرای دستور مدیریت پکیج (APT)</b>\n\n"
        f"• <b>عملیات:</b> <code>{action_desc}</code>\n"
        f"• <b>دستور سیستمی:</b> <code>apt {html.escape(cmd_args)}</code>\n"
        f"• <b>درخواست‌کننده:</b> <code>{user_id}</code>\n\n"
        f"<i>این عملیات بر روی پکیج‌های سیستم‌عامل سرور اعمال خواهد شد. آیا از اجرای مستقیم آن اطمینان دارید؟</i>\n\n"
        f"⏱ <i>مهلت تایید این درخواست ۲ دقیقه می‌باشد.</i>"
    )
    await msg.reply_text(confirm_text, reply_markup=keyboard, parse_mode=ParseMode.HTML)


async def apt_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles confirmation callbacks for modifying APT commands."""
    query = update.callback_query
    if not query:
        return

    data = query.data or ""
    if not data.startswith("apt_"):
        return

    user_id = query.from_user.id if query.from_user else 0

    # Verify user permission
    if not has_tool_permission(user_id, "apt"):
        await query.answer("⛔️ شما مجوز اجرای دستورات APT را ندارید.", show_alert=True)
        return

    parts = data.split(":", 1)
    if len(parts) != 2:
        await query.answer("درخواست نامعتبر است.")
        return

    action_type = parts[0]  # apt_exec or apt_cancel
    token = parts[1]

    _clean_expired_pending_apt()
    pending = _PENDING_APT_COMMANDS.pop(token, None)

    if not pending:
        await query.answer("⏱ این درخواست منقضی یا قبلاً پردازش شده است.", show_alert=True)
        try:
            await query.edit_message_text("⏱ <i>مهلت تایید اجرای دستور APT به پایان رسیده است.</i>", parse_mode=ParseMode.HTML)
        except Exception:
            pass
        return

    cmd = pending["cmd"]
    action_desc = pending.get("action_desc", cmd)

    if action_type == "apt_cancel":
        await query.answer("اجرای دستور پکیج منیجر لغو شد.")
        cancel_text = (
            f"❌ <b>اجرای دستور APT لغو شد:</b>\n"
            f"• <b>دستور:</b> <code>apt {html.escape(cmd)}</code>\n"
            f"• <b>توسط:</b> <code>{user_id}</code>"
        )
        await query.edit_message_text(cancel_text, parse_mode=ParseMode.HTML)
        return

    if action_type == "apt_exec":
        await query.answer("در حال اجرای دستور APT بر روی سرور...")
        wait_text = (
            f"⏳ <b>در حال اجرای دستور پکیج منیجر بر روی سرور:</b>\n"
            f"• <b>دستور:</b> <code>apt {html.escape(cmd)}</code>\n"
            f"• <b>عملیات:</b> {action_desc}\n\n"
            f"<i>لطفاً شکیبا باشید...</i>"
        )
        try:
            await query.edit_message_text(wait_text, parse_mode=ParseMode.HTML)
        except Exception:
            pass

        # Execute with extended timeout for installs/upgrades
        res = await execute_apt_command(cmd, timeout_sec=180.0)
        formatted = format_apt_result(res, cmd)
        try:
            await query.edit_message_text(formatted, parse_mode=ParseMode.HTML)
        except Exception as ee:
            logger.warning(f"Could not edit message with APT output: {ee}")
            if query.message:
                await query.message.reply_text(formatted, parse_mode=ParseMode.HTML)
