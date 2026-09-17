"""
Prometheus Multi-Tier Shell & Terminal Execution Engine:
Allows secure, responsive execution of Linux shell commands with granular access control:
- Safe Commands (ls, uptime, uname, df, free, cat, whoami, etc.):
  Available to ordinary users and bot admins for inspection, metrics, and diagnostics.
- Dangerous / Modifying Commands (rm, kill, reboot, chmod, chown, package installs, etc.):
  Strictly restricted to bot administrators, with mandatory interactive Telegram
  confirmation (Inline Keyboard approval) before execution.
- Wall-clock timeout enforcement (default 12s)
- Environment credential sanitization (prevents secret leakage)
- Clean Telegram HTML output formatting with execution timing and exit codes
"""

import re
import html
import time
import secrets
import asyncio
import logging
from typing import Dict, Any, Optional, Tuple

from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from config import is_admin
from tools.sandbox import _get_sanitized_env
from tools.permissions import has_tool_permission

logger = logging.getLogger("HermesTelegramAgent.Shell")

_MAX_SHELL_OUTPUT_CHARS = 3800
_PENDING_TTL_SECONDS = 120.0

# Active pending confirmation cache: token -> {cmd, user_id, chat_id, risk, created_at}
_PENDING_SHELL_COMMANDS: Dict[str, Dict[str, Any]] = {}


def _clean_expired_pending_commands():
    """Purges pending commands older than TTL."""
    now = time.time()
    expired = [t for t, data in _PENDING_SHELL_COMMANDS.items() if now - data.get("created_at", 0) > _PENDING_TTL_SECONDS]
    for t in expired:
        _PENDING_SHELL_COMMANDS.pop(t, None)


# =========================================================================
# Command Security Classifier
# =========================================================================

# Explicit dangerous tokens, binaries, and syntax patterns
_DANGEROUS_PATTERNS: list[Tuple[str, str]] = [
    (r"\brm\b", "حذف فایل یا دایرکتوری (rm)"),
    (r"\brmdir\b", "حذف دایرکتوری (rmdir)"),
    (r"\bkill\b", "متوقف‌سازی پروسه‌ها (kill)"),
    (r"\bpkill\b", "متوقف‌سازی پروسه‌ها (pkill)"),
    (r"\bkillall\b", "متوقف‌سازی دسته‌جمعی پروسه‌ها (killall)"),
    (r"\breboot\b", "راه‌اندازی مجدد سرور (reboot)"),
    (r"\bshutdown\b", "خاموش کردن سرور (shutdown)"),
    (r"\bpoweroff\b", "خاموش کردن سیستم (poweroff)"),
    (r"\binit\s+[0-6]", "تغییر runlevel سیستم (init)"),
    (r"\bmkfs\b", "فرمت پارتیشن (mkfs)"),
    (r"\bdd\b", "کپی مستقیم یا بازنویسی بلوک‌های دیسک (dd)"),
    (r"\bfdisk\b", "پارتیشن‌بندی دیسک (fdisk)"),
    (r"\bparted\b", "دستکاری پارتیشن دیسک (parted)"),
    (r"\bchmod\b", "تغییر سطح دسترسی فایل‌ها (chmod)"),
    (r"\bchown\b", "تغییر مالکیت فایل‌ها (chown)"),
    (r"\bchgrp\b", "تغییر گروه فایل‌ها (chgrp)"),
    (r"\bmv\b", "انتقال یا تغییر نام فایل‌ها (mv)"),
    (r"\bcp\b", "کپی یا رونویسی فایل‌ها (cp)"),
    (r"\btouch\b", "ایجاد یا تغییر تاریخ فایل (touch)"),
    (r"\btruncate\b", "خالی کردن محتوای فایل (truncate)"),
    (r"\biptables\b", "تغییر قوانین فایروال (iptables)"),
    (r"\bufw\b", "تغییر تنظیمات فایروال (ufw)"),
    (r"\bsystemctl\b", "کنترل سرویس‌های سیستم‌عامل (systemctl)"),
    (r"\bservice\b", "کنترل سرویس‌های سیستم‌عامل (service)"),
    (r"\bapt(?:-get)?\b", "مدیریت پکیج‌های سیستم (apt)"),
    (r"\bdpkg\b", "نصب یا حذف پکیج سیستم (dpkg)"),
    (r"\bpip\s+(?:install|uninstall)\b", "نصب یا حذف بسته‌های پایتون (pip)"),
    (r"\bnpm\s+(?:install|uninstall|i)\b", "نصب یا حذف پکیج‌های npm"),
    (r"\bsu\b", "سوئیچ به کاربر دیگر یا روت (su)"),
    (r"\bsudo\b", "اجرای دستور با دسترسی روت (sudo)"),
    (r"\bpasswd\b", "تغییر کلمه عبور (passwd)"),
    (r"\buseradd\b|\buserdel\b|\busermod\b", "مدیریت کاربران سیستم"),
    (r"\bcrontab\b", "ویرایش جاب‌های زمان‌بندی (crontab)"),
    (r"\bmount\b|\bumount\b", "مونت یا آنمونت درایوها"),
    (r"\bmkfifo\b", "ایجاد پایپ نامگذاری‌شده (mkfifo)"),
    (r"\bnc\b|\bnetcat\b|\bsocat\b", "سوکت شبکه و ابزارهای شنود (netcat)"),
    (r"(?:\bcurl\b|\bwget\b).*?\|\s*(?:bash|sh)", "دانلود و اجرای مستقیم اسکریپت ریموت"),
    (r">\s*", "تغییر یا بازنویسی محتوای فایل با ریدایرکت (>)"),
    (r"<\s*", "تغییر ورودی با ریدایرکت (<)"),
    (r"\$\(.*?\)", "اجرای کد در پس‌زمینه با Command Substitution ($())"),
    (r"`.*?`", "اجرای کد درون بک‌تیک (``)"),
    (r"\b(?:eval|exec|source|\.)\s+", "اجرای کد داینامیک درون شل"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "حمله Fork Bomb"),
    (r"\b(?:python3?|node|ruby|perl|bash|sh|zsh)\s+-[ce]\b", "اجرای کد داینامیک درون شل"),
]

# Binaries recognized as safe read-only inspection tools
_SAFE_BINARIES = {
    "ls", "dir", "cat", "head", "tail", "grep", "egrep", "fgrep", "wc",
    "uname", "uptime", "whoami", "id", "date", "cal", "df", "free", "pwd",
    "which", "du", "echo", "printf", "ps", "top", "env", "printenv",
    "neofetch", "lscpu", "nproc", "vmstat", "arch", "hostname"
}

# Sensitive files that regular users should not read via cat/head/tail
_RESTRICTED_FILE_PATTERNS = [
    r"\.env", r"token", r"secret", r"password", r"credential",
    r"/etc/shadow", r"/etc/gshadow", r"id_rsa", r"\.ssh"
]


def classify_shell_command(cmd: str) -> Tuple[bool, str]:
    """
    Analyzes a shell command string and determines whether it is safe or dangerous.
    Returns:
        (is_safe: bool, risk_description: str)
    """
    cleaned = cmd.strip()
    if not cleaned:
        return False, "دستور خالی"

    # Check for explicit dangerous patterns
    for pattern, risk in _DANGEROUS_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE):
            return False, risk

    # Check for access to restricted credential files
    for r_pat in _RESTRICTED_FILE_PATTERNS:
        if re.search(r_pat, cleaned, re.IGNORECASE):
            return False, "تلاش برای خواندن فایل‌های حساس یا کلیدهای امنیتی"

    # Split pipelines, sequential commands, and newlines
    # e.g. "ls -la | grep py ; uptime \n whoami"
    segments = re.split(r"[|;&\n\r]+", cleaned)
    for seg in segments:
        seg_clean = seg.strip()
        if not seg_clean:
            continue
        tokens = seg_clean.split()
        if not tokens:
            continue
        primary_binary = tokens[0].lower()

        # Handle version flags (e.g. "python3 --version", "git --version", "git status")
        if primary_binary in ("python", "python3", "pip", "node", "git", "docker", "curl", "tar", "gzip", "find"):
            # Allowed if only querying version or read-only status
            sub_or_flag = tokens[1].lower() if len(tokens) > 1 else ""
            if sub_or_flag in ("--version", "-v", "-v", "status", "log", "branch", "-h", "--help"):
                continue
            return False, f"دستور پیشرفته یا تغییردهنده ({primary_binary})"

        if primary_binary not in _SAFE_BINARIES:
            return False, f"دستور غیرمجاز برای کاربران عادی ({primary_binary})"

    return True, "دستور امن و مشاهده‌ای"


# =========================================================================
# Subprocess Shell Execution
# =========================================================================

async def execute_shell_command(cmd: str, timeout_sec: float = 12.0) -> Dict[str, Any]:
    """
    Executes a shell command in a subprocess with sanitized environment and timeout.
    Returns:
      {
        "success": bool,
        "stdout": str,
        "stderr": str,
        "exit_code": int,
        "duration_ms": float,
        "timed_out": bool,
        "error": Optional[str]
      }
    """
    cleaned_cmd = cmd.strip()
    if not cleaned_cmd:
        return {
            "success": False,
            "stdout": "",
            "stderr": "دستوری برای اجرا وارد نشده است.",
            "exit_code": 1,
            "duration_ms": 0.0,
            "timed_out": False,
            "error": "Empty command"
        }

    t0 = time.perf_counter()
    env = _get_sanitized_env()

    try:
        proc = await asyncio.create_subprocess_shell(
            cleaned_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd="/root/hermes-telegram-agent"
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            dur = (time.perf_counter() - t0) * 1000

            stdout_str = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()

            if len(stdout_str) > _MAX_SHELL_OUTPUT_CHARS:
                stdout_str = stdout_str[:_MAX_SHELL_OUTPUT_CHARS] + "\n... [خروجی طولانی بود و کوتاه شد]"

            if len(stderr_str) > _MAX_SHELL_OUTPUT_CHARS:
                stderr_str = stderr_str[:_MAX_SHELL_OUTPUT_CHARS] + "\n... [خطا کوتاه شد]"

            return {
                "success": proc.returncode == 0,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "exit_code": proc.returncode or 0,
                "duration_ms": round(dur, 2),
                "timed_out": False,
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
                "stderr": f"⏱ زمان اجرای دستور از {timeout_sec:.1f} ثانیه فراتر رفت و متوقف شد.",
                "exit_code": -1,
                "duration_ms": round(dur, 2),
                "timed_out": True,
                "error": "Execution timed out"
            }

    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        logger.error(f"Failed to execute shell command '{cleaned_cmd}': {e}")
        return {
            "success": False,
            "stdout": "",
            "stderr": f"خطا در اجرای دستور شل: {str(e)}",
            "exit_code": 1,
            "duration_ms": round(dur, 2),
            "timed_out": False,
            "error": str(e)
        }


def format_shell_result(res: Dict[str, Any], cmd: str) -> str:
    """Formats shell execution result into an elegant Telegram HTML response."""
    success = res.get("success", False)
    timed_out = res.get("timed_out", False)
    dur_ms = res.get("duration_ms", 0.0)
    stdout = res.get("stdout", "").strip()
    stderr = res.get("stderr", "").strip()
    exit_code = res.get("exit_code", 0)

    if timed_out:
        status_emoji = "⏱"
        status_text = "تایم‌اوت (Timeout)"
    elif success:
        status_emoji = "✅"
        status_text = "موفقیت‌آمیز (Exit 0)"
    else:
        status_emoji = "❌"
        status_text = f"خطای اجرا (Exit {exit_code})"

    lines = [
        f"💻 <b>ترمینال سرور پرومته (Prometheus Shell):</b>",
        f"• <b>وضعیت:</b> {status_emoji} <code>{status_text}</code>",
        f"• <b>زمان اجرا:</b> <code>{dur_ms}ms</code>",
        "",
        f"<blockquote expandable>⌨️ <b>دستور:</b>\n<pre><code class=\"language-bash\">{html.escape(cmd.strip())}</code></pre></blockquote>",
        ""
    ]

    if stdout:
        lines.append(f"📤 <b>خروجی استاندارد (stdout):</b>")
        lines.append(f"<pre>{html.escape(stdout)}</pre>")
    elif success and not stderr:
        lines.append("ℹ️ <i>دستور بدون خروجی متنی با موفقیت انجام شد.</i>")

    if stderr:
        lines.append("")
        lines.append(f"⚠️ <b>پیام سیستمی / خطا (stderr):</b>")
        lines.append(f"<pre>{html.escape(stderr)}</pre>")

    return "\n".join(lines)


# =========================================================================
# Intent Detection & Command Extraction
# =========================================================================

_SHELL_COMMAND_PREFIXES = (
    "/sh", "/shell", "/bash", "/terminal", "/cmd",
    "/psh", "/pshell", "/pbash", "/pterminal", "/pcmd",
    "/pro_sh", "/p_sh", "/pro_bash", "/p_bash", "/pro_terminal", "/p_terminal"
)

_SHELL_TRIGGER_PATTERNS = [
    re.compile(r"^(?:لطف[ااً]|میشه|بی‌زحمت|بی\s*زحمت)?\s*(?:دستور|کامند)?\s*(?:شل|shell|bash|بش|ترمینال)\s*(?:رو|را|زیر\s*رو|زیر\s*را)?\s*(?:اجرا\s*کن|ران\s*کن|بزن)", re.IGNORECASE),
    re.compile(r"^(?:دستور|کامند)\s*(?:شل|shell|ترمینال|bash|بش)\s*[:\n]", re.IGNORECASE),
    re.compile(r"^(?:شل|ترمینال)\s*[:\n]", re.IGNORECASE),
]


def is_shell_request(text: str) -> bool:
    """Matches commands and natural Persian queries requesting shell command execution."""
    if not text:
        return False
    t = text.strip()
    first_token = t.split()[0].lower() if t.split() else ""
    if any(first_token == cmd or first_token.startswith(f"{cmd}@") for cmd in _SHELL_COMMAND_PREFIXES):
        return True
    if any(p.search(t) for p in _SHELL_TRIGGER_PATTERNS):
        return True
    return False


def extract_shell_command(text: str) -> Optional[str]:
    """Extracts shell command string from markdown blocks, arguments, or natural language."""
    if not text:
        return None

    # Check for fenced code block ```bash ... ``` or ```sh ... ```
    code_blocks = re.findall(r"```(?:bash|sh|shell)?\n([\s\S]*?)```", text, re.IGNORECASE)
    if code_blocks:
        return code_blocks[0].strip()

    # Check for inline backtick `cmd`
    inline_blocks = re.findall(r"`([^`\n]+)`", text)
    if inline_blocks and len(inline_blocks[0].strip()) >= 2:
        return inline_blocks[0].strip()

    t = text.strip()
    # Strip slash command
    t = re.sub(r"^/(?:p|pro|prom|prometheus)?_?(?:sh|shell|bash|terminal|cmd)(?:@\w+)?\s*", "", t, flags=re.IGNORECASE)
    # Strip natural language trigger
    for p in _SHELL_TRIGGER_PATTERNS:
        t = p.sub("", t).strip()

    t = t.lstrip(":\n -").strip()
    return t if len(t) >= 1 else None


# =========================================================================
# Telegram Command and Callback Handlers
# =========================================================================

async def shell_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles /sh, /shell, /bash, /terminal commands.
    Enforces two-tier security:
    - Ordinary users: Safe read-only inspection commands only.
    - Admins: Unrestricted execution, but dangerous commands require interactive confirmation.
    """
    msg = update.effective_message
    if not msg:
        return

    raw_text = msg.text or msg.caption or ""
    args = context.args or []
    cmd = " ".join(args).strip()

    if not cmd:
        # Check reply message
        reply_msg = msg.reply_to_message
        if reply_msg and (reply_msg.text or reply_msg.caption):
            cmd = extract_shell_command(reply_msg.text or reply_msg.caption or "") or ""
        else:
            cmd = extract_shell_command(raw_text) or ""

    if not cmd:
        guide = (
            "💻 <b>ترمینال و شل پرومته (Prometheus Shell Engine):</b>\n\n"
            "موتور اجرای مستقیم دستورات سیستم‌عامل با تفکیک سطوح دسترسی امنیتی:\n\n"
            "🟢 <b>کاربران عادی (دستورات بی‌خطر):</b>\n"
            "• <code>/sh uname -a</code>\n"
            "• <code>/sh uptime</code>\n"
            "• <code>/sh ls -la</code>\n"
            "• <code>/sh df -h</code> | <code>/sh free -m</code> | <code>/sh whoami</code>\n\n"
            "🔴 <b>ادمین‌های ربات (دستورات پیشرفته و حساس):</b>\n"
            "• اجرای کلیه دستورات سیستمی.\n"
            "• ⚠️ <i>دستورات خطرناک و تغییردهنده (مانند rm, kill, reboot, chmod) نیازمند تایید دکمه‌ای ادمین قبل از اجرا می‌باشند.</i>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    user = update.effective_user
    user_id = user.id if user else 0
    is_adm = is_admin(user_id)
    is_permitted = is_adm or has_tool_permission(user_id, "shell")

    is_safe, risk = classify_shell_command(cmd)

    # Policy 1: Non-permitted user requesting a non-safe command -> Refuse
    if not is_permitted and not is_safe:
        err_text = (
            f"⛔️ <b>دسترسی غیرمجاز به دستور ترمینال:</b>\n\n"
            f"اجرای دستور «<code>{html.escape(cmd)}</code>» به دلیل حساسیت بالا (<code>{risk}</code>) تنها برای ادمین یا کاربران مجاز است.\n\n"
            f"💡 <i>کاربران عادی تنها به دستورات مشاهده‌ای و تشخیصی بی‌خطر (مانند <code>ls</code>, <code>uptime</code>, <code>uname</code>, <code>cat</code>, <code>df</code>, <code>free</code>, <code>whoami</code>) دسترسی دارند.</i>\n\n"
            f"▫️ <i>ادمین ربات می‌تواند با دستور <code>/grant_tool {user_id} shell</code> این ابزار را برای شما آزاد کند.</i>"
        )
        await msg.reply_text(err_text, parse_mode=ParseMode.HTML)
        return

    # Policy 2: Safe command (Admin or Ordinary user) -> Execute immediately
    if is_safe:
        res = await execute_shell_command(cmd)
        formatted = format_shell_result(res, cmd)
        await msg.reply_text(formatted, parse_mode=ParseMode.HTML)
        return

    # Policy 3: Permitted user/admin requesting a dangerous command -> Prompt for explicit confirmation
    _clean_expired_pending_commands()
    token = secrets.token_hex(6)
    _PENDING_SHELL_COMMANDS[token] = {
        "cmd": cmd,
        "user_id": user_id,
        "chat_id": update.effective_chat.id if update.effective_chat else 0,
        "risk": risk,
        "created_at": time.time(),
    }

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("✅ بله، دستور اجرا شود", callback_data=f"sh_exec:{token}"),
            InlineKeyboardButton("❌ انصراف", callback_data=f"sh_cancel:{token}")
        ]
    ])

    user_title = "👑 ادمین" if is_adm else "👤 کاربر مجاز"
    confirm_text = (
        f"⚠️ <b>هشدار امنیتی: تایید اجرای دستور حساس ترمینال</b>\n\n"
        f"• <b>دستور درخواستی:</b> <code>{html.escape(cmd)}</code>\n"
        f"• <b>دسته ریسک:</b> ⚠️ <code>{risk}</code>\n"
        f"• <b>درخواست‌کننده:</b> {user_title} (<code>{user_id}</code>)\n\n"
        f"<i>این دستور دارای پتانسیل تغییر در فایل‌ها، پروسه‌ها یا سرور است. آیا از اجرای مستقیم آن اطمینان کامل دارید؟</i>\n\n"
        f"⏱ <i>مهلت تایید این درخواست ۲ دقیقه می‌باشد.</i>"
    )
    await msg.reply_text(confirm_text, reply_markup=keyboard, parse_mode=ParseMode.HTML)


async def shell_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles confirmation callbacks for dangerous shell commands."""
    query = update.callback_query
    if not query:
        return

    data = query.data or ""
    if not data.startswith("sh_"):
        return

    user_id = query.from_user.id if query.from_user else 0
    if not (is_admin(user_id) or has_tool_permission(user_id, "shell")):
        await query.answer("⛔️ این تاییدیه صرفاً توسط ادمین یا کاربران مجاز امکان‌پذیر است.", show_alert=True)
        return

    parts = data.split(":", 1)
    if len(parts) != 2:
        await query.answer("درخواست نامعتبر است.")
        return

    action_type = parts[0]  # sh_exec or sh_cancel
    token = parts[1]

    _clean_expired_pending_commands()
    pending = _PENDING_SHELL_COMMANDS.pop(token, None)

    if not pending:
        await query.answer("⏱ این درخواست منقضی یا لغو شده است.", show_alert=True)
        try:
            await query.edit_message_text("⏱ <i>مهلت زمانی تایید دستور ترمینال به پایان رسید.</i>", parse_mode=ParseMode.HTML)
        except Exception:
            pass
        return

    cmd = pending["cmd"]

    # Security check: User must be original requester or bot admin
    req_uid = pending.get("user_id")
    if user_id != req_uid and not is_admin(user_id):
        await query.answer("⛔️ این تاییدیه صرفاً توسط کاربر درخواست‌کننده یا ادمین ربات قابل انجام است.", show_alert=True)
        _PENDING_SHELL_COMMANDS[token] = pending
        return

    # Security check: Chat ID verification
    req_chat_id = pending.get("chat_id")
    msg_chat_id = getattr(query.message, "chat_id", None) if query.message else None
    if msg_chat_id is None and query.message and getattr(query.message, "chat", None):
        msg_chat_id = getattr(query.message.chat, "id", None)
    if isinstance(msg_chat_id, int) and req_chat_id and msg_chat_id != req_chat_id:
        await query.answer("⛔️ این درخواست متعلق به این چت نیست.", show_alert=True)
        _PENDING_SHELL_COMMANDS[token] = pending
        return

    if action_type == "sh_cancel":
        await query.answer("اجرای دستور لغو شد.")
        cancel_text = (
            f"❌ <b>اجرای دستور ترمینال با انصراف ادمین لغو شد:</b>\n"
            f"<code>{html.escape(cmd)}</code>"
        )
        await query.edit_message_text(cancel_text, parse_mode=ParseMode.HTML)
        return

    if action_type == "sh_exec":
        await query.answer("در حال اجرای دستور در ترمینال سرور...")
        wait_text = (
            f"⏳ <b>در حال اجرای دستور در ترمینال سرور:</b>\n"
            f"<code>{html.escape(cmd)}</code>"
        )
        try:
            await query.edit_message_text(wait_text, parse_mode=ParseMode.HTML)
        except Exception:
            pass

        res = await execute_shell_command(cmd)
        formatted = format_shell_result(res, cmd)
        try:
            await query.edit_message_text(formatted, parse_mode=ParseMode.HTML)
        except Exception as ee:
            logger.warning(f"Could not edit message with shell output: {ee}")
            if query.message:
                await query.message.reply_text(formatted, parse_mode=ParseMode.HTML)
