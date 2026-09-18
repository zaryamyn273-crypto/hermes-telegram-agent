"""
Prometheus OSINT Suite - Hash Identification, JWT Token Inspector & Cryptographic Analyzer
Detects hash types (MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt, Argon2, etc.),
decodes and inspects JSON Web Tokens (JWT) for OSINT analysis, and computes reference digests.
"""

import re
import json
import base64
import hashlib
import datetime
import html
import logging
from typing import Dict, Any, List, Optional

from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_Hash")

# Hash Regex Patterns
_HASH_PATTERNS = [
    ("CRC32", re.compile(r"^[a-fA-F0-9]{8}$"), "الگوریتم خطایابی چرخشی ۳۲ بیتی"),
    ("MD5", re.compile(r"^[a-fA-F0-9]{32}$"), "چکیده پیام MD5 (بسیار رایج در پسوردها و فایل‌ها)"),
    ("NTLM", re.compile(r"^[a-fA-F0-9]{32}$"), "هش پسورد ویندوز NT/Active Directory"),
    ("SHA-1", re.compile(r"^[a-fA-F0-9]{40}$"), "الگوریتم هش ایمن SHA-1 (۴۰ کاراکتر هگز)"),
    ("RIPEMD-160", re.compile(r"^[a-fA-F0-9]{40}$"), "الگوریتم RIPEMD-160 (رایج در آدرس‌های بیت‌کوین)"),
    ("MySQL 4.1+", re.compile(r"^\*[a-fA-F0-9]{40}$"), "هش دیتابیس MySQL نسخه ۴.۱ به بالا"),
    ("SHA-224", re.compile(r"^[a-fA-F0-9]{56}$"), "الگوریتم SHA-224 از خانواده SHA-2"),
    ("SHA-256", re.compile(r"^[a-fA-F0-9]{64}$"), "الگوریتم SHA-256 (استاندارد بلاکچین و گواهی‌ها)"),
    ("SHA-384", re.compile(r"^[a-fA-F0-9]{96}$"), "الگوریتم SHA-384 از خانواده SHA-2"),
    ("SHA-512", re.compile(r"^[a-fA-F0-9]{128}$"), "الگوریتم ۵۱۲ بیتی فوق‌ایمن SHA-512"),
    ("bcrypt", re.compile(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$"), "الگوریتم پیشرفته هش رمز عبور bcrypt"),
    ("Argon2", re.compile(r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$"), "برنده رقابت رمزنگاری Argon2 (مقاوم در برابر GPU)"),
    ("PBKDF2", re.compile(r"^sha256\$\d+\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+$"), "مشتق‌سازی کلید PBKDF2"),
    ("WordPress/phpBB", re.compile(r"^\$[PH]\$[a-zA-Z0-9./]{31}$"), "هش پسورد وردپرس / فروم phpBB"),
]


def decode_base64url(segment: str) -> str:
    """Decodes standard or URL-safe base64 string with automatic padding."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment.encode("utf-8")).decode("utf-8", errors="replace")


def analyze_jwt_token(raw_token: str) -> Dict[str, Any]:
    """
    Decodes and analyzes a JWT token (Header, Payload, Signature) without secret verification
    for open source reconnaissance and security analysis.
    """
    token = raw_token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {"is_jwt": False, "error": "فرمت توکن JWT معتبر نیست (باید شامل ۳ بخش باشد)."}

    try:
        header_raw = decode_base64url(parts[0])
        header = json.loads(header_raw)
    except Exception as e:
        return {"is_jwt": False, "error": f"خطا در دیکود هدر JWT: {e}"}

    try:
        payload_raw = decode_base64url(parts[1])
        payload = json.loads(payload_raw)
    except Exception as e:
        return {"is_jwt": False, "error": f"خطا در دیکود بدنه (Payload) توکن JWT: {e}"}

    signature = parts[2]

    # Security Audits
    alg = header.get("alg", "none")
    typ = header.get("typ", "JWT")
    is_none_alg = (alg.lower() == "none")

    # Time validations
    now_ts = int(datetime.datetime.utcnow().timestamp())
    exp_ts = payload.get("exp")
    iat_ts = payload.get("iat")
    nbf_ts = payload.get("nbf")

    exp_date_str = None
    is_expired = False
    if exp_ts and isinstance(exp_ts, (int, float)):
        exp_dt = datetime.datetime.utcfromtimestamp(exp_ts)
        exp_date_str = exp_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        is_expired = now_ts > exp_ts

    iat_date_str = None
    if iat_ts and isinstance(iat_ts, (int, float)):
        iat_dt = datetime.datetime.utcfromtimestamp(iat_ts)
        iat_date_str = iat_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Key claims
    subject = payload.get("sub", "")
    issuer = payload.get("iss", "")
    audience = payload.get("aud", "")
    email = payload.get("email") or payload.get("upn", "")
    roles = payload.get("roles") or payload.get("role") or payload.get("scope", "")

    return {
        "success": True,
        "is_jwt": True,
        "algorithm": alg,
        "token_type": typ,
        "is_vulnerable_none_alg": is_none_alg,
        "header": header,
        "payload": payload,
        "subject": subject,
        "issuer": issuer,
        "audience": audience,
        "email": email,
        "roles": roles,
        "issued_at": iat_date_str,
        "expires_at": exp_date_str,
        "is_expired": is_expired,
        "signature_sample": signature[:16] + "...",
    }


def identify_hash_or_token(input_str: str) -> Dict[str, Any]:
    """
    Identifies hash types or analyzes JWT tokens.
    Also computes reference cryptographic hashes if plaintext is provided.
    """
    val = input_str.strip()
    if not val:
        return {"success": False, "error": "ورودی برای شناسایی وارد نشده است."}

    # 1. Check if JWT Token
    if val.count(".") == 2 and (val.startswith("ey") or len(val) > 40):
        jwt_res = analyze_jwt_token(val)
        if jwt_res.get("is_jwt"):
            return {
                "success": True,
                "input": val,
                "type": "JWT",
                "jwt_data": jwt_res,
            }

    # 2. Match against Known Hash Signatures
    matched_types = []
    for name, pattern, desc in _HASH_PATTERNS:
        if pattern.match(val):
            matched_types.append({
                "name": name,
                "description": desc,
            })

    # 3. Always compute reference digests of input string
    val_bytes = val.encode("utf-8")
    computed = {
        "md5": hashlib.md5(val_bytes).hexdigest(),
        "sha1": hashlib.sha1(val_bytes).hexdigest(),
        "sha256": hashlib.sha256(val_bytes).hexdigest(),
    }

    return {
        "success": True,
        "input": val,
        "type": "HASH" if matched_types else "PLAINTEXT_OR_UNKNOWN",
        "matches": matched_types,
        "matches_count": len(matched_types),
        "computed_hashes": computed,
    }


def format_hash_report(res: Dict[str, Any]) -> str:
    """Formats hash identification and JWT inspection report in Persian Telegram HTML."""
    if not res.get("success"):
        return f"🔐 <b>خطا در تحلیل هش یا توکن:</b> {html.escape(res.get('error', 'ناشناخته'))}"

    val = res.get("input", "")
    val_disp = val if len(val) <= 40 else val[:20] + "..." + val[-15:]

    # Case 1: JWT Token
    if res.get("type") == "JWT":
        j = res["jwt_data"]
        alg = html.escape(str(j.get("algorithm", "")))
        typ = html.escape(str(j.get("token_type", "")))
        status_badge = "🚨 <b>منقضی‌شده (Expired)</b>" if j.get("is_expired") else "✅ <b>فعال / دارای اعتبار</b>"
        if j.get("is_vulnerable_none_alg"):
            status_badge += " | ⚠️ <b>آسیب‌پذیر به None Algorithm!</b>"

        lines = [
            f"🔐 <b>کالبدشکافی و تحلیل توکن امنیتی JWT (Token Inspector):</b>\n",
            f"• <b>نوع توکن:</b> <code>{typ}</code> | <b>الگوریتم امضا:</b> <code>{alg}</code>",
            f"• <b>وضعیت اعتبار زمانی:</b> {status_badge}",
        ]

        if j.get("issuer"):
            lines.append(f"• <b>صادرکننده (iss):</b> <code>{html.escape(str(j['issuer']))}</code>")
        if j.get("subject"):
            lines.append(f"• <b>شناسه کاربر (sub):</b> <code>{html.escape(str(j['subject']))}</code>")
        if j.get("email"):
            lines.append(f"• <b>ایمیل کاربری:</b> <code>{html.escape(str(j['email']))}</code>")
        if j.get("roles"):
            lines.append(f"• <b>نقش‌ها / دسترسی‌ها:</b> <code>{html.escape(str(j['roles']))}</code>")
        if j.get("issued_at"):
            lines.append(f"• <b>زمان صدور (iat):</b> <code>{j['issued_at']}</code>")
        if j.get("expires_at"):
            lines.append(f"• <b>زمان انقضا (exp):</b> <code>{j['expires_at']}</code>")

        payload_pretty = json.dumps(j.get("payload", {}), indent=2, ensure_ascii=False)
        lines.append(f"\n📦 <b>محتوای کامل پی‌لود (Decoded Claims):</b>\n{wrap_in_expandable_blockquote(html.escape(payload_pretty))}")

        lines.append("\n⚡️ <i>دیکود بلادرنگ توکن‌های وب با حفظ حریم خصوصی</i>")
        return "\n".join(lines)

    # Case 2: Hash Match
    matches = res.get("matches", [])
    if matches:
        lines = [
            f"🔐 <b>تحلیل و شناسایی نوع هش (Hash Identifier):</b>\n",
            f"🎯 <b>مقدار ورودی:</b> <code>{html.escape(val_disp)}</code>\n",
            f"🔍 <b>الگوریتم‌های تطبیق‌یافته ({len(matches)} مورد):</b>",
        ]
        for m in matches:
            lines.append(f"• <b>{html.escape(m['name'])}:</b> {html.escape(m['description'])}")

        lines.append("\n⚡️ <i>شناسایی ساختار کریپتوگرافیک بر پایه طول و الگوهای امضا</i>")
        return "\n".join(lines)

    # Case 3: Plaintext / Unknown - Show computed hashes
    computed = res.get("computed_hashes", {})
    lines = [
        f"🔐 <b>محاسبه هش‌های مرجع برای ورودی (Hash Calculator):</b>\n",
        f"🎯 <b>ورودی متنی:</b> <code>{html.escape(val_disp)}</code>\n",
        "📋 <b>چکیده‌های رمزنگاری محاسبه‌شده:</b>",
        f"• <b>MD5:</b> <code>{computed.get('md5')}</code>",
        f"• <b>SHA-1:</b> <code>{computed.get('sha1')}</code>",
        f"• <b>SHA-256:</b> <code>{computed.get('sha256')}</code>",
        "\n⚡️ <i>محاسبه با استفاده از کتابخانه‌های استاندارد رمزنگاری امن</i>"
    ]
    return "\n".join(lines)
