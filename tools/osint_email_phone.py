"""
Prometheus OSINT Suite - Email & Phone Intelligence (شناسایی ایمیل و شماره تماس)
Email syntax and MX domain verification, Gravatar profile extraction,
phone parsing, country and carrier detection.
"""

import re
import hashlib
import logging
from typing import Dict, Any, Optional
import httpx
import dns.resolver

logger = logging.getLogger("OSINT_EmailPhone")

_EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$")


async def investigate_email(email_str: str) -> Dict[str, Any]:
    """
    Analyzes an email address:
    - Regex syntax validation
    - MX domain verification (can receive emails?)
    - Gravatar profile lookup (Avatar, Display name, About, Social accounts)
    - Google search link for OSINT investigation
    """
    clean_em = email_str.strip().lower()
    match = _EMAIL_REGEX.match(clean_em)
    if not match:
        return {"success": False, "email": clean_em, "error": "فرمت ایمیل نامعتبر است."}

    domain = match.group(1)

    # 1. MX Record Check
    has_mx = False
    mx_records = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.5
        resolver.lifetime = 3.5
        answers = resolver.resolve(domain, "MX")
        mx_records = [str(r.exchange).rstrip(".") for r in answers]
        has_mx = len(mx_records) > 0
    except Exception:
        has_mx = False

    # 2. Gravatar Lookup
    email_hash = hashlib.md5(clean_em.encode("utf-8")).hexdigest()
    gravatar_profile = None
    has_gravatar = False
    avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            res = await client.get(f"https://en.gravatar.com/{email_hash}.json")
            if res.status_code == 200:
                has_gravatar = True
                entry = res.json().get("entry", [{}])[0]
                gravatar_profile = {
                    "preferred_username": entry.get("preferredUsername", ""),
                    "display_name": entry.get("displayName", ""),
                    "about_me": entry.get("aboutMe", ""),
                    "profile_url": entry.get("profileUrl", ""),
                    "avatar_url": entry.get("thumbnailUrl", avatar_url),
                }
    except Exception:
        pass

    google_dork = f"https://www.google.com/search?q=%22{clean_em}%22"

    return {
        "success": True,
        "email": clean_em,
        "domain": domain,
        "has_mx": has_mx,
        "mx_servers": mx_records[:3],
        "has_gravatar": has_gravatar,
        "gravatar": gravatar_profile,
        "google_dork_url": google_dork
    }


def analyze_phone_number(phone_str: str) -> Dict[str, Any]:
    """
    Basic phone number normalization and country/operator identification.
    """
    clean_p = phone_str.strip()
    digits = re.sub(r"\D", "", clean_p)

    country = "نامشخص"
    operator = "نامشخص"

    if clean_p.startswith("+98") or digits.startswith("98") or clean_p.startswith("09") or digits.startswith("09"):
        country = "ایران (Iran)"
        # Iranian mobile prefixes: 989...
        if "989" in digits or clean_p.startswith("09"):
            prefix = ""
            if digits.startswith("98"):
                prefix = "0" + digits[2:5]
            elif clean_p.startswith("0"):
                prefix = clean_p[:4]

            if prefix in ("0910", "0911", "0912", "0913", "0914", "0915", "0916", "0917", "0918", "0919", "0990", "0991", "0992", "0993", "0994"):
                operator = "همراه اول (MCI)"
            elif prefix in ("0930", "0933", "0935", "0936", "0937", "0938", "0939", "0901", "0902", "0903", "0904", "0905"):
                operator = "ایرانسل (Irancell)"
            elif prefix in ("0920", "0921", "0922", "0923"):
                operator = "رایتل (Rightel)"
            elif prefix in ("0999"):
                operator = "شاتل موبایل / سامانتل"
    elif clean_p.startswith("+1") or (digits.startswith("1") and len(digits) == 11):
        country = "ایالات متحده / کانادا (US/CA)"
    elif clean_p.startswith("+44"):
        country = "انگلستان (United Kingdom)"
    elif clean_p.startswith("+49"):
        country = "آلمان (Germany)"
    elif clean_p.startswith("+7"):
        country = "روسیه (Russia)"
    elif clean_p.startswith("+90"):
        country = "ترکیه (Turkey)"
    elif clean_p.startswith("+971"):
        country = "امارات متحده عربی (UAE)"

    return {
        "success": True,
        "input": phone_str,
        "digits_only": digits,
        "country": country,
        "operator": operator,
        "google_dork": f"https://www.google.com/search?q=%22{digits}%22+OR+%22{phone_str}%22"
    }
