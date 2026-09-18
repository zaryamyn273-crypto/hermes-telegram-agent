"""
Prometheus OSINT Suite - Phishing, IDN Homograph & Brand Impersonation Heuristics Engine.
Detects typosquatting, Cyrillic/mixed-script homoglyphs, Punycode deception,
credential harvesting keywords, and high-risk domain entropy.
"""

import re
import math
import html
import logging
import unicodedata
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set

from utils.cache import phish_cache
from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_Phish")

# Monitored high-value target brands for typosquatting & impersonation
_TARGET_BRANDS = [
    # Global Tech & Social
    "google", "telegram", "microsoft", "apple", "facebook", "instagram",
    "whatsapp", "twitter", "netflix", "amazon", "discord", "tiktok", "yahoo",
    # Crypto & Web3
    "binance", "coinbase", "metamask", "trustwallet", "kucoin", "bybit", "kraken",
    # Finance & Payment
    "paypal", "stripe", "visa", "mastercard",
    # Iranian Financial & Crypto
    "shaparak", "nobitex", "wallex", "ramzinex", "tabdeal", "saman", "mellat", "melli",
]

_HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "fit", "work",
    "loan", "click", "country", "stream", "gdn", "mom", "date", "racing",
    "win", "bid", "party", "pro", "icu", "cam", "rest", "bar", "lat"
}

_DECEPTIVE_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "security",
    "update", "recover", "recovery", "password", "wallet", "airdrop",
    "claim", "free", "gift", "bonus", "support", "billing", "invoice",
    "confirm", "authenticate", "banking", "connect", "portal",
]


def _shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy of string (higher means more random/algorithmic)."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return round(-sum(p * math.log2(p) for p in prob), 2)


def _detect_mixed_scripts(s: str) -> Tuple[bool, List[str]]:
    """Detects if string mixes Latin with Cyrillic, Greek, or other visually confusable scripts."""
    scripts: Set[str] = set()
    for ch in s:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            if "CYRILLIC" in name:
                scripts.add("Cyrillic (سیریلیک)")
            elif "LATIN" in name:
                scripts.add("Latin (لاتین)")
            elif "GREEK" in name:
                scripts.add("Greek (یونانی)")
            elif "ARABIC" in name:
                scripts.add("Arabic/Persian")
    return len(scripts) > 1, sorted(list(scripts))


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Computes minimum edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


async def analyze_phishing_heuristics(url_or_domain: str) -> Dict[str, Any]:
    """
    Performs forensic heuristic inspection of URLs and domain names for phishing,
    homograph attacks, brand typosquatting, and deceptive patterns.
    """
    raw_input = url_or_domain.strip()
    if not raw_input.startswith("http://") and not raw_input.startswith("https://"):
        url_to_parse = f"http://{raw_input}"
    else:
        url_to_parse = raw_input

    try:
        parsed = urllib.parse.urlparse(url_to_parse)
    except Exception as e:
        return {"success": False, "input": raw_input, "error": f"آدرس نامعتبر است: {e}"}

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full_url = url_to_parse

    if not hostname or "." not in hostname:
        return {"success": False, "input": raw_input, "error": "دامنه معتبر جهت ارزیابی یافت نشد."}

    cached = await phish_cache.get(hostname)
    if cached:
        logger.debug(f"Phish cache hit for {hostname}")
        return cached

    red_flags: List[str] = []
    risk_score = 0

    # 1. Punycode & IDN Homograph Attack Check
    is_punycode = "xn--" in hostname
    unicode_domain = hostname
    try:
        unicode_domain = hostname.encode("utf-8").decode("idna")
    except Exception:
        pass

    has_homograph, mixed_scripts = _detect_mixed_scripts(unicode_domain)
    if has_homograph:
        risk_score += 45
        scripts_str = ", ".join(mixed_scripts)
        red_flags.append(f"حمله جعل حروف بصری (Homograph Attack): ترکیب خط‌های {scripts_str}")

    if is_punycode and not has_homograph:
        risk_score += 15
        red_flags.append(f"استفاده از دامنه کدگذاری شده Punycode (نمایش بصری: {unicode_domain})")

    # 2. Extract Base Domain & TLD
    parts = hostname.split(".")
    tld = parts[-1]
    domain_label = parts[-2] if len(parts) >= 2 else parts[0]
    subdomain_count = max(len(parts) - 2, 0)

    if subdomain_count >= 3:
        risk_score += 15
        red_flags.append(f"تعداد بالای ساب‌دامین ({subdomain_count} سطح ساب‌دامین) جهت پنهان‌سازی مقصد اصلی")

    # 3. High-Risk / Abused TLD Check
    if tld in _HIGH_RISK_TLDS:
        risk_score += 20
        red_flags.append(f"پسوند دامنه با ریسک امنیتی بالا و سابقه هرزنامه/فیشینگ (.{tld})")

    # 4. Brand Impersonation & Typosquatting Check
    impersonated_brand = None
    typosquatting_type = None

    # Check exact keyword embedding in hostname (e.g. login-telegram-support.com)
    for brand in _TARGET_BRANDS:
        if brand in hostname:
            # Check if it's the official brand domain
            official_tlds = [f"{brand}.com", f"{brand}.org", f"{brand}.net", f"{brand}.ir", f"{brand}.me"]
            if not any(hostname == off or hostname.endswith(f".{off}") for off in official_tlds):
                impersonated_brand = brand
                typosquatting_type = "استفاده غیرمجاز از نام برند تجاری در ساب‌دامین یا نام دامنه"
                risk_score += 35
                red_flags.append(f"جعل هویت و سوءاستفاده از نام برند شناخته‌شده: <b>{brand.upper()}</b>")
                break

    # Check edit distance on the second-level domain (SLD)
    if not impersonated_brand:
        for brand in _TARGET_BRANDS:
            dist = _levenshtein_distance(domain_label, brand)
            if dist in (1, 2) and domain_label != brand and len(domain_label) >= 4:
                impersonated_brand = brand
                typosquatting_type = f"تایپواسکواتینگ (فاصله ویرایشی {dist} با {brand})"
                risk_score += 40
                red_flags.append(f"شبیه‌سازی املایی فریبنده (Typosquatting) از برند <b>{brand.upper()}</b>")
                break

    # 5. Deceptive Keywords Check in Hostname & Path
    found_keywords = []
    combined_target = f"{hostname} {path} {query}".lower()
    for kw in _DECEPTIVE_KEYWORDS:
        if re.search(rf"\b{kw}\b|[-_]{kw}|{kw}[-_]", combined_target):
            found_keywords.append(kw)

    if found_keywords:
        kw_score = min(len(found_keywords) * 10, 30)
        risk_score += kw_score
        red_flags.append(f"کلمات کلیدی فریبنده و دریافت رمزعبور/حساب ({', '.join(found_keywords[:5])})")

    # 6. Basic Auth Deception Check (@ in URL authority)
    if "@" in parsed.netloc:
        risk_score += 40
        red_flags.append("سوءاستفاده از کاراکتر '@' برای فریب کاربر در نمایش آدرس مقصد")

    # 7. IP Address as Hostname Check
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        risk_score += 25
        red_flags.append("استفاده مستقیم از آدرس عددی IP به جای دامنه معتبر")

    # 8. Domain Shannon Entropy Check
    entropy = _shannon_entropy(domain_label)
    if entropy > 4.1 and len(domain_label) > 10:
        risk_score += 15
        red_flags.append(f"آنتروپی و بی‌نظمی بسیار بالا در حروف دامنه ({entropy}) - مشکوک به دامنه‌های تولید خودکار (DGA)")

    # Normalize risk score to 100
    risk_score = min(risk_score, 100)

    # Classification
    if risk_score >= 70:
        classification = "🚨 بدافزار / فیشینگ قطعی (خطر شدید سرقت هویت)"
    elif risk_score >= 45:
        classification = "🟠 با احتمال زیاد فیشینگ یا دامنه مشکوک"
    elif risk_score >= 20:
        classification = "🟡 مشکوک و نیازمند احتیاط کاربر"
    else:
        classification = "🟢 ساختار طبیعی و امن (ریسک پایین فیشینگ)"

    result = {
        "success": True,
        "input": raw_input,
        "hostname": hostname,
        "unicode_domain": unicode_domain,
        "tld": tld,
        "entropy": entropy,
        "risk_score": risk_score,
        "classification": classification,
        "has_homograph": has_homograph,
        "mixed_scripts": mixed_scripts,
        "is_punycode": is_punycode,
        "impersonated_brand": impersonated_brand,
        "typosquatting_type": typosquatting_type,
        "detected_keywords": found_keywords,
        "red_flags_count": len(red_flags),
        "red_flags": red_flags,
    }

    await phish_cache.set(hostname, result, ttl=600.0)
    return result


def format_phish_report(data: Dict[str, Any]) -> str:
    """Formats phishing heuristic inspection into Persian Telegram HTML."""
    if not data.get("success"):
        return f"🎣 <b>خطا در ارزیابی فیشینگ:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    host = html.escape(data.get("hostname", ""))
    u_domain = html.escape(data.get("unicode_domain", ""))
    score = data.get("risk_score", 0)
    verdict = data.get("classification", "نامشخص")
    entropy = data.get("entropy", 0.0)

    lines = [
        f"🎣 <b>کالبدشکافی پیشرفته هیوستیک فیشینگ و جعل برند (Phishing Heuristics):</b>\n<code>{host}</code>\n",
        f"📊 <b>ضریب احتمال فیشینگ:</b> <code>{score}%</code>",
        f"🛡 <b>نتیجه ارزیابی امنیتی:</b> <b>{verdict}</b>",
        f"📐 <b>آنتروپی حروف دامنه:</b> <code>{entropy}</code> (طبیعی: کمتر از ۳.۸)",
    ]

    if data.get("is_punycode") or data.get("has_homograph"):
        lines.append(f"🔤 <b>نمایش بصری یونیکد:</b> <code>{u_domain}</code>")

    if data.get("impersonated_brand"):
        lines.append(f"🎯 <b>برند هدف شبیه‌سازی:</b> <b>{html.escape(data['impersonated_brand'].upper())}</b>")

    # Red Flags
    flags = data.get("red_flags", [])
    if flags:
        lines.append(f"\n🚨 <b>ردپاهای فریب و شاخص‌های آسیب‌پذیری ({len(flags)} مورد):</b>")
        for f in flags:
            lines.append(f"• {f}")
    else:
        lines.append("\n✅ <b>ردپاهای فریب:</b> هیچ الگوی شناخته‌شده‌ای از فیشینگ یا جعل حروف یافت نشد.")

    lines.append("\n⚡️ <i>پویش بر پایه الگوریتم‌های فاصله‌سنجی Damerau-Levenshtein، آنتروپی Shannon و تحلیل چندزبانه IDN</i>")
    return "\n".join(lines)
