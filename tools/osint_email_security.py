"""
Prometheus OSINT Suite - Email Anti-Spoofing & Deliverability Security Auditor
Audits DNS SPF, DMARC, MX, and BIMI records to evaluate domain email spoofing risk,
phishing vulnerability, and mail infrastructure hygiene.
"""

import re
import html
import logging
from typing import Dict, Any, List, Optional
import dns.resolver
import asyncio

from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_EmailSecurity")


def _clean_domain(domain_or_email: str) -> str:
    """Extracts a clean domain from email or host string."""
    d = domain_or_email.strip().lower()
    if "@" in d:
        d = d.split("@")[-1]
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0].strip()
    return d


def audit_domain_email_security(target: str) -> Dict[str, Any]:
    """
    Evaluates domain email security posture:
    - SPF (Sender Policy Framework)
    - DMARC (Domain-based Message Authentication, Reporting, and Conformance)
    - MX (Mail Exchange) infrastructure
    - BIMI (Brand Indicators for Message Identification)
    - Computes overall anti-spoofing resilience grade (A+ to F).
    """
    domain = _clean_domain(target)
    if not domain or "." not in domain:
        return {"success": False, "domain": domain, "error": "دامنه نامعتبر است."}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 4.0

    # 1. SPF Record Audit
    spf_record = None
    spf_all_qualifier = None
    spf_lookups_count = 0
    spf_issues = []

    try:
        txt_answers = resolver.resolve(domain, "TXT")
        for rdata in txt_answers:
            record_txt = "".join([part.decode("utf-8", errors="ignore") for part in rdata.strings])
            if record_txt.startswith("v=spf1"):
                spf_record = record_txt
                break
    except Exception:
        spf_record = None

    if spf_record:
        # Detect qualifier for 'all'
        all_match = re.search(r"([\+\-\~\?]?all)\b", spf_record, re.I)
        if all_match:
            spf_all_qualifier = all_match.group(1).lower()

        # Count DNS lookup mechanisms (include, a, mx, ptr, exists, redirect)
        lookups = re.findall(r"\b(include:|a\b|mx\b|ptr\b|exists:|redirect=)", spf_record, re.I)
        spf_lookups_count = len(lookups)
        if spf_lookups_count > 10:
            spf_issues.append("تعداد مکانیزم‌های جستجوی DNS بیشتر از سقف مجاز RFC (بیش از ۱۰ مورد) است که منجر به خطای PermError می‌شود.")

        if spf_all_qualifier in ("+all", "all"):
            spf_issues.append("⚠️ بحرانی (+all): تمامی سرورهای دنیا مجاز به ارسال ایمیل از نام این دامنه هستند (بدون حفاظت)!")
        elif spf_all_qualifier == "?all":
            spf_issues.append("⚠️ ضعیف (?all): سیاست خنثی؛ هیچ‌گونه اقدام بازدارنده‌ای روی ایمیل‌های مشکوک اعمال نمی‌شود.")
    else:
        spf_issues.append("❌ فقدان رکورد SPF: سرورهای مجاز ارسال ایمیل مشخص نشده‌اند.")

    # 2. DMARC Record Audit
    dmarc_record = None
    dmarc_policy = None
    dmarc_subdomain_policy = None
    dmarc_pct = 100
    dmarc_rua = []
    dmarc_ruf = []
    dmarc_issues = []

    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            record_txt = "".join([part.decode("utf-8", errors="ignore") for part in rdata.strings])
            if "v=DMARC1" in record_txt:
                dmarc_record = record_txt
                break
    except Exception:
        dmarc_record = None

    if dmarc_record:
        p_match = re.search(r"\bp=([a-zA-Z]+)", dmarc_record, re.I)
        sp_match = re.search(r"\bsp=([a-zA-Z]+)", dmarc_record, re.I)
        pct_match = re.search(r"\bpct=(\d+)", dmarc_record, re.I)
        rua_match = re.search(r"\brua=([^\s;]+)", dmarc_record, re.I)
        ruf_match = re.search(r"\bruf=([^\s;]+)", dmarc_record, re.I)

        dmarc_policy = p_match.group(1).lower() if p_match else "none"
        dmarc_subdomain_policy = sp_match.group(1).lower() if sp_match else dmarc_policy
        if pct_match:
            try:
                dmarc_pct = int(pct_match.group(1))
            except ValueError:
                dmarc_pct = 100

        if rua_match:
            dmarc_rua = [addr.strip() for addr in rua_match.group(1).split(",")]
        if ruf_match:
            dmarc_ruf = [addr.strip() for addr in ruf_match.group(1).split(",")]

        if dmarc_policy == "none":
            dmarc_issues.append("⚠️ سیاست DMARC روی حالت p=none (صرفاً پایش) قرار دارد؛ ایمیل‌های جعلی ریجکت نمی‌شوند.")
        elif dmarc_policy in ("quarantine", "reject"):
            if dmarc_pct < 100:
                dmarc_issues.append(f"سیاست DMARC تنها روی {dmarc_pct}٪ ایمیل‌ها اعمال می‌گردد.")
    else:
        dmarc_issues.append("🚨 فاقد رکورد DMARC: دامنه کاملاً در برابر جعل ایمیل (Spoofing) و فیشینگ بدون دفاع است!")

    # 3. MX Records Audit
    mx_records = []
    try:
        mx_answers = resolver.resolve(domain, "MX")
        for rdata in mx_answers:
            mx_records.append({
                "host": str(rdata.exchange).rstrip(".").lower(),
                "priority": int(rdata.preference)
            })
        mx_records.sort(key=lambda x: x["priority"])
    except Exception:
        pass

    # 4. BIMI Check
    bimi_record = None
    try:
        bimi_answers = resolver.resolve(f"default._bimi.{domain}", "TXT")
        for rdata in bimi_answers:
            record_txt = "".join([part.decode("utf-8", errors="ignore") for part in rdata.strings])
            if "v=BIMI1" in record_txt:
                bimi_record = record_txt
                break
    except Exception:
        pass

    # 5. Calculate Security Grade & Spoofing Risk
    score = 0
    # DMARC Scoring (Max 50)
    if dmarc_record:
        if dmarc_policy == "reject":
            score += 50
        elif dmarc_policy == "quarantine":
            score += 40
        elif dmarc_policy == "none":
            score += 20
    # SPF Scoring (Max 40)
    if spf_record:
        if spf_all_qualifier == "-all":
            score += 40
        elif spf_all_qualifier == "~all":
            score += 30
        elif spf_all_qualifier == "?all":
            score += 15
        elif spf_all_qualifier in ("+all", "all"):
            score += 0
        else:
            score += 20
    # MX & BIMI Bonus (Max 10)
    if mx_records:
        score += 5
    if bimi_record:
        score += 5

    if score >= 90:
        grade = "A+"
        spoofing_risk = "بسیار پایین (مقاوم در برابر جعل)"
    elif score >= 80:
        grade = "A"
        spoofing_risk = "پایین (حفاظت استاندارد)"
    elif score >= 65:
        grade = "B"
        spoofing_risk = "متوسط (احتمال عبور ایمیل مشکوک)"
    elif score >= 45:
        grade = "C"
        spoofing_risk = "بالا (حفاظت ضعیف)"
    elif score >= 25:
        grade = "D"
        spoofing_risk = "بسیار بالا (فاقد DMARC موثر)"
    else:
        grade = "F"
        spoofing_risk = "بحرانی (امکان ارسال ایمیل جعلی به نام دامنه)"

    return {
        "success": True,
        "domain": domain,
        "grade": grade,
        "score": score,
        "spoofing_risk": spoofing_risk,
        "spf": {
            "has_spf": bool(spf_record),
            "record": spf_record,
            "qualifier": spf_all_qualifier,
            "lookups_count": spf_lookups_count,
            "issues": spf_issues,
        },
        "dmarc": {
            "has_dmarc": bool(dmarc_record),
            "record": dmarc_record,
            "policy": dmarc_policy,
            "subdomain_policy": dmarc_subdomain_policy,
            "percentage": dmarc_pct,
            "rua": dmarc_rua,
            "ruf": dmarc_ruf,
            "issues": dmarc_issues,
        },
        "mx_records": mx_records,
        "bimi": {
            "has_bimi": bool(bimi_record),
            "record": bimi_record,
        }
    }


def format_email_security_report(data: Dict[str, Any]) -> str:
    """Formats email anti-spoofing and deliverability audit report into Persian Telegram HTML."""
    if not data.get("success"):
        return f"🛡 <b>خطا در ارزیابی امنیت ایمیل:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    domain = html.escape(data.get("domain", ""))
    grade = data.get("grade", "F")
    score = data.get("score", 0)
    risk = data.get("spoofing_risk", "نامشخص")

    grade_badge = {
        "A+": "🟢 رتبه A+ (فوق‌العاده امن)",
        "A": "🟢 رتبه A (عالی)",
        "B": "🟡 رتبه B (خوب)",
        "C": "🟠 رتبه C (آسیب‌پذیر)",
        "D": "🔴 رتبه D (بسیار ضعیف)",
        "F": "🚨 رتبه F (بحرانی - خطر جعل)",
    }.get(grade, f"رتبه {grade}")

    lines = [
        f"🛡 <b>ارزیابی امنیت ایمیل و ضدجعل دامنه (Email Security & Anti-Spoofing):</b>\n<code>{domain}</code>\n",
        f"📊 <b>رتبه امنیت ایمیل:</b> {grade_badge} (امتیاز: <code>{score}/100</code>)",
        f"⚠️ <b>ریسک جعل ایمیل (Spoofing Risk):</b> <b>{risk}</b>\n",
    ]

    # DMARC Section
    dmarc = data.get("dmarc", {})
    if dmarc.get("has_dmarc"):
        p = dmarc.get("policy", "none")
        pct = dmarc.get("percentage", 100)
        p_badge = "✅ Reject (مسدودسازی قطعی)" if p == "reject" else ("🟡 Quarantine (پوشه اسپم)" if p == "quarantine" else "⚠️ None (صرفاً پایش)")
        lines.append(
            f"📋 <b>رکورد DMARC:</b> فعال\n"
            f"▫️ سیاست اعمالی (Policy): <code>p={p}</code> ({p_badge})\n"
            f"▫️ درصد اعمال: <code>{pct}%</code>"
        )
        if dmarc.get("rua"):
            lines.append(f"▫️ گزارش‌گیری (rua): <code>{html.escape(', '.join(dmarc['rua']))}</code>")
        lines.append(f"▫️ محتوای کامل: <code>{html.escape(dmarc.get('record', ''))}</code>\n")
    else:
        lines.append("📋 <b>رکورد DMARC:</b> ❌ <b>غیرفعال!</b> (هیچ رکوردی برای جلوگیری از ارسال ایمیل جعلی به نام این دامنه تنظیم نشده است)\n")

    # SPF Section
    spf = data.get("spf", {})
    if spf.get("has_spf"):
        q = spf.get("qualifier", "N/A")
        q_badge = "✅ سخت‌گیرانه (-all)" if q == "-all" else ("🟡 رد نرم (~all)" if q == "~all" else "⚠️ آزاد/خنثی")
        lines.append(
            f"📑 <b>رکورد SPF:</b> فعال\n"
            f"▫️ وضعیت انتها: <code>{q}</code> ({q_badge})\n"
            f"▫️ تعداد جستجوهای DNS: <code>{spf.get('lookups_count', 0)}/10</code>\n"
            f"▫️ محتوای رکورد:\n<code>{html.escape(spf.get('record', ''))}</code>\n"
        )
    else:
        lines.append("📑 <b>رکورد SPF:</b> ❌ <b>یافت نشد!</b> (سرورهای مجاز مشخص نشده‌اند)\n")

    # MX Section
    mx_list = data.get("mx_records", [])
    if mx_list:
        mx_lines = [f"• اولویت {m['priority']}: <code>{html.escape(m['host'])}</code>" for m in mx_list]
        lines.append(f"📬 <b>سرورهای میل (MX Records - {len(mx_list)} مورد):</b>\n{wrap_in_expandable_blockquote(chr(10).join(mx_lines))}\n")

    # BIMI Section
    bimi = data.get("bimi", {})
    bimi_status = "✅ فعال (نمایش لوگوی رسمی در اینباکس)" if bimi.get("has_bimi") else "غیرفعال"
    lines.append(f"🎖 <b>شاخص هویت برند (BIMI):</b> {bimi_status}")

    lines.append("\n⚡️ <i>استعلام مستقیم رکوردهای احراز هویت پست الکترونیک بر پایه استانداردهای RFC 7208 و RFC 7489</i>")
    return "\n".join(lines)


async def audit_domain_email_security_async(target: str) -> Dict[str, Any]:
    """Non-blocking asynchronous email security auditor offloaded to threadpool."""
    return await asyncio.to_thread(audit_domain_email_security, target)
