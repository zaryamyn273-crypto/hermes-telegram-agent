"""
Prometheus OSINT Suite - Domain, IP & Network Intelligence (شناسایی شبکه، دامنه و آی‌پی)
DNS records resolution, Certificate Transparency subdomain enumeration (crt.sh),
IP geolocation, ASN intelligence, SSL/TLS certificate inspection, and HTTP security headers audit.
"""

import ssl
import socket
import datetime
import html
import logging
from typing import Dict, Any, List, Optional
import httpx
import dns.resolver

from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_Network")


async def resolve_dns_records(domain: str) -> Dict[str, Any]:
    """
    Resolves comprehensive DNS records: A, AAAA, MX, TXT, NS, CNAME, SOA.
    """
    clean_d = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    records: Dict[str, List[str]] = {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 4.0

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in record_types:
        try:
            answers = resolver.resolve(clean_d, rtype)
            records[rtype] = [str(r.to_text()) for r in answers]
        except Exception:
            records[rtype] = []

    # Get Primary IP
    primary_ip = records.get("A", [""])[0] if records.get("A") else ""

    return {
        "success": True,
        "domain": clean_d,
        "primary_ip": primary_ip,
        "records": {k: v for k, v in records.items() if v}
    }


async def enumerate_subdomains_crtsh(domain: str, max_results: int = 30) -> Dict[str, Any]:
    """
    Extracts registered subdomains from public Certificate Transparency logs via crt.sh.
    Passive, non-intrusive, extremely effective.
    """
    clean_d = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    url = f"https://crt.sh/?q=%25.{clean_d}&output=json"

    subdomains = set()
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            res = await client.get(url)
            if res.status_code == 200:
                data = res.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub_clean = sub.strip().lower().lstrip("*.")
                        if sub_clean.endswith(clean_d) and sub_clean != clean_d:
                            subdomains.add(sub_clean)
    except Exception as e:
        logger.debug(f"crt.sh lookup error for {clean_d}: {e}")

    return {
        "success": True,
        "domain": clean_d,
        "total_subdomains": len(subdomains),
        "subdomains": sorted(list(subdomains))[:max_results]
    }


async def lookup_ip_intel(ip_or_domain: str) -> Dict[str, Any]:
    """
    Fetches IP Geolocation, ASN, ISP, and reverse DNS.
    """
    target = ip_or_domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]

    # If it's a domain, resolve to IP first
    ip_addr = target
    try:
        socket.inet_aton(target)
    except socket.error:
        try:
            ip_addr = socket.gethostbyname(target)
        except Exception as e:
            return {"success": False, "target": target, "error": f"عدم توانایی در یافتن آی‌پی دامنه: {e}"}

    # Query IP Geolocation & ASN
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            res = await client.get(
                f"http://ip-api.com/json/{ip_addr}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            )
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    # Reverse DNS lookup
                    rdns = ""
                    try:
                        rdns = socket.gethostbyaddr(ip_addr)[0]
                    except Exception:
                        pass

                    return {
                        "success": True,
                        "ip": ip_addr,
                        "original_target": target,
                        "country": data.get("country", ""),
                        "country_code": data.get("countryCode", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "asn": data.get("as", ""),
                        "timezone": data.get("timezone", ""),
                        "reverse_dns": rdns,
                    }
    except Exception as e:
        return {"success": False, "ip": ip_addr, "error": f"خطا در دریافت اطلاعات آی‌پی: {e}"}

    return {"success": False, "ip": ip_addr, "error": "اطلاعاتی برای این آی‌پی یافت نشد."}


def inspect_ssl_certificate(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Extracts SSL/TLS certificate details, Subject Alternative Names (SANs) for subdomain discovery,
    validity dates, issuer organization, and cipher suite.
    """
    clean_d = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in clean_d:
        parts = clean_d.split(":")
        clean_d = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            pass

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_d, port), timeout=7.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_d) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                tls_version = ssock.version()

                # Extract SANs
                sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

                # Extract Issuer
                issuer_dict = {}
                for rdn in cert.get("issuer", []):
                    for k, v in rdn:
                        issuer_dict[k] = v

                # Extract Subject
                subject_dict = {}
                for rdn in cert.get("subject", []):
                    for k, v in rdn:
                        subject_dict[k] = v

                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")

                # Check expiration
                is_expired = False
                days_left = None
                if not_after:
                    try:
                        exp_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        now_dt = datetime.datetime.utcnow()
                        days_left = (exp_dt - now_dt).days
                        is_expired = days_left < 0
                    except Exception:
                        pass

                return {
                    "success": True,
                    "domain": clean_d,
                    "port": port,
                    "common_name": subject_dict.get("commonName", ""),
                    "issuer_org": issuer_dict.get("organizationName", issuer_dict.get("commonName", "نامشخص")),
                    "issuer_full": issuer_dict,
                    "subject_full": subject_dict,
                    "sans_count": len(sans),
                    "sans": sorted(list(set(sans))),
                    "tls_version": tls_version,
                    "cipher": cipher_info[0] if cipher_info else "",
                    "cipher_bits": cipher_info[2] if cipher_info and len(cipher_info) > 2 else None,
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "days_remaining": days_left,
                    "is_expired": is_expired,
                    "serial_number": cert.get("serialNumber", ""),
                }
    except Exception as e:
        logger.warning(f"SSL cert inspection error for {clean_d}:{port} - {e}")
        return {
            "success": False,
            "domain": clean_d,
            "port": port,
            "error": f"خطا در استعلام گواهی امنیتی SSL: {str(e)}"
        }


async def audit_http_security_headers(target: str) -> Dict[str, Any]:
    """
    Audits HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.),
    detects server version disclosures, and calculates an OSINT security rating.
    """
    clean_t = target.strip()
    if not clean_t.startswith(("http://", "https://")):
        clean_t = "https://" + clean_t

    try:
        async with httpx.AsyncClient(
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            timeout=10.0,
            follow_redirects=True
        ) as client:
            resp = await client.get(clean_t)
            headers = resp.headers

            # Key security headers analysis
            hsts = headers.get("strict-transport-security")
            csp = headers.get("content-security-policy")
            xfo = headers.get("x-frame-options")
            xcto = headers.get("x-content-type-options")
            referrer = headers.get("referrer-policy")
            permissions = headers.get("permissions-policy") or headers.get("feature-policy")
            server = headers.get("server")
            x_powered_by = headers.get("x-powered-by")
            cors = headers.get("access-control-allow-origin")

            score = 0
            max_score = 6
            findings = []

            # 1. HSTS
            if hsts:
                score += 1
                findings.append({"header": "Strict-Transport-Security", "status": "pass", "value": hsts, "desc": "فعال - تضمین ارتباط امن HTTPS"})
            else:
                findings.append({"header": "Strict-Transport-Security", "status": "fail", "value": None, "desc": "غیرفعال - آسیب‌پذیر به حملات SSL-Strip"})

            # 2. CSP
            if csp:
                score += 1
                findings.append({"header": "Content-Security-Policy", "status": "pass", "value": csp[:100] + ("..." if len(csp) > 100 else ""), "desc": "فعال - محافظت در برابر XSS و تزریق اسکریپت"})
            else:
                findings.append({"header": "Content-Security-Policy", "status": "fail", "value": None, "desc": "غیرفعال - ریسک بالای حملات XSS"})

            # 3. X-Frame-Options
            if xfo:
                score += 1
                findings.append({"header": "X-Frame-Options", "status": "pass", "value": xfo, "desc": f"فعال ({xfo}) - محافظت در برابر Clickjacking"})
            else:
                findings.append({"header": "X-Frame-Options", "status": "fail", "value": None, "desc": "غیرفعال - ریسک جعل کلیک (Clickjacking)"})

            # 4. X-Content-Type-Options
            if xcto and "nosniff" in xcto.lower():
                score += 1
                findings.append({"header": "X-Content-Type-Options", "status": "pass", "value": xcto, "desc": "فعال (nosniff) - جلوگیری از حدس نوع فایل"})
            else:
                findings.append({"header": "X-Content-Type-Options", "status": "fail", "value": None, "desc": "غیرفعال - ریسک MIME Sniffing"})

            # 5. Referrer-Policy
            if referrer:
                score += 1
                findings.append({"header": "Referrer-Policy", "status": "pass", "value": referrer, "desc": f"فعال ({referrer}) - کنترل نشت آدرس‌های ارجاعی"})
            else:
                findings.append({"header": "Referrer-Policy", "status": "warn", "value": None, "desc": "تنظیم نشده - امکان نشت در هدر Referer"})

            # 6. Permissions-Policy
            if permissions:
                score += 1
                findings.append({"header": "Permissions-Policy", "status": "pass", "value": permissions[:80], "desc": "فعال - محدودسازی دسترسی به دوربین و میکروفون"})
            else:
                findings.append({"header": "Permissions-Policy", "status": "warn", "value": None, "desc": "غیرفعال"})

            # Information Leaks
            leaks = []
            if server:
                leaks.append(f"Server: {server}")
            if x_powered_by:
                leaks.append(f"X-Powered-By: {x_powered_by}")

            # Grade calculation
            grade_pct = (score / max_score) * 100
            if grade_pct >= 85:
                grade = "A"
            elif grade_pct >= 65:
                grade = "B"
            elif grade_pct >= 45:
                grade = "C"
            elif grade_pct >= 25:
                grade = "D"
            else:
                grade = "F"

            return {
                "success": True,
                "target_url": str(resp.url),
                "status_code": resp.status_code,
                "grade": grade,
                "score": f"{score}/{max_score}",
                "findings": findings,
                "information_leaks": leaks,
                "cors": cors,
            }
    except Exception as e:
        logger.warning(f"HTTP headers audit error for {clean_t} - {e}")
        return {
            "success": False,
            "target_url": clean_t,
            "error": f"خطا در ارسال درخواست به سرور: {str(e)}"
        }


def format_ssl_report(data: Dict[str, Any]) -> str:
    """Formats SSL certificate report in Persian Telegram HTML."""
    if not data.get("success"):
        return f"🔒 <b>خطا در استعلام گواهی SSL:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    domain = html.escape(data.get("domain", ""))
    cn = html.escape(data.get("common_name", "") or domain)
    issuer = html.escape(data.get("issuer_org", "نامشخص"))
    tls_ver = html.escape(data.get("tls_version", ""))
    cipher = html.escape(data.get("cipher", ""))
    days = data.get("days_remaining")
    is_exp = data.get("is_expired", False)

    if is_exp:
        status_txt = "🚨 <b>منقضی‌شده (Expired)</b>"
    elif days is not None:
        status_txt = f"✅ معتبر ({days} روز باقی‌مانده)"
    else:
        status_txt = "✅ معتبر"

    lines = [
        f"🔒 <b>گزارش بازرسی گواهی امنیتی SSL/TLS:</b> <code>{domain}</code>\n",
        f"• <b>نام دامنه اصلی (CN):</b> <code>{cn}</code>",
        f"• <b>صادرکننده گواهی (Issuer):</b> <code>{issuer}</code>",
        f"• <b>وضعیت اعتبار:</b> {status_txt}",
        f"• <b>پروتکل ارتباطی:</b> <code>{tls_ver}</code> | <b>الگوریتم رمزنگاری:</b> <code>{cipher}</code>",
        f"• <b>تاریخ انقضا:</b> <code>{data.get('valid_until', 'نامشخص')}</code>",
    ]

    sans = data.get("sans", [])
    if sans:
        sans_lines = [f"• <code>{html.escape(s)}</code>" for s in sans[:20]]
        if len(sans) > 20:
            sans_lines.append(f"<i>... و {len(sans) - 20} زیردامنه دیگر</i>")
        sans_block = "\n".join(sans_lines)
        lines.append(f"\n🌐 <b>ساب‌دامین‌ها و دامنه‌های مشمول گواهی (SANs - {len(sans)} مورد):</b>\n{wrap_in_expandable_blockquote(sans_block)}")

    lines.append("\n⚡️ <i>استخراج بلادرنگ مشخصات رمزنگاری و زنجیره اعتماد سرور</i>")
    return "\n".join(lines)


def format_http_headers_report(data: Dict[str, Any]) -> str:
    """Formats HTTP security headers audit report in Persian Telegram HTML."""
    if not data.get("success"):
        return f"🛡 <b>خطا در بررسی هدرهای امنیتی:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    url = html.escape(data.get("target_url", ""))
    grade = data.get("grade", "F")
    score = data.get("score", "0/6")

    grade_badge = {
        "A": "🟢 رتبه A (عالی)",
        "B": "🟡 رتبه B (خوب)",
        "C": "🟠 رتبه C (متوسط)",
        "D": "🔴 رتبه D (ضعیف)",
        "F": "🚨 رتبه F (بحرانی)",
    }.get(grade, f"رتبه {grade}")

    lines = [
        f"🛡 <b>ارزیابی هدرهای امنیتی وب (Security Headers Audit):</b>\n<code>{url}</code>\n",
        f"📊 <b>سطح امنیت کلی:</b> {grade_badge} (امتیاز: <code>{score}</code>)\n",
        "📋 <b>وضعیت مکانیزم‌های دفاعی:</b>",
    ]

    for f in data.get("findings", []):
        icon = "✅" if f["status"] == "pass" else ("⚠️" if f["status"] == "warn" else "❌")
        lines.append(f"{icon} <b>{f['header']}:</b> {f['desc']}")

    leaks = data.get("information_leaks", [])
    if leaks:
        leak_txt = "\n".join([f"• <code>{html.escape(l)}</code>" for l in leaks])
        lines.append(f"\n⚠️ <b>افشای نسخه و اطلاعات سرور (Banner Grabbing):</b>\n{wrap_in_expandable_blockquote(leak_txt)}")

    cors = data.get("cors")
    if cors:
        lines.append(f"\n🌐 <b>سیاست CORS:</b> <code>{html.escape(cors)}</code>")

    lines.append("\n⚡️ <i>ارزیابی استاندارد OWASP برای پیکربندی امن وب‌سرور</i>")
    return "\n".join(lines)
