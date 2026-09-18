"""
Prometheus OSINT Suite - Domain WHOIS & RDAP Intelligence Engine
Fetches domain registration records, registrar information, creation/expiration dates,
status flags, and nameservers using RESTful RDAP with socket WHOIS fallback.
"""

import re
import socket
import datetime
import html
import logging
from typing import Dict, Any, List, Optional
import httpx
import asyncio

from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_Whois")

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Accept": "application/rdap+json, application/json",
}


def _clean_domain(domain_or_url: str) -> str:
    """Extracts a clean hostname/domain from user input."""
    d = domain_or_url.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0].strip()
    return d


def _socket_whois(domain: str, server: str = "whois.iana.org", timeout: float = 5.0) -> str:
    """Performs traditional socket WHOIS query via port 43."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, 43))
        s.send((domain + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        s.close()
        text = b"".join(chunks).decode("utf-8", errors="replace")
        
        # Check if referral server exists
        ref_match = re.search(r"(?:refer|whois server):\s*([a-zA-Z0-9.-]+)", text, re.I)
        if ref_match and ref_match.group(1).strip().lower() != server.lower():
            ref_server = ref_match.group(1).strip()
            # Follow referral once
            return _socket_whois(domain, server=ref_server, timeout=timeout)
        return text
    except Exception as e:
        return f"WHOIS error: {str(e)}"


async def lookup_domain_whois(domain: str) -> Dict[str, Any]:
    """
    Unified WHOIS & RDAP domain intelligence.
    Queries modern RDAP protocol first; falls back to traditional port 43 WHOIS if necessary.
    """
    clean_d = _clean_domain(domain)
    if not clean_d or "." not in clean_d:
        return {"success": False, "domain": clean_d, "error": "دامنه نامعتبر است."}

    # 1. Try RDAP (Registration Data Access Protocol)
    rdap_url = f"https://rdap.org/domain/{clean_d}"
    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(rdap_url)
            if resp.status_code == 200:
                data = resp.json()
                events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
                
                created_date = events.get("registration") or events.get("created", "")
                expires_date = events.get("expiration") or events.get("expires", "")
                updated_date = events.get("last changed") or events.get("last update", "")

                # Calculate days remaining until expiry
                days_left = None
                is_expired = False
                if expires_date:
                    try:
                        exp_clean = expires_date.split("T")[0]
                        exp_dt = datetime.datetime.strptime(exp_clean, "%Y-%m-%d")
                        now_dt = datetime.datetime.utcnow()
                        days_left = (exp_dt - now_dt).days
                        is_expired = days_left < 0
                    except Exception:
                        pass

                # Extract Nameservers
                nameservers = []
                for ns in data.get("nameservers", []):
                    ns_name = ns.get("ldhName") or ns.get("handle") or ""
                    if ns_name:
                        nameservers.append(ns_name.lower())

                # Extract Registrar
                registrar_name = "نامشخص"
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles or "sponsor" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if prop[0] == "fn":
                                    registrar_name = prop[3]
                                    break
                        if registrar_name == "نامشخص":
                            registrar_name = entity.get("handle", "نامشخص")
                        break

                statuses = data.get("status", [])

                return {
                    "success": True,
                    "protocol": "RDAP",
                    "domain": clean_d,
                    "handle": data.get("handle", ""),
                    "registrar": registrar_name,
                    "created_at": created_date.replace("T", " ").replace("Z", " UTC") if created_date else "نامشخص",
                    "expires_at": expires_date.replace("T", " ").replace("Z", " UTC") if expires_date else "نامشخص",
                    "updated_at": updated_date.replace("T", " ").replace("Z", " UTC") if updated_date else "نامشخص",
                    "days_remaining": days_left,
                    "is_expired": is_expired,
                    "nameservers": sorted(list(set(nameservers))),
                    "statuses": statuses,
                    "raw_summary": f"RDAP Handle: {data.get('handle', '')}",
                }
    except Exception as e:
        logger.debug(f"RDAP query failed for {clean_d}: {e}")

    # 2. Fallback to Socket WHOIS
    try:
        raw_text = await asyncio.to_thread(_socket_whois, clean_d)
        if raw_text and "error" not in raw_text.lower():
            # Basic parsing of common WHOIS keys
            reg_match = re.search(r"(?:registrar|registrar name):\s*(.+)", raw_text, re.I)
            created_match = re.search(r"(?:creation date|created|registration date):\s*(.+)", raw_text, re.I)
            exp_match = re.search(r"(?:registry expiry date|expiration date|expires|expire):\s*(.+)", raw_text, re.I)
            ns_matches = re.findall(r"(?:name server|nserver):\s*([a-zA-Z0-9.-]+)", raw_text, re.I)

            registrar = reg_match.group(1).strip() if reg_match else "نامشخص در پایگاه WHOIS"
            created = created_match.group(1).strip() if created_match else "نامشخص"
            expires = exp_match.group(1).strip() if exp_match else "نامشخص"

            return {
                "success": True,
                "protocol": "WHOIS-Port43",
                "domain": clean_d,
                "registrar": registrar,
                "created_at": created,
                "expires_at": expires,
                "updated_at": "نامشخص",
                "days_remaining": None,
                "is_expired": False,
                "nameservers": sorted(list(set([n.lower() for n in ns_matches])))[:8],
                "statuses": [],
                "raw_text": raw_text[:2000],
            }
    except Exception as e:
        logger.warning(f"Socket WHOIS failed for {clean_d}: {e}")

    return {
        "success": False,
        "domain": clean_d,
        "error": "عدم توانایی در دریافت رکوردهای WHOIS یا RDAP برای این دامنه."
    }


def format_whois_report(data: Dict[str, Any]) -> str:
    """Formats domain WHOIS/RDAP report into Persian Telegram HTML."""
    if not data.get("success"):
        return f"🌐 <b>خطا در استعلام WHOIS دامنه:</b> {html.escape(data.get('error', 'اطلاعاتی یافت نشد.'))}"

    domain = html.escape(data.get("domain", ""))
    registrar = html.escape(data.get("registrar", "نامشخص"))
    proto = data.get("protocol", "WHOIS")
    created = html.escape(str(data.get("created_at", "نامشخص")))
    expires = html.escape(str(data.get("expires_at", "نامشخص")))
    updated = html.escape(str(data.get("updated_at", "نامشخص")))
    days = data.get("days_remaining")
    is_exp = data.get("is_expired", False)

    if is_exp:
        status_badge = "🚨 <b>منقضی‌شده (Expired)</b>"
    elif days is not None:
        status_badge = f"✅ معتبر ({days} روز تا انقضا)"
    else:
        status_badge = "✅ فعال"

    lines = [
        f"🏛 <b>اطلاعات ثبتی و هویتی دامنه (Domain WHOIS / RDAP):</b>\n<code>{domain}</code>\n",
        f"• <b>ثبت‌کننده (Registrar):</b> <code>{registrar}</code>",
        f"• <b>وضعیت اعتبار:</b> {status_badge}",
        f"• <b>تاریخ ثبت / ایجاد:</b> <code>{created}</code>",
        f"• <b>تاریخ انقضا:</b> <code>{expires}</code>",
        f"• <b>آخرین بروزرسانی:</b> <code>{updated}</code>",
        f"• <b>پروتکل استعلام:</b> <code>{proto}</code>",
    ]

    ns = data.get("nameservers", [])
    if ns:
        ns_lines = [f"• <code>{html.escape(n)}</code>" for n in ns]
        ns_block = "\n".join(ns_lines)
        lines.append(f"\n📡 <b>نیم‌سرورها (Name Servers):</b>\n{wrap_in_expandable_blockquote(ns_block)}")

    statuses = data.get("statuses", [])
    if statuses:
        st_txt = "\n".join([f"• <code>{html.escape(s)}</code>" for s in statuses])
        lines.append(f"\n🔒 <b>وضعیت‌های امنیتی (Domain Statuses):</b>\n{wrap_in_expandable_blockquote(st_txt)}")

    raw_t = data.get("raw_text")
    if raw_t:
        lines.append(f"\n📋 <b>خلاصه خام WHOIS:</b>\n{wrap_in_expandable_blockquote(html.escape(raw_t[:1000]))}")

    lines.append("\n⚡️ <i>استعلام بلادرنگ از مراجع رسمی ثبت دامنه‌های جهانی (ICANN & RDAP)</i>")
    return "\n".join(lines)
