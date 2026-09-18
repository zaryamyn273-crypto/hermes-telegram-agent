"""
Prometheus OSINT Suite - IP Threat Reputation, Tor, Proxy & Abuse Intelligence Engine.
Evaluates IP addresses for malicious reputation, active Tor exit node presence,
cloud hosting providers, DNSBL blacklists, and AlienVault OTX threat pulses.
"""

import re
import socket
import ipaddress
import html
import datetime
import logging
import asyncio
from typing import Dict, Any, List, Optional, Set
import httpx
import dns.resolver

from utils.cache import threat_intel_cache
from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_ThreatIntel")

# Cache for Tor exit nodes set & timestamp
_TOR_EXIT_NODES: Set[str] = set()
_TOR_LAST_FETCH: float = 0.0
_TOR_CACHE_TTL: float = 3600.0  # 1 hour

_KNOWN_HOSTING_PROVIDERS = [
    ("Amazon Web Services / AWS", re.compile(r"amazon|aws", re.I)),
    ("Google Cloud Platform / GCP", re.compile(r"google cloud|google llc", re.I)),
    ("Microsoft Azure", re.compile(r"microsoft|azure", re.I)),
    ("Cloudflare", re.compile(r"cloudflare", re.I)),
    ("DigitalOcean", re.compile(r"digitalocean", re.I)),
    ("Hetzner Online", re.compile(r"hetzner", re.I)),
    ("OVH SAS", re.compile(r"ovh", re.I)),
    ("Linode / Akamai", re.compile(r"linode|akamai", re.I)),
    ("Vultr / Choopa", re.compile(r"vultr|choopa", re.I)),
    ("Oracle Cloud", re.compile(r"oracle", re.I)),
    ("Alibaba Cloud", re.compile(r"alibaba|aliyun", re.I)),
]

_DNSBL_ZONES = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("b.barracudacentral.org", "Barracuda"),
    ("dnsbl.sorbs.net", "SORBS"),
]


async def _get_tor_exit_nodes() -> Set[str]:
    """Fetches and caches the official Tor Project bulk exit node list."""
    global _TOR_EXIT_NODES, _TOR_LAST_FETCH
    now = datetime.datetime.utcnow().timestamp()
    if _TOR_EXIT_NODES and (now - _TOR_LAST_FETCH) < _TOR_CACHE_TTL:
        return _TOR_EXIT_NODES

    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get("https://check.torproject.org/torbulkexitlist")
            if resp.status_code == 200:
                nodes = {line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")}
                _TOR_EXIT_NODES = nodes
                _TOR_LAST_FETCH = now
                logger.info(f"Loaded {len(_TOR_EXIT_NODES)} active Tor exit nodes.")
    except Exception as e:
        logger.warning(f"Failed to fetch Tor bulk exit list: {e}")

    return _TOR_EXIT_NODES


async def _check_dnsbl_single(reversed_ip: str, zone: str, zone_name: str) -> Optional[Dict[str, str]]:
    """Checks a single DNSBL zone for an IP."""
    query = f"{reversed_ip}.{zone}"
    def _query():
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            answers = resolver.resolve(query, "A")
            res_ips = [str(r.to_text()) for r in answers]
            return res_ips
        except Exception:
            return None

    res = await asyncio.to_thread(_query)
    if res:
        return {"zone": zone, "name": zone_name, "return_codes": res}
    return None


async def inspect_ip_threat_reputation(target: str) -> Dict[str, Any]:
    """
    Comprehensive threat reputation check:
    - Tor exit node detection
    - Hosting / Cloud provider detection
    - Multi-zone DNSBL blacklist checking
    - AlienVault OTX threat pulses & malware tags
    - Calculates Threat Risk Score (0-100)
    """
    clean_target = target.strip().lower()
    clean_target = re.sub(r"^https?://", "", clean_target).split("/")[0].split(":")[0].strip()

    # Resolve hostname to IP if domain passed
    ip_str = clean_target
    is_domain = False
    try:
        ipaddress.ip_address(clean_target)
    except ValueError:
        is_domain = True
        try:
            ip_str = await asyncio.to_thread(socket.gethostbyname, clean_target)
        except Exception as e:
            return {
                "success": False,
                "target": clean_target,
                "error": f"دامنه به هیچ آی‌پی معتبری اشاره نمی‌کند: {e}",
            }

    cached = await threat_intel_cache.get(ip_str)
    if cached:
        logger.debug(f"Threat intel cache hit for {ip_str}")
        return cached

    # Check for private or bogon IPs
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
            return {
                "success": True,
                "target": clean_target,
                "ip": ip_str,
                "is_private": True,
                "threat_score": 0,
                "risk_level": "امن (شبکه خصوصی / Local)",
                "details": "آدرس در محدوده شبکه‌های محلی (RFC 1918) یا آدرس‌های رزروشده قرار دارد.",
                "is_tor_exit": False,
                "is_datacenter": False,
                "blacklists": [],
                "otx_pulses_count": 0,
            }
    except Exception:
        pass

    # 1. Tor Exit Node Check
    tor_nodes = await _get_tor_exit_nodes()
    is_tor_exit = ip_str in tor_nodes

    # 2. DNSBL checks (for IPv4 only)
    blacklists: List[Dict[str, Any]] = []
    if ":" not in ip_str:
        octets = ip_str.split(".")
        reversed_ip = ".".join(reversed(octets))
        tasks = [_check_dnsbl_single(reversed_ip, z[0], z[1]) for z in _DNSBL_ZONES]
        dnsbl_results = await asyncio.gather(*tasks)
        blacklists = [r for r in dnsbl_results if r]

    # 3. AlienVault OTX Threat Pulses Check
    otx_pulses_count = 0
    otx_tags: List[str] = []
    otx_malware_families: List[str] = []
    otx_adversaries: List[str] = []
    try:
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_str}/general"
        async with httpx.AsyncClient(timeout=4.5) as client:
            resp = await client.get(otx_url)
            if resp.status_code == 200:
                otx_data = resp.json()
                pulse_info = otx_data.get("pulse_info", {})
                otx_pulses_count = pulse_info.get("count", 0)
                pulses = pulse_info.get("pulses", [])
                for p in pulses[:5]:
                    for tag in p.get("tags", []):
                        if tag and tag not in otx_tags:
                            otx_tags.append(tag)
                    for mal in p.get("malware_families", []):
                        m_name = mal.get("display_name")
                        if m_name and m_name not in otx_malware_families:
                            otx_malware_families.append(m_name)
                    adv = p.get("adversary")
                    if adv and adv not in otx_adversaries:
                        otx_adversaries.append(adv)
    except Exception as e:
        logger.debug(f"AlienVault OTX lookup failed for {ip_str}: {e}")

    # 4. Detect Datacenter / Cloud Provider
    is_datacenter = False
    detected_provider = "نامشخص / مسکونی (Residential/ISP)"
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            res = await client.get(f"http://ip-api.com/json/{ip_str}?fields=isp,org,as,hosting")
            if res.status_code == 200:
                ip_meta = res.json()
                combined = f"{ip_meta.get('isp', '')} {ip_meta.get('org', '')} {ip_meta.get('as', '')}"
                is_datacenter = ip_meta.get("hosting", False)
                for p_name, p_regex in _KNOWN_HOSTING_PROVIDERS:
                    if p_regex.search(combined):
                        is_datacenter = True
                        detected_provider = p_name
                        break
                if is_datacenter and detected_provider.startswith("نامشخص"):
                    detected_provider = ip_meta.get("isp") or ip_meta.get("org") or "دیتاسنتر ابری"
    except Exception:
        pass

    # 5. Compute Consolidated Threat Score (0 to 100)
    threat_score = 0
    threat_factors = []

    if is_tor_exit:
        threat_score += 45
        threat_factors.append("نود خروجی فعال شبکه ناشناس تور (Tor Exit Node)")

    if blacklists:
        bl_points = min(len(blacklists) * 25, 50)
        threat_score += bl_points
        bl_names = ", ".join([b["name"] for b in blacklists])
        threat_factors.append(f"ثبت در لیست‌های سیاه هرزنامه/حمله ({bl_names})")

    if otx_pulses_count > 0:
        otx_points = min(otx_pulses_count * 15, 45)
        threat_score += otx_points
        threat_factors.append(f"دارای {otx_pulses_count} گزارش تهدید و نفوذ در AlienVault OTX")

    if otx_malware_families:
        threat_score += 25
        threat_factors.append(f"ارتباط مستقیم با بدافزارهای: {', '.join(otx_malware_families[:3])}")

    threat_score = min(threat_score, 100)

    # Risk level classification
    if threat_score >= 75:
        risk_level = "🔴 بحرانی (خطر بالا / آلوده به بدافزار یا نود ناشناس)"
    elif threat_score >= 45:
        risk_level = "🟠 مشکوک و ناامن (دارای سابقه حمله یا مسدودسازی)"
    elif threat_score >= 20:
        risk_level = "🟡 نیازمند احتیاط (مشکوک در برخی پایگاه‌ها)"
    else:
        risk_level = "🟢 پاک و کم‌خطر (بدون گزارش تهدید معتبر)"

    result = {
        "success": True,
        "target": clean_target,
        "ip": ip_str,
        "is_domain": is_domain,
        "is_private": False,
        "threat_score": threat_score,
        "risk_level": risk_level,
        "threat_factors": threat_factors,
        "is_tor_exit": is_tor_exit,
        "is_datacenter": is_datacenter,
        "hosting_provider": detected_provider,
        "blacklists_count": len(blacklists),
        "blacklists": blacklists,
        "otx_pulses_count": otx_pulses_count,
        "otx_tags": otx_tags[:8],
        "otx_malware_families": otx_malware_families,
        "otx_adversaries": otx_adversaries,
    }

    await threat_intel_cache.set(ip_str, result, ttl=900.0)
    return result


def format_threat_intel_report(data: Dict[str, Any]) -> str:
    """Formats IP threat intelligence and reputation audit into Persian Telegram HTML."""
    if not data.get("success"):
        return f"🚨 <b>خطا در ارزیابی تهدید آی‌پی:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    ip = html.escape(data.get("ip", ""))
    target = html.escape(data.get("target", ""))
    score = data.get("threat_score", 0)
    risk = data.get("risk_level", "نامشخص")
    is_tor = data.get("is_tor_exit", False)
    provider = html.escape(data.get("hosting_provider", "نامشخص"))

    if data.get("is_private"):
        return (
            f"🛡 <b>ارزیابی شهرت امنیتی آی‌پی (IP Threat Intelligence):</b>\n"
            f"<code>{ip}</code>\n\n"
            f"🟢 <b>وضعیت:</b> {risk}\n"
            f"ℹ️ {data.get('details', '')}"
        )

    lines = [
        f"🚨 <b>ارزیابی شهرت امنیتی و هوش تهدیدات آی‌پی (IP Threat & Abuse):</b>\n<code>{ip}</code>" + (f" (دامنه: <code>{target}</code>)" if data.get("is_domain") else "") + "\n",
        f"📊 <b>ضریب تهدید امنیتی:</b> <code>{score}/100</code>",
        f"🛡 <b>سطح ریسک:</b> <b>{risk}</b>",
        f"🧅 <b>نود خروجی تور (Tor Exit):</b> {'🚨 بله (فعال)' if is_tor else 'خیر (معمولی)'}",
        f"🏢 <b>نوع و میزبان شبکه:</b> <code>{provider}</code>\n",
    ]

    # Threat factors
    factors = data.get("threat_factors", [])
    if factors:
        lines.append("⚠️ <b>شاخص‌های ریسک و سوابق شناسایی‌شده:</b>")
        for f in factors:
            lines.append(f"• {html.escape(f)}")
        lines.append("")

    # DNSBL Blacklists
    bls = data.get("blacklists", [])
    if bls:
        bl_lines = [f"• <b>{html.escape(b['name'])}</b>: مسدودشده (کد: {', '.join(b['return_codes'])})" for b in bls]
        lines.append(f"🚫 <b>لیست‌های سیاه DNSBL ({len(bls)} مورد):</b>\n" + wrap_in_expandable_blockquote("\n".join(bl_lines)))
    else:
        lines.append("✅ <b>لیست‌های سیاه DNSBL:</b> فاقد سابقه در هرزنامه‌نگارهای جهانی")

    # AlienVault OTX
    pulses = data.get("otx_pulses_count", 0)
    if pulses > 0:
        otx_txt = f"دارای <code>{pulses}</code> گزارش فعال در شبکه AlienVault OTX."
        if data.get("otx_malware_families"):
            otx_txt += f"\nبدافزارهای شناسایی‌شده: <code>{html.escape(', '.join(data['otx_malware_families']))}</code>"
        if data.get("otx_tags"):
            otx_txt += f"\nبرچسب‌ها: <i>{html.escape(', '.join(data['otx_tags']))}</i>"
        lines.append(f"\n📡 <b>هوش تهدیدات OTX AlienVault:</b>\n{wrap_in_expandable_blockquote(otx_txt)}")

    lines.append("\n⚡️ <i>استعلام بلادرنگ از مراجع بین‌المللی رصد بدافزارها، خروجی‌های Tor و پایگاه‌های DNSBL</i>")
    return "\n".join(lines)
