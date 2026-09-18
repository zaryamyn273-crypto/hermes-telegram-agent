"""
Prometheus OSINT Suite - BGP Routing, Autonomous System (ASN) & Topology Intelligence.
Queries global RIR data and RIPE Stat for AS holders, announced IP prefixes,
upstream routing providers, peerings, and network topology.
"""

import re
import socket
import html
import logging
import asyncio
from typing import Dict, Any, List, Optional
import httpx

from utils.cache import bgp_cache
from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_BGP")


def _extract_asn_number(target: str) -> Optional[int]:
    """Extracts integer ASN from string like 'AS15169', 'as 15169', or '15169'."""
    m = re.search(r"(?:AS)?\s*(\d{1,10})\b", target, re.I)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


async def lookup_bgp_asn_intel(target: str) -> Dict[str, Any]:
    """
    Comprehensive BGP and Autonomous System intelligence lookup.
    Accepts an ASN (e.g. 'AS15169'), IP address, or domain name.
    """
    clean_target = target.strip()
    asn_num = _extract_asn_number(clean_target)
    resolved_ip = ""

    # If not direct ASN, try resolving domain or IP to ASN
    if not asn_num:
        host_or_ip = re.sub(r"^https?://", "", clean_target).split("/")[0].split(":")[0].strip()
        try:
            # Check if domain needs DNS resolution
            try:
                socket.inet_aton(host_or_ip)
                resolved_ip = host_or_ip
            except socket.error:
                resolved_ip = await asyncio.to_thread(socket.gethostbyname, host_or_ip)

            # Query ASN for this IP
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.get(f"http://ip-api.com/json/{resolved_ip}?fields=as")
                if res.status_code == 200:
                    as_str = res.json().get("as", "")
                    asn_num = _extract_asn_number(as_str)
        except Exception as e:
            logger.debug(f"Failed to resolve ASN from target {clean_target}: {e}")

    if not asn_num:
        return {
            "success": False,
            "target": clean_target,
            "error": "شناسه سامانه خودمختار (ASN) یا آی‌پی معتبر برای مسیریابی BGP یافت نشد.",
        }

    asn_key = f"AS{asn_num}"
    cached = await bgp_cache.get(asn_key)
    if cached:
        logger.debug(f"BGP cache hit for {asn_key}")
        return cached

    # Query RIPE Stat endpoints concurrently
    headers = {"User-Agent": "Mozilla/5.0 (Prometheus OSINT Suite)"}
    async with httpx.AsyncClient(headers=headers, timeout=6.5) as client:
        overview_url = f"https://stat.ripe.net/data/as-overview/data.json?resource={asn_key}"
        prefixes_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn_key}"
        neighbours_url = f"https://stat.ripe.net/data/asn-neighbours/data.json?resource={asn_key}"

        tasks = [
            client.get(overview_url),
            client.get(prefixes_url),
            client.get(neighbours_url),
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    # Process Overview
    holder = "نامشخص"
    announced = False
    block_type = ""
    if not isinstance(responses[0], Exception) and responses[0].status_code == 200:
        ov_data = responses[0].json().get("data", {})
        holder = ov_data.get("holder", "نامشخص")
        announced = ov_data.get("announced", False)
        block_type = ov_data.get("block", {}).get("name", "")

    # Process Announced Prefixes
    v4_prefixes = []
    v6_prefixes = []
    if not isinstance(responses[1], Exception) and responses[1].status_code == 200:
        pref_data = responses[1].json().get("data", {}).get("prefixes", [])
        for p in pref_data:
            prefix_str = p.get("prefix", "")
            if ":" in prefix_str:
                v6_prefixes.append(prefix_str)
            elif "." in prefix_str:
                v4_prefixes.append(prefix_str)

    # Process Neighbours / Routing Topology
    upstreams: List[int] = []
    downstreams: List[int] = []
    peers: List[int] = []
    if not isinstance(responses[2], Exception) and responses[2].status_code == 200:
        neigh_data = responses[2].json().get("data", {}).get("neighbours", [])
        for n in neigh_data:
            ntype = n.get("type", "")
            n_asn = n.get("asn")
            if not n_asn:
                continue
            if ntype == "left":
                upstreams.append(n_asn)
            elif ntype == "right":
                downstreams.append(n_asn)
            else:
                peers.append(n_asn)

    result = {
        "success": True,
        "target": clean_target,
        "asn": asn_key,
        "asn_number": asn_num,
        "resolved_ip": resolved_ip,
        "holder": holder,
        "is_announced": announced,
        "registry_block": block_type,
        "v4_prefixes_count": len(v4_prefixes),
        "v6_prefixes_count": len(v6_prefixes),
        "total_prefixes_count": len(v4_prefixes) + len(v6_prefixes),
        "sample_v4_prefixes": v4_prefixes[:8],
        "sample_v6_prefixes": v6_prefixes[:4],
        "upstreams_count": len(upstreams),
        "downstreams_count": len(downstreams),
        "peers_count": len(peers),
        "sample_upstreams": [f"AS{a}" for a in upstreams[:8]],
        "sample_downstreams": [f"AS{a}" for a in downstreams[:8]],
    }

    await bgp_cache.set(asn_key, result, ttl=3600.0)
    return result


def format_bgp_report(data: Dict[str, Any]) -> str:
    """Formats BGP routing and Autonomous System intelligence into Persian Telegram HTML."""
    if not data.get("success"):
        return f"📡 <b>خطا در استعلام مسیریابی BGP:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    asn = html.escape(data.get("asn", ""))
    holder = html.escape(data.get("holder", "نامشخص"))
    is_ann = data.get("is_announced", False)
    v4_cnt = data.get("v4_prefixes_count", 0)
    v6_cnt = data.get("v6_prefixes_count", 0)
    total_pref = data.get("total_prefixes_count", 0)
    up_cnt = data.get("upstreams_count", 0)
    down_cnt = data.get("downstreams_count", 0)

    status_badge = "🟢 فعال و در حال تبلیغ (Announced)" if is_ann else "🔴 غیرفعال (Unannounced)"

    lines = [
        f"📡 <b>کالبدشکافی مسیریابی جهانی اینترنت و سامانه خودمختار (BGP & ASN Intel):</b>\n",
        f"• <b>شماره سامانه (ASN):</b> <code>{asn}</code>",
        f"• <b>مالک و اپراتور (Holder):</b> <b>{holder}</b>",
        f"• <b>وضعیت در جدول جهانی BGP:</b> {status_badge}",
        f"• <b>مجموع بلاک‌های IP تبلیغ‌شده:</b> <code>{total_pref:,}</code> (IPv4: <code>{v4_cnt:,}</code> | IPv6: <code>{v6_cnt:,}</code>)",
        f"• <b>تامین‌کنندگان بالادستی (Upstream Transit):</b> <code>{up_cnt:,}</code> شبکه",
        f"• <b>مشتریان و هم‌پایگان (Downstreams/Peers):</b> <code>{down_cnt:,}</code> شبکه\n",
    ]

    # Sample Upstreams
    up_samples = data.get("sample_upstreams", [])
    if up_samples:
        lines.append(f"🔗 <b>ارائه‌دهندگان بالادستی اینترنت (Upstreams - نمونه):</b>\n<code>{', '.join(up_samples)}</code>\n")

    # Sample Prefixes Block
    v4_samples = data.get("sample_v4_prefixes", [])
    if v4_samples:
        pref_lines = [f"• <code>{html.escape(p)}</code>" for p in v4_samples]
        if data.get("sample_v6_prefixes"):
            pref_lines.extend([f"• <code>{html.escape(p)}</code> (IPv6)" for p in data["sample_v6_prefixes"]])
        lines.append(f"🌐 <b>پیشوندهای مسیریابی اعلام‌شده (Announced CIDR Prefixes):</b>\n" + wrap_in_expandable_blockquote("\n".join(pref_lines)))

    lines.append("\n⚡️ <i>استعلام بلادرنگ از مراجع رسمی هماهنگی شبکه‌های اینترنتی جهان (RIPE NCC & RIRs)</i>")
    return "\n".join(lines)
