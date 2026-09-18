"""
Prometheus OSINT Suite - Subnet & CIDR Arithmetic & Reverse DNS PTR Discovery Engine.
Calculates network ranges, broadcast, wildcard masks, usable hosts,
and concurrently resolves reverse DNS PTR hostnames across the subnet.
"""

import ipaddress
import socket
import html
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
import dns.resolver

from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_Subnet")


def _get_ipv4_class(ip_str: str) -> str:
    """Returns traditional IPv4 class (A, B, C, D, E)."""
    try:
        first_octet = int(ip_str.split(".")[0])
        if 1 <= first_octet <= 126:
            return "Class A"
        elif 128 <= first_octet <= 191:
            return "Class B"
        elif 192 <= first_octet <= 223:
            return "Class C"
        elif 224 <= first_octet <= 239:
            return "Class D (Multicast)"
        elif 240 <= first_octet <= 255:
            return "Class E (Experimental)"
    except Exception:
        pass
    return "نامشخص"


async def _resolve_ptr_single(ip_str: str) -> Tuple[str, Optional[str]]:
    """Non-blocking PTR lookup for a single IP."""
    def _sync():
        try:
            return socket.gethostbyaddr(ip_str)[0]
        except Exception:
            return None

    hostname = await asyncio.to_thread(_sync)
    return ip_str, hostname


async def calculate_subnet_and_scan_ptr(cidr_input: str, max_ptr_scan: int = 32) -> Dict[str, Any]:
    """
    Computes complete CIDR parameters and conducts mass asynchronous PTR reverse lookups.
    """
    clean_input = cidr_input.strip()
    if "/" not in clean_input:
        # Default single IP to /32 or /128
        clean_input += "/32" if ":" not in clean_input else "/128"

    try:
        net = ipaddress.ip_network(clean_input, strict=False)
    except Exception as e:
        return {
            "success": False,
            "input": cidr_input,
            "error": f"ساختار محدوده CIDR یا آی‌پی نامعتبر است: {e}",
        }

    is_v4 = net.version == 4
    num_addresses = net.num_addresses

    # Usable hosts calculation
    if is_v4:
        if net.prefixlen == 32:
            usable_hosts = 1
            first_usable = str(net.network_address)
            last_usable = str(net.network_address)
        elif net.prefixlen == 31:
            usable_hosts = 2
            first_usable = str(net.network_address)
            last_usable = str(net.broadcast_address)
        else:
            usable_hosts = max(num_addresses - 2, 0)
            first_usable = str(net.network_address + 1)
            last_usable = str(net.broadcast_address - 1)
        broadcast_addr = str(net.broadcast_address)
        netmask_str = str(net.netmask)
        wildcard_str = str(net.hostmask)
        ip_class = _get_ipv4_class(str(net.network_address))
    else:
        usable_hosts = num_addresses
        first_usable = str(net.network_address)
        last_usable = str(net[-1])
        broadcast_addr = "N/A (IPv6 uses Multicast)"
        netmask_str = str(net.netmask)
        wildcard_str = str(net.hostmask)
        ip_class = "IPv6"

    # Scope detection
    scope = "عمومی اینترنت (Public IP)"
    if net.is_private:
        scope = "شبکه خصوصی محلی (Private RFC 1918 / Unique Local)"
    elif net.is_loopback:
        scope = "آدرس لوپ‌بک سیستم (Loopback)"
    elif net.is_reserved:
        scope = "آدرس رزروشده IETF"

    # Reverse DNS PTR Discovery Scan
    # Limit scanning to max_ptr_scan IPs to keep response fast (<1.5s)
    ptr_results: List[Dict[str, str]] = []
    if is_v4:
        # Collect IPs to scan
        scan_targets = []
        if net.prefixlen >= 24 or num_addresses <= max_ptr_scan:
            for ip in net.hosts():
                scan_targets.append(str(ip))
                if len(scan_targets) >= max_ptr_scan:
                    break
        else:
            # For larger blocks, scan first 16 and last 16
            for ip in list(net.hosts())[:16]:
                scan_targets.append(str(ip))

        if scan_targets:
            tasks = [_resolve_ptr_single(ip) for ip in scan_targets]
            resolved = await asyncio.gather(*tasks)
            for ip_s, h_name in resolved:
                if h_name:
                    ptr_results.append({"ip": ip_s, "hostname": h_name})

    return {
        "success": True,
        "input": cidr_input,
        "cidr": str(net),
        "version": f"IPv{net.version}",
        "network_address": str(net.network_address),
        "broadcast_address": broadcast_addr,
        "netmask": netmask_str,
        "wildcard_mask": wildcard_str,
        "prefix_len": net.prefixlen,
        "total_addresses": num_addresses,
        "usable_hosts": usable_hosts,
        "first_usable": first_usable,
        "last_usable": last_usable,
        "ip_class": ip_class,
        "scope": scope,
        "ptr_discovered_count": len(ptr_results),
        "ptr_records": ptr_results,
    }


def format_subnet_report(data: Dict[str, Any]) -> str:
    """Formats subnet calculations and PTR discovery results into Persian Telegram HTML."""
    if not data.get("success"):
        return f"📐 <b>خطا در تحلیل محدوده شبکه (Subnet/CIDR):</b> {html.escape(data.get('error', 'ناشناخته'))}"

    cidr = html.escape(data.get("cidr", ""))
    net_addr = html.escape(data.get("network_address", ""))
    bcast = html.escape(data.get("broadcast_address", ""))
    nmask = html.escape(data.get("netmask", ""))
    wmask = html.escape(data.get("wildcard_mask", ""))
    first_u = html.escape(data.get("first_usable", ""))
    last_u = html.escape(data.get("last_usable", ""))
    total_addrs = data.get("total_addresses", 0)
    usable_hosts = data.get("usable_hosts", 0)
    scope = html.escape(data.get("scope", ""))
    ip_class = html.escape(data.get("ip_class", ""))

    lines = [
        f"📐 <b>کالبدشکافی و محاسبات مهندسی ساب‌نت (Subnet & CIDR Intelligence):</b>\n<code>{cidr}</code>\n",
        f"• <b>آدرس شبکه (Network ID):</b> <code>{net_addr}</code>",
        f"• <b>آدرس برودکست (Broadcast):</b> <code>{bcast}</code>",
        f"• <b>نت‌ماسک (Subnet Mask):</b> <code>{nmask}</code>",
        f"• <b>ماسک وایلدکارد (Wildcard):</b> <code>{wmask}</code>",
        f"• <b>دامنه هاست‌های قابل استفاده:</b>\n  <code>{first_u}</code> <b>تا</b> <code>{last_u}</code>",
        f"• <b>تعداد کل آدرس‌ها:</b> <code>{total_addrs:,}</code> | هاست مفید: <code>{usable_hosts:,}</code>",
        f"• <b>کلاس شبکه و دامنه:</b> <code>{ip_class}</code> ({scope})\n",
    ]

    # PTR Discovery Section
    ptr_list = data.get("ptr_records", [])
    if ptr_list:
        ptr_lines = [f"• <code>{html.escape(p['ip'])}</code> ➔ <b>{html.escape(p['hostname'])}</b>" for p in ptr_list]
        lines.append(f"🔍 <b>هاست‌های شناسایی‌شده با اسکن Reverse DNS PTR ({len(ptr_list)} سرور):</b>\n" + wrap_in_expandable_blockquote("\n".join(ptr_lines)))
    else:
        lines.append("🔍 <b>اسکن Reverse DNS:</b> هیچ نام دامنه‌ای (PTR) روی این محدوده ثبت نشده است.")

    lines.append("\n⚡️ <i>محاسبات ساختار IPv4/IPv6 بر اساس استانداردهای RFC 4632 و پویش بلادرنگ PTR</i>")
    return "\n".join(lines)
