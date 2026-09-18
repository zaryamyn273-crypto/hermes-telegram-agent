"""
Prometheus OSINT Suite - Hardware & Network Device MAC/OUI Intelligence Engine
Identifies hardware manufacturers, virtual machine vendors (VMware, VirtualBox, KVM),
mobile device privacy randomization, and network card fingerprints from MAC addresses.
"""

import re
import html
import logging
from typing import Dict, Any, Optional
import httpx

logger = logging.getLogger("OSINT_Hardware")

# Built-in fast lookup for well-known virtual and hardware OUIs (instant zero-network fallback)
_COMMON_OUIS = {
    "005056": ("VMware, Inc.", "ماشین مجازی و تجهیزات سرور وی‌ام‌ویر"),
    "000C29": ("VMware, Inc.", "ماشین مجازی وی‌ام‌ویر"),
    "000569": ("VMware, Inc.", "ماشین مجازی وی‌ام‌ویر"),
    "080027": ("Oracle VirtualBox", "ماشین مجازی اوراکل ویرچوال‌باکس"),
    "525400": ("QEMU / KVM", "ماشین مجازی لینوکس KVM/QEMU"),
    "B827EB": ("Raspberry Pi Foundation", "مینی‌کامپیوتر رزبری‌پای"),
    "DCA632": ("Raspberry Pi Trading Ltd", "مینی‌کامپیوتر رزبری‌پای"),
    "E45F01": ("Raspberry Pi Trading Ltd", "مینی‌کامپیوتر رزبری‌پای"),
    "001A2B": ("Ayecom Technology Co., Ltd.", "تجهیزات شبکه و مخابرات"),
    "F09FC2": ("Ubiquiti Networks Inc.", "تجهیزات وایرلس و رادیویی یوبی‌کوئیتی"),
    "00156D": ("Ubiquiti Networks Inc.", "تجهیزات شبکه یوبی‌کوئیتی"),
    "488AD2": ("Cisco Systems, Inc", "سوئیچ‌ها و روترهای سیسکو"),
    "00000C": ("Cisco Systems, Inc", "تجهیزات سیسکو"),
    "001C10": ("Cisco Systems, Inc", "تجهیزات سیسکو"),
    "CC46D6": ("Cisco Systems, Inc", "تجهیزات سیسکو"),
    "BC9FE4": ("Apple, Inc.", "دستگاه‌های اپل (آیفون/مک/آیپد)"),
    "F01898": ("Apple, Inc.", "دستگاه‌های اپل"),
    "ACDE48": ("Apple, Inc.", "دستگاه‌های اپل"),
    "A483E7": ("Apple, Inc.", "دستگاه‌های اپل"),
    "002596": ("Cisco Systems, Inc", "تجهیزات سیسکو"),
    "B06CBF": ("TP-Link Corporation Limited", "مودم و روترهای تی‌پی‌لینک"),
    "50C7BF": ("TP-Link Corporation Limited", "تجهیزات وای‌فای تی‌پی‌لینک"),
    "C006C3": ("MikroTik", "روتربورد و تجهیزات میکروتیک"),
    "6C3B6B": ("MikroTik", "روتربورد و تجهیزات میکروتیک"),
    "CC2DE0": ("MikroTik", "روتربورد و تجهیزات میکروتیک"),
    "2C8A72": ("Xiaomi Communications Co Ltd", "گوشی‌ها و گجت‌های شیائومی"),
    "7811DC": ("Xiaomi Communications Co Ltd", "گوشی‌ها و تجهیزات شیائومی"),
    "3CD92B": ("HUAWEI TECHNOLOGIES CO.,LTD", "تجهیزات مخابراتی و مودم هوآوی"),
    "F4E3FB": ("HUAWEI TECHNOLOGIES CO.,LTD", "تجهیزات شبکه و گوشی هوآوی"),
    "5820B1": ("Samsung Electronics Co.,Ltd", "گوشی‌ها و تلویزیون‌های سامسونگ"),
    "B407C3": ("Samsung Electronics Co.,Ltd", "محصولات الکترونیکی سامسونگ"),
    "001A11": ("Google, Inc.", "سرورها و تجهیزات سخت‌افزاری گوگل"),
    "3C5AB4": ("Google, Inc.", "دستگاه‌های نست و پیکسل گوگل"),
}


async def lookup_mac_vendor(mac_or_oui: str) -> Dict[str, Any]:
    """
    Analyzes a MAC address or OUI prefix:
    - Identifies manufacturer / company name
    - Checks for locally administered (randomized MAC for privacy)
    - Multicast vs Unicast
    - Detects Virtual Machine hardware (VMware, VirtualBox, KVM)
    """
    clean = re.sub(r"[^a-fA-F0-9]", "", mac_or_oui.strip()).upper()
    if len(clean) < 6:
        return {"success": False, "error": "فرمت مک‌آدرس یا شناسه OUI نامعتبر است (حداقل ۶ نویسه هگزادسیمال الزامی است)."}

    oui = clean[:6]
    formatted_mac = ":".join([clean[i:i+2] for i in range(0, min(len(clean), 12), 2)])

    # Bit analysis on the first byte:
    first_byte = int(clean[:2], 16)
    is_multicast = bool(first_byte & 1)
    is_locally_administered = bool(first_byte & 2)

    company = "نامشخص"
    country = ""
    description = ""
    is_vm = False

    # 1. Check local fast-lookup cache
    if oui in _COMMON_OUIS:
        company, description = _COMMON_OUIS[oui]
        if "vmware" in company.lower() or "virtualbox" in company.lower() or "qemu" in company.lower():
            is_vm = True

    # 2. Query public open MAC API if not found or for extra details
    if company == "نامشخص":
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(f"https://api.maclookup.app/v2/macs/{oui}")
                if res.status_code == 200:
                    d = res.json()
                    c = d.get("company", "")
                    if c:
                        company = c
                        country = d.get("country", "")
                        if "vmware" in c.lower() or "virtualbox" in c.lower() or "qemu" in c.lower() or "parallels" in c.lower():
                            is_vm = True
        except Exception as e:
            logger.debug(f"External MAC API query error for {oui}: {e}")

    # Fallback to secondary vendor lookup if still not found
    if company == "نامشخص":
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.get(f"https://api.macvendors.com/{oui}")
                if res.status_code == 200 and res.text:
                    company = res.text.strip()
        except Exception:
            pass

    return {
        "success": True,
        "input": mac_or_oui,
        "mac_formatted": formatted_mac,
        "oui": f"{oui[:2]}:{oui[2:4]}:{oui[4:6]}",
        "company": company,
        "country": country,
        "description": description,
        "is_virtual_machine": is_vm,
        "is_locally_administered": is_locally_administered,
        "is_multicast": is_multicast,
    }


def format_mac_report(data: Dict[str, Any]) -> str:
    """Formats MAC address and hardware vendor intelligence in Persian Telegram HTML."""
    if not data.get("success"):
        return f"📟 <b>خطا در استعلام سخت‌افزار:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    mac = html.escape(data.get("mac_formatted", ""))
    oui = html.escape(data.get("oui", ""))
    company = html.escape(data.get("company", "نامشخص"))
    country = html.escape(data.get("country", ""))
    is_vm = data.get("is_virtual_machine", False)
    is_laa = data.get("is_locally_administered", False)
    is_mc = data.get("is_multicast", False)

    lines = [
        f"📟 <b>شناسایی مشخصات سخت‌افزاری و کارت شبکه (MAC & OUI Intelligence):</b>\n",
        f"• <b>مک‌آدرس:</b> <code>{mac}</code>",
        f"• <b>پیشوند سازنده (OUI):</b> <code>{oui}</code>",
        f"• <b>سازنده تجهیزات (Vendor):</b> <b>{company}</b>" + (f" ({country})" if country else ""),
    ]

    if data.get("description"):
        lines.append(f"• <b>دسته‌بندی تجهیزات:</b> {html.escape(data['description'])}")

    if is_vm:
        lines.append("💻 <b>نوع بستر:</b> ⚠️ <b>ماشین مجازی (Virtual Machine / Hypervisor)</b>")

    if is_laa:
        lines.append("🎭 <b>مک‌آدرس تصادفی (Randomized MAC):</b> بله (قابلیت حفظ حریم خصوصی Private Wi-Fi فعال در اندروید یا iOS)")

    cast_type = "چندپخشی (Multicast)" if is_mc else "تک‌پخشی (Unicast)"
    lines.append(f"📡 <b>نوع ارسال فریم:</b> <code>{cast_type}</code>")

    lines.append("\n⚡️ <i>استعلام مستقیم بر پایه پایگاه ثبت مراجع مهندسی اینترنت IEEE OUI</i>")
    return "\n".join(lines)
