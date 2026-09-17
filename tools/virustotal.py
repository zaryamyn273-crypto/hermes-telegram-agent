"""
VirusTotal Tool for Prometheus (Hermes Telegram Agent).
Integrates directly with VirusTotal v3 REST API for:
1. File scanning by SHA-256 / MD5 hash (instant lookup across 70+ antivirus engines)
2. Live file upload and analysis for new / unseen files
3. Web URL, Domain, and IP address threat intelligence scanning
4. Rich, real-time Persian security reports with clickable copyable IDs
"""

import io
import re
import html
import base64
import hashlib
import logging
import asyncio
from typing import Optional, Dict, Any, Tuple, List

import httpx

from config import settings

logger = logging.getLogger("HermesTelegramAgent.VirusTotal")

VT_API_BASE = "https://www.virustotal.com/api/v3"

# Top recognized commercial antivirus engines to spotlight in reports
PROMINENT_ENGINES = [
    "Microsoft", "Kaspersky", "BitDefender", "ESET-NOD32", "Sophos",
    "Avast", "AVG", "CrowdStrike", "SentinelOne", "Symantec", "Fortinet",
    "Google", "Malwarebytes", "F-Secure", "TrendMicro"
]


def _get_api_key() -> str:
    return getattr(settings, "VIRUSTOTAL_API_KEY", "") or "8c715c84eef42a06fcc42d407e547c63cb77ababf962877bfcea30834d1ff084"


def compute_sha256(data: bytes) -> str:
    """Computes SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


# =========================================================================
# 1. File Hash & Live Upload Scanners
# =========================================================================

async def scan_file_hash(file_hash: str) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 for an existing file report by hash (SHA-256, MD5, SHA-1).
    Returns structured analysis or {"found": False}.
    """
    api_key = _get_api_key()
    if not api_key:
        return {"error": "کلید VirusTotal API تنظیم نشده است."}

    h = file_hash.strip().lower()
    url = f"{VT_API_BASE}/files/{h}"
    headers = {"x-apikey": api_key, "User-Agent": "Prometheus-Agent/2.0"}

    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attrs = data.get("attributes", {})
                return _parse_file_attributes(attrs, h)
            elif resp.status_code == 404:
                return {"found": False, "hash": h}
            elif resp.status_code == 401:
                return {"error": "کلید VirusTotal نامعتبر است یا منقضی شده است."}
            else:
                return {"error": f"خطای VirusTotal (کد {resp.status_code}): {resp.text[:200]}"}
        except Exception as e:
            logger.warning(f"Error querying VirusTotal for hash '{h}': {e}")
            return {"error": f"خطا در برقراری ارتباط با VirusTotal: {e}"}


async def upload_and_scan_file(file_bytes: bytes, file_name: str) -> Dict[str, Any]:
    """
    Uploads a file to VirusTotal and awaits immediate analysis.
    First checks SHA-256 hash for instant response; if not found, uploads file.
    """
    api_key = _get_api_key()
    if not api_key:
        return {"error": "کلید VirusTotal API تنظیم نشده است."}

    sha256_val = compute_sha256(file_bytes)
    # Check if already analyzed
    existing = await scan_file_hash(sha256_val)
    if existing.get("found") is True:
        return existing

    if len(file_bytes) > 32 * 1024 * 1024:
        return {
            "error": "حجم فایل بیش از ۳۲ مگابایت است و برای اسکن لایو مستقیم بیش از حد مجاز می‌باشد.",
            "sha256": sha256_val
        }

    url = f"{VT_API_BASE}/files"
    headers = {"x-apikey": api_key, "User-Agent": "Prometheus-Agent/2.0"}
    files = {"file": (file_name or "file.bin", file_bytes)}

    async with httpx.AsyncClient(timeout=45.0) as client:
        try:
            resp = await client.post(url, headers=headers, files=files)
            if resp.status_code in (200, 201):
                res_data = resp.json().get("data", {})
                analysis_id = res_data.get("id")
                if not analysis_id:
                    return {"found": False, "sha256": sha256_val, "message": "فایل آپلود شد اما شناسه تحلیل دریافت نشد."}

                # Poll analysis up to 3 times (5-7 seconds) for immediate verdict
                for _ in range(3):
                    await asyncio.sleep(2.5)
                    poll_url = f"{VT_API_BASE}/analyses/{analysis_id}"
                    poll_resp = await client.get(poll_url, headers=headers)
                    if poll_resp.status_code == 200:
                        p_data = poll_resp.json().get("data", {})
                        p_attrs = p_data.get("attributes", {})
                        status = p_attrs.get("status")
                        if status == "completed":
                            stats = p_attrs.get("stats", {})
                            results = p_attrs.get("results", {})
                            return _format_analysis_result(stats, results, sha256_val, file_name)

                # If still queued, return queued status with permalink
                return {
                    "found": True,
                    "queued": True,
                    "sha256": sha256_val,
                    "file_name": file_name,
                    "permalink": f"https://www.virustotal.com/gui/file/{sha256_val}"
                }
            else:
                return {"error": f"خطا در ارسال فایل به VirusTotal (کد {resp.status_code}): {resp.text[:200]}"}
        except Exception as e:
            logger.warning(f"Error uploading file to VirusTotal: {e}")
            return {"error": f"خطا در آپلود فایل به VirusTotal: {e}"}


# =========================================================================
# 2. URL & Domain Scanners
# =========================================================================

async def scan_url_or_domain(target: str) -> Dict[str, Any]:
    """
    Scans a web URL or domain name using VirusTotal v3 threat intelligence.
    """
    api_key = _get_api_key()
    if not api_key:
        return {"error": "کلید VirusTotal API تنظیم نشده است."}

    raw = target.strip()
    headers = {"x-apikey": api_key, "User-Agent": "Prometheus-Agent/2.0"}

    # Check if pure domain (e.g. example.com) or IP
    is_domain = bool(re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/\S*)?$", raw)) and not raw.startswith(("http://", "https://"))

    async with httpx.AsyncClient(timeout=20.0) as client:
        try:
            if is_domain and "/" not in raw:
                # Domain lookup
                url = f"{VT_API_BASE}/domains/{raw.lower()}"
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    results = attrs.get("last_analysis_results", {})
                    return {
                        "found": True,
                        "target_type": "domain",
                        "target": raw,
                        "stats": stats,
                        "reputation": attrs.get("reputation", 0),
                        "categories": attrs.get("categories", {}),
                        "results": results,
                        "permalink": f"https://www.virustotal.com/gui/domain/{raw}"
                    }

            # URL lookup
            url_target = raw if raw.startswith(("http://", "https://")) else f"https://{raw}"
            url_id = base64.urlsafe_b64encode(url_target.encode()).decode().strip("=")
            url = f"{VT_API_BASE}/urls/{url_id}"
            resp = await client.get(url, headers=headers)

            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                results = attrs.get("last_analysis_results", {})
                return {
                    "found": True,
                    "target_type": "url",
                    "target": url_target,
                    "stats": stats,
                    "reputation": attrs.get("reputation", 0),
                    "results": results,
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}"
                }
            elif resp.status_code == 404:
                # Submit URL for scanning
                post_resp = await client.post(f"{VT_API_BASE}/urls", headers=headers, data={"url": url_target})
                if post_resp.status_code in (200, 201):
                    return {
                        "found": True,
                        "queued": True,
                        "target_type": "url",
                        "target": url_target,
                        "permalink": f"https://www.virustotal.com/gui/url/{url_id}"
                    }

            return {"error": f"پاسخ VirusTotal (کد {resp.status_code}): {resp.text[:200]}"}
        except Exception as e:
            logger.warning(f"Error scanning URL/domain '{target}': {e}")
            return {"error": f"خطا در اسکن آدرس اینترنتی: {e}"}


# =========================================================================
# 3. Parsers & Report Formatters
# =========================================================================

def _parse_file_attributes(attrs: Dict[str, Any], sha256_hash: str) -> Dict[str, Any]:
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})
    file_name = attrs.get("meaningful_name") or attrs.get("names", ["فایل"])[0] if attrs.get("names") else "فایل"
    file_type = attrs.get("type_description") or attrs.get("magic") or "ناشناخته"
    file_size = attrs.get("size", 0)

    # Extract detected threats
    detections: List[Dict[str, str]] = []
    for eng_name, eng_info in results.items():
        cat = eng_info.get("category")
        if cat in ("malicious", "suspicious"):
            detections.append({
                "engine": eng_name,
                "category": cat,
                "result": eng_info.get("result") or "تهدید شناسایی شد"
            })

    threat_class = ""
    pop_threat = attrs.get("popular_threat_classification")
    if pop_threat and isinstance(pop_threat, dict):
        suggested = pop_threat.get("suggested_threat_label")
        if suggested:
            threat_class = suggested

    return {
        "found": True,
        "sha256": sha256_hash,
        "md5": attrs.get("md5", ""),
        "file_name": file_name,
        "file_type": file_type,
        "file_size": file_size,
        "stats": stats,
        "reputation": attrs.get("reputation", 0),
        "threat_class": threat_class,
        "detections": detections,
        "results": results,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}"
    }


def _format_analysis_result(stats: Dict[str, Any], results: Dict[str, Any], sha256_hash: str, file_name: str) -> Dict[str, Any]:
    detections: List[Dict[str, str]] = []
    for eng_name, eng_info in results.items():
        cat = eng_info.get("category")
        if cat in ("malicious", "suspicious"):
            detections.append({
                "engine": eng_name,
                "category": cat,
                "result": eng_info.get("result") or "تهدید شناسایی شد"
            })

    return {
        "found": True,
        "sha256": sha256_hash,
        "file_name": file_name,
        "stats": stats,
        "detections": detections,
        "results": results,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}"
    }


def format_virustotal_report(data: Dict[str, Any], target_name: Optional[str] = None, target_type: str = "file") -> str:
    """
    Formats a clean, professional, Persian HTML report from VirusTotal scan results.
    """
    if not target_name:
        target_name = data.get("target") or data.get("file_name") or data.get("url") or data.get("sha256") or "فایل / آدرس"

    if data.get("error"):
        return f"⚠️ <b>خطا در استعلام VirusTotal:</b>\n{html.escape(str(data['error']))}"

    if data.get("found") is False:
        sha = data.get("hash") or data.get("sha256") or ""
        return (
            "🔍 <b>نتیجه بررسی VirusTotal:</b>\n\n"
            f"🏷 <b>نام هدف:</b> <code>{html.escape(target_name)}</code>\n"
            f"🆔 <b>شناسه هش (SHA-256):</b> <code>{sha}</code>\n\n"
            "ℹ️ <i>این فایل تاکنون در پایگاه داده جهانی VirusTotal ثبت نشده است.</i>\n"
            "جهت آنالیز زنده و ارسال به بیش از ۷۰ آنتی‌ویروس، فایل را مستقیماً برای ربات ارسال فرمایید."
        )

    if data.get("queued"):
        sha = data.get("sha256") or ""
        link = data.get("permalink") or f"https://www.virustotal.com/gui/file/{sha}"
        return (
            "⏳ <b>فایل برای آنالیز زنده در VirusTotal ثبت گردید</b>\n\n"
            f"🏷 <b>هدف:</b> <code>{html.escape(target_name)}</code>\n"
            f"🆔 <b>شناسه SHA-256:</b> <code>{sha}</code>\n\n"
            "🔄 <i>آنالیز توسط بیش از ۷۰ موتور امنیتی در صف پردازش قرار دارد.</i>\n"
            f"🔗 <a href=\"{link}\">مشاهده لحظه‌ای گزارش در وبسایت VirusTotal</a>"
        )

    stats = data.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total_engines = malicious + suspicious + harmless + undetected

    # Determine security verdict & status icon
    if malicious > 0:
        verdict_icon = "🔴"
        verdict_title = "بدافزار و خطرناک (Malicious Detected)"
        verdict_desc = "⚠️ <b>هشدار امنیتی:</b> این فایل توسط یک یا چند آنتی‌ویروس معتبر به عنوان بدافزار یا تهدید شناسایی شد!"
    elif suspicious > 0:
        verdict_icon = "🟡"
        verdict_title = "مشکوک (Suspicious)"
        verdict_desc = "⚠️ <i>این هدف رفتار مشکوک داشته است و احتیاط در اجرای آن توصیه می‌شود.</i>"
    else:
        verdict_icon = "🟢"
        verdict_title = "کاملاً پاک و بدون تهدید (Clean / Safe)"
        verdict_desc = "✅ <i>هیچ‌کدام از موتورهای آنتی‌ویروس جهانی موردی از بدافزار یا کد مخرب در این فایل نیافتند.</i>"

    lines: List[str] = [
        f"{verdict_icon} <b>گزارش رسمی امنیت VirusTotal</b>",
        f"<b>وضعیت نهایی:</b> {verdict_title}",
        verdict_desc,
        "",
        "📊 <b>آمار شناسایی موتورها:</b>",
        f"• بدافزار (Malicious): <b>{malicious}</b>",
        f"• مشکوک (Suspicious): <b>{suspicious}</b>",
        f"• پاک و بدون خطر (Clean): <b>{harmless + undetected}</b>",
        f"• کل آنتی‌ویروس‌های بررسی‌کننده: <b>{total_engines}</b>",
        ""
    ]

    # File / Target Details
    lines.append("🏷 <b>مشخصات هدف:</b>")
    lines.append(f"• نام: <code>{html.escape(target_name)}</code>")
    if data.get("file_type"):
        lines.append(f"• نوع: <code>{html.escape(data['file_type'])}</code>")
    if data.get("file_size"):
        size_kb = data["file_size"] / 1024
        lines.append(f"• حجم: <code>{size_kb:.1f} KB</code>")
    if data.get("sha256"):
        lines.append(f"• هش SHA-256 (کپی یک‌لمسی):\n<code>{data['sha256']}</code>")
    if data.get("threat_class"):
        lines.append(f"• رده‌بندی تهدید: <code>{html.escape(data['threat_class'])}</code>")

    # Spotlight Prominent Commercial Antivirus Engines
    results = data.get("results", {})
    if results:
        prom_lines: List[str] = []
        for eng in PROMINENT_ENGINES:
            if eng in results:
                info = results[eng]
                cat = info.get("category")
                if cat == "malicious":
                    prom_lines.append(f"• 🔴 <b>{eng}:</b> {html.escape(info.get('result') or 'Malware')}")
                elif cat == "suspicious":
                    prom_lines.append(f"• 🟡 <b>{eng}:</b> Suspicious")
                else:
                    prom_lines.append(f"• 🟢 <b>{eng}:</b> Clean")

        if prom_lines:
            lines.append("")
            lines.append("🛡 <b>آنتی‌ویروس‌های برجسته:</b>")
            lines.extend(prom_lines[:8])

    # Highlight top specific malicious detections if any
    detections = data.get("detections", [])
    if detections and malicious > 0:
        lines.append("")
        lines.append("⚠️ <b>تشخیص‌های امنیتی مهم:</b>")
        for det in detections[:6]:
            lines.append(f"• <b>{html.escape(det['engine'])}:</b> <code>{html.escape(det['result'])}</code>")

    link = data.get("permalink")
    if link:
        lines.append("")
        lines.append(f"🔗 <a href=\"{link}\">مشاهده گزارش تفصیلی و آنلاین در وب‌سایت VirusTotal</a>")

    return "\n".join(lines)


# =========================================================================
# 4. Request Detector
# =========================================================================

def is_virustotal_request(text: str) -> Tuple[bool, Optional[str]]:
    """
    Detects if a user message is requesting a virus/malware scan.
    Returns: (is_scan_request: bool, extracted_target: Optional[str])
    """
    t = (text or "").strip()
    if not t:
        return False, None

    # Slash commands: /scan, /pscan, /p_scan, /vt, /pvt, /p_vt, /virustotal, /pvirustotal, /antivirus
    m_cmd = re.match(r"^(?:/)?(?:p_|pro_|p|pro)?(?:scan|vt|virustotal|antivirus|antivir|virus)(?:\s+(.*))?$", t, re.IGNORECASE)
    if m_cmd:
        target = (m_cmd.group(1) or "").strip()
        return True, target or None

    t_low = t.lower()
    scan_phrases = [
        "اسکن کن", "ویروس یابی", "ویروسیابی", "ویروسیه", "ویروسی هست", "چک کن ویروسی",
        "توی ویروس توتال", "virustotal", "ویروس توتال", "آنتی ویروس", "انتی ویروس",
        "اسکنش کن", "امنه یا نه", "امنیت این فایل", "بررسی امنیت"
    ]
    if any(p in t_low for p in scan_phrases):
        # Extract possible URL from text
        url_m = re.search(r"(https?://\S+|[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/\S*)?)", t)
        target = url_m.group(1) if url_m else None
        return True, target

    return False, None
