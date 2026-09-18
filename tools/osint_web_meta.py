"""
Prometheus OSINT Suite - Web Metadata & Hidden Paths Reconnaissance
Inspects robots.txt, .well-known/security.txt, and sitemap.xml to uncover hidden endpoints,
disallowed admin directories, security disclosure policies, and sitemap architecture.
"""

import re
import html
import logging
from typing import Dict, Any, List, Optional
import httpx

from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_WebMeta")

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_HEADERS = {
    "User-Agent": _USER_AGENT,
    "Accept": "text/plain, text/html, application/xml, */*",
}


def _clean_domain(target: str) -> str:
    """Extracts base host domain from user input."""
    t = target.strip().lower()
    t = re.sub(r"^https?://", "", t)
    t = t.split("/")[0].split(":")[0].strip()
    return t


async def inspect_web_meta(target: str) -> Dict[str, Any]:
    """
    Crawls and analyzes robots.txt, security.txt, and sitemap.xml.
    Discovers hidden paths, sensitive routes, and official security disclosure policies.
    """
    domain = _clean_domain(target)
    if not domain or "." not in domain:
        return {"success": False, "domain": domain, "error": "دامنه وارد شده نامعتبر است."}

    base_url = f"https://{domain}"
    report: Dict[str, Any] = {
        "success": True,
        "domain": domain,
        "robots": {"found": False, "disallowed": [], "sitemaps": [], "content_sample": ""},
        "security_txt": {"found": False, "contacts": [], "policy": "", "canonical": "", "acknowledgments": ""},
        "sitemap": {"found": False, "url_count": 0, "sample_urls": []},
    }

    async with httpx.AsyncClient(headers=_HEADERS, timeout=8.0, follow_redirects=True) as client:
        # 1. Fetch robots.txt
        try:
            r_resp = await client.get(f"{base_url}/robots.txt")
            if r_resp.status_code == 200 and r_resp.text:
                text = r_resp.text
                report["robots"]["found"] = True
                disallows = set()
                sitemaps = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.lower().startswith("disallow:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1 and parts[1].strip():
                            disallows.add(parts[1].strip())
                    elif line.lower().startswith("sitemap:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1 and parts[1].strip():
                            sitemaps.append(parts[1].strip())

                report["robots"]["disallowed"] = sorted(list(disallows))
                report["robots"]["sitemaps"] = sorted(list(set(sitemaps)))
                report["robots"]["content_sample"] = "\n".join(text.splitlines()[:20])
        except Exception as e:
            logger.debug(f"robots.txt fetch failed for {domain}: {e}")

        # 2. Fetch .well-known/security.txt
        try:
            s_resp = await client.get(f"{base_url}/.well-known/security.txt")
            if s_resp.status_code != 200:
                s_resp = await client.get(f"{base_url}/security.txt")

            if s_resp.status_code == 200 and s_resp.text and ("contact:" in s_resp.text.lower() or "policy:" in s_resp.text.lower()):
                report["security_txt"]["found"] = True
                contacts = []
                policy = ""
                canonical = ""
                ack = ""
                for line in s_resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("contact:"):
                        contacts.append(line.split(":", 1)[1].strip())
                    elif line.lower().startswith("policy:"):
                        policy = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("canonical:"):
                        canonical = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("acknowledgments:"):
                        ack = line.split(":", 1)[1].strip()

                report["security_txt"]["contacts"] = contacts
                report["security_txt"]["policy"] = policy
                report["security_txt"]["canonical"] = canonical
                report["security_txt"]["acknowledgments"] = ack
        except Exception as e:
            logger.debug(f"security.txt fetch failed for {domain}: {e}")

        # 3. Check sitemap.xml
        try:
            sm_url = report["robots"]["sitemaps"][0] if report["robots"]["sitemaps"] else f"{base_url}/sitemap.xml"
            sm_resp = await client.get(sm_url)
            if sm_resp.status_code == 200 and sm_resp.text:
                report["sitemap"]["found"] = True
                urls = re.findall(r"<loc>(.*?)</loc>", sm_resp.text, re.I)
                report["sitemap"]["url_count"] = len(urls)
                report["sitemap"]["sample_urls"] = urls[:10]
        except Exception as e:
            logger.debug(f"sitemap.xml fetch failed for {domain}: {e}")

    return report


def format_web_meta_report(data: Dict[str, Any]) -> str:
    """Formats robots.txt and security.txt findings into Persian Telegram HTML."""
    if not data.get("success"):
        return f"🕷 <b>خطا در استخراج ساختار و مسیرهای سایت:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    domain = html.escape(data.get("domain", ""))
    lines = [
        f"🕷 <b>کالبدشکافی مسیرهای مخفی و متاداده وب (Web Recon & Robots):</b>\n<code>{domain}</code>\n"
    ]

    # 1. robots.txt
    rb = data.get("robots", {})
    if rb.get("found"):
        dis = rb.get("disallowed", [])
        lines.append(f"🤖 <b>فایل robots.txt:</b> یافت شد ✅ (شامل <code>{len(dis)}</code> مسیر مسدودشده)")
        if dis:
            dis_lines = [f"• <code>{html.escape(d)}</code>" for d in dis[:25]]
            if len(dis) > 25:
                dis_lines.append(f"<i>... و {len(dis) - 25} مسیر دیگر</i>")
            dis_block = "\n".join(dis_lines)
            lines.append(f"🚫 <b>مسیرهای مستثنی‌شده (Disallow - اغلب مسیرهای حساس یا پنل‌ها):</b>\n{wrap_in_expandable_blockquote(dis_block)}\n")
        if rb.get("sitemaps"):
            lines.append(f"🗺 <b>نقشه‌های سایت کشف‌شده در robots.txt:</b>")
            for sm in rb["sitemaps"][:3]:
                lines.append(f"• <a href=\"{sm}\">{html.escape(sm)}</a>")
            lines.append("")
    else:
        lines.append("🤖 <b>فایل robots.txt:</b> یافت نشد یا در دسترس نیست.\n")

    # 2. security.txt
    sec = data.get("security_txt", {})
    if sec.get("found"):
        lines.append("🛡 <b>فایل خط‌مشی امنیتی (security.txt):</b> کشف شد ✅")
        if sec.get("contacts"):
            lines.append(f"• <b>کانال‌های ارتباطی امنیتی:</b> <code>{html.escape(', '.join(sec['contacts']))}</code>")
        if sec.get("policy"):
            lines.append(f"• <b>قوانین باگ‌بانتی:</b> <a href=\"{sec['policy']}\">مشاهده خط‌مشی</a>")
        if sec.get("acknowledgments"):
            lines.append(f"• <b>تالار افتخارات (Hall of Fame):</b> <a href=\"{sec['acknowledgments']}\">مشاهده تقدیرنامه</a>")
        lines.append("")
    else:
        lines.append("🛡 <b>فایل security.txt:</b> تنظیم نشده است.\n")

    # 3. sitemap.xml
    sm = data.get("sitemap", {})
    if sm.get("found"):
        cnt = sm.get("url_count", 0)
        lines.append(f"🗺 <b>نقشه سایت (Sitemap.xml):</b> فعال (تعداد لینک‌های استخراج‌شده: <code>{cnt:,}</code>)")
        if sm.get("sample_urls"):
            sm_lines = [f"• <code>{html.escape(u)}</code>" for u in sm["sample_urls"][:5]]
            lines.append(wrap_in_expandable_blockquote("\n".join(sm_lines)))
    else:
        lines.append("🗺 <b>نقشه سایت:</b> کشف نشد.")

    lines.append("\n⚡️ <i>استخراج بلادرنگ متاداده ساختاری وب‌سایت</i>")
    return "\n".join(lines)
