"""
Prometheus OSINT Suite - HTTP Redirect Chain & Canonical URL Tracer
Traces multi-hop HTTP redirects (301, 302, 307, 308), unshortens malicious or affiliate links,
detects tracking parameters, protocol transitions, and unmasks destination landing pages.
"""

import urllib.parse
import html
import logging
from typing import Dict, Any, List, Optional
import httpx

from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_Redirects")

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
_HEADERS = {
    "User-Agent": _USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


async def trace_http_redirect_chain(target_url: str, max_hops: int = 12) -> Dict[str, Any]:
    """
    Step-by-step redirect tracer. Unshortens URLs and exposes intermediate routing hops.
    """
    raw_url = target_url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    hops = []
    current_url = raw_url
    seen_urls = set()

    try:
        async with httpx.AsyncClient(headers=_HEADERS, timeout=8.0, follow_redirects=False) as client:
            for step in range(1, max_hops + 1):
                if current_url in seen_urls:
                    hops.append({
                        "step": step,
                        "url": current_url,
                        "status": 0,
                        "note": "حلقه ریدایرکت بی‌پایان (Redirect Loop) شناسایی شد!"
                    })
                    break

                seen_urls.add(current_url)

                from tools.web_reader import is_safe_public_url
                if not is_safe_public_url(current_url):
                    hops.append({
                        "step": step,
                        "url": current_url,
                        "status": 0,
                        "note": "دسترسی به شبکه محلی یا منابع داخلی مسدود است (حفاظت SSRF)."
                    })
                    break

                try:
                    resp = await client.get(current_url)
                except Exception as req_err:
                    hops.append({
                        "step": step,
                        "url": current_url,
                        "status": 0,
                        "note": f"خطا در برقراری ارتباط: {str(req_err)}"
                    })
                    break

                status = resp.status_code
                loc = resp.headers.get("location", "")
                server = resp.headers.get("server", "")

                # Parse tracking parameters
                parsed = urllib.parse.urlparse(current_url)
                params = urllib.parse.parse_qs(parsed.query)
                tracking = [k for k in params if k.lower().startswith(("utm_", "fbclid", "gclid", "aff", "ref", "track"))]

                hops.append({
                    "step": step,
                    "url": current_url,
                    "status": status,
                    "location": loc,
                    "server": server,
                    "tracking_params": tracking,
                })

                if status in (301, 302, 303, 307, 308) and loc:
                    # Resolve relative redirect URLs
                    current_url = str(urllib.parse.urljoin(current_url, loc))
                else:
                    break

    except Exception as e:
        logger.warning(f"Redirect trace error for {target_url}: {e}")
        return {
            "success": False,
            "initial_url": raw_url,
            "error": f"خطا در ردگیری مسیر ریدایرکت: {str(e)}"
        }

    final_hop = hops[-1] if hops else {}
    initial_domain = urllib.parse.urlparse(raw_url).netloc
    final_domain = urllib.parse.urlparse(final_hop.get("url", "")).netloc
    is_cross_domain = bool(initial_domain and final_domain and initial_domain != final_domain)

    return {
        "success": True,
        "initial_url": raw_url,
        "final_url": final_hop.get("url", raw_url),
        "final_status": final_hop.get("status", 0),
        "total_hops": len(hops),
        "is_cross_domain": is_cross_domain,
        "is_redirected": len(hops) > 1,
        "hops": hops,
    }


def format_redirects_report(data: Dict[str, Any]) -> str:
    """Formats HTTP redirect chain report into Persian Telegram HTML."""
    if not data.get("success"):
        return f"🔄 <b>خطا در رهگیری ریدایرکت‌ها:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    init_url = html.escape(data.get("initial_url", ""))
    final_url = html.escape(data.get("final_url", ""))
    hops_count = data.get("total_hops", 0)
    final_status = data.get("final_status", 0)
    is_cross = data.get("is_cross_domain", False)

    cross_badge = "⚠️ <b>انتقال بین دامنه‌ای (Cross-Domain)</b>" if is_cross else "همان دامنه"

    lines = [
        f"🔄 <b>رهگیری زنجیره ریدایرکت و مقصد نهایی لینک (HTTP Redirect Tracer):</b>\n",
        f"🔗 <b>لینک اولیه:</b> <code>{init_url}</code>",
        f"🎯 <b>مقصد نهایی:</b> <a href=\"{final_url}\">{final_url}</a>",
        f"📊 <b>تعداد گام‌ها (Hops):</b> <code>{hops_count}</code> | وضعیت نهایی: <code>{final_status}</code> ({cross_badge})\n",
        "📋 <b>گام‌های انتقال:</b>"
    ]

    for h in data.get("hops", []):
        step = h.get("step", 1)
        st = h.get("status", 0)
        u = html.escape(h.get("url", ""))
        loc = html.escape(h.get("location", ""))
        tr = h.get("tracking_params", [])
        
        status_color = "🟢" if st == 200 else ("🟡" if st in (301, 302, 307, 308) else "🔴")
        hop_txt = f"{status_color} <b>گام {step}:</b> [کد: <code>{st}</code>] <code>{u}</code>"
        if loc:
            hop_txt += f"\n   ↳ <i>هدایت به:</i> <code>{loc}</code>"
        if tr:
            hop_txt += f"\n   ↳ <i>پارامترهای رهگیری/تبلیغاتی:</i> <code>{html.escape(', '.join(tr))}</code>"
        lines.append(hop_txt)

    lines.append("\n⚡️ <i>ردگیری بلادرنگ مسیرهای هدایت و رمزگشایی لینک‌های کوتاه و فیشینگ</i>")
    return "\n".join(lines)
