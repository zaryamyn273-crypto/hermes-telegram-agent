"""
Prometheus OSINT Suite - Sherlock-Grade High-Speed Username Reconnaissance Engine.
Scans 65+ global online platforms across 8 distinct operational categories concurrently,
with anti-false-positive verification, async semaphore throttling, and categorized reporting.
"""

import html
import logging
import asyncio
from typing import Dict, Any, List, Optional
import httpx

from utils.cache import username_cache
from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_Username")

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# 65+ High-Value Target Platforms categorized across 8 domains
PLATFORMS: List[Dict[str, Any]] = [
    # 1. Social & Community
    {"name": "Telegram", "cat": "social", "url": "https://t.me/{u}", "custom_check": "telegram"},
    {"name": "Twitter / X", "cat": "social", "url": "https://x.com/{u}", "error_code": 404},
    {"name": "Instagram", "cat": "social", "url": "https://www.instagram.com/{u}/", "error_code": 404},
    {"name": "TikTok", "cat": "social", "url": "https://www.tiktok.com/@{u}", "error_code": 404},
    {"name": "Reddit", "cat": "social", "url": "https://www.reddit.com/user/{u}/about.json", "error_code": 404},
    {"name": "Pinterest", "cat": "social", "url": "https://www.pinterest.com/{u}/", "error_code": 404},
    {"name": "Threads", "cat": "social", "url": "https://www.threads.net/@{u}", "error_code": 404},
    {"name": "Snapchat", "cat": "social", "url": "https://www.snapchat.com/add/{u}", "error_code": 404},
    {"name": "Tumblr", "cat": "social", "url": "https://{u}.tumblr.com", "error_code": 404},
    {"name": "Bluesky", "cat": "social", "url": "https://bsky.app/profile/{u}.bsky.social", "error_code": 404},
    {"name": "Mastodon", "cat": "social", "url": "https://mastodon.social/@{u}", "error_code": 404},
    {"name": "Quora", "cat": "social", "url": "https://www.quora.com/profile/{u}", "error_code": 404},

    # 2. Developer & Tech
    {"name": "GitHub", "cat": "developer", "url": "https://github.com/{u}", "error_code": 404},
    {"name": "GitLab", "cat": "developer", "url": "https://gitlab.com/{u}", "error_code": 404},
    {"name": "Bitbucket", "cat": "developer", "url": "https://bitbucket.org/{u}/", "error_code": 404},
    {"name": "DockerHub", "cat": "developer", "url": "https://hub.docker.com/v2/users/{u}/", "error_code": 404},
    {"name": "PyPI", "cat": "developer", "url": "https://pypi.org/user/{u}/", "error_code": 404},
    {"name": "NPM", "cat": "developer", "url": "https://www.npmjs.com/~{u}", "error_code": 404},
    {"name": "Dev.to", "cat": "developer", "url": "https://dev.to/{u}", "error_code": 404},
    {"name": "HuggingFace", "cat": "developer", "url": "https://huggingface.co/{u}", "error_code": 404},
    {"name": "Kaggle", "cat": "developer", "url": "https://www.kaggle.com/{u}", "error_code": 404},
    {"name": "Codeforces", "cat": "developer", "url": "https://codeforces.com/profile/{u}", "error_code": 404},
    {"name": "LeetCode", "cat": "developer", "url": "https://leetcode.com/{u}/", "error_code": 404},
    {"name": "Replit", "cat": "developer", "url": "https://replit.com/@{u}", "error_code": 404},
    {"name": "CodePen", "cat": "developer", "url": "https://codepen.io/{u}", "error_code": 404},

    # 3. Cybersecurity & Bug Bounty
    {"name": "HackerOne", "cat": "security", "url": "https://hackerone.com/{u}", "error_code": 404},
    {"name": "Bugcrowd", "cat": "security", "url": "https://bugcrowd.com/{u}", "error_code": 404},
    {"name": "Keybase", "cat": "security", "url": "https://keybase.io/{u}", "error_code": 404},
    {"name": "Pastebin", "cat": "security", "url": "https://pastebin.com/u/{u}", "error_code": 404},
    {"name": "TryHackMe", "cat": "security", "url": "https://tryhackme.com/p/{u}", "error_code": 404},
    {"name": "HackTheBox", "cat": "security", "url": "https://app.hackthebox.com/users/{u}", "error_code": 404},

    # 4. Professional & Writing
    {"name": "Medium", "cat": "professional", "url": "https://medium.com/@{u}", "error_code": 404},
    {"name": "Substack", "cat": "professional", "url": "https://{u}.substack.com", "error_code": 404},
    {"name": "LinkedIn", "cat": "professional", "url": "https://www.linkedin.com/in/{u}/", "error_code": 404},
    {"name": "Linktree", "cat": "professional", "url": "https://linktr.ee/{u}", "error_code": 404},
    {"name": "About.me", "cat": "professional", "url": "https://about.me/{u}", "error_code": 404},
    {"name": "Gravatar", "cat": "professional", "url": "https://en.gravatar.com/{u}.json", "error_code": 404},
    {"name": "Patreon", "cat": "professional", "url": "https://www.patreon.com/{u}", "error_code": 404},
    {"name": "BuyMeACoffee", "cat": "professional", "url": "https://www.buymeacoffee.com/{u}", "error_code": 404},

    # 5. Gaming & Streaming
    {"name": "Steam", "cat": "gaming", "url": "https://steamcommunity.com/id/{u}", "error_code": 404},
    {"name": "Twitch", "cat": "gaming", "url": "https://www.twitch.tv/{u}", "error_code": 404},
    {"name": "YouTube", "cat": "gaming", "url": "https://www.youtube.com/@{u}", "error_code": 404},
    {"name": "Kick", "cat": "gaming", "url": "https://kick.com/{u}", "error_code": 404},
    {"name": "Chess.com", "cat": "gaming", "url": "https://api.chess.com/pub/player/{u}", "error_code": 404},
    {"name": "Lichess", "cat": "gaming", "url": "https://lichess.org/@/{u}", "error_code": 404},
    {"name": "Roblox", "cat": "gaming", "url": "https://www.roblox.com/user.aspx?username={u}", "error_code": 404},

    # 6. Creative, Design & Media
    {"name": "Behance", "cat": "creative", "url": "https://www.behance.net/{u}", "error_code": 404},
    {"name": "Dribbble", "cat": "creative", "url": "https://dribbble.com/{u}", "error_code": 404},
    {"name": "ArtStation", "cat": "creative", "url": "https://www.artstation.com/{u}", "error_code": 404},
    {"name": "DeviantArt", "cat": "creative", "url": "https://www.deviantart.com/{u}", "error_code": 404},
    {"name": "500px", "cat": "creative", "url": "https://500px.com/p/{u}", "error_code": 404},
    {"name": "Flickr", "cat": "creative", "url": "https://www.flickr.com/photos/{u}/", "error_code": 404},
    {"name": "Vimeo", "cat": "creative", "url": "https://vimeo.com/{u}", "error_code": 404},
    {"name": "Unsplash", "cat": "creative", "url": "https://unsplash.com/@{u}", "error_code": 404},

    # 7. Music & Audio
    {"name": "SoundCloud", "cat": "audio", "url": "https://soundcloud.com/{u}", "error_code": 404},
    {"name": "Spotify", "cat": "audio", "url": "https://open.spotify.com/user/{u}", "error_code": 404},
    {"name": "Bandcamp", "cat": "audio", "url": "https://{u}.bandcamp.com", "error_code": 404},
    {"name": "Last.fm", "cat": "audio", "url": "https://www.last.fm/user/{u}", "error_code": 404},

    # 8. Web3 & Crypto
    {"name": "OpenSea", "cat": "web3", "url": "https://opensea.io/{u}", "error_code": 404},
    {"name": "Rarible", "cat": "web3", "url": "https://rarible.com/{u}", "error_code": 404},
    {"name": "Etherscan", "cat": "web3", "url": "https://etherscan.io/address/{u}", "error_code": 404},
    {"name": "Mirror.xyz", "cat": "web3", "url": "https://mirror.xyz/{u}.eth", "error_code": 404},

    # 9. Additional Global Platforms
    {"name": "VKontakte", "cat": "social", "url": "https://vk.com/{u}", "error_code": 404},
    {"name": "ProductHunt", "cat": "social", "url": "https://www.producthunt.com/@{u}", "error_code": 404},
    {"name": "StackOverflow", "cat": "developer", "url": "https://stackoverflow.com/users/{u}", "error_code": 404},
    {"name": "SourceForge", "cat": "developer", "url": "https://sourceforge.net/u/{u}/profile/", "error_code": 404},
    {"name": "CTFtime", "cat": "security", "url": "https://ctftime.org/user/{u}", "error_code": 404},
    {"name": "Fiverr", "cat": "professional", "url": "https://www.fiverr.com/{u}", "error_code": 404},
]

CATEGORY_METADATA = {
    "social": {"title": "شبکه‌های اجتماعی و ارتباطی", "emoji": "📱"},
    "developer": {"title": "توسعه‌دهندگان و گیک‌ها", "emoji": "💻"},
    "security": {"title": "امنیت سایبری و باگ‌بانتی", "emoji": "🛡"},
    "professional": {"title": "پروفایل‌های حرفه‌ای و وبلاگ", "emoji": "💼"},
    "gaming": {"title": "گیمینگ و استریمینگ", "emoji": "🎮"},
    "creative": {"title": "هنر، عکاسی و طراحی", "emoji": "🎨"},
    "audio": {"title": "موسیقی و پادکست", "emoji": "🎵"},
    "web3": {"title": "رمزارز و وب۳", "emoji": "⛓"},
}


async def _check_single_platform(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    p: Dict[str, Any],
    username: str,
) -> Optional[Dict[str, str]]:
    """Validates presence of username on a platform with anti-false-positive checks."""
    url = p["url"].format(u=username)
    name = p["name"]
    category = p.get("cat", "social")

    async with sem:
        try:
            if p.get("custom_check") == "telegram":
                resp = await client.get(url, timeout=3.5, follow_redirects=True)
                if resp.status_code == 200 and "tgme_page_title" in resp.text:
                    if "If you have Telegram, you can contact" in resp.text or "tgme_action_button_new" in resp.text:
                        return {"platform": name, "category": category, "url": f"https://t.me/{username}"}
                return None

            resp = await client.get(url, timeout=3.5, follow_redirects=False)
            if resp.status_code == 200:
                # Anti-false-positive verification on body text
                t = resp.text.lower()
                soft_404_markers = [
                    "user not found", "profile not found", "page not found",
                    "doesn't exist", "this page is not available", "sorry, this content"
                ]
                if any(m in t for m in soft_404_markers):
                    return None
                return {"platform": name, "category": category, "url": url}
        except Exception:
            pass

    return None


async def search_username_across_platforms(username: str) -> Dict[str, Any]:
    """
    Scans 65+ online platforms in parallel for profile presence of a username.
    Throttled via asyncio Semaphore for high concurrency without local socket exhaustion.
    """
    clean_u = username.strip().lstrip("@")
    if not clean_u:
        return {"success": False, "error": "نام کاربری نامعتبر است."}

    # Check cache
    cached = await username_cache.get(clean_u.lower())
    if cached:
        logger.debug(f"Username cache hit for {clean_u}")
        return cached

    headers = {"User-Agent": _USER_AGENT}
    sem = asyncio.Semaphore(25)  # 25 parallel worker threads

    async with httpx.AsyncClient(headers=headers, timeout=4.5) as client:
        tasks = [_check_single_platform(client, sem, p, clean_u) for p in PLATFORMS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    found: List[Dict[str, str]] = []
    categorized: Dict[str, List[Dict[str, str]]] = {k: [] for k in CATEGORY_METADATA}

    for r in results:
        if isinstance(r, dict) and r is not None:
            found.append(r)
            cat = r.get("category", "social")
            if cat in categorized:
                categorized[cat].append(r)

    result = {
        "success": True,
        "username": clean_u,
        "total_scanned": len(PLATFORMS),
        "total_checked": len(PLATFORMS),
        "total_found": len(found),
        "found_count": len(found),
        "profiles": found,
        "results": found,
        "found": found,
        "categorized": categorized,
    }

    await username_cache.set(clean_u.lower(), result, ttl=1800.0)
    return result


def format_username_recon_report(data: Dict[str, Any]) -> str:
    """Formats 65+ platform username search findings into categorized Persian Telegram HTML."""
    if not data.get("success"):
        return f"👤 <b>خطا در استعلام نام کاربری:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    user = html.escape(data.get("username", ""))
    total_found = data.get("total_found", 0)
    total_scanned = data.get("total_scanned", len(PLATFORMS))
    categorized = data.get("categorized", {})

    lines = [
        f"👤 <b>ردیابی هویتی نام‌کاربری در سراسر وب (Username OSINT Scanner):</b>\n<code>@{user}</code>\n",
        f"📊 <b>آمار ردیابی:</b> کشف در <code>{total_found}</code> پلتفرم از مجموع <code>{total_scanned}</code> سرویس بررسی‌شده\n",
    ]

    if total_found == 0:
        lines.append("⚠️ <i>این نام کاربری در هیچ‌یک از پلتفرم‌های عمومی بررسی‌شده یافت نشد.</i>")
    else:
        for cat_key, meta in CATEGORY_METADATA.items():
            cat_list = categorized.get(cat_key, [])
            if cat_list:
                cat_title = meta["title"]
                cat_emoji = meta["emoji"]
                p_lines = [f"• <a href=\"{p['url']}\"><b>{html.escape(p['platform'])}</b></a>" for p in cat_list]
                block_content = "\n".join(p_lines)
                lines.append(f"{cat_emoji} <b>{cat_title} ({len(cat_list)} حساب):</b>\n{wrap_in_expandable_blockquote(block_content)}\n")

    lines.append("⚡️ <i>پویش سریع موازی در ۶۵+ سرویس جهانی (شبکه‌های اجتماعی، گیت‌هاب، باگ‌بانتی، گیمینگ و وب۳)</i>")
    return "\n".join(lines)
