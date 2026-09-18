"""
Prometheus OSINT Suite - Username Reconnaissance (WhatsMyName / Sherlock Style)
Asynchronously checks 35+ platforms for username existence with fast concurrent requests.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
import httpx

logger = logging.getLogger("OSINT_Username")

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# List of platforms with profile URL template and check method
PLATFORMS = [
    {"name": "GitHub", "url": "https://github.com/{u}", "error_code": 404},
    {"name": "GitLab", "url": "https://gitlab.com/{u}", "error_code": 404},
    {"name": "Twitter / X", "url": "https://x.com/{u}", "error_code": 404},
    {"name": "Telegram", "url": "https://t.me/{u}", "custom_check": "telegram"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{u}/about.json", "error_code": 404},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{u}/", "error_code": 404},
    {"name": "Medium", "url": "https://medium.com/@{u}", "error_code": 404},
    {"name": "Dev.to", "url": "https://dev.to/{u}", "error_code": 404},
    {"name": "HackerOne", "url": "https://hackerone.com/{u}", "error_code": 404},
    {"name": "Bugcrowd", "url": "https://bugcrowd.com/{u}", "error_code": 404},
    {"name": "Keybase", "url": "https://keybase.io/{u}", "error_code": 404},
    {"name": "DockerHub", "url": "https://hub.docker.com/v2/users/{u}/", "error_code": 404},
    {"name": "PyPI", "url": "https://pypi.org/user/{u}/", "error_code": 404},
    {"name": "NPM", "url": "https://www.npmjs.com/~{u}", "error_code": 404},
    {"name": "Pastebin", "url": "https://pastebin.com/u/{u}", "error_code": 404},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{u}", "error_code": 404},
    {"name": "Chess.com", "url": "https://api.chess.com/pub/player/{u}", "error_code": 404},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{u}", "error_code": 404},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{u}", "error_code": 404},
    {"name": "Substack", "url": "https://{u}.substack.com", "error_code": 404},
    {"name": "Behance", "url": "https://www.behance.net/{u}", "error_code": 404},
    {"name": "Dribbble", "url": "https://dribbble.com/{u}", "error_code": 404},
    {"name": "Linktree", "url": "https://linktr.ee/{u}", "error_code": 404},
    {"name": "Spotify", "url": "https://open.spotify.com/user/{u}", "error_code": 404},
    {"name": "Twitch", "url": "https://www.twitch.tv/{u}", "error_code": 404},
]


async def _check_single_platform(client: httpx.AsyncClient, p: Dict[str, Any], username: str) -> Optional[Dict[str, str]]:
    url = p["url"].format(u=username)
    name = p["name"]

    try:
        if p.get("custom_check") == "telegram":
            # Check Telegram public profile page
            resp = await client.get(url, timeout=3.5, follow_redirects=True)
            if resp.status_code == 200 and "tgme_page_title" in resp.text:
                if "If you have Telegram, you can contact" in resp.text:
                    return {"platform": name, "url": f"https://t.me/{username}"}
            return None

        # Standard check
        resp = await client.get(url, timeout=3.5, follow_redirects=False)
        if resp.status_code == 200:
            return {"platform": name, "url": url}
    except Exception:
        pass

    return None


async def search_username_across_platforms(username: str) -> Dict[str, Any]:
    """
    Scans 25+ online platforms in parallel for profile presence of a username.
    """
    clean_u = username.strip().lstrip("@")
    headers = {"User-Agent": _USER_AGENT}

    async with httpx.AsyncClient(headers=headers, timeout=4.0) as client:
        tasks = [_check_single_platform(client, p, clean_u) for p in PLATFORMS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    found: List[Dict[str, str]] = []
    for r in results:
        if isinstance(r, dict) and r is not None:
            found.append(r)

    return {
        "success": True,
        "username": clean_u,
        "total_scanned": len(PLATFORMS),
        "total_checked": len(PLATFORMS),
        "total_found": len(found),
        "found_count": len(found),
        "profiles": found,
        "results": found,
        "found": found
    }
