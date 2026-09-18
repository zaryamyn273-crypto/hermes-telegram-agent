"""
Prometheus OSINT Suite - GitHub Intelligence Engine (شناسایی و OSINT در گیت‌هاب)
Deep profile investigation, public commit email extraction, SSH keys, repository analysis,
and code/credential leak search via GitHub API.
"""

import re
import logging
from typing import Dict, Any, List, Optional, Set
import httpx

from config import get_github_token

logger = logging.getLogger("OSINT_GitHub")

_GITHUB_API_BASE = "https://api.github.com"


def _get_github_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Prometheus-OSINT-Agent/1.0",
    }
    token = get_github_token()
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


async def investigate_github_user(username: str) -> Dict[str, Any]:
    """
    Performs full OSINT analysis on a GitHub username:
    - Profile details (Bio, Company, Location, Blog, Twitter, Created At)
    - Commit history analysis to uncover hidden/real author emails
    - Public SSH keys
    - Top repositories and primary languages
    - Organizations
    """
    clean_user = username.strip().lstrip("@")
    headers = _get_github_headers()

    async with httpx.AsyncClient(timeout=12.0) as client:
        # 1. Fetch User Profile
        user_res = await client.get(f"{_GITHUB_API_BASE}/users/{clean_user}", headers=headers)
        if user_res.status_code == 404:
            return {"success": False, "username": clean_user, "error": f"کاربر گیت‌هاب '{clean_user}' یافت نشد."}
        if user_res.status_code != 200:
            return {"success": False, "username": clean_user, "error": f"خطای گیت‌هاب: کد {user_res.status_code}"}

        user_data = user_res.json()

        # 2. Extract Hidden Emails from Public Commit Events
        discovered_emails: Set[str] = set()
        if user_data.get("email"):
            discovered_emails.add(user_data["email"])

        try:
            events_res = await client.get(f"{_GITHUB_API_BASE}/users/{clean_user}/events/public", headers=headers)
            if events_res.status_code == 200:
                events = events_res.json()
                for ev in events:
                    if ev.get("type") == "PushEvent":
                        commits = ev.get("payload", {}).get("commits", [])
                        for cm in commits:
                            author = cm.get("author", {})
                            em = author.get("email", "")
                            # Exclude generic noreply emails
                            if em and not em.endswith("@users.noreply.github.com"):
                                discovered_emails.add(em)
        except Exception as e:
            logger.debug(f"Failed to fetch commit events for {clean_user}: {e}")

        # 3. Fetch Top Repositories
        repos: List[Dict[str, Any]] = []
        try:
            repos_res = await client.get(
                f"{_GITHUB_API_BASE}/users/{clean_user}/repos?sort=updated&per_page=6",
                headers=headers
            )
            if repos_res.status_code == 200:
                for r in repos_res.json():
                    repos.append({
                        "name": r.get("name"),
                        "url": r.get("html_url"),
                        "description": r.get("description") or "",
                        "language": r.get("language") or "نامشخص",
                        "stars": r.get("stargazers_count", 0),
                        "forks": r.get("forks_count", 0),
                        "updated_at": r.get("updated_at")
                    })
        except Exception as e:
            logger.debug(f"Failed to fetch repos for {clean_user}: {e}")

        # 4. Fetch Public SSH Keys
        ssh_keys: List[str] = []
        try:
            ssh_res = await client.get(f"https://github.com/{clean_user}.keys")
            if ssh_res.status_code == 200 and ssh_res.text.strip():
                ssh_keys = [k.strip() for k in ssh_res.text.splitlines() if k.strip()][:3]
        except Exception:
            pass

        # 5. Fetch User Organizations
        orgs: List[str] = []
        try:
            orgs_res = await client.get(f"{_GITHUB_API_BASE}/users/{clean_user}/orgs", headers=headers)
            if orgs_res.status_code == 200:
                for o in orgs_res.json():
                    orgs.append(o.get("login", ""))
        except Exception:
            pass

        return {
            "success": True,
            "username": clean_user,
            "name": user_data.get("name") or "",
            "profile_url": user_data.get("html_url"),
            "avatar_url": user_data.get("avatar_url"),
            "bio": user_data.get("bio") or "",
            "company": user_data.get("company") or "",
            "location": user_data.get("location") or "",
            "blog": user_data.get("blog") or "",
            "twitter": user_data.get("twitter_username") or "",
            "public_repos_count": user_data.get("public_repos", 0),
            "followers": user_data.get("followers", 0),
            "following": user_data.get("following", 0),
            "created_at": user_data.get("created_at"),
            "updated_at": user_data.get("updated_at"),
            "discovered_emails": sorted(list(discovered_emails)),
            "ssh_keys_count": len(ssh_keys),
            "ssh_keys_sample": ssh_keys,
            "top_repos": repos,
            "organizations": orgs
        }


async def search_github(query: str, search_type: str = "users", max_results: int = 5) -> Dict[str, Any]:
    """
    Searches GitHub users or repositories by query string.
    search_type: 'users' or 'repositories'
    """
    clean_q = query.strip()
    headers = _get_github_headers()
    endpoint = f"{_GITHUB_API_BASE}/search/{search_type}"

    async with httpx.AsyncClient(timeout=12.0) as client:
        try:
            res = await client.get(f"{endpoint}?q={clean_q}&per_page={max_results}", headers=headers)
            if res.status_code != 200:
                return {"success": False, "query": clean_q, "error": f"خطا در جستجوی گیت‌هاب: کد {res.status_code}"}

            data = res.json()
            total_count = data.get("total_count", 0)
            items = []

            for it in data.get("items", [])[:max_results]:
                if search_type == "users":
                    items.append({
                        "username": it.get("login"),
                        "profile_url": it.get("html_url"),
                        "avatar_url": it.get("avatar_url"),
                        "type": it.get("type")
                    })
                else:
                    items.append({
                        "name": it.get("full_name"),
                        "url": it.get("html_url"),
                        "description": it.get("description") or "",
                        "language": it.get("language") or "",
                        "stars": it.get("stargazers_count", 0),
                        "forks": it.get("forks_count", 0),
                    })

            return {
                "success": True,
                "query": clean_q,
                "search_type": search_type,
                "total_count": total_count,
                "results": items
            }
        except Exception as e:
            return {"success": False, "query": clean_q, "error": f"خطای ارتباط با گیت‌هاب: {str(e)}"}
