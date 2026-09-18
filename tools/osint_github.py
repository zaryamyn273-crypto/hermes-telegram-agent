"""
Prometheus OSINT Suite - GitHub Intelligence & Deep Repository Engine (شناسایی، OSINT و کالبدشکافی سورس‌کد در گیت‌هاب)
Deep profile investigation, public commit email extraction, SSH keys, repository inspection,
README extraction, directory tree browsing, specific file reading, code search, and release analysis via GitHub API.
"""

import re
import base64
import html
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
import httpx

from config import get_github_token

logger = logging.getLogger("OSINT_GitHub")

_GITHUB_API_BASE = "https://api.github.com"


def _get_github_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Prometheus-OSINT-Agent/2.0",
    }
    token = get_github_token()
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


# =========================================================================
# Target Classifier & URL Parser
# =========================================================================

def parse_github_target(raw_target: str) -> Dict[str, Any]:
    """
    Intelligently parses user input into GitHub target types:
    - Repo: 'owner/repo' or 'https://github.com/owner/repo'
    - File: 'https://github.com/owner/repo/blob/main/path/to/file.py' or 'file owner/repo path'
    - Tree: 'https://github.com/owner/repo/tree/main/path' or 'tree owner/repo [path]'
    - Readme: 'readme owner/repo'
    - Search: 'search query'
    - Code search: 'code query [owner/repo]'
    - User: 'username' or '@username' or 'https://github.com/username'
    """
    t = raw_target.strip()
    if not t:
        return {"type": "empty"}

    # Clean markdown links or brackets like [text](url) or <url>
    url_m = re.search(r"https?://github\.com/[^\s<>\"'\)]+", t)
    if url_m:
        raw_url = url_m.group(0).rstrip(".,;")
        clean_path = re.sub(r"^https?://github\.com/", "", raw_url).strip("/")
        parts = [p for p in clean_path.split("/") if p]

        if len(parts) == 1:
            return {"type": "user", "username": parts[0]}
        elif len(parts) == 2:
            return {"type": "repo", "owner": parts[0], "repo": parts[1]}
        elif len(parts) >= 4 and parts[2] == "blob":
            return {
                "type": "file",
                "owner": parts[0],
                "repo": parts[1],
                "ref": parts[3],
                "path": "/".join(parts[4:]),
            }
        elif len(parts) >= 4 and parts[2] == "tree":
            return {
                "type": "tree",
                "owner": parts[0],
                "repo": parts[1],
                "ref": parts[3],
                "path": "/".join(parts[4:]),
            }
        elif len(parts) >= 3 and parts[2] in ("releases", "commits", "issues", "pulls"):
            return {"type": "repo", "owner": parts[0], "repo": parts[1], "subview": parts[2]}
        elif len(parts) >= 2:
            return {"type": "repo", "owner": parts[0], "repo": parts[1]}

    # Text subcommands
    t_lower = t.lower()
    if t_lower.startswith(("search ", "find ", "جستجو ", "سرچ ")):
        q = re.sub(r"^(?:search|find|جستجو|سرچ)\s+", "", t, flags=re.IGNORECASE).strip()
        return {"type": "search", "query": q}

    if t_lower.startswith(("code ", "grep ")):
        q = re.sub(r"^(?:code|grep)\s+", "", t, flags=re.IGNORECASE).strip()
        repo = None
        if " in:" in q or " repo:" in q:
            pass
        elif " " in q:
            p = q.split(maxsplit=1)
            if "/" in p[0]:
                repo = p[0]
                q = p[1]
        return {"type": "code", "query": q, "repo": repo}

    if t_lower.startswith(("file ", "read ", "cat ", "فایل ", "خواندن ")):
        rem = re.sub(r"^(?:file|read|cat|فایل|خواندن)\s+", "", t, flags=re.IGNORECASE).strip()
        parts = rem.split(maxsplit=1)
        if len(parts) >= 2 and "/" in parts[0]:
            owner, _, repo = parts[0].partition("/")
            return {"type": "file", "owner": owner, "repo": repo, "path": parts[1].strip()}

    if t_lower.startswith(("tree ", "dir ", "ls ", "پوشه ", "ساختار ")):
        rem = re.sub(r"^(?:tree|dir|ls|پوشه|ساختار)\s+", "", t, flags=re.IGNORECASE).strip()
        parts = rem.split(maxsplit=1)
        if parts and "/" in parts[0]:
            owner, _, repo = parts[0].partition("/")
            path = parts[1].strip() if len(parts) > 1 else ""
            return {"type": "tree", "owner": owner, "repo": repo, "path": path}

    if t_lower.startswith(("readme ", "ریدیمی ")):
        rem = re.sub(r"^(?:readme|ریدیمی)\s+", "", t, flags=re.IGNORECASE).strip()
        if "/" in rem:
            owner, _, repo = rem.partition("/")
            return {"type": "readme", "owner": owner, "repo": repo}

    # Slug formats: owner/repo:path/to/file or owner/repo
    if ":" in t and "/" in t.split(":")[0]:
        slug, path = t.split(":", 1)
        owner, _, repo = slug.partition("/")
        return {"type": "file", "owner": owner.strip(), "repo": repo.strip(), "path": path.strip()}

    repo_slug_match = re.match(r"^([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)$", t)
    if repo_slug_match:
        return {"type": "repo", "owner": repo_slug_match.group(1), "repo": repo_slug_match.group(2)}

    # User format: @username or single word username
    user_match = re.match(r"^@?([a-zA-Z0-9_\-\.]+)$", t)
    if user_match:
        return {"type": "user", "username": user_match.group(1)}

    # Default fallback to search
    return {"type": "search", "query": t}


# =========================================================================
# 1. User Investigation (OSINT)
# =========================================================================

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

    async with httpx.AsyncClient(timeout=14.0) as client:
        # 1. Fetch User Profile
        try:
            user_res = await client.get(f"{_GITHUB_API_BASE}/users/{clean_user}", headers=headers)
        except Exception as e:
            return {"success": False, "username": clean_user, "error": f"خطا در برقراری ارتباط با گیت‌هاب: {e}"}

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
                        "full_name": r.get("full_name") or f"{clean_user}/{r.get('name')}",
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


# =========================================================================
# 2. Deep Repository Inspector (Metadata, Languages, README, Structure, Commits, Releases)
# =========================================================================

def _clean_readme_content(raw_text: str) -> str:
    """Removes HTML badges, massive image tags and cleans up markdown for concise reading."""
    text = raw_text
    # Remove markdown badges [![...](...)](...)
    text = re.sub(r"\[\!\[.*?\]\(.*?\)\]\(.*?\)", "", text)
    # Remove standalone markdown images ![...](...)
    text = re.sub(r"\!\[.*?\]\(.*?\)", "", text)
    # Remove HTML tags like <img>, <p align=...>
    text = re.sub(r"<img[^>]*>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"</?(?:div|p|span|a|h[1-6]|center|picture|source)[^>]*>", "", text, flags=re.IGNORECASE)
    # Remove comments <!-- ... -->
    text = re.sub(r"<!--[\s\S]*?-->", "", text)
    # Collapse multiple blank lines
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


async def inspect_github_repo(owner: str, repo: str) -> Dict[str, Any]:
    """
    Performs comprehensive inspection of a GitHub repository:
    - General metadata (stars, forks, open issues, watchers, license, size)
    - Language breakdown with percentage shares
    - Decoded README summary
    - Root directory files and key architecture files (Dockerfile, requirements, etc.)
    - Latest Release details
    - 5 Recent Commits
    """
    clean_owner = owner.strip().lstrip("@")
    clean_repo = repo.strip().rstrip(".git")
    headers = _get_github_headers()

    async with httpx.AsyncClient(timeout=15.0) as client:
        # 1. Fetch Repository Core Metadata
        try:
            repo_res = await client.get(
                f"{_GITHUB_API_BASE}/repos/{clean_owner}/{clean_repo}",
                headers=headers
            )
        except Exception as e:
            return {"success": False, "error": f"خطا در برقراری ارتباط با سرور گیت‌هاب: {e}"}

        if repo_res.status_code == 404:
            return {
                "success": False,
                "error": f"مخزن «{clean_owner}/{clean_repo}» در گیت‌هاب یافت نشد (احتمالاً خصوصی است یا آدرس نادرست است)."
            }
        if repo_res.status_code != 200:
            return {"success": False, "error": f"خطای گیت‌هاب: کد وضعیت {repo_res.status_code}"}

        r_data = repo_res.json()

        # Concurrently fetch complementary details
        async def _fetch_languages():
            try:
                res = await client.get(f"{_GITHUB_API_BASE}/repos/{clean_owner}/{clean_repo}/languages", headers=headers)
                return res.json() if res.status_code == 200 else {}
            except Exception:
                return {}

        async def _fetch_readme():
            try:
                res = await client.get(f"{_GITHUB_API_BASE}/repos/{clean_owner}/{clean_repo}/readme", headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    content_b64 = data.get("content", "")
                    if content_b64:
                        raw_md = base64.b64decode(content_b64).decode("utf-8", errors="replace")
                        return {
                            "name": data.get("name", "README.md"),
                            "size": data.get("size", 0),
                            "content": raw_md,
                            "clean": _clean_readme_content(raw_md)
                        }
            except Exception as e:
                logger.debug(f"Failed to fetch README for {clean_owner}/{clean_repo}: {e}")
            return None

        async def _fetch_contents():
            try:
                res = await client.get(f"{_GITHUB_API_BASE}/repos/{clean_owner}/{clean_repo}/contents", headers=headers)
                if res.status_code == 200 and isinstance(res.json(), list):
                    items = res.json()
                    dirs = []
                    files = []
                    key_files = []
                    known_keys = {
                        "readme.md", "license", "dockerfile", "docker-compose.yml", "docker-compose.yaml",
                        "requirements.txt", "pyproject.toml", "setup.py", "package.json", "tsconfig.json",
                        "cargo.toml", "go.mod", "makefile", "gemfile", "composer.json", ".env.example"
                    }
                    for it in items:
                        name = it.get("name", "")
                        t = it.get("type", "file")
                        size = it.get("size", 0)
                        if t == "dir":
                            dirs.append(name)
                        else:
                            files.append({"name": name, "size": size})
                            if name.lower() in known_keys:
                                key_files.append(name)
                    return {
                        "dirs": dirs,
                        "files": files,
                        "key_files": key_files,
                        "total_items": len(items)
                    }
            except Exception as e:
                logger.debug(f"Failed to fetch root contents for {clean_owner}/{clean_repo}: {e}")
            return None

        async def _fetch_latest_release():
            try:
                res = await client.get(f"{_GITHUB_API_BASE}/repos/{clean_owner}/{clean_repo}/releases/latest", headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    return {
                        "tag_name": data.get("tag_name", ""),
                        "name": data.get("name") or data.get("tag_name", ""),
                        "published_at": data.get("published_at", ""),
                        "html_url": data.get("html_url", ""),
                        "body": (data.get("body") or "")[:500],
                        "assets_count": len(data.get("assets", []))
                    }
            except Exception:
                pass
            return None

        async def _fetch_recent_commits():
            try:
                res = await client.get(f"{_GITHUB_API_BASE}/repos/{clean_owner}/{clean_repo}/commits?per_page=5", headers=headers)
                if res.status_code == 200:
                    commits = []
                    for c in res.json():
                        sha = (c.get("sha") or "")[:7]
                        c_info = c.get("commit", {})
                        author_name = c_info.get("author", {}).get("name", "Unknown")
                        date = (c_info.get("author", {}).get("date") or "")[:10]
                        message = (c_info.get("message") or "").splitlines()[0] if c_info.get("message") else ""
                        commits.append({
                            "sha": sha,
                            "author": author_name,
                            "date": date,
                            "message": message[:80],
                            "url": c.get("html_url", "")
                        })
                    return commits
            except Exception:
                pass
            return []

        # Run concurrent sub-requests
        langs_raw, readme_data, contents_data, latest_rel, recent_commits = await asyncio.gather(
            _fetch_languages(),
            _fetch_readme(),
            _fetch_contents(),
            _fetch_latest_release(),
            _fetch_recent_commits(),
        )

        # Process languages breakdown into percentages
        languages: List[Dict[str, Any]] = []
        total_bytes = sum(langs_raw.values())
        if total_bytes > 0:
            for lang_name, b_count in sorted(langs_raw.items(), key=lambda x: x[1], reverse=True)[:6]:
                pct = (b_count / total_bytes) * 100
                languages.append({
                    "name": lang_name,
                    "bytes": b_count,
                    "percentage": round(pct, 1)
                })

        # License extraction
        lic_obj = r_data.get("license") or {}
        license_name = lic_obj.get("spdx_id") or lic_obj.get("name") or "ثبت‌نشده"

        return {
            "success": True,
            "owner": clean_owner,
            "repo": clean_repo,
            "full_name": r_data.get("full_name") or f"{clean_owner}/{clean_repo}",
            "html_url": r_data.get("html_url"),
            "description": r_data.get("description") or "",
            "homepage": r_data.get("homepage") or "",
            "default_branch": r_data.get("default_branch", "main"),
            "stars": r_data.get("stargazers_count", 0),
            "forks": r_data.get("forks_count", 0),
            "open_issues": r_data.get("open_issues_count", 0),
            "watchers": r_data.get("subscribers_count", r_data.get("watchers_count", 0)),
            "primary_language": r_data.get("language") or "نامشخص",
            "license": license_name,
            "size_kb": r_data.get("size", 0),
            "created_at": (r_data.get("created_at") or "")[:10],
            "pushed_at": (r_data.get("pushed_at") or "")[:10],
            "is_fork": r_data.get("fork", False),
            "is_archived": r_data.get("archived", False),
            "topics": r_data.get("topics", [])[:8],
            "languages": languages,
            "readme": readme_data,
            "contents": contents_data,
            "latest_release": latest_rel,
            "recent_commits": recent_commits,
        }


# =========================================================================
# 3. Read Specific File Content or Directory Tree
# =========================================================================

async def read_github_file(
    owner: str,
    repo: str,
    path: str,
    ref: Optional[str] = None
) -> Dict[str, Any]:
    """
    Fetches and decodes a specific file or directory from a repository.
    Supports branch/tag/commit ref, automatic base64 decoding, line counts, and size metrics.
    """
    clean_owner = owner.strip().lstrip("@")
    clean_repo = repo.strip().rstrip(".git")
    clean_path = path.strip().lstrip("/")
    headers = _get_github_headers()

    url = f"{_GITHUB_API_BASE}/repos/{clean_owner}/{clean_repo}/contents/{clean_path}"
    params = {}
    if ref:
        params["ref"] = ref

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            res = await client.get(url, headers=headers, params=params)
        except Exception as e:
            return {"success": False, "error": f"خطا در ارتباط با گیت‌هاب: {e}"}

        if res.status_code == 404:
            return {
                "success": False,
                "error": f"فایل یا مسیر «{clean_path}» در مخزن «{clean_owner}/{clean_repo}» یافت نشد."
            }
        if res.status_code != 200:
            return {"success": False, "error": f"خطای گیت‌هاب: کد وضعیت {res.status_code}"}

        data = res.json()

        # If path is a directory
        if isinstance(data, list):
            items = []
            for it in data:
                items.append({
                    "name": it.get("name"),
                    "path": it.get("path"),
                    "type": it.get("type"),
                    "size": it.get("size", 0),
                    "html_url": it.get("html_url")
                })
            return {
                "success": True,
                "type": "directory",
                "owner": clean_owner,
                "repo": clean_repo,
                "path": clean_path,
                "items": items,
                "total_items": len(items)
            }

        # It is a file
        file_name = data.get("name", clean_path.split("/")[-1])
        size_bytes = data.get("size", 0)
        html_url = data.get("html_url", "")
        raw_content = ""

        # Decode base64 if present
        if data.get("encoding") == "base64" and data.get("content"):
            try:
                raw_content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except Exception as e:
                raw_content = f"خطا در دی‌کد محتوای باینری یا متنی: {e}"
        elif data.get("download_url"):
            try:
                dl_res = await client.get(data["download_url"])
                if dl_res.status_code == 200:
                    raw_content = dl_res.text
            except Exception as e:
                raw_content = f"خطا در بارگیری مستقیم سورس‌کد: {e}"

        lines = raw_content.splitlines() if raw_content else []

        # Guess language for syntax highlighting
        ext = file_name.split(".")[-1].lower() if "." in file_name else ""
        lang_map = {
            "py": "python", "js": "javascript", "ts": "typescript", "json": "json",
            "md": "markdown", "yml": "yaml", "yaml": "yaml", "sh": "bash", "bash": "bash",
            "go": "go", "rs": "rust", "cpp": "cpp", "c": "c", "h": "c", "java": "java",
            "html": "html", "css": "css", "sql": "sql", "php": "php", "rb": "ruby",
            "toml": "toml", "xml": "xml", "txt": "text"
        }
        lang = lang_map.get(ext, ext or "text")

        return {
            "success": True,
            "type": "file",
            "owner": clean_owner,
            "repo": clean_repo,
            "name": file_name,
            "path": clean_path,
            "size_bytes": size_bytes,
            "line_count": len(lines),
            "language": lang,
            "content": raw_content,
            "html_url": html_url,
            "ref": ref or data.get("sha", "")[:7],
        }


# =========================================================================
# 4. Search Repositories and Code
# =========================================================================

async def search_github_repos(query: str, max_results: int = 6) -> Dict[str, Any]:
    """Searches GitHub repositories sorted by stars."""
    clean_q = query.strip()
    headers = _get_github_headers()

    async with httpx.AsyncClient(timeout=14.0) as client:
        try:
            res = await client.get(
                f"{_GITHUB_API_BASE}/search/repositories?q={clean_q}&sort=stars&order=desc&per_page={max_results}",
                headers=headers
            )
            if res.status_code != 200:
                return {"success": False, "query": clean_q, "error": f"خطا در جستجوی مخازن گیت‌هاب: کد {res.status_code}"}

            data = res.json()
            total_count = data.get("total_count", 0)
            items = []
            for r in data.get("items", [])[:max_results]:
                items.append({
                    "name": r.get("name"),
                    "full_name": r.get("full_name"),
                    "url": r.get("html_url"),
                    "description": r.get("description") or "",
                    "language": r.get("language") or "نامشخص",
                    "stars": r.get("stargazers_count", 0),
                    "forks": r.get("forks_count", 0),
                    "updated_at": (r.get("updated_at") or "")[:10],
                    "owner": r.get("owner", {}).get("login", "")
                })

            return {
                "success": True,
                "query": clean_q,
                "total_count": total_count,
                "results": items,
                "repositories": items,  # Backward compatible alias
            }
        except Exception as e:
            return {"success": False, "query": clean_q, "error": f"خطای ارتباط با گیت‌هاب: {e}"}


async def search_github_code(
    query: str,
    repo: Optional[str] = None,
    max_results: int = 5
) -> Dict[str, Any]:
    """Searches code within a specific repository or across GitHub."""
    clean_q = query.strip()
    q_param = f"{clean_q} repo:{repo.strip()}" if repo else clean_q
    headers = _get_github_headers()

    async with httpx.AsyncClient(timeout=14.0) as client:
        try:
            res = await client.get(
                f"{_GITHUB_API_BASE}/search/code?q={q_param}&per_page={max_results}",
                headers=headers
            )
            if res.status_code != 200:
                return {"success": False, "query": clean_q, "error": f"خطا در جستجوی کد گیت‌هاب: کد {res.status_code}"}

            data = res.json()
            items = []
            for it in data.get("items", [])[:max_results]:
                items.append({
                    "name": it.get("name"),
                    "path": it.get("path"),
                    "repo": it.get("repository", {}).get("full_name", ""),
                    "html_url": it.get("html_url"),
                })
            return {
                "success": True,
                "query": clean_q,
                "repo": repo,
                "total_count": data.get("total_count", 0),
                "results": items
            }
        except Exception as e:
            return {"success": False, "query": clean_q, "error": f"خطای جستجوی کد: {e}"}


async def search_github(query: str, search_type: str = "repositories", max_results: int = 5) -> Dict[str, Any]:
    """
    Searches GitHub users or repositories by query string.
    Backward-compatible entrypoint. Defaults search_type to 'repositories'
    and provides both 'results' and 'repositories' keys in response.
    """
    clean_q = query.strip()
    if search_type == "repositories" or search_type == "repos":
        return await search_github_repos(clean_q, max_results=max_results)

    headers = _get_github_headers()
    endpoint = f"{_GITHUB_API_BASE}/search/{search_type}"

    async with httpx.AsyncClient(timeout=14.0) as client:
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
                "results": items,
                "repositories": items if search_type != "users" else []
            }
        except Exception as e:
            return {"success": False, "query": clean_q, "error": f"خطای ارتباط با گیت‌هاب: {str(e)}"}


# =========================================================================
# 5. Telegram HTML Formatters
# =========================================================================

def format_github_repo_report(data: Dict[str, Any]) -> str:
    """Formats full repository inspection data into rich Telegram HTML."""
    if not data.get("success"):
        return f"❌ <b>خطا در بررسی مخزن گیت‌هاب:</b> {html.escape(data.get('error', 'مخزن یافت نشد.'))}"

    full_name = html.escape(data.get("full_name", ""))
    url = data.get("html_url", f"https://github.com/{full_name}")
    desc = html.escape(data.get("description") or "توضیحاتی ثبت نشده است.")
    stars = data.get("stars", 0)
    forks = data.get("forks", 0)
    issues = data.get("open_issues", 0)
    watchers = data.get("watchers", 0)
    branch = html.escape(data.get("default_branch", "main"))
    license_name = html.escape(data.get("license", "ثبت‌نشده"))
    created = data.get("created_at", "")
    pushed = data.get("pushed_at", "")
    size_mb = data.get("size_kb", 0) / 1024

    lines = [
        f"🐙 <b>کالبدشکافی مخزن گیت‌هاب:</b> <a href=\"{url}\">{full_name}</a>",
        f"📝 <i>{desc}</i>\n",
        f"⭐ <b>ستاره‌ها:</b> <code>{stars:,}</code> | 🍴 <b>فورک‌ها:</b> <code>{forks:,}</code>",
        f"🐞 <b>ایشوهای باز:</b> <code>{issues:,}</code> | 👁 <b>دنبال‌کنندگان:</b> <code>{watchers:,}</code>",
        f"🌿 <b>شاخه پیش‌فرض:</b> <code>{branch}</code> | 📜 <b>مجوز:</b> <code>{license_name}</code>",
        f"💾 <b>حجم کل:</b> <code>{size_mb:.2f} MB</code> | 📅 <b>آخرین به‌روزرسانی:</b> <code>{pushed}</code>",
    ]

    # Languages Breakdown
    langs = data.get("languages", [])
    if langs:
        lang_parts = [f"<b>{html.escape(l['name'])}</b>: <code>{l['percentage']}%</code>" for l in langs]
        lines.append(f"\n📊 <b>زبان‌های برنامه‌نویسی:</b>\n• " + " | ".join(lang_parts))

    # Key project files and directories
    contents = data.get("contents")
    if contents:
        dirs = contents.get("dirs", [])
        key_files = contents.get("key_files", [])
        dir_display = " ".join([f"📁 <code>{html.escape(d)}/</code>" for d in dirs[:5]])
        key_display = " ".join([f"📄 <code>{html.escape(k)}</code>" for k in key_files[:5]])

        struct_line = "\n🗂 <b>ساختار و فایل‌های کلیدی پروژه:</b>"
        if dir_display:
            struct_line += f"\n• پوشه‌ها: {dir_display}"
        if key_display:
            struct_line += f"\n• پیکربندی‌ها: {key_display}"
        lines.append(struct_line)

    # Latest Release
    rel = data.get("latest_release")
    if rel:
        tag = html.escape(rel.get("tag_name") or rel.get("name") or "")
        rel_url = rel.get("html_url", url)
        rel_date = (rel.get("published_at") or "")[:10]
        lines.append(f"\n🚀 <b>آخرین نسخه (Release):</b> <a href=\"{rel_url}\">{tag}</a> <i>(تاریخ: {rel_date})</i>")

    # Recent Commits
    commits = data.get("recent_commits", [])
    if commits:
        commit_lines = ["\n🕒 <b>آخرین کامیت‌های پروژه:</b>"]
        for c in commits[:4]:
            sha = html.escape(c.get("sha", ""))
            c_msg = html.escape(c.get("message", ""))
            author = html.escape(c.get("author", ""))
            commit_lines.append(f"• <code>{sha}</code> {c_msg} <i>({author})</i>")
        lines.append("\n".join(commit_lines))

    # Decoded README summary in expandable blockquote
    readme = data.get("readme")
    if readme and readme.get("clean"):
        clean_rm = readme["clean"]
        snippet = clean_rm[:1400]
        if len(clean_rm) > 1400:
            snippet += "\n..."
        lines.append(
            f"\n📖 <b>خلاصه مستندات (README):</b>\n"
            f"<blockquote expandable>{html.escape(snippet)}</blockquote>"
        )

    # Quick Action Tips
    lines.append(
        f"\n💡 <b>فرامین سریع برای این مخزن:</b>\n"
        f"• خواندن فایل: <code>/github file {full_name} [نام_فایل]</code>\n"
        f"• ریدیمی کامل: <code>/github readme {full_name}</code>\n"
        f"• درخت پوشه‌ها: <code>/github tree {full_name}</code>"
    )

    return "\n".join(lines)


def format_github_file_report(data: Dict[str, Any], max_display_chars: int = 3200) -> str:
    """Formats file inspection or code viewing into clean Telegram HTML."""
    if not data.get("success"):
        return f"❌ <b>خطا در دریافت فایل:</b> {html.escape(data.get('error', 'فایل یافت نشد.'))}"

    # If it was a directory listing
    if data.get("type") == "directory":
        owner = html.escape(data.get("owner", ""))
        repo = html.escape(data.get("repo", ""))
        path = html.escape(data.get("path", "") or "روت")
        items = data.get("items", [])

        lines = [
            f"📁 <b>محتویات مسیر «{path}» در مخزن</b> <code>{owner}/{repo}</code>:\n"
        ]
        for it in items[:25]:
            icon = "📁" if it.get("type") == "dir" else "📄"
            name = html.escape(it.get("name", ""))
            it_path = it.get("path", "")
            if it.get("type") == "dir":
                lines.append(f"{icon} <code>/github tree {owner}/{repo} {it_path}</code>")
            else:
                lines.append(f"{icon} <code>/github file {owner}/{repo} {it_path}</code>")
        return "\n".join(lines)

    owner = html.escape(data.get("owner", ""))
    repo = html.escape(data.get("repo", ""))
    path = html.escape(data.get("path", ""))
    size_kb = data.get("size_bytes", 0) / 1024
    lines_count = data.get("line_count", 0)
    lang = data.get("language", "text")
    html_url = data.get("html_url", "")
    content = data.get("content", "")

    header = (
        f"📄 <b>فایل:</b> <a href=\"{html_url}\"><code>{path}</code></a>\n"
        f"📦 مخزن: <code>{owner}/{repo}</code> | 📏 خطوط: <code>{lines_count:,}</code> | 💾 حجم: <code>{size_kb:.1f} KB</code>\n"
    )

    if not content.strip():
        return header + "\n⚠️ <i>این فایل خالی است یا محتوای آن قابل نمایش متنی نیست.</i>"

    if len(content) > max_display_chars:
        trimmed = content[:max_display_chars]
        footer = f"\n\n✂️ <i>(نمایش {max_display_chars:,} کاراکتر اول از کل فایل. فایل کامل {size_kb:.1f} KB است)</i>"
    else:
        trimmed = content
        footer = ""

    code_block = f"<pre><code class=\"language-{lang}\">{html.escape(trimmed)}</code></pre>"
    return header + "\n" + code_block + footer


def format_github_search_report(data: Dict[str, Any]) -> str:
    """Formats repository search results."""
    if not data.get("success"):
        return f"❌ <b>خطا در جستجو:</b> {html.escape(data.get('error', 'خطایی رخ داد.'))}"

    q = html.escape(data.get("query", ""))
    results = data.get("results") or data.get("repositories") or []
    total = data.get("total_count", 0)

    if not results:
        return f"🔍 نتیجه‌ای در مخازن گیت‌هاب برای «<code>{q}</code>» یافت نشد."

    lines = [
        f"🐙 <b>مخازن برتر گیت‌هاب برای:</b> <code>{q}</code>",
        f"<i>تعداد کل نتایج یافت‌شده: {total:,} مخزن</i>\n"
    ]
    for r in results[:6]:
        r_name = html.escape(r.get("full_name") or r.get("name", ""))
        r_url = r.get("url", "")
        stars = r.get("stars", 0)
        forks = r.get("forks", 0)
        lang = html.escape(r.get("language") or "N/A")
        desc = html.escape((r.get("description") or "بدون توضیح")[:120])
        lines.append(
            f"• <b><a href=\"{r_url}\">{r_name}</a></b> (⭐ {stars:,} | 🍴 {forks:,} | 💻 {lang})\n"
            f"  <i>{desc}</i>\n"
            f"  کالبدشکافی: <code>/github {r_name}</code>\n"
        )
    return "\n".join(lines)


def format_github_user_report(data: Dict[str, Any]) -> str:
    """Formats OSINT profile report for a GitHub user."""
    if not data.get("success"):
        return f"❌ {html.escape(data.get('error', 'کاربر یافت نشد.'))}"

    username = html.escape(data.get("username", ""))
    name = html.escape(data.get("name") or username)
    bio = html.escape(data.get("bio") or "ندارد")
    company = html.escape(data.get("company") or "ندارد")
    location = html.escape(data.get("location") or "ندارد")
    created = (data.get("created_at") or "")[:10]
    followers = data.get("followers", 0)
    public_repos = data.get("public_repos_count", 0)
    html_url = data.get("profile_url", f"https://github.com/{username}")

    lines = [
        f"🐙 <b>اطلاعات OSINT کاربر گیت‌هاب:</b> <a href=\"{html_url}\">@{username}</a>",
        f"👤 <b>نام:</b> {name}",
        f"📝 <b>بیو:</b> {bio}",
        f"🏢 <b>سازمان/شرکت:</b> {company} | 📍 <b>موقعیت:</b> {location}",
        f"👥 <b>دنبال‌کنندگان:</b> <code>{followers:,}</code> | 📁 <b>مخازن عمومی:</b> <code>{public_repos:,}</code>",
        f"📅 <b>تاریخ عضویت:</b> <code>{created}</code>",
    ]

    emails = data.get("discovered_emails") or []
    if emails:
        lines.append(f"\n📧 <b>ایمیل‌های استخراج‌شده از تاریخچه کامیت‌ها ({len(emails)}):</b>")
        for em in emails:
            lines.append(f"  • <code>{html.escape(em)}</code>")
    else:
        lines.append("\n📧 <b>ایمیل کامیت:</b> <i>هیچ ایمیل عمومی در کامیت‌های اخیر یافت نشد.</i>")

    ssh_keys = data.get("ssh_keys_sample") or []
    if ssh_keys:
        lines.append(f"\n🔑 <b>کلیدهای SSH عمومی ({data.get('ssh_keys_count', len(ssh_keys))} کلید):</b>")
        for k in ssh_keys[:2]:
            lines.append(f"  • <code>{html.escape(k[:45])}...</code>")

    top_repos = data.get("top_repos") or []
    if top_repos:
        lines.append("\n⭐ <b>مخازن برتر کاربر:</b>")
        for r in top_repos[:4]:
            r_fname = html.escape(r.get("full_name") or f"{username}/{r.get('name')}")
            lines.append(f"  • <a href=\"{r.get('url')}\">{r_fname}</a> (⭐ {r.get('stars')} | {html.escape(r.get('language') or 'N/A')})")
            lines.append(f"    بررسی مخزن: <code>/github {r_fname}</code>")

    return "\n".join(lines)
