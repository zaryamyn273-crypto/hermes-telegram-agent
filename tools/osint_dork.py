"""
Prometheus OSINT Suite - Smart Google Dorking Engine (گوگل دورکینگ هوشمند)
Generates high-impact Google Dorks for domains, organizations, usernames, and sensitive assets,
and executes them live via multi-engine search while generating direct clickable Google dork links.
"""

import urllib.parse
import html
import logging
from typing import Dict, Any, List, Optional
from tools.osint_search import search_web_osint
from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_Dork")

DORK_CATEGORIES = {
    "sensitive_files": {
        "title": "فایل‌های حساس و کانفیگ (Sensitive Files & Configs)",
        "dorks": [
            'site:{target} ext:env OR ext:sql OR ext:log OR ext:conf OR ext:bak OR ext:yml',
            'site:{target} filetype:sql "dump" OR "INSERT INTO"',
            'site:{target} inurl:wp-config.php OR inurl:configuration.php OR inurl:config.json',
        ]
    },
    "admin_portals": {
        "title": "پنل‌های مدیریت و ورود (Admin & Login Portals)",
        "dorks": [
            'site:{target} inurl:admin OR inurl:login OR inurl:cpanel OR inurl:portal OR inurl:dashboard',
            'site:{target} intitle:"admin login" OR intitle:"control panel" OR intitle:"sign in"',
        ]
    },
    "open_directories": {
        "title": "دایرکتوری‌های باز (Open Directories / Index of)",
        "dorks": [
            'site:{target} intitle:"index of /" OR intitle:"index of /admin" OR intitle:"index of /backup"',
            'site:{target} intitle:"index of" intext:"parent directory"',
        ]
    },
    "confidential_docs": {
        "title": "اسناد محرمانه و مدارک داخلی (Confidential Documents)",
        "dorks": [
            'site:{target} (ext:pdf OR ext:doc OR ext:docx OR ext:xlsx) ("confidential" OR "محرمانه" OR "internal use only")',
            'site:{target} ext:pdf "not for public release"',
        ]
    },
    "exposed_credentials": {
        "title": "اطلاعات هویتی و کلیدهای افشا شده (Exposed Credentials & Keys)",
        "dorks": [
            'site:{target} intext:"api_key" OR intext:"secret_key" OR intext:"access_token" OR intext:"authorization: Bearer"',
            'site:{target} intext:"db_password" OR intext:"database_password" OR intext:"mysql_connect"',
        ]
    },
    "exposed_git_docker": {
        "title": "مخازن گیت و محیط داکر افشا شده (Exposed .git & Docker)",
        "dorks": [
            'site:{target} inurl:".git/config" OR inurl:".git/HEAD" OR inurl:".gitignore"',
            'site:{target} inurl:"docker-compose.yml" OR inurl:"Dockerfile" OR inurl:".gitlab-ci.yml"',
            'site:{target} inurl:".env" OR inurl:"id_rsa" OR inurl:".bash_history"',
        ]
    },
    "swagger_api_docs": {
        "title": "مستندات ای‌پی‌آی و سواگر باز (Swagger & API Docs)",
        "dorks": [
            'site:{target} inurl:swagger-ui.html OR inurl:api-docs OR inurl:v2/api-docs OR inurl:v3/api-docs',
            'site:{target} inurl:graphql OR inurl:graphiql OR inurl:altair',
            'site:{target} intitle:"Swagger UI" OR inurl:"/docs" OR inurl:"/redoc"',
        ]
    },
    "database_dumps": {
        "title": "بک‌آپ‌ها و دامپ‌های پایگاه داده (Database Backups & Dumps)",
        "dorks": [
            'site:{target} (ext:sql OR ext:dump OR ext:tar OR ext:gz OR ext:zip OR ext:7z) ("backup" OR "dump" OR "users")',
            'site:{target} inurl:phpmyadmin OR inurl:pma OR inurl:adminer.php',
        ]
    },
    "subdomain_discovery": {
        "title": "شناسایی ساب‌دامین‌ها (Subdomain Discovery)",
        "dorks": [
            'site:*.{target} -site:www.{target}',
        ]
    },
    "cloud_buckets": {
        "title": "باکت‌های ابری عمومی (Exposed Cloud Buckets)",
        "dorks": [
            'site:s3.amazonaws.com "{target}"',
            'site:blob.core.windows.net "{target}"',
            'site:storage.googleapis.com "{target}"',
        ]
    },
    "iot_cameras": {
        "title": "تجهیزات اینترنت اشیا و دوربین‌ها (IoT & Cameras)",
        "dorks": [
            'site:{target} intitle:"Live View / - AXIS" OR inurl:view/view.shtml',
            'site:{target} intitle:"Network Camera" OR intitle:"Toshiba Network Camera"',
        ]
    },
    "code_leaks": {
        "title": "نشت کد در مخازن عمومی (Public Code / Leak Repositories)",
        "dorks": [
            'site:pastebin.com "{target}"',
            'site:github.com "{target}" password OR token OR secret',
        ]
    }
}

# Aliases to map user-friendly short names to official category keys
CATEGORY_ALIASES = {
    "sensitive": "sensitive_files",
    "files": "sensitive_files",
    "config": "sensitive_files",
    "admin": "admin_portals",
    "login": "admin_portals",
    "portal": "admin_portals",
    "dirs": "open_directories",
    "directory": "open_directories",
    "index": "open_directories",
    "docs": "confidential_docs",
    "documents": "confidential_docs",
    "creds": "exposed_credentials",
    "credentials": "exposed_credentials",
    "keys": "exposed_credentials",
    "git": "exposed_git_docker",
    "docker": "exposed_git_docker",
    "api": "swagger_api_docs",
    "swagger": "swagger_api_docs",
    "graphql": "swagger_api_docs",
    "db": "database_dumps",
    "sql": "database_dumps",
    "backup": "database_dumps",
    "subdomains": "subdomain_discovery",
    "subdomain": "subdomain_discovery",
    "cloud": "cloud_buckets",
    "s3": "cloud_buckets",
    "iot": "iot_cameras",
    "camera": "iot_cameras",
    "cameras": "iot_cameras",
    "code": "code_leaks",
    "leaks": "code_leaks",
}


def clean_target_domain(target: str) -> str:
    """Extracts a clean domain or keyword from user input."""
    t = target.strip()
    if t.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(t)
        t = parsed.netloc or t
    # Strip port if present
    if ":" in t:
        t = t.split(":")[0]
    return t.strip().lower()


def resolve_category_key(category: Optional[str]) -> Optional[str]:
    """Resolves user-supplied category string (or alias) to the canon category key."""
    if not category:
        return None
    cat_lower = category.strip().lower()
    if cat_lower in DORK_CATEGORIES:
        return cat_lower
    return CATEGORY_ALIASES.get(cat_lower)


def generate_smart_dorks(target: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Generates tailored Google Dorks with titles, dork query, and direct Google URL.
    """
    clean_target = clean_target_domain(target)
    generated = []

    resolved_cat = resolve_category_key(category)
    categories_to_process = (
        {resolved_cat: DORK_CATEGORIES[resolved_cat]}
        if resolved_cat and resolved_cat in DORK_CATEGORIES
        else DORK_CATEGORIES
    )

    for cat_key, cat_data in categories_to_process.items():
        cat_title = cat_data["title"]
        for dork_tpl in cat_data["dorks"]:
            query = dork_tpl.format(target=clean_target)
            google_url = f"https://www.google.com/search?q={urllib.parse.quote_plus(query)}"
            generated.append({
                "category": cat_key,
                "category_title": cat_title,
                "query": query,
                "dork": query,
                "google_url": google_url,
                "google_search_url": google_url
            })

    return generated


async def execute_smart_dork(target: str, dork_type: str = "all", max_results_per_dork: int = 3) -> Dict[str, Any]:
    """
    Generates and immediately executes the top Google Dorks live via search engines,
    aggregating real-world findings.
    """
    clean_target = clean_target_domain(target)
    all_dorks = generate_smart_dorks(clean_target, category=dork_type if dork_type != "all" else None)

    # Select representative dorks to execute live
    # Pick 1 dork per category to avoid search rate limiting
    dorks_to_run = []
    seen_cats = set()
    for d in all_dorks:
        if d["category"] not in seen_cats:
            dorks_to_run.append(d)
            seen_cats.add(d["category"])
        if len(dorks_to_run) >= 4:
            break

    findings = []
    for d in dorks_to_run:
        res = await search_web_osint(d["query"], max_results=max_results_per_dork)
        items = res.get("results", [])
        findings.append({
            "category": d["category"],
            "category_title": d["category_title"],
            "query": d["query"],
            "google_url": d["google_url"],
            "results_count": len(items),
            "results": items
        })

    return {
        "success": True,
        "target": clean_target,
        "total_dorks_generated": len(all_dorks),
        "dorks_executed": len(findings),
        "findings": findings,
        "all_generated_dorks": all_dorks[:15]
    }


def format_smart_dorks_report(target: str, dorks: List[Dict[str, Any]], live_findings: Optional[List[Dict[str, Any]]] = None) -> str:
    """Formats generated Google Dorks cleanly into Persian Telegram HTML."""
    target_clean = html.escape(clean_target_domain(target))
    lines = [
        f"🎯 <b>دورک‌های هوشمند گوگل برای هدف:</b> <code>{target_clean}</code>\n"
    ]

    for i, d in enumerate(dorks[:8], 1):
        name = html.escape(d.get("category_title", ""))
        dork_query = html.escape(d.get("query", ""))
        google_url = d.get("google_url", "")
        lines.append(
            f"<b>{i}. {name}</b>\n"
            f"▫️ <code>{dork_query}</code>\n"
            f"▫️ <a href=\"{google_url}\">جستجوی مستقیم در Google</a>\n"
        )

    if live_findings:
        live_blocks = []
        for f in live_findings:
            if f.get("results"):
                cat_t = html.escape(f.get("category_title", ""))
                res_lines = [f"• <b>{cat_t}:</b>"]
                for r in f["results"][:2]:
                    t = html.escape(r.get("title", ""))
                    u = r.get("url", "")
                    res_lines.append(f"  ▫️ <a href=\"{u}\">{t}</a>")
                live_blocks.append("\n".join(res_lines))
        if live_blocks:
            live_text = "\n\n".join(live_blocks)
            lines.append(f"⚡️ <b>نتایج بررسی زنده (Live Recon):</b>\n{wrap_in_expandable_blockquote(live_text)}\n")

    lines.append("⚡️ <i>طراحی‌شده بر پایه جدیدترین الگوهای گوگل دورکینگ و بهره‌برداری OSINT</i>")
    return "\n".join(lines)
