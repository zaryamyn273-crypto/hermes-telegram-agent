"""
Prometheus OSINT Suite - Smart Google Dorking Engine (گوگل دورکینگ هوشمند)
Generates high-impact Google Dorks for domains, organizations, usernames, and sensitive assets,
and executes them live via multi-engine search while generating direct clickable Google dork links.
"""

import urllib.parse
import logging
from typing import Dict, Any, List, Optional
from tools.osint_search import search_web_osint

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
    "code_leaks": {
        "title": "نشت کد در مخازن عمومی (Public Code / Leak Repositories)",
        "dorks": [
            'site:pastebin.com "{target}"',
            'site:github.com "{target}" password OR token OR secret',
        ]
    }
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


def generate_smart_dorks(target: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Generates tailored Google Dorks with titles, dork query, and direct Google URL.
    """
    clean_target = clean_target_domain(target)
    generated = []

    categories_to_process = (
        {category: DORK_CATEGORIES[category]}
        if category and category in DORK_CATEGORIES
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
