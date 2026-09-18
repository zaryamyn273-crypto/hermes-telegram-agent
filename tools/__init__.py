"""
Specialized OSINT Tools Package for Prometheus Telegram Agent.
"""

from .osint_search import (
    search_web_osint,
    crawl_webpage_layers,
    format_osint_search_results,
    format_crawler_report,
)
from .osint_dork import (
    generate_smart_dorks,
    execute_smart_dork,
    format_smart_dorks_report,
)
from .osint_linkedin import (
    search_linkedin_profile,
    search_linkedin_company,
)
from .osint_github import (
    investigate_github_user,
    search_github,
)
from .osint_username import (
    search_username_across_platforms,
)
from .osint_network import (
    resolve_dns_records,
    enumerate_subdomains_crtsh,
    lookup_ip_intel,
    inspect_ssl_certificate,
    audit_http_security_headers,
    format_ssl_report,
    format_http_headers_report,
)
from .osint_hash import (
    identify_hash_or_token,
    analyze_jwt_token,
    format_hash_report,
)
from .osint_email_phone import (
    investigate_email,
    analyze_phone_number,
)
from .public_db_intel import (
    query_public_intel_databases,
    query_wayback_snapshots,
    format_public_intel_report,
)
from .telegram_osint import (
    investigate_telegram_target,
    format_telegram_target_report,
)
from .virustotal import (
    scan_url_or_domain,
    scan_file_hash,
    format_virustotal_report,
)

__all__ = [
    "search_web_osint",
    "crawl_webpage_layers",
    "format_osint_search_results",
    "format_crawler_report",
    "generate_smart_dorks",
    "execute_smart_dork",
    "format_smart_dorks_report",
    "search_linkedin_profile",
    "search_linkedin_company",
    "investigate_github_user",
    "search_github",
    "search_username_across_platforms",
    "resolve_dns_records",
    "enumerate_subdomains_crtsh",
    "lookup_ip_intel",
    "inspect_ssl_certificate",
    "audit_http_security_headers",
    "format_ssl_report",
    "format_http_headers_report",
    "identify_hash_or_token",
    "analyze_jwt_token",
    "format_hash_report",
    "investigate_email",
    "analyze_phone_number",
    "query_public_intel_databases",
    "query_wayback_snapshots",
    "format_public_intel_report",
    "investigate_telegram_target",
    "format_telegram_target_report",
    "scan_url_or_domain",
    "scan_file_hash",
    "format_virustotal_report",
]
