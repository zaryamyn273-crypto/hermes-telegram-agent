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
    resolve_category_key,
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
from .osint_whois import (
    lookup_domain_whois,
    format_whois_report,
)
from .osint_email_security import (
    audit_domain_email_security,
    format_email_security_report,
)
from .osint_web_meta import (
    inspect_web_meta,
    format_web_meta_report,
)
from .osint_redirects import (
    trace_http_redirect_chain,
    format_redirects_report,
)
from .osint_hardware import (
    lookup_mac_vendor,
    format_mac_report,
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
    format_telegram_osint_report,
)
from .virustotal import (
    scan_url_or_domain,
    scan_file_hash,
    format_virustotal_report,
)
from .osint_threat_intel import (
    inspect_ip_threat_reputation,
    format_threat_intel_report,
)
from .osint_bgp import (
    lookup_bgp_asn_intel,
    format_bgp_report,
)
from .osint_subnet import (
    calculate_subnet_and_scan_ptr,
    format_subnet_report,
)
from .osint_exif import (
    extract_exif_metadata,
    extract_exif_from_url,
    format_exif_report,
)
from .osint_phish_intel import (
    analyze_phishing_heuristics,
    format_phish_report,
)

__all__ = [
    "search_web_osint",
    "crawl_webpage_layers",
    "format_osint_search_results",
    "format_crawler_report",
    "generate_smart_dorks",
    "execute_smart_dork",
    "format_smart_dorks_report",
    "resolve_category_key",
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
    "lookup_domain_whois",
    "format_whois_report",
    "audit_domain_email_security",
    "format_email_security_report",
    "inspect_web_meta",
    "format_web_meta_report",
    "trace_http_redirect_chain",
    "format_redirects_report",
    "lookup_mac_vendor",
    "format_mac_report",
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
    "format_telegram_osint_report",
    "scan_url_or_domain",
    "scan_file_hash",
    "format_virustotal_report",
    "inspect_ip_threat_reputation",
    "format_threat_intel_report",
    "lookup_bgp_asn_intel",
    "format_bgp_report",
    "calculate_subnet_and_scan_ptr",
    "format_subnet_report",
    "extract_exif_metadata",
    "extract_exif_from_url",
    "format_exif_report",
    "analyze_phishing_heuristics",
    "format_phish_report",
]
