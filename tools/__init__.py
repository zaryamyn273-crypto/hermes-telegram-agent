"""
Specialized OSINT Tools Package for Prometheus Telegram Agent.
"""

from .osint_search import search_web_osint, crawl_webpage_layers
from .osint_dork import generate_smart_dorks, execute_smart_dork
from .osint_linkedin import search_linkedin_profile, search_linkedin_company
from .osint_github import investigate_github_user, search_github
from .osint_username import search_username_across_platforms
from .osint_network import resolve_dns_records, enumerate_subdomains_crtsh, lookup_ip_intel
from .osint_email_phone import investigate_email, analyze_phone_number
from .virustotal import scan_url_or_domain, scan_file_hash, format_virustotal_report

__all__ = [
    "search_web_osint",
    "crawl_webpage_layers",
    "generate_smart_dorks",
    "execute_smart_dork",
    "search_linkedin_profile",
    "search_linkedin_company",
    "investigate_github_user",
    "search_github",
    "search_username_across_platforms",
    "resolve_dns_records",
    "enumerate_subdomains_crtsh",
    "lookup_ip_intel",
    "investigate_email",
    "analyze_phone_number",
    "scan_url_or_domain",
    "scan_file_hash",
    "format_virustotal_report",
]
