"""
Prometheus OSINT Suite - LinkedIn Intelligence & Reconnaissance (گشتن و شناسایی در لینکدین)
Deep search for LinkedIn profiles, employees, companies, and roles via search engine profiling and dorking.
"""

import re
import urllib.parse
import logging
from typing import Dict, Any, List, Optional
from tools.osint_search import search_web_osint

logger = logging.getLogger("OSINT_LinkedIn")


def _clean_linkedin_title(raw_title: str) -> Dict[str, str]:
    """
    Parses typical LinkedIn title format: 'Full Name - Job Title - Company | LinkedIn'
    """
    cleaned = raw_title.replace(" | LinkedIn", "").replace(" - LinkedIn", "").strip()
    parts = [p.strip() for p in cleaned.split(" - ") if p.strip()]

    name = parts[0] if parts else cleaned
    headline = " - ".join(parts[1:]) if len(parts) > 1 else ""

    return {
        "name": name,
        "headline": headline,
        "raw_title": cleaned
    }


async def search_linkedin_profile(
    query: str,
    company: Optional[str] = None,
    role: Optional[str] = None,
    max_results: int = 6
) -> Dict[str, Any]:
    """
    Searches LinkedIn profiles matching the person's name, optional company, or role.
    """
    clean_q = query.strip()
    search_parts = [f'site:linkedin.com/in/ "{clean_q}"']
    if company:
        search_parts.append(f'"{company.strip()}"')
    if role:
        search_parts.append(f'"{role.strip()}"')

    full_query = " ".join(search_parts)
    search_res = await search_web_osint(full_query, max_results=max_results)

    profiles: List[Dict[str, Any]] = []
    for r in search_res.get("results", []):
        url = r.get("url", "")
        # Ensure it's a profile URL
        if "linkedin.com/in/" in url:
            parsed_title = _clean_linkedin_title(r.get("title", ""))
            # Extract vanity username from URL
            vanity_match = re.search(r"linkedin\.com/in/([^/?#]+)", url)
            vanity = vanity_match.group(1) if vanity_match else ""

            profiles.append({
                "name": parsed_title["name"],
                "headline": parsed_title["headline"],
                "url": url,
                "vanity": vanity,
                "snippet": r.get("snippet", "")
            })

    google_direct = f"https://www.google.com/search?q={urllib.parse.quote_plus(full_query)}"

    return {
        "success": True,
        "query": clean_q,
        "company_filter": company or "",
        "role_filter": role or "",
        "engine": search_res.get("engine", "Tavily"),
        "total_found": len(profiles),
        "profiles": profiles,
        "direct_google_url": google_direct
    }


async def search_linkedin_company(company_name: str, max_results: int = 5) -> Dict[str, Any]:
    """
    Searches for LinkedIn Company page and top employees of that company.
    """
    clean_name = company_name.strip()
    company_query = f'site:linkedin.com/company/ "{clean_name}"'
    emp_query = f'site:linkedin.com/in/ "{clean_name}"'

    c_res = await search_web_osint(company_query, max_results=3)
    e_res = await search_web_osint(emp_query, max_results=max_results)

    companies = []
    for r in c_res.get("results", []):
        if "linkedin.com/company/" in r.get("url", ""):
            companies.append({
                "title": r.get("title", "").replace(" | LinkedIn", "").strip(),
                "url": r.get("url", ""),
                "snippet": r.get("snippet", "")
            })

    employees = []
    for r in e_res.get("results", []):
        if "linkedin.com/in/" in r.get("url", ""):
            parsed = _clean_linkedin_title(r.get("title", ""))
            employees.append({
                "name": parsed["name"],
                "headline": parsed["headline"],
                "url": r.get("url", ""),
                "snippet": r.get("snippet", "")
            })

    return {
        "success": True,
        "company": clean_name,
        "companies": companies,
        "employees": employees,
        "total_employees_found": len(employees)
    }
