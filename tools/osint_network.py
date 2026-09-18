"""
Prometheus OSINT Suite - Domain, IP & Network Intelligence (شناسایی شبکه، دامنه و آی‌پی)
DNS records resolution, Certificate Transparency subdomain enumeration (crt.sh),
IP geolocation, ASN intelligence, and HTTP security headers inspection.
"""

import socket
import logging
from typing import Dict, Any, List, Optional
import httpx
import dns.resolver

logger = logging.getLogger("OSINT_Network")


async def resolve_dns_records(domain: str) -> Dict[str, Any]:
    """
    Resolves comprehensive DNS records: A, AAAA, MX, TXT, NS, CNAME, SOA.
    """
    clean_d = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    records: Dict[str, List[str]] = {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 4.0

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in record_types:
        try:
            answers = resolver.resolve(clean_d, rtype)
            records[rtype] = [str(r.to_text()) for r in answers]
        except Exception:
            records[rtype] = []

    # Get Primary IP
    primary_ip = records.get("A", [""])[0] if records.get("A") else ""

    return {
        "success": True,
        "domain": clean_d,
        "primary_ip": primary_ip,
        "records": {k: v for k, v in records.items() if v}
    }


async def enumerate_subdomains_crtsh(domain: str, max_results: int = 30) -> Dict[str, Any]:
    """
    Extracts registered subdomains from public Certificate Transparency logs via crt.sh.
    Passive, non-intrusive, extremely effective.
    """
    clean_d = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    url = f"https://crt.sh/?q=%25.{clean_d}&output=json"

    subdomains = set()
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            res = await client.get(url)
            if res.status_code == 200:
                data = res.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub_clean = sub.strip().lower().lstrip("*.")
                        if sub_clean.endswith(clean_d) and sub_clean != clean_d:
                            subdomains.add(sub_clean)
    except Exception as e:
        logger.debug(f"crt.sh lookup error for {clean_d}: {e}")

    return {
        "success": True,
        "domain": clean_d,
        "total_subdomains": len(subdomains),
        "subdomains": sorted(list(subdomains))[:max_results]
    }


async def lookup_ip_intel(ip_or_domain: str) -> Dict[str, Any]:
    """
    Fetches IP Geolocation, ASN, ISP, and reverse DNS.
    """
    target = ip_or_domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]

    # If it's a domain, resolve to IP first
    ip_addr = target
    try:
        socket.inet_aton(target)
    except socket.error:
        try:
            ip_addr = socket.gethostbyname(target)
        except Exception as e:
            return {"success": False, "target": target, "error": f"عدم توانایی در یافتن آی‌پی دامنه: {e}"}

    # Query IP Geolocation & ASN
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            res = await client.get(f"http://ip-api.com/json/{ip_addr}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query")
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    # Reverse DNS lookup
                    rdns = ""
                    try:
                        rdns = socket.gethostbyaddr(ip_addr)[0]
                    except Exception:
                        pass

                    return {
                        "success": True,
                        "ip": ip_addr,
                        "original_target": target,
                        "country": data.get("country", ""),
                        "country_code": data.get("countryCode", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "asn": data.get("as", ""),
                        "timezone": data.get("timezone", ""),
                        "reverse_dns": rdns,
                    }
    except Exception as e:
        return {"success": False, "ip": ip_addr, "error": f"خطا در دریافت اطلاعات آی‌پی: {e}"}

    return {"success": False, "ip": ip_addr, "error": "اطلاعاتی برای این آی‌پی یافت نشد."}
