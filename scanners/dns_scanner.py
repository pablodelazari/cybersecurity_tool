"""
DNS Enumeration & Subdomain Discovery Module
Resolves DNS records and discovers subdomains.
"""
import socket
import dns.resolver
import dns.rdatatype
import concurrent.futures
from typing import Dict, Any, List

# Common subdomains for discovery
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "imap", "cpanel", "whm", "autodiscover", "autoconfig",
    "admin", "portal", "vpn", "remote", "blog", "dev", "staging", "test",
    "api", "app", "cdn", "cloud", "db", "demo", "docs", "forum", "git",
    "help", "intranet", "jenkins", "jira", "login", "mobile", "monitor",
    "mx", "mysql", "news", "old", "panel", "proxy", "secure", "shop",
    "sql", "ssh", "status", "store", "support", "wiki", "www2", "beta",
    "dashboard", "gateway", "grafana", "kibana", "prometheus", "sentry",
    "registry", "auth", "sso", "oauth", "media", "assets", "static",
    "backup", "uat", "sandbox", "staging2", "preprod", "prod"
]

# DNS record types to enumerate
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def scan(target: str, callback=None) -> Dict[str, Any]:
    """
    Perform DNS enumeration and subdomain discovery.
    
    Args:
        target: domain to analyze
        callback: function(progress_pct, message) for progress updates
    """
    domain = _clean_domain(target)
    
    if callback:
        callback(5, "Starting DNS enumeration...")

    results = {
        "domain": domain,
        "records": {},
        "subdomains": [],
        "risk_level": "info",
        "issues": []
    }

    # Enumerate DNS records
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for i, rtype in enumerate(RECORD_TYPES):
        if callback:
            callback(5 + int((i / len(RECORD_TYPES)) * 30), f"Querying {rtype} records...")
        
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                record_data = {"value": str(rdata)}
                
                # Add extra info for specific record types
                if rtype == "MX":
                    record_data["priority"] = rdata.preference
                elif rtype == "SOA":
                    record_data["serial"] = rdata.serial
                    record_data["refresh"] = rdata.refresh
                    record_data["retry"] = rdata.retry
                    record_data["expire"] = rdata.expire
                    record_data["minimum"] = rdata.minimum
                
                records.append(record_data)
            
            results["records"][rtype] = records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            results["records"][rtype] = []
        except dns.exception.Timeout:
            results["records"][rtype] = [{"value": "Query timed out"}]
        except Exception:
            results["records"][rtype] = []

    if callback:
        callback(40, "Starting subdomain discovery...")

    # Subdomain discovery
    found_subdomains = []
    total_subs = len(COMMON_SUBDOMAINS)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        future_to_sub = {
            executor.submit(_check_subdomain, sub, domain): sub 
            for sub in COMMON_SUBDOMAINS
        }
        completed = 0
        for future in concurrent.futures.as_completed(future_to_sub):
            completed += 1
            try:
                result = future.result()
                if result:
                    found_subdomains.append(result)
            except Exception:
                pass
            
            if callback and completed % 10 == 0:
                callback(40 + int((completed / total_subs) * 50), 
                        f"Checked {completed}/{total_subs} subdomains")

    found_subdomains.sort(key=lambda x: x["subdomain"])
    results["subdomains"] = found_subdomains
    results["subdomain_count"] = len(found_subdomains)

    if callback:
        callback(95, "Analyzing DNS security...")

    # Security checks
    _check_dns_security(results)

    if callback:
        callback(100, "DNS enumeration complete")

    return results


def _clean_domain(target: str) -> str:
    """Extract clean domain from input."""
    target = target.strip()
    for prefix in ["https://", "http://"]:
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0]
    target = target.split(":")[0]
    return target


def _check_subdomain(subdomain: str, domain: str) -> Dict[str, str]:
    """Check if a subdomain exists."""
    fqdn = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return {"subdomain": fqdn, "ip": ip}
    except socket.gaierror:
        return None


def _check_dns_security(results: Dict[str, Any]):
    """Analyze DNS configuration for security issues."""
    issues = []
    
    # Check for SPF record
    txt_records = results["records"].get("TXT", [])
    has_spf = any("v=spf" in r.get("value", "").lower() for r in txt_records)
    if not has_spf:
        issues.append({
            "severity": "medium",
            "title": "No SPF Record",
            "detail": "Missing SPF record allows email spoofing. Add a TXT record with SPF policy."
        })
    
    # Check for DMARC
    has_dmarc = any("v=dmarc" in r.get("value", "").lower() for r in txt_records)
    if not has_dmarc:
        issues.append({
            "severity": "medium", 
            "title": "No DMARC Record",
            "detail": "Missing DMARC policy. Consider adding _dmarc TXT record."
        })

    # Check number of subdomains (attack surface)
    sub_count = results.get("subdomain_count", 0)
    if sub_count > 20:
        issues.append({
            "severity": "low",
            "title": "Large Attack Surface",
            "detail": f"Found {sub_count} subdomains. Review and decommission unused ones."
        })

    # Check for wildcard DNS
    try:
        domain = results["domain"]
        socket.gethostbyname(f"randomnonexistent12345.{domain}")
        issues.append({
            "severity": "medium",
            "title": "Wildcard DNS Detected",
            "detail": "Wildcard DNS is enabled, which can mask subdomain takeover vulnerabilities."
        })
    except socket.gaierror:
        pass

    results["issues"] = issues
    if any(i["severity"] == "high" for i in issues):
        results["risk_level"] = "high"
    elif any(i["severity"] == "medium" for i in issues):
        results["risk_level"] = "medium"
    elif issues:
        results["risk_level"] = "low"
