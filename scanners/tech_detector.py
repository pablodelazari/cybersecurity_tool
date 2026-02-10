"""
Technology Fingerprinting Module
Detects server software, frameworks, CMS, and cookie security flags.
"""
import requests
import re
from typing import Dict, Any, List

# Technology detection signatures
TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            "PHP": "PHP",
            "ASP.NET": "ASP.NET",
            "Express": "Express.js",
            "Next.js": "Next.js",
        },
        "Server": {
            "nginx": "Nginx",
            "Apache": "Apache HTTP Server",
            "Microsoft-IIS": "Microsoft IIS",
            "cloudflare": "Cloudflare",
            "LiteSpeed": "LiteSpeed",
            "openresty": "OpenResty",
            "Caddy": "Caddy",
            "gunicorn": "Gunicorn",
            "Kestrel": "ASP.NET Kestrel",
        },
        "X-Generator": {
            "WordPress": "WordPress",
            "Drupal": "Drupal",
            "Joomla": "Joomla",
        }
    },
    "html": [
        {"pattern": r'wp-content|wp-includes', "tech": "WordPress", "category": "CMS"},
        {"pattern": r'Drupal\.settings', "tech": "Drupal", "category": "CMS"},
        {"pattern": r'Joomla!', "tech": "Joomla", "category": "CMS"},
        {"pattern": r'__next|_next/static', "tech": "Next.js", "category": "Framework"},
        {"pattern": r'react-root|__react', "tech": "React", "category": "Framework"},
        {"pattern": r'ng-version|ng-app', "tech": "Angular", "category": "Framework"},
        {"pattern": r'vue\.js|v-app|vue-app', "tech": "Vue.js", "category": "Framework"},
        {"pattern": r'jquery|jQuery', "tech": "jQuery", "category": "Library"},
        {"pattern": r'bootstrap\.min\.(css|js)', "tech": "Bootstrap", "category": "Framework"},
        {"pattern": r'tailwindcss|tailwind\.', "tech": "Tailwind CSS", "category": "Framework"},
        {"pattern": r'google-analytics|gtag|ga\.js', "tech": "Google Analytics", "category": "Analytics"},
        {"pattern": r'cloudflare|cf-ray', "tech": "Cloudflare", "category": "CDN"},
        {"pattern": r'shopify', "tech": "Shopify", "category": "E-Commerce"},
        {"pattern": r'recaptcha', "tech": "Google reCAPTCHA", "category": "Security"},
    ],
    "meta": [
        {"name": "generator", "pattern": r'WordPress\s*([\d.]+)?', "tech": "WordPress"},
        {"name": "generator", "pattern": r'Drupal\s*([\d.]+)?', "tech": "Drupal"},
        {"name": "generator", "pattern": r'Hugo\s*([\d.]+)?', "tech": "Hugo"},
        {"name": "generator", "pattern": r'Jekyll\s*([\d.]+)?', "tech": "Jekyll"},
    ]
}


def scan(target: str, callback=None) -> Dict[str, Any]:
    """
    Detect technologies used by the target.
    
    Args:
        target: URL or domain to analyze
        callback: function(progress_pct, message) for progress updates
    """
    url = _normalize_url(target)
    
    if callback:
        callback(10, "Fetching target page...")

    response = _try_connect(url)
    if response is None:
        return {"error": f"Connection failed: could not reach {target} via HTTPS or HTTP"}

    if callback:
        callback(30, "Analyzing server headers...")

    results = {
        "url": response.url,
        "technologies": [],
        "cookies": [],
        "server_info": {},
        "risk_level": "info",
        "issues": []
    }

    headers = dict(response.headers)
    body = response.text[:50000]  # Limit body analysis to first 50KB

    # Header-based detection
    for header_name, signatures in TECH_SIGNATURES["headers"].items():
        header_value = headers.get(header_name, "")
        if header_value:
            for sig_key, tech_name in signatures.items():
                if sig_key.lower() in header_value.lower():
                    _add_tech(results, tech_name, "Server/Infrastructure", f"Header: {header_name}: {header_value}")

    # Server info
    server = headers.get("Server", "")
    if server:
        results["server_info"]["server"] = server
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        results["server_info"]["powered_by"] = powered_by

    if callback:
        callback(50, "Scanning HTML for technology fingerprints...")

    # HTML-based detection
    for sig in TECH_SIGNATURES["html"]:
        if re.search(sig["pattern"], body, re.IGNORECASE):
            _add_tech(results, sig["tech"], sig["category"], f"HTML pattern: {sig['pattern']}")

    if callback:
        callback(70, "Analyzing meta tags...")

    # Meta tag detection
    for meta_sig in TECH_SIGNATURES["meta"]:
        pattern = f'<meta[^>]+name=["\']?{meta_sig["name"]}["\']?[^>]+content=["\']([^"\']+)'
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            content = match.group(1)
            tech_match = re.search(meta_sig["pattern"], content, re.IGNORECASE)
            if tech_match:
                version = tech_match.group(1) if tech_match.lastindex else ""
                name = f"{meta_sig['tech']} {version}".strip()
                _add_tech(results, name, "CMS", f"Meta generator: {content}")

    if callback:
        callback(85, "Analyzing cookies...")

    # Cookie analysis
    for cookie_header in response.headers.get("Set-Cookie", "").split(","):
        if not cookie_header.strip():
            continue
        cookie_info = _analyze_cookie(cookie_header.strip())
        if cookie_info:
            results["cookies"].append(cookie_info)

    # Security issues
    _check_tech_security(results, headers)

    if callback:
        callback(100, "Technology detection complete")

    return results


def _normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _try_connect(url: str):
    """Try HTTPS first, fall back to HTTP if it fails."""
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    try:
        return requests.get(url, timeout=10, allow_redirects=True, verify=True, headers=ua)
    except Exception:
        pass
    
    try:
        return requests.get(url, timeout=10, allow_redirects=True, verify=False, headers=ua)
    except Exception:
        pass
    
    http_url = url.replace("https://", "http://")
    if http_url != url:
        try:
            return requests.get(http_url, timeout=10, allow_redirects=True, verify=False, headers=ua)
        except Exception:
            pass
    
    return None


def _add_tech(results: Dict, name: str, category: str, evidence: str):
    """Add a detected technology, avoiding duplicates."""
    existing = [t["name"] for t in results["technologies"]]
    if name not in existing:
        results["technologies"].append({
            "name": name,
            "category": category,
            "evidence": evidence
        })


def _analyze_cookie(cookie_str: str) -> Dict[str, Any]:
    """Analyze a cookie for security flags."""
    parts = [p.strip() for p in cookie_str.split(";")]
    if not parts:
        return None
    
    name_value = parts[0].split("=", 1)
    name = name_value[0].strip() if name_value else "unknown"
    
    flags = [p.lower().strip() for p in parts[1:]]
    
    issues = []
    has_secure = any("secure" in f for f in flags)
    has_httponly = any("httponly" in f for f in flags)
    has_samesite = any("samesite" in f for f in flags)
    
    if not has_secure:
        issues.append("Missing Secure flag — cookie sent over HTTP")
    if not has_httponly:
        issues.append("Missing HttpOnly flag — accessible via JavaScript")
    if not has_samesite:
        issues.append("Missing SameSite flag — vulnerable to CSRF")
    
    return {
        "name": name,
        "secure": has_secure,
        "httponly": has_httponly,
        "samesite": has_samesite,
        "issues": issues
    }


def _check_tech_security(results: Dict, headers: Dict):
    """Check for technology-related security issues."""
    # Version disclosure
    server = headers.get("Server", "")
    if re.search(r'\d+\.\d+', server):
        results["issues"].append({
            "severity": "medium",
            "title": "Server Version Disclosed",
            "detail": f"Server header reveals version: '{server}'. This aids targeted exploits."
        })

    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        results["issues"].append({
            "severity": "medium",
            "title": "Technology Stack Disclosed",
            "detail": f"X-Powered-By header reveals: '{powered_by}'. Remove for security."
        })

    # Cookie issues
    insecure_cookies = [c for c in results["cookies"] if c.get("issues")]
    if insecure_cookies:
        results["issues"].append({
            "severity": "medium",
            "title": "Insecure Cookie Configuration",
            "detail": f"{len(insecure_cookies)} cookie(s) missing security flags."
        })

    # Risk assessment
    if any(i["severity"] == "high" for i in results["issues"]):
        results["risk_level"] = "high"
    elif any(i["severity"] == "medium" for i in results["issues"]):
        results["risk_level"] = "medium"
    elif results["issues"]:
        results["risk_level"] = "low"
