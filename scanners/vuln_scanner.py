"""
OWASP-Aligned Vulnerability Scanner
Checks for common web vulnerabilities: clickjacking, MIME sniffing,
open redirects, information disclosure, and mixed content.
"""
import requests
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List

# Open redirect test payloads
REDIRECT_PARAMS = ["url", "redirect", "next", "return", "returnTo", "goto", "target", "redir", "destination", "out"]
REDIRECT_PAYLOAD = "https://evil.example.com"


def scan(target: str, callback=None) -> Dict[str, Any]:
    """
    Run OWASP-aligned vulnerability checks.
    
    Args:
        target: URL or domain to analyze
        callback: function(progress_pct, message) for progress updates
    """
    url = _normalize_url(target)
    
    if callback:
        callback(5, "Connecting to target...")

    response = _try_connect(url)
    if response is None:
        return {"error": f"Connection failed: could not reach {target} via HTTPS or HTTP"}

    results = {
        "url": response.url,
        "vulnerabilities": [],
        "risk_level": "info",
        "summary": {}
    }

    headers = dict(response.headers)
    body = response.text[:50000]

    if callback:
        callback(15, "Checking for clickjacking vulnerability...")

    # 1. Clickjacking (X-Frame-Options / CSP frame-ancestors)
    _check_clickjacking(results, headers)

    if callback:
        callback(25, "Checking for MIME sniffing...")

    # 2. MIME Type Sniffing
    _check_mime_sniffing(results, headers)

    if callback:
        callback(35, "Checking for information disclosure...")

    # 3. Information Disclosure
    _check_info_disclosure(results, headers, body)

    if callback:
        callback(50, "Checking for mixed content...")

    # 4. Mixed Content
    _check_mixed_content(results, response.url, body)

    if callback:
        callback(65, "Testing for open redirects...")

    # 5. Open Redirect (passive check)
    _check_open_redirect(results, url)

    if callback:
        callback(80, "Checking HTTP methods...")

    # 6. Dangerous HTTP Methods
    _check_http_methods(results, url)

    if callback:
        callback(90, "Checking HTTPS enforcement...")

    # 7. HTTPS Enforcement
    _check_https(results, target)

    # Calculate overall risk
    _calculate_risk(results)

    # Summary
    results["summary"] = {
        "total_checks": 7,
        "vulnerabilities_found": len(results["vulnerabilities"]),
        "critical": len([v for v in results["vulnerabilities"] if v["severity"] == "critical"]),
        "high": len([v for v in results["vulnerabilities"] if v["severity"] == "high"]),
        "medium": len([v for v in results["vulnerabilities"] if v["severity"] == "medium"]),
        "low": len([v for v in results["vulnerabilities"] if v["severity"] == "low"]),
        "info": len([v for v in results["vulnerabilities"] if v["severity"] == "info"]),
    }

    if callback:
        callback(100, "Vulnerability scan complete")

    return results


def _normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _try_connect(url: str):
    """Try HTTPS first, fall back to HTTP if it fails."""
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
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


def _check_clickjacking(results: Dict, headers: Dict):
    """Check if the site is vulnerable to clickjacking."""
    x_frame = headers.get("X-Frame-Options", "").lower()
    csp = headers.get("Content-Security-Policy", "")
    
    has_xfo = x_frame in ("deny", "sameorigin")
    has_csp_fa = "frame-ancestors" in csp.lower()
    
    if not has_xfo and not has_csp_fa:
        results["vulnerabilities"].append({
            "severity": "medium",
            "title": "Clickjacking Vulnerability",
            "category": "OWASP A05 — Security Misconfiguration",
            "detail": "No X-Frame-Options or CSP frame-ancestors directive. The page can be embedded in iframes on malicious sites.",
            "remediation": "Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors none;' header."
        })


def _check_mime_sniffing(results: Dict, headers: Dict):
    """Check for MIME type sniffing vulnerability."""
    xcto = headers.get("X-Content-Type-Options", "").lower()
    
    if xcto != "nosniff":
        results["vulnerabilities"].append({
            "severity": "low",
            "title": "MIME Type Sniffing Enabled",
            "category": "OWASP A05 — Security Misconfiguration",
            "detail": "Missing X-Content-Type-Options: nosniff. Browsers may interpret files as a different MIME type, enabling XSS attacks via uploaded files.",
            "remediation": "Add 'X-Content-Type-Options: nosniff' header."
        })


def _check_info_disclosure(results: Dict, headers: Dict, body: str):
    """Check for information disclosure in headers and HTML."""
    # Server version
    server = headers.get("Server", "")
    if re.search(r'\d+\.\d+', server):
        results["vulnerabilities"].append({
            "severity": "low",
            "title": "Server Version Disclosure",
            "category": "OWASP A01 — Broken Access Control",
            "detail": f"Server header reveals version information: '{server}'. Attackers can target known vulnerabilities for this version.",
            "remediation": "Configure the server to suppress version information."
        })
    
    # Debug/error information in body
    debug_patterns = [
        (r'Traceback \(most recent call last\)', "Python traceback exposed"),
        (r'<b>Warning</b>:.*on line <b>\d+', "PHP warning exposed"),
        (r'Stack Trace:', "Stack trace exposed"),
        (r'at [\w.]+\([\w.]+\.java:\d+\)', "Java stack trace exposed"),
        (r'Microsoft \.NET Framework Version:', ".NET version exposed"),
    ]
    
    for pattern, description in debug_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            results["vulnerabilities"].append({
                "severity": "medium",
                "title": "Debug Information Disclosure",
                "category": "OWASP A05 — Security Misconfiguration",
                "detail": f"{description}. This reveals internal architecture details to potential attackers.",
                "remediation": "Disable debug mode and implement custom error pages in production."
            })
            break  # One finding is enough

    # HTML comments with sensitive info
    comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
    sensitive_comment_patterns = [r'password', r'api.?key', r'secret', r'TODO', r'FIXME', r'HACK', r'token']
    for comment in comments:
        for pattern in sensitive_comment_patterns:
            if re.search(pattern, comment, re.IGNORECASE):
                results["vulnerabilities"].append({
                    "severity": "low",
                    "title": "Sensitive Information in HTML Comments",
                    "category": "OWASP A01 — Broken Access Control",
                    "detail": "HTML comments contain potentially sensitive information (passwords, API keys, TODOs).",
                    "remediation": "Remove all sensitive comments from production HTML."
                })
                return  # One finding is enough


def _check_mixed_content(results: Dict, page_url: str, body: str):
    """Check if HTTPS page loads HTTP resources."""
    if not page_url.startswith("https://"):
        return
    
    http_resources = re.findall(r'(src|href|action)=["\']http://[^"\']+["\']', body, re.IGNORECASE)
    
    if http_resources:
        results["vulnerabilities"].append({
            "severity": "medium",
            "title": "Mixed Content Detected",
            "category": "OWASP A02 — Cryptographic Failures",
            "detail": f"HTTPS page loads {len(http_resources)} resource(s) over insecure HTTP. These can be intercepted via MITM attacks.",
            "remediation": "Ensure all resources are loaded over HTTPS."
        })


def _check_open_redirect(results: Dict, url: str):
    """Test for open redirect vulnerabilities."""
    for param in REDIRECT_PARAMS:
        try:
            test_url = f"{url}?{param}={REDIRECT_PAYLOAD}"
            response = requests.get(test_url, timeout=5, allow_redirects=False, verify=False,
                                  headers={"User-Agent": "Mozilla/5.0"})
            
            location = response.headers.get("Location", "")
            if REDIRECT_PAYLOAD in location or "evil.example.com" in location:
                results["vulnerabilities"].append({
                    "severity": "medium",
                    "title": "Open Redirect Vulnerability",
                    "category": "OWASP A01 — Broken Access Control",
                    "detail": f"Parameter '{param}' allows redirection to arbitrary external URLs. This can be used in phishing attacks.",
                    "remediation": "Validate redirect URLs against a whitelist. Never redirect based on user-supplied URLs."
                })
                return  # One finding is enough
        except Exception:
            continue


def _check_http_methods(results: Dict, url: str):
    """Check for dangerous HTTP methods."""
    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
    allowed = []
    
    try:
        response = requests.options(url, timeout=5, verify=False)
        allow_header = response.headers.get("Allow", "")
        if allow_header:
            methods = [m.strip().upper() for m in allow_header.split(",")]
            allowed = [m for m in methods if m in dangerous_methods]
    except Exception:
        pass
    
    # Also test TRACE directly
    try:
        response = requests.request("TRACE", url, timeout=5, verify=False)
        if response.status_code == 200 and "TRACE" not in allowed:
            allowed.append("TRACE")
    except Exception:
        pass
    
    if allowed:
        results["vulnerabilities"].append({
            "severity": "medium",
            "title": "Dangerous HTTP Methods Enabled",
            "category": "OWASP A05 — Security Misconfiguration",
            "detail": f"The server allows dangerous HTTP methods: {', '.join(allowed)}. TRACE enables Cross-Site Tracing attacks.",
            "remediation": "Disable unnecessary HTTP methods in the web server configuration."
        })


def _check_https(results: Dict, target: str):
    """Check if HTTP redirects to HTTPS."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    
    try:
        response = requests.get(f"http://{domain}", timeout=5, allow_redirects=False, verify=False)
        
        if response.status_code not in (301, 302, 307, 308):
            results["vulnerabilities"].append({
                "severity": "high",
                "title": "No HTTPS Redirect",
                "category": "OWASP A02 — Cryptographic Failures",
                "detail": "HTTP requests are not redirected to HTTPS. User traffic can be intercepted.",
                "remediation": "Configure permanent (301) redirect from HTTP to HTTPS."
            })
        else:
            location = response.headers.get("Location", "")
            if not location.startswith("https://"):
                results["vulnerabilities"].append({
                    "severity": "high",
                    "title": "Insecure HTTP Redirect",
                    "category": "OWASP A02 — Cryptographic Failures",
                    "detail": f"HTTP redirects to non-HTTPS location: {location}",
                    "remediation": "Ensure redirects point to HTTPS URLs."
                })
    except Exception:
        pass


def _calculate_risk(results: Dict):
    """Calculate overall risk level."""
    vulns = results["vulnerabilities"]
    if not vulns:
        results["risk_level"] = "low"
        return
    
    severities = [v["severity"] for v in vulns]
    if "critical" in severities:
        results["risk_level"] = "critical"
    elif "high" in severities:
        results["risk_level"] = "high"
    elif "medium" in severities:
        results["risk_level"] = "medium"
    else:
        results["risk_level"] = "low"
