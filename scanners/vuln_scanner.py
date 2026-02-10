"""
OWASP Top 10:2025 — Vulnerability Scanner
Aligned with the latest OWASP Top 10 (2025 edition).
https://owasp.org/Top10/2025/

Categories checked:
  A01:2025 — Broken Access Control
  A02:2025 — Security Misconfiguration
  A03:2025 — Software Supply Chain Failures
  A04:2025 — Cryptographic Failures
  A05:2025 — Injection
  A08:2025 — Software or Data Integrity Failures
  A09:2025 — Security Logging and Alerting Failures
  A10:2025 — Mishandling of Exceptional Conditions
"""
import requests
import re
from urllib.parse import urlparse
from typing import Dict, Any

# Open redirect test payloads
REDIRECT_PARAMS = ["url", "redirect", "next", "return", "returnTo", "goto", "target", "redir", "destination", "out"]
REDIRECT_PAYLOAD = "https://evil.example.com"

# Known vulnerable JS libraries (supply chain check)
VULNERABLE_LIBS = [
    {"pattern": r'jquery[/-]([12]\.\d+\.\d+)', "name": "jQuery", "max_safe": "3.7.0", "severity": "medium"},
    {"pattern": r'angular[./-]v?1\.([0-6])\.\d+', "name": "AngularJS 1.x (EOL)", "max_safe": "N/A", "severity": "high"},
    {"pattern": r'bootstrap[/-]([23]\.\d+\.\d+)', "name": "Bootstrap", "max_safe": "5.3.0", "severity": "low"},
    {"pattern": r'lodash[/-]([34]\.\d+\.\d+)', "name": "Lodash", "max_safe": "4.17.21", "severity": "medium"},
    {"pattern": r'moment[/-](\d+\.\d+\.\d+)', "name": "Moment.js (deprecated)", "max_safe": "N/A", "severity": "low"},
    {"pattern": r'vue@?([12]\.\d+\.\d+)', "name": "Vue.js", "max_safe": "3.4.0", "severity": "medium"},
    {"pattern": r'react@?(1[0-6]\.\d+\.\d+)', "name": "React (outdated)", "max_safe": "18.0.0", "severity": "low"},
]

# SRI-protected resource patterns
SRI_PATTERN = re.compile(r'integrity=["\']sha(256|384|512)-', re.IGNORECASE)


def scan(target: str, callback=None) -> Dict[str, Any]:
    """
    Run OWASP Top 10:2025 aligned vulnerability checks.

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
    final_url = response.url

    # ── A01:2025 — Broken Access Control ──
    if callback:
        callback(10, "[A01] Checking access control issues...")
    _check_clickjacking(results, headers)
    _check_open_redirect(results, url)
    _check_cors_misconfiguration(results, headers)

    # ── A02:2025 — Security Misconfiguration ──
    if callback:
        callback(25, "[A02] Checking security misconfiguration...")
    _check_mime_sniffing(results, headers)
    _check_http_methods(results, url)
    _check_info_disclosure(results, headers, body)
    _check_permissions_policy(results, headers)

    # ── A03:2025 — Software Supply Chain Failures ──
    if callback:
        callback(40, "[A03] Checking supply chain risks...")
    _check_supply_chain(results, body)
    _check_subresource_integrity(results, body)

    # ── A04:2025 — Cryptographic Failures ──
    if callback:
        callback(55, "[A04] Checking cryptographic protections...")
    _check_mixed_content(results, final_url, body)
    _check_https(results, target)
    _check_hsts(results, headers, final_url)

    # ── A05:2025 — Injection ──
    if callback:
        callback(70, "[A05] Checking injection protections...")
    _check_csp(results, headers)

    # ── A08:2025 — Software or Data Integrity Failures ──
    if callback:
        callback(80, "[A08] Checking integrity protections...")
    _check_integrity_headers(results, headers)

    # ── A09:2025 — Security Logging & Alerting Failures ──
    if callback:
        callback(88, "[A09] Checking logging & security headers...")
    _check_security_txt(results, url)

    # ── A10:2025 — Mishandling of Exceptional Conditions ──
    if callback:
        callback(93, "[A10] Checking error handling...")
    _check_error_handling(results, url, body)

    # Calculate overall risk
    _calculate_risk(results)

    # Summary
    total_checks = 15
    results["summary"] = {
        "total_checks": total_checks,
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


# ═══════════════════════════════════════════════════════
#  Helper: connection
# ═══════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════
#  A01:2025 — Broken Access Control
# ═══════════════════════════════════════════════════════

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
            "category": "A02:2025 — Security Misconfiguration",
            "detail": "No X-Frame-Options or CSP frame-ancestors directive. The page can be embedded in iframes on malicious sites.",
            "remediation": "Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors none;' header."
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
                    "category": "A01:2025 — Broken Access Control",
                    "detail": f"Parameter '{param}' allows redirection to arbitrary external URLs. Used in phishing attacks.",
                    "remediation": "Validate redirect URLs against a whitelist. Never redirect based on user-supplied URLs."
                })
                return
        except Exception:
            continue


def _check_cors_misconfiguration(results: Dict, headers: Dict):
    """Check for overly permissive CORS configuration."""
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*" and acac == "true":
        results["vulnerabilities"].append({
            "severity": "high",
            "title": "CORS Misconfiguration — Wildcard with Credentials",
            "category": "A01:2025 — Broken Access Control",
            "detail": "Access-Control-Allow-Origin is set to '*' while credentials are allowed. Any origin can make authenticated requests.",
            "remediation": "Restrict Access-Control-Allow-Origin to specific trusted origins when credentials are enabled."
        })
    elif acao == "*":
        results["vulnerabilities"].append({
            "severity": "low",
            "title": "CORS — Wildcard Origin Allowed",
            "category": "A01:2025 — Broken Access Control",
            "detail": "Access-Control-Allow-Origin is set to '*'. Any site can read responses from this API.",
            "remediation": "Restrict to specific trusted origins if the API returns sensitive data."
        })


# ═══════════════════════════════════════════════════════
#  A02:2025 — Security Misconfiguration
# ═══════════════════════════════════════════════════════

def _check_mime_sniffing(results: Dict, headers: Dict):
    """Check for MIME type sniffing vulnerability."""
    xcto = headers.get("X-Content-Type-Options", "").lower()

    if xcto != "nosniff":
        results["vulnerabilities"].append({
            "severity": "low",
            "title": "MIME Type Sniffing Enabled",
            "category": "A02:2025 — Security Misconfiguration",
            "detail": "Missing X-Content-Type-Options: nosniff. Browsers may interpret files as a different MIME type, enabling XSS via uploaded files.",
            "remediation": "Add 'X-Content-Type-Options: nosniff' header."
        })


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
            "category": "A02:2025 — Security Misconfiguration",
            "detail": f"The server allows dangerous HTTP methods: {', '.join(allowed)}. TRACE enables Cross-Site Tracing attacks.",
            "remediation": "Disable unnecessary HTTP methods in the web server configuration."
        })


def _check_info_disclosure(results: Dict, headers: Dict, body: str):
    """Check for information disclosure in headers and HTML."""
    server = headers.get("Server", "")
    if re.search(r'\d+\.\d+', server):
        results["vulnerabilities"].append({
            "severity": "low",
            "title": "Server Version Disclosure",
            "category": "A02:2025 — Security Misconfiguration",
            "detail": f"Server header reveals version: '{server}'. Attackers can target known CVEs for this version.",
            "remediation": "Configure the server to suppress version information."
        })

    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        results["vulnerabilities"].append({
            "severity": "low",
            "title": "Technology Stack Disclosed",
            "category": "A02:2025 — Security Misconfiguration",
            "detail": f"X-Powered-By: '{powered_by}' reveals the backend technology. Aids targeted attacks.",
            "remediation": "Remove the X-Powered-By header from server responses."
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
                "category": "A02:2025 — Security Misconfiguration",
                "detail": f"{description}. Reveals internal architecture details to potential attackers.",
                "remediation": "Disable debug mode and implement custom error pages in production."
            })
            break

    # Sensitive HTML comments
    comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
    sensitive_patterns = [r'password', r'api.?key', r'secret', r'TODO', r'FIXME', r'HACK', r'token']
    for comment in comments:
        for pattern in sensitive_patterns:
            if re.search(pattern, comment, re.IGNORECASE):
                results["vulnerabilities"].append({
                    "severity": "low",
                    "title": "Sensitive Information in HTML Comments",
                    "category": "A02:2025 — Security Misconfiguration",
                    "detail": "HTML comments contain potentially sensitive data (passwords, API keys, TODOs).",
                    "remediation": "Remove all sensitive comments from production HTML."
                })
                return


def _check_permissions_policy(results: Dict, headers: Dict):
    """Check for Permissions-Policy (Feature-Policy) header."""
    pp = headers.get("Permissions-Policy", "")
    fp = headers.get("Feature-Policy", "")

    if not pp and not fp:
        results["vulnerabilities"].append({
            "severity": "low",
            "title": "Missing Permissions-Policy Header",
            "category": "A02:2025 — Security Misconfiguration",
            "detail": "No Permissions-Policy header. Browser features (camera, mic, geolocation) are unrestricted.",
            "remediation": "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' header."
        })


# ═══════════════════════════════════════════════════════
#  A03:2025 — Software Supply Chain Failures (NEW)
# ═══════════════════════════════════════════════════════

def _check_supply_chain(results: Dict, body: str):
    """Check for known vulnerable or deprecated JavaScript libraries."""
    for lib in VULNERABLE_LIBS:
        match = re.search(lib["pattern"], body, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else "unknown"
            results["vulnerabilities"].append({
                "severity": lib["severity"],
                "title": f"Outdated/Vulnerable Library: {lib['name']} v{version}",
                "category": "A03:2025 — Software Supply Chain Failures",
                "detail": f"Detected {lib['name']} version {version}. Outdated libraries may contain known CVEs.",
                "remediation": f"Update {lib['name']} to the latest stable version or replace with a maintained alternative."
            })


def _check_subresource_integrity(results: Dict, body: str):
    """Check if external scripts/stylesheets use Subresource Integrity (SRI)."""
    # Find external script/link tags loading from CDNs
    external_resources = re.findall(
        r'<(?:script|link)[^>]+(?:src|href)=["\']https?://(?!(?:localhost|127\.0\.0\.1))[^"\']+["\'][^>]*>',
        body, re.IGNORECASE
    )

    if not external_resources:
        return

    missing_sri = []
    for resource in external_resources:
        if not SRI_PATTERN.search(resource):
            src_match = re.search(r'(?:src|href)=["\']([^"\']+)', resource)
            if src_match:
                missing_sri.append(src_match.group(1))

    if missing_sri:
        count = len(missing_sri)
        example = missing_sri[0][:80]
        results["vulnerabilities"].append({
            "severity": "medium",
            "title": f"Missing Subresource Integrity ({count} resources)",
            "category": "A03:2025 — Software Supply Chain Failures",
            "detail": f"{count} external resource(s) loaded without SRI hashes (e.g., '{example}'). A compromised CDN could inject malicious code.",
            "remediation": "Add 'integrity' and 'crossorigin' attributes to all external script/link tags."
        })


# ═══════════════════════════════════════════════════════
#  A04:2025 — Cryptographic Failures
# ═══════════════════════════════════════════════════════

def _check_mixed_content(results: Dict, page_url: str, body: str):
    """Check if HTTPS page loads HTTP resources."""
    if not page_url.startswith("https://"):
        return

    http_resources = re.findall(r'(src|href|action)=["\']http://[^"\']+["\']', body, re.IGNORECASE)

    if http_resources:
        results["vulnerabilities"].append({
            "severity": "medium",
            "title": "Mixed Content Detected",
            "category": "A04:2025 — Cryptographic Failures",
            "detail": f"HTTPS page loads {len(http_resources)} resource(s) over insecure HTTP. Can be intercepted via MITM.",
            "remediation": "Ensure all resources are loaded over HTTPS."
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
                "category": "A04:2025 — Cryptographic Failures",
                "detail": "HTTP requests are not redirected to HTTPS. User traffic can be intercepted in transit.",
                "remediation": "Configure permanent (301) redirect from HTTP to HTTPS."
            })
        else:
            location = response.headers.get("Location", "")
            if not location.startswith("https://"):
                results["vulnerabilities"].append({
                    "severity": "high",
                    "title": "Insecure HTTP Redirect",
                    "category": "A04:2025 — Cryptographic Failures",
                    "detail": f"HTTP redirects to non-HTTPS location: {location}",
                    "remediation": "Ensure redirects point to HTTPS URLs."
                })
    except Exception:
        pass


def _check_hsts(results: Dict, headers: Dict, final_url: str):
    """Check HTTP Strict Transport Security configuration."""
    if not final_url.startswith("https://"):
        return

    hsts = headers.get("Strict-Transport-Security", "")
    if not hsts:
        results["vulnerabilities"].append({
            "severity": "medium",
            "title": "Missing HSTS Header",
            "category": "A04:2025 — Cryptographic Failures",
            "detail": "No Strict-Transport-Security header on HTTPS site. Users can be downgraded to HTTP via MITM.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
        })
    else:
        try:
            max_age = int(re.search(r'max-age=(\d+)', hsts).group(1))
            if max_age < 31536000:
                results["vulnerabilities"].append({
                    "severity": "low",
                    "title": "HSTS max-age Too Short",
                    "category": "A04:2025 — Cryptographic Failures",
                    "detail": f"HSTS max-age is {max_age}s ({max_age//86400} days). Recommended minimum is 1 year (31536000s).",
                    "remediation": "Increase max-age to at least 31536000 (1 year)."
                })
        except (AttributeError, ValueError):
            pass


# ═══════════════════════════════════════════════════════
#  A05:2025 — Injection
# ═══════════════════════════════════════════════════════

def _check_csp(results: Dict, headers: Dict):
    """Check Content-Security-Policy for injection protections."""
    csp = headers.get("Content-Security-Policy", "")

    if not csp:
        results["vulnerabilities"].append({
            "severity": "medium",
            "title": "Missing Content-Security-Policy",
            "category": "A05:2025 — Injection",
            "detail": "No CSP header. The page is unprotected against XSS and code injection attacks.",
            "remediation": "Add a Content-Security-Policy header. Start with: default-src 'self'; script-src 'self'."
        })
    else:
        csp_lower = csp.lower()
        issues = []
        if "'unsafe-inline'" in csp_lower and "script-src" in csp_lower:
            issues.append("'unsafe-inline' in script-src allows inline scripts (XSS risk)")
        if "'unsafe-eval'" in csp_lower:
            issues.append("'unsafe-eval' permits eval() and similar dynamic code execution")
        if "default-src *" in csp_lower or "script-src *" in csp_lower:
            issues.append("Wildcard (*) in CSP allows loading resources from any origin")

        if issues:
            results["vulnerabilities"].append({
                "severity": "medium",
                "title": "Weak Content-Security-Policy",
                "category": "A05:2025 — Injection",
                "detail": f"CSP is present but weak: {'; '.join(issues)}.",
                "remediation": "Remove 'unsafe-inline', 'unsafe-eval', and wildcards. Use nonces or hashes for inline scripts."
            })


# ═══════════════════════════════════════════════════════
#  A08:2025 — Software or Data Integrity Failures
# ═══════════════════════════════════════════════════════

def _check_integrity_headers(results: Dict, headers: Dict):
    """Check for headers that prevent data tampering."""
    # Cross-Origin-Opener-Policy
    coop = headers.get("Cross-Origin-Opener-Policy", "")
    coep = headers.get("Cross-Origin-Embedder-Policy", "")

    if not coop and not coep:
        results["vulnerabilities"].append({
            "severity": "low",
            "title": "Missing Cross-Origin Isolation Headers",
            "category": "A08:2025 — Software or Data Integrity Failures",
            "detail": "No COOP/COEP headers. The page may be vulnerable to Spectre-style side-channel attacks.",
            "remediation": "Add 'Cross-Origin-Opener-Policy: same-origin' and 'Cross-Origin-Embedder-Policy: require-corp'."
        })


# ═══════════════════════════════════════════════════════
#  A09:2025 — Security Logging and Alerting Failures
# ═══════════════════════════════════════════════════════

def _check_security_txt(results: Dict, url: str):
    """Check for .well-known/security.txt (RFC 9116)."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        resp = requests.get(f"{base}/.well-known/security.txt", timeout=5, verify=False)
        if resp.status_code != 200 or "Contact:" not in resp.text:
            results["vulnerabilities"].append({
                "severity": "info",
                "title": "Missing security.txt",
                "category": "A09:2025 — Security Logging and Alerting Failures",
                "detail": "No valid security.txt found at /.well-known/security.txt (RFC 9116). Security researchers cannot report vulnerabilities.",
                "remediation": "Create /.well-known/security.txt with Contact, Expires, and Policy fields."
            })
    except Exception:
        results["vulnerabilities"].append({
            "severity": "info",
            "title": "Missing security.txt",
            "category": "A09:2025 — Security Logging and Alerting Failures",
            "detail": "Could not check for security.txt. This file helps researchers report vulnerabilities responsibly.",
            "remediation": "Create /.well-known/security.txt following RFC 9116."
        })


# ═══════════════════════════════════════════════════════
#  A10:2025 — Mishandling of Exceptional Conditions (NEW)
# ═══════════════════════════════════════════════════════

def _check_error_handling(results: Dict, url: str, body: str):
    """Check how the application handles error conditions."""
    # Check for verbose error pages in the main response
    error_signatures = [
        (r'Traceback \(most recent call last\)', "Python traceback in response"),
        (r'<b>Fatal error</b>', "PHP fatal error in response"),
        (r'Internal Server Error', "Generic 500 error page exposed"),
        (r'SQLException|ORA-\d+|mysql_|pg_', "Database error messages exposed"),
        (r'Exception in thread', "Java exception exposed"),
    ]

    for pattern, description in error_signatures:
        if re.search(pattern, body, re.IGNORECASE):
            results["vulnerabilities"].append({
                "severity": "medium",
                "title": "Verbose Error Messages Exposed",
                "category": "A10:2025 — Mishandling of Exceptional Conditions",
                "detail": f"{description}. Detailed error messages leak internal implementation details.",
                "remediation": "Implement custom error pages. Never expose stack traces or database errors to users."
            })
            break

    # Test a non-existent path to see error handling
    try:
        test_url = f"{url}/nonexistent_path_securitool_test_404"
        resp = requests.get(test_url, timeout=5, verify=False,
                           headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code == 200:
            results["vulnerabilities"].append({
                "severity": "low",
                "title": "Soft 404 — Invalid Paths Return 200",
                "category": "A10:2025 — Mishandling of Exceptional Conditions",
                "detail": "Non-existent paths return HTTP 200 instead of 404. This can confuse crawlers and hide issues.",
                "remediation": "Return proper HTTP status codes (404 for not found, 500 for server errors)."
            })

        error_body = resp.text[:10000]
        for pattern, description in error_signatures:
            if re.search(pattern, error_body, re.IGNORECASE):
                results["vulnerabilities"].append({
                    "severity": "medium",
                    "title": "Error Page Leaks Implementation Details",
                    "category": "A10:2025 — Mishandling of Exceptional Conditions",
                    "detail": f"404 error page contains: {description}. Attackers use this to map the tech stack.",
                    "remediation": "Use generic error pages in production. Log details server-side only."
                })
                break
    except Exception:
        pass


# ═══════════════════════════════════════════════════════
#  Risk calculation
# ═══════════════════════════════════════════════════════

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
