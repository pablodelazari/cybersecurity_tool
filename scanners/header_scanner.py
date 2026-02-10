"""
HTTP Security Headers Analyzer
Checks for OWASP-recommended security headers and grades them.
"""
import requests
from typing import Dict, Any, List

# Security headers to check with their descriptions and references
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections, preventing protocol downgrade attacks and cookie hijacking.",
        "reference": "https://owasp.org/www-project-secure-headers/#strict-transport-security",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "severity": "high"
    },
    "Content-Security-Policy": {
        "description": "Mitigates XSS and data injection attacks by controlling resource loading origins.",
        "reference": "https://owasp.org/www-project-secure-headers/#content-security-policy",
        "recommended": "default-src 'self'; script-src 'self'; style-src 'self'",
        "severity": "high"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks by controlling iframe embedding.",
        "reference": "https://owasp.org/www-project-secure-headers/#x-frame-options",
        "recommended": "DENY or SAMEORIGIN",
        "severity": "high"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing, reducing drive-by download attacks.",
        "reference": "https://owasp.org/www-project-secure-headers/#x-content-type-options",
        "recommended": "nosniff",
        "severity": "medium"
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is shared with other sites.",
        "reference": "https://owasp.org/www-project-secure-headers/#referrer-policy",
        "recommended": "strict-origin-when-cross-origin",
        "severity": "medium"
    },
    "Permissions-Policy": {
        "description": "Controls which browser features (camera, mic, geolocation) the page can use.",
        "reference": "https://owasp.org/www-project-secure-headers/#permissions-policy",
        "recommended": "geolocation=(), camera=(), microphone=()",
        "severity": "medium"
    },
    "X-XSS-Protection": {
        "description": "Legacy header for browser XSS filtering. Modern CSP is preferred.",
        "reference": "https://owasp.org/www-project-secure-headers/#x-xss-protection",
        "recommended": "0 (disabled — rely on CSP instead)",
        "severity": "low"
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Prevents cross-origin documents from sharing a browsing context group.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
        "recommended": "same-origin",
        "severity": "medium"
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Prevents other origins from reading the response of cross-origin resources.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
        "recommended": "same-origin",
        "severity": "medium"
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Prevents loading cross-origin resources that don't explicitly grant permission.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
        "recommended": "require-corp",
        "severity": "low"
    }
}

# Headers that indicate information leakage
INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def scan(target: str, callback=None) -> Dict[str, Any]:
    """
    Analyze HTTP security headers for a target.
    
    Args:
        target: URL or domain to analyze
        callback: function(progress_pct, message) for progress updates
    """
    url = _normalize_url(target)
    
    if callback:
        callback(10, "Connecting to target...")
    
    response = _try_connect(url)
    if response is None:
        return {"error": f"Connection failed: could not reach {target} via HTTPS or HTTP"}

    if callback:
        callback(30, "Analyzing security headers...")

    headers = dict(response.headers)
    results = {
        "url": response.url,
        "status_code": response.status_code,
        "headers_found": [],
        "headers_missing": [],
        "info_leaks": [],
        "score": 0,
        "max_score": 0,
        "grade": "F",
        "all_response_headers": headers
    }

    # Check each security header
    total_checks = len(SECURITY_HEADERS)
    for i, (header_name, header_info) in enumerate(SECURITY_HEADERS.items()):
        header_value = headers.get(header_name)
        
        severity_weight = {"high": 15, "medium": 10, "low": 5}
        weight = severity_weight[header_info["severity"]]
        results["max_score"] += weight

        entry = {
            "name": header_name,
            "description": header_info["description"],
            "reference": header_info["reference"],
            "recommended": header_info["recommended"],
            "severity": header_info["severity"]
        }

        if header_value:
            entry["value"] = header_value
            entry["status"] = "present"
            strength = _evaluate_header_strength(header_name, header_value)
            entry["strength"] = strength
            if strength == "strong":
                results["score"] += weight
            elif strength == "weak":
                results["score"] += weight // 2
                entry["status"] = "weak"
            results["headers_found"].append(entry)
        else:
            entry["status"] = "missing"
            entry["value"] = None
            results["headers_missing"].append(entry)

        if callback and (i + 1) % 3 == 0:
            callback(30 + int(((i + 1) / total_checks) * 50), f"Checked {i+1}/{total_checks} headers")

    if callback:
        callback(85, "Checking for information leakage...")

    # Check for information leakage headers
    for leak_header in INFO_LEAK_HEADERS:
        value = headers.get(leak_header)
        if value:
            results["info_leaks"].append({
                "header": leak_header,
                "value": value,
                "risk": "Server version disclosure can aid targeted attacks."
            })

    # Calculate grade
    if results["max_score"] > 0:
        percentage = (results["score"] / results["max_score"]) * 100
    else:
        percentage = 0

    if percentage >= 90:
        results["grade"] = "A+"
    elif percentage >= 80:
        results["grade"] = "A"
    elif percentage >= 70:
        results["grade"] = "B"
    elif percentage >= 60:
        results["grade"] = "C"
    elif percentage >= 40:
        results["grade"] = "D"
    else:
        results["grade"] = "F"

    results["percentage"] = round(percentage, 1)
    results["risk_level"] = _grade_to_risk(results["grade"])

    if callback:
        callback(100, "Header analysis complete")

    return results


def _normalize_url(target: str) -> str:
    """Ensure target has a proper URL scheme."""
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _try_connect(url: str):
    """Try HTTPS first, fall back to HTTP if it fails."""
    # Try as-is first (usually https)
    try:
        return requests.get(url, timeout=10, allow_redirects=True, verify=True)
    except Exception:
        pass
    
    # Try with verify=False (self-signed certs)
    try:
        return requests.get(url, timeout=10, allow_redirects=True, verify=False)
    except Exception:
        pass
    
    # Fall back to HTTP
    http_url = url.replace("https://", "http://")
    if http_url != url:
        try:
            return requests.get(http_url, timeout=10, allow_redirects=True, verify=False)
        except Exception:
            pass
    
    return None


def _evaluate_header_strength(header_name: str, value: str) -> str:
    """Evaluate how well a header is configured."""
    value_lower = value.lower()
    
    if header_name == "Strict-Transport-Security":
        if "max-age=0" in value_lower:
            return "weak"
        if "includesubdomains" in value_lower and "preload" in value_lower:
            return "strong"
        if "max-age=" in value_lower:
            try:
                max_age = int(value_lower.split("max-age=")[1].split(";")[0].strip())
                return "strong" if max_age >= 31536000 else "weak"
            except (ValueError, IndexError):
                return "weak"
    
    elif header_name == "Content-Security-Policy":
        if "unsafe-inline" in value_lower or "unsafe-eval" in value_lower:
            return "weak"
        if "*" in value:
            return "weak"
        return "strong"
    
    elif header_name == "X-Frame-Options":
        if value_lower in ("deny", "sameorigin"):
            return "strong"
        return "weak"
    
    elif header_name == "X-Content-Type-Options":
        return "strong" if value_lower == "nosniff" else "weak"
    
    elif header_name == "Referrer-Policy":
        strong_policies = ["no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"]
        return "strong" if value_lower in strong_policies else "weak"
    
    return "strong" if value else "weak"


def _grade_to_risk(grade: str) -> str:
    """Convert letter grade to risk level."""
    if grade in ("A+", "A"):
        return "low"
    elif grade in ("B", "C"):
        return "medium"
    return "high"
