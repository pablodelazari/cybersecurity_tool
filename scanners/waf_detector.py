"""
WAF (Web Application Firewall) Detection Module
Identifies security products protecting the target using:
- Response headers fingerprinting
- Cookie analysis
- Error page signatures
- Connection behavior analysis
"""
import requests
import re
from typing import Dict, Any, List

# ── WAF Signatures ──
WAF_HEADERS = {
    # Header name -> list of (value pattern, WAF name)
    "Server": [
        (r"cloudflare", "Cloudflare"),
        (r"AkamaiGHost", "Akamai"),
        (r"Sucuri", "Sucuri"),
        (r"Imperva", "Imperva / Incapsula"),
        (r"BIG-IP|BigIP|F5", "F5 BIG-IP"),
        (r"BarracudaWAF", "Barracuda WAF"),
        (r"FortiWeb", "Fortinet FortiWeb"),
        (r"DenyAll", "DenyAll WAF"),
    ],
    "X-Powered-By": [
        (r"AWS Lambda", "AWS (Lambda@Edge)"),
    ],
    "X-CDN": [
        (r"Incapsula", "Imperva / Incapsula"),
        (r"Akamai", "Akamai"),
    ],
    "X-Sucuri-ID": [
        (r".", "Sucuri WAF"),
    ],
    "X-Sucuri-Cache": [
        (r".", "Sucuri WAF"),
    ],
    "CF-RAY": [
        (r".", "Cloudflare"),
    ],
    "CF-Cache-Status": [
        (r".", "Cloudflare"),
    ],
    "X-Akamai-Transformed": [
        (r".", "Akamai"),
    ],
    "X-CDN-Geo": [
        (r".", "CDN with Geo-based WAF"),
    ],
    "X-Azure-Ref": [
        (r".", "Azure Front Door / Azure WAF"),
    ],
    "X-Amz-Cf-Id": [
        (r".", "AWS CloudFront"),
    ],
    "X-Amz-Cf-Pop": [
        (r".", "AWS CloudFront"),
    ],
    "X-Cache": [
        (r"cloudfront", "AWS CloudFront"),
        (r"varnish", "Varnish Cache"),
    ],
    "Via": [
        (r"vegur", "Heroku"),
        (r"varnish", "Varnish Cache"),
        (r"cloudfront", "AWS CloudFront"),
    ],
    "X-Fastly-Request-ID": [
        (r".", "Fastly CDN"),
    ],
    "X-Vercel-Id": [
        (r".", "Vercel Edge Network"),
    ],
    "X-Served-By": [
        (r"cache-", "Fastly CDN"),
    ],
    "Set-Cookie": [
        (r"__cfduid|__cf_bm|cf_clearance", "Cloudflare"),
        (r"incap_ses|visid_incap", "Imperva / Incapsula"),
        (r"sucuri_cloudproxy", "Sucuri WAF"),
        (r"AWSALB|AWSALBCORS", "AWS ALB"),
        (r"ak_bmsc|bm_sv", "Akamai Bot Manager"),
        (r"ts[a-zA-Z0-9]+=(0[86]|akamai)", "Akamai"),
    ],
}

# Error page patterns
WAF_ERROR_PATTERNS = [
    (r"Attention Required.*Cloudflare", "Cloudflare"),
    (r"cloudflare-nginx|cf-browser-verification", "Cloudflare"),
    (r"Incapsula incident ID", "Imperva / Incapsula"),
    (r"Powered by Sucuri", "Sucuri WAF"),
    (r"Request unsuccessful.*Incapsula", "Imperva / Incapsula"),
    (r"Access Denied.*Sucuri Website Firewall", "Sucuri WAF"),
    (r"ModSecurity|mod_security|NOYB", "ModSecurity"),
    (r"<title>Blocked</title>", "Generic WAF"),
    (r"Web Application Firewall", "Generic WAF"),
    (r"FortiGuard", "Fortinet FortiGuard"),
    (r"StackPath.*EdgeSSL", "StackPath WAF"),
    (r"Wordfence", "Wordfence (WordPress WAF)"),
    (r"Shield Security", "Shield Security"),
    (r"AWS WAF", "AWS WAF"),
    (r"DDoS protection by", "DDoS Protection Service"),
]

# Trigger payloads that might activate WAF responses
TRIGGER_PAYLOADS = [
    "?test=<script>alert(1)</script>",
    "?id=1' OR '1'='1",
    "?file=../../../etc/passwd",
    "?cmd=;cat /etc/passwd",
]


def scan(target: str, callback=None) -> Dict[str, Any]:
    """
    Detect WAF/CDN protecting the target.

    Args:
        target: URL or domain to analyze
        callback: function(progress_pct, message) for progress updates
    """
    url = _normalize_url(target)

    if callback:
        callback(5, "Connecting to target...")

    results = {
        "url": url,
        "waf_detected": False,
        "waf_products": [],
        "cdn_detected": False,
        "cdn_products": [],
        "protection_headers": [],
        "risk_level": "info",
        "issues": [],
    }

    # Phase 1: Normal request analysis
    if callback:
        callback(15, "Analyzing response headers...")

    response = _try_connect(url)
    if response is None:
        return {"error": f"Connection failed: could not reach {target} via HTTPS or HTTP"}

    headers = dict(response.headers)
    _analyze_headers(results, headers)

    # Phase 2: Check for protection headers
    if callback:
        callback(35, "Checking security infrastructure...")
    _check_protection_headers(results, headers)

    # Phase 3: Trigger WAF with suspicious payloads
    if callback:
        callback(50, "Testing WAF response to suspicious requests...")
    _trigger_waf(results, url)

    # Phase 4: Analyze error pages
    if callback:
        callback(70, "Analyzing error page signatures...")
    body = response.text[:30000]
    _analyze_error_pages(results, body)

    # Phase 5: Check multiple IPs (CDN detection)
    if callback:
        callback(85, "Checking CDN indicators...")
    _check_cdn_indicators(results, headers)

    # Build final assessment
    _build_assessment(results)

    if callback:
        callback(100, "WAF detection complete")

    return results


def _normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _try_connect(url: str):
    """Try HTTPS first, fall back to HTTP."""
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


def _analyze_headers(results: Dict, headers: Dict):
    """Detect WAF/CDN from response headers."""
    detected = set()

    for header_name, signatures in WAF_HEADERS.items():
        header_value = ""
        if header_name == "Set-Cookie":
            # Combine all Set-Cookie headers
            header_value = headers.get("Set-Cookie", "")
        else:
            header_value = headers.get(header_name, "")

        if not header_value:
            continue

        for pattern, product in signatures:
            if re.search(pattern, header_value, re.IGNORECASE):
                if product not in detected:
                    detected.add(product)
                    _add_product(results, product, f"Header: {header_name}")


def _check_protection_headers(results: Dict, headers: Dict):
    """Check for rate limiting and bot protection headers."""
    protection_indicators = {
        "X-RateLimit-Limit": "Rate limiting active",
        "X-RateLimit-Remaining": "Rate limiting active",
        "X-Rate-Limit-Limit": "Rate limiting active",
        "Retry-After": "Rate limiting / throttling",
        "X-Request-Id": "Request tracking enabled",
        "X-Correlation-Id": "Request correlation tracking",
        "X-Content-Security-Policy": "Legacy CSP header",
        "Report-To": "Security reporting configured",
        "NEL": "Network Error Logging enabled",
        "Expect-CT": "Certificate Transparency enforcement",
    }

    for header, description in protection_indicators.items():
        if header in headers:
            results["protection_headers"].append({
                "header": header,
                "value": headers[header][:100],
                "description": description,
            })


def _trigger_waf(results: Dict, url: str):
    """Send suspicious payloads to trigger WAF responses."""
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    detected = set()

    for payload in TRIGGER_PAYLOADS:
        try:
            test_url = url.rstrip("/") + payload
            resp = requests.get(test_url, timeout=5, allow_redirects=True, verify=False, headers=ua)

            # WAF typically blocks with 403, 406, 429, 503
            if resp.status_code in (403, 406, 429, 503):
                body = resp.text[:10000]
                for pattern, product in WAF_ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        if product not in detected:
                            detected.add(product)
                            _add_product(results, product, f"Blocked request with status {resp.status_code}")
                        break
                else:
                    if "Generic WAF Block" not in detected:
                        detected.add("Generic WAF Block")
                        _add_product(results, "WAF (unidentified)",
                                    f"Suspicious request blocked with HTTP {resp.status_code}")

        except requests.exceptions.ConnectionError:
            # Connection dropped = aggressive WAF
            if "Connection Drop WAF" not in detected:
                detected.add("Connection Drop WAF")
                _add_product(results, "Aggressive WAF/IPS",
                            "Connection dropped when sending malicious payload")
        except Exception:
            continue


def _analyze_error_pages(results: Dict, body: str):
    """Check main page body for WAF signatures."""
    detected = set()
    for pattern, product in WAF_ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            if product not in detected:
                detected.add(product)
                _add_product(results, product, "Page content pattern match")


def _check_cdn_indicators(results: Dict, headers: Dict):
    """Check for CDN-specific indicators."""
    cdn_headers = {
        "X-Cache": "CDN cache layer",
        "X-Cache-Hits": "CDN cache hits tracking",
        "Age": "CDN-cached response",
        "X-Served-By": "CDN edge server",
        "X-Timer": "CDN timing information",
    }

    for header, description in cdn_headers.items():
        if header in headers:
            results["cdn_detected"] = True


def _add_product(results: Dict, product: str, evidence: str):
    """Add a detected WAF/CDN product, avoiding duplicates."""
    existing_names = [p["name"] for p in results["waf_products"]]
    if product in existing_names:
        return

    is_cdn = any(cdn in product.lower() for cdn in
                 ["cloudfront", "fastly", "varnish", "heroku", "vercel", "cdn"])

    entry = {
        "name": product,
        "evidence": evidence,
        "type": "CDN" if is_cdn else "WAF/Security",
    }

    if is_cdn:
        results["cdn_detected"] = True
        results["cdn_products"].append(entry)
    else:
        results["waf_detected"] = True
        results["waf_products"].append(entry)


def _build_assessment(results: Dict):
    """Build the final security assessment."""
    waf_count = len(results["waf_products"])
    cdn_count = len(results["cdn_products"])

    if waf_count > 0:
        results["issues"].append({
            "severity": "info",
            "title": f"WAF Detected: {', '.join(p['name'] for p in results['waf_products'])}",
            "detail": f"{waf_count} web application firewall(s) identified protecting this target.",
        })
        results["risk_level"] = "low"  # Protected = lower risk

    if cdn_count > 0:
        results["issues"].append({
            "severity": "info",
            "title": f"CDN Detected: {', '.join(p['name'] for p in results['cdn_products'])}",
            "detail": f"{cdn_count} CDN/edge service(s) identified. Real server IP may be hidden.",
        })

    if not results["waf_detected"] and not results["cdn_detected"]:
        results["issues"].append({
            "severity": "medium",
            "title": "No WAF/CDN Detected",
            "detail": "No web application firewall or CDN was detected. The server may be directly exposed to attacks.",
            "remediation": "Consider deploying a WAF (e.g., Cloudflare, AWS WAF, ModSecurity) to filter malicious traffic.",
        })
        results["risk_level"] = "medium"

    if results["protection_headers"]:
        results["issues"].append({
            "severity": "info",
            "title": f"{len(results['protection_headers'])} Protection Headers Found",
            "detail": "Additional security headers indicate active monitoring and rate limiting.",
        })
