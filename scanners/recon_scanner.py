"""
Sensitive File & Directory Discovery
Searches for exposed configuration files, backups, admin panels,
version control artifacts, and other files that should not be public.
"""
import requests
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Paths to probe ──
SENSITIVE_PATHS = {
    "Version Control": [
        ("/.git/HEAD", "Git repository exposed"),
        ("/.git/config", "Git config exposed"),
        ("/.svn/entries", "SVN repository exposed"),
        ("/.hg/requires", "Mercurial repository exposed"),
        ("/.bzr/README", "Bazaar repository exposed"),
    ],
    "Environment & Config": [
        ("/.env", "Environment variables file (may contain API keys, DB passwords)"),
        ("/.env.local", "Local environment file exposed"),
        ("/.env.production", "Production environment file exposed"),
        ("/.env.backup", "Environment backup file exposed"),
        ("/config.yml", "YAML configuration file exposed"),
        ("/config.json", "JSON configuration file exposed"),
        ("/config.xml", "XML configuration file exposed"),
        ("/config.php", "PHP configuration file exposed"),
        ("/wp-config.php", "WordPress configuration (DB credentials)"),
        ("/web.config", "IIS configuration file exposed"),
        ("/.htaccess", "Apache configuration file exposed"),
        ("/nginx.conf", "Nginx configuration file exposed"),
        ("/docker-compose.yml", "Docker Compose file exposed"),
        ("/Dockerfile", "Dockerfile exposed"),
    ],
    "Backups & Archives": [
        ("/backup.zip", "Backup archive exposed"),
        ("/backup.tar.gz", "Backup archive exposed"),
        ("/backup.sql", "Database backup exposed"),
        ("/db.sql", "Database dump exposed"),
        ("/database.sql", "Database dump exposed"),
        ("/dump.sql", "Database dump exposed"),
        ("/site.tar.gz", "Site archive exposed"),
        ("/www.zip", "Web root archive exposed"),
    ],
    "Debug & Info": [
        ("/phpinfo.php", "PHP info page (reveals server configuration)"),
        ("/info.php", "PHP info page exposed"),
        ("/server-status", "Apache server status exposed"),
        ("/server-info", "Apache server info exposed"),
        ("/_debug", "Debug endpoint exposed"),
        ("/debug", "Debug endpoint exposed"),
        ("/trace", "Trace endpoint exposed"),
        ("/elmah.axd", ".NET error log exposed"),
        ("/actuator", "Spring Boot Actuator exposed"),
        ("/actuator/health", "Spring Boot health endpoint"),
        ("/actuator/env", "Spring Boot environment (may contain secrets)"),
        ("/__debug__/", "Django debug toolbar exposed"),
    ],
    "Admin Panels": [
        ("/admin", "Admin panel found"),
        ("/admin/", "Admin panel found"),
        ("/administrator", "Admin panel found"),
        ("/wp-admin", "WordPress admin panel"),
        ("/wp-login.php", "WordPress login page"),
        ("/phpmyadmin", "phpMyAdmin database manager exposed"),
        ("/cpanel", "cPanel control panel"),
        ("/webmail", "Webmail interface exposed"),
        ("/manager/html", "Tomcat manager exposed"),
        ("/jenkins", "Jenkins CI/CD exposed"),
        ("/grafana", "Grafana dashboard exposed"),
    ],
    "API & Documentation": [
        ("/api", "API endpoint found"),
        ("/api/v1", "API v1 endpoint found"),
        ("/api/v2", "API v2 endpoint found"),
        ("/swagger.json", "Swagger/OpenAPI spec exposed"),
        ("/swagger-ui.html", "Swagger UI exposed"),
        ("/openapi.json", "OpenAPI specification exposed"),
        ("/api-docs", "API documentation exposed"),
        ("/graphql", "GraphQL endpoint found"),
        ("/graphiql", "GraphiQL IDE exposed"),
    ],
    "Security Files": [
        ("/robots.txt", "Robots file (may reveal hidden paths)"),
        ("/sitemap.xml", "Sitemap file found"),
        ("/security.txt", "Security contact info"),
        ("/.well-known/security.txt", "Security contact info (RFC 9116)"),
        ("/crossdomain.xml", "Flash cross-domain policy"),
        ("/clientaccesspolicy.xml", "Silverlight cross-domain policy"),
    ],
    "Sensitive Data": [
        ("/id_rsa", "SSH private key exposed!"),
        ("/id_rsa.pub", "SSH public key exposed"),
        ("/.ssh/authorized_keys", "SSH authorized keys exposed"),
        ("/.npmrc", "npm configuration (may contain auth tokens)"),
        ("/.dockerignore", "Docker ignore file exposed"),
        ("/package.json", "Node.js package manifest"),
        ("/composer.json", "PHP Composer manifest"),
        ("/Gemfile", "Ruby Gemfile exposed"),
        ("/requirements.txt", "Python dependencies file"),
    ],
}

# Status codes that indicate a file exists
FOUND_CODES = {200, 301, 302, 403}
# Status codes that mean "interesting but forbidden"
FORBIDDEN = {403}


def scan(target: str, callback=None) -> Dict[str, Any]:
    """
    Discover sensitive files and directories on the target.

    Args:
        target: URL or domain to scan
        callback: function(progress_pct, message) for progress updates
    """
    base_url = _normalize_url(target)
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    if callback:
        callback(5, "Preparing file discovery scan...")

    results = {
        "base_url": base,
        "found": [],
        "forbidden": [],
        "info_files": [],
        "risk_level": "info",
        "total_checked": 0,
        "issues": [],
    }

    # Flatten all paths
    all_paths = []
    for category, paths in SENSITIVE_PATHS.items():
        for path, desc in paths:
            all_paths.append((category, path, desc))

    total = len(all_paths)
    completed = 0

    if callback:
        callback(10, f"Scanning {total} paths...")

    def check_path(item):
        category, path, description = item
        url = urljoin(base, path)
        try:
            resp = requests.get(
                url, timeout=5, allow_redirects=False, verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                }
            )
            return {
                "category": category,
                "path": path,
                "url": url,
                "description": description,
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "content_type": resp.headers.get("Content-Type", ""),
            }
        except Exception:
            return None

    # Scan concurrently
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_item = {executor.submit(check_path, item): item for item in all_paths}

        for future in as_completed(future_to_item):
            completed += 1
            result = future.result()

            if result and result["status_code"] in FOUND_CODES:
                # Filter false positives
                if _is_false_positive(result):
                    continue

                entry = {
                    "category": result["category"],
                    "path": result["path"],
                    "status": result["status_code"],
                    "size": result["content_length"],
                    "description": result["description"],
                    "severity": _get_severity(result),
                }

                if result["status_code"] in FORBIDDEN:
                    entry["note"] = "Forbidden (403) — file exists but access denied"
                    results["forbidden"].append(entry)
                elif result["category"] == "Security Files":
                    results["info_files"].append(entry)
                else:
                    results["found"].append(entry)

            if callback and completed % 10 == 0:
                pct = 10 + int((completed / total) * 80)
                callback(pct, f"Checked {completed}/{total} paths...")

    results["total_checked"] = total

    # Analyze robots.txt for hidden paths
    if callback:
        callback(92, "Analyzing robots.txt for hidden paths...")
    _analyze_robots(results, base)

    # Build issues summary
    _build_issues(results)

    # Risk assessment
    if any(f["severity"] == "critical" for f in results["found"]):
        results["risk_level"] = "critical"
    elif any(f["severity"] == "high" for f in results["found"]):
        results["risk_level"] = "high"
    elif results["found"]:
        results["risk_level"] = "medium"
    elif results["forbidden"]:
        results["risk_level"] = "low"

    if callback:
        callback(100, "File discovery complete")

    return results


def _normalize_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def _is_false_positive(result: Dict) -> bool:
    """Filter out common false positives."""
    # Very small responses are likely custom 404 pages
    if result["status_code"] == 200 and result["content_length"] < 20:
        return True

    # HTML responses for non-HTML paths might be custom error pages
    ct = result["content_type"].lower()
    path = result["path"].lower()
    if result["status_code"] == 200:
        # If we get HTML for a .sql, .zip, .env, etc. file, it's likely a 404 page
        non_html_exts = ['.sql', '.zip', '.tar.gz', '.env', '.yml', '.json', '.xml', '.php']
        if any(path.endswith(ext) for ext in non_html_exts):
            if 'text/html' in ct and result["content_length"] > 500:
                return True

    # Redirect to login/home pages (likely catch-all)
    if result["status_code"] in (301, 302):
        return True  # We skip redirects to avoid false positives

    return False


def _get_severity(result: Dict) -> str:
    """Determine severity based on file type."""
    path = result["path"].lower()
    category = result["category"]

    if category == "Security Files":
        return "info"

    # Critical: actual secrets or credentials
    critical_paths = ['.env', 'id_rsa', 'wp-config.php', '.git/config',
                      'backup.sql', 'db.sql', 'database.sql', 'dump.sql',
                      'actuator/env', '.npmrc']
    if any(p in path for p in critical_paths):
        return "critical" if result["status_code"] == 200 else "high"

    # High: admin panels, debug endpoints
    if category in ("Admin Panels", "Debug & Info"):
        return "high" if result["status_code"] == 200 else "medium"

    # High: VCS exposure
    if category == "Version Control":
        return "high"

    # Medium: config files, backups
    if category in ("Environment & Config", "Backups & Archives", "Sensitive Data"):
        return "medium"

    return "low"


def _analyze_robots(results: Dict, base_url: str):
    """Extract interesting paths from robots.txt."""
    try:
        resp = requests.get(f"{base_url}/robots.txt", timeout=5, verify=False)
        if resp.status_code == 200 and "Disallow" in resp.text:
            disallowed = re.findall(r'Disallow:\s*(.+)', resp.text)
            interesting = [d.strip() for d in disallowed if d.strip() and d.strip() != "/"]
            if interesting:
                results["robots_disallowed"] = interesting[:20]  # Cap at 20
    except Exception:
        pass


def _build_issues(results: Dict):
    """Create a summary of issues found."""
    if results["found"]:
        for item in results["found"]:
            results["issues"].append({
                "severity": item["severity"],
                "title": f"Exposed: {item['path']}",
                "detail": item["description"],
                "remediation": _get_remediation(item["category"]),
            })

    if results["forbidden"]:
        results["issues"].append({
            "severity": "low",
            "title": f"{len(results['forbidden'])} Forbidden Paths Detected",
            "detail": "These paths return 403 Forbidden, confirming they exist but access is denied.",
            "remediation": "Return 404 instead of 403 to avoid confirming file existence.",
        })


def _get_remediation(category: str) -> str:
    """Get remediation advice by category."""
    remediations = {
        "Version Control": "Remove .git/.svn/.hg directories from production. Add to .htaccess or nginx deny rules.",
        "Environment & Config": "Move config files outside the web root. Block access via server config.",
        "Backups & Archives": "Never store backups in the web root. Use secure off-site storage.",
        "Debug & Info": "Disable debug endpoints in production. Remove phpinfo() calls.",
        "Admin Panels": "Restrict admin panels by IP whitelist. Use strong authentication and 2FA.",
        "API & Documentation": "Restrict API docs to authenticated users. Disable in production if not needed.",
        "Sensitive Data": "Never expose private keys or credentials in the web root. Use .gitignore properly.",
    }
    return remediations.get(category, "Remove or restrict access to this file in production.")
