"""
SSL/TLS Certificate Analyzer
Inspects certificate details, TLS version, cipher suites, and trust chain.
"""
import socket
import ssl
from datetime import datetime
from typing import Dict, Any

# Weak cipher patterns
WEAK_CIPHERS = ["RC4", "DES", "MD5", "NULL", "EXPORT", "anon"]
STRONG_TLS_VERSIONS = ["TLSv1.2", "TLSv1.3"]


def scan(target: str, callback=None) -> Dict[str, Any]:
    """
    Perform SSL/TLS analysis on a target.
    
    Args:
        target: hostname to analyze
        callback: function(progress_pct, message) for progress updates
    """
    hostname = _clean_hostname(target)
    
    if callback:
        callback(10, "Initiating TLS handshake...")

    results = {
        "hostname": hostname,
        "certificate": {},
        "tls_version": "",
        "cipher_suite": {},
        "issues": [],
        "risk_level": "low"
    }

    # Test SSL connection
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                if callback:
                    callback(40, "Analyzing certificate...")

                # Certificate info
                results["certificate"] = _parse_certificate(cert)
                
                # TLS version
                results["tls_version"] = ssock.version()
                
                # Cipher info
                cipher_info = ssock.cipher()
                results["cipher_suite"] = {
                    "name": cipher_info[0],
                    "protocol": cipher_info[1],
                    "bits": cipher_info[2]
                }

    except ssl.SSLCertVerificationError as e:
        results["issues"].append({
            "severity": "critical",
            "title": "Certificate Verification Failed",
            "detail": str(e)
        })
        results["risk_level"] = "critical"
        # Try without verification for analysis
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    results["tls_version"] = ssock.version()
                    cipher_info = ssock.cipher()
                    results["cipher_suite"] = {
                        "name": cipher_info[0],
                        "protocol": cipher_info[1],
                        "bits": cipher_info[2]
                    }
        except Exception:
            pass
    except ssl.SSLError as e:
        results["issues"].append({
            "severity": "critical",
            "title": "SSL Connection Error",
            "detail": str(e)
        })
        results["risk_level"] = "critical"
        if callback:
            callback(100, "SSL analysis failed")
        return results
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"error": f"Cannot connect to {hostname}:443 — {str(e)}"}

    if callback:
        callback(60, "Checking TLS configuration...")

    # Analyze TLS version
    if results["tls_version"] and results["tls_version"] not in STRONG_TLS_VERSIONS:
        results["issues"].append({
            "severity": "high",
            "title": "Outdated TLS Version",
            "detail": f"Using {results['tls_version']}. TLSv1.2+ is recommended."
        })

    # Analyze cipher strength
    cipher_name = results.get("cipher_suite", {}).get("name", "")
    for weak in WEAK_CIPHERS:
        if weak in cipher_name.upper():
            results["issues"].append({
                "severity": "high",
                "title": "Weak Cipher Suite",
                "detail": f"Cipher {cipher_name} uses weak algorithm {weak}."
            })
            break

    cipher_bits = results.get("cipher_suite", {}).get("bits", 0)
    if cipher_bits and cipher_bits < 128:
        results["issues"].append({
            "severity": "high",
            "title": "Insufficient Cipher Strength",
            "detail": f"Cipher key length is {cipher_bits}-bit. Minimum 128-bit recommended."
        })

    if callback:
        callback(80, "Checking certificate validity...")

    # Check certificate expiry
    cert_data = results.get("certificate", {})
    if cert_data.get("days_until_expiry") is not None:
        days = cert_data["days_until_expiry"]
        if days < 0:
            results["issues"].append({
                "severity": "critical",
                "title": "Certificate Expired",
                "detail": f"Certificate expired {abs(days)} days ago."
            })
        elif days < 30:
            results["issues"].append({
                "severity": "high",
                "title": "Certificate Expiring Soon",
                "detail": f"Certificate expires in {days} days."
            })
        elif days < 90:
            results["issues"].append({
                "severity": "medium",
                "title": "Certificate Renewal Recommended",
                "detail": f"Certificate expires in {days} days. Consider renewal."
            })

    # Determine overall risk
    if not results["issues"]:
        results["risk_level"] = "low"
    else:
        severities = [i["severity"] for i in results["issues"]]
        if "critical" in severities:
            results["risk_level"] = "critical"
        elif "high" in severities:
            results["risk_level"] = "high"
        elif "medium" in severities:
            results["risk_level"] = "medium"
        else:
            results["risk_level"] = "low"

    if callback:
        callback(100, "SSL analysis complete")

    return results


def _clean_hostname(target: str) -> str:
    """Extract hostname from URL or input."""
    target = target.strip()
    for prefix in ["https://", "http://"]:
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0]
    target = target.split(":")[0]
    return target


def _parse_certificate(cert: dict) -> Dict[str, Any]:
    """Parse certificate details into a clean structure."""
    result = {}
    
    # Subject
    subject = dict(x[0] for x in cert.get("subject", ()))
    result["common_name"] = subject.get("commonName", "N/A")
    result["organization"] = subject.get("organizationName", "N/A")
    
    # Issuer
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    result["issuer"] = issuer.get("organizationName", issuer.get("commonName", "N/A"))
    result["issuer_cn"] = issuer.get("commonName", "N/A")
    
    # Dates
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    result["valid_from"] = not_before
    result["valid_until"] = not_after
    
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            result["days_until_expiry"] = (expiry - datetime.utcnow()).days
        except ValueError:
            result["days_until_expiry"] = None
    
    # SANs
    sans = cert.get("subjectAltName", ())
    result["san"] = [name for type_, name in sans if type_ == "DNS"]
    
    # Serial
    result["serial_number"] = cert.get("serialNumber", "N/A")
    
    return result
