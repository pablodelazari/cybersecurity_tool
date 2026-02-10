"""
Port Scanner Module
Performs TCP connect scans with service banner grabbing.
"""
import socket
import concurrent.futures
from typing import Dict, List, Any

# Top 100 most common ports (based on nmap data)
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000,
    2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009,
    5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001,
    6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157
]

COMMON_SERVICES = {
    7: "Echo", 9: "Discard", 13: "Daytime", 20: "FTP Data", 21: "FTP",
    22: "SSH", 23: "Telnet", 25: "SMTP", 26: "RSFTP", 37: "Time",
    53: "DNS", 79: "Finger", 80: "HTTP", 81: "HTTP Alt", 88: "Kerberos",
    106: "POP3PW", 110: "POP3", 111: "RPCBind", 113: "Ident",
    119: "NNTP", 135: "MSRPC", 139: "NetBIOS-SSN", 143: "IMAP",
    144: "NEWS", 179: "BGP", 199: "SMUX", 389: "LDAP", 427: "SLP",
    443: "HTTPS", 444: "SNPP", 445: "Microsoft-DS", 465: "SMTPS",
    513: "rLogin", 514: "Syslog", 515: "LPD", 543: "Klogin",
    544: "Kshell", 548: "AFP", 554: "RTSP", 587: "SMTP Submission",
    631: "IPP/CUPS", 646: "LDP", 873: "Rsync", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1025: "NFS", 1433: "MSSQL",
    1434: "MSSQL Monitor", 1521: "Oracle DB", 1720: "H.323",
    1723: "PPTP", 1755: "MMS", 1900: "UPnP/SSDP", 2000: "Cisco SCCP",
    2049: "NFS", 2121: "FTP Alt", 2717: "PN Requester",
    3000: "Node.js/Grafana", 3128: "Squid Proxy", 3306: "MySQL",
    3389: "RDP", 3986: "MAPPER", 4899: "Radmin", 5000: "UPnP/Flask",
    5009: "Airport Admin", 5051: "ITA Agent", 5060: "SIP",
    5190: "AIM/ICQ", 5357: "WSDAPI", 5432: "PostgreSQL",
    5631: "pcAnywhere", 5666: "Nagios NRPE", 5800: "VNC HTTP",
    5900: "VNC", 6000: "X11", 6001: "X11:1", 6646: "McAfee",
    7070: "RealServer", 8000: "HTTP Alt", 8008: "HTTP Alt",
    8009: "AJP13", 8080: "HTTP Proxy", 8081: "HTTP Alt",
    8443: "HTTPS Alt", 8888: "HTTP Alt", 9100: "JetDirect",
    9999: "Urchin", 10000: "Webmin", 27017: "MongoDB",
    32768: "Filenet", 49152: "Dynamic", 49153: "Dynamic",
    49154: "Dynamic", 49155: "Dynamic", 49156: "Dynamic",
    49157: "Dynamic"
}


def _check_port(ip: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """Check if a single port is open and grab its banner."""
    result = {"port": port, "state": "closed", "service": COMMON_SERVICES.get(port, "Unknown"), "banner": ""}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                result["state"] = "open"
                # Attempt banner grab
                try:
                    s.settimeout(2.0)
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                    if banner:
                        result["banner"] = banner[:200]  # Truncate long banners
                except Exception:
                    pass
    except Exception:
        result["state"] = "filtered"
    return result


def scan(target: str, port_range: str = "top100", callback=None) -> Dict[str, Any]:
    """
    Run a port scan on the target.
    
    Args:
        target: IP address or hostname
        port_range: 'top100', 'top1000', or 'custom:1-1024'
        callback: function(progress_pct, message) for progress updates
    """
    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"error": f"Could not resolve hostname: {target}"}

    # Determine ports to scan
    if port_range == "top100":
        ports = TOP_100_PORTS
    elif port_range == "top1000":
        ports = list(range(1, 1001))
    elif port_range.startswith("custom:"):
        try:
            start, end = map(int, port_range.split(":")[1].split("-"))
            ports = list(range(start, end + 1))
        except ValueError:
            ports = TOP_100_PORTS
    else:
        ports = TOP_100_PORTS

    open_ports = []
    total = len(ports)
    completed = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(_check_port, ip, port): port for port in ports}
        
        for future in concurrent.futures.as_completed(future_to_port):
            completed += 1
            try:
                result = future.result()
                if result["state"] == "open":
                    open_ports.append(result)
            except Exception:
                pass
            
            if callback and completed % 10 == 0:
                callback(int((completed / total) * 100), f"Scanned {completed}/{total} ports")

    open_ports.sort(key=lambda x: x["port"])
    
    return {
        "target_ip": ip,
        "ports_scanned": total,
        "open_ports": open_ports,
        "open_count": len(open_ports),
        "risk_level": _assess_risk(open_ports)
    }


def _assess_risk(open_ports: List[Dict]) -> str:
    """Assess risk level based on open ports."""
    high_risk_ports = {21, 23, 135, 139, 445, 1433, 1434, 3389, 5900, 27017}
    medium_risk_ports = {25, 53, 110, 143, 389, 514, 873, 3306, 5432, 8080}
    
    open_port_numbers = {p["port"] for p in open_ports}
    
    if open_port_numbers & high_risk_ports:
        return "high"
    elif open_port_numbers & medium_risk_ports:
        return "medium"
    elif len(open_ports) > 10:
        return "medium"
    elif len(open_ports) > 0:
        return "low"
    return "info"
