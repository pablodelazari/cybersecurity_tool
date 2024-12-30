# Cybersecurity Tool for Vulnerability Scanning
import socket
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading

# Module 1: Port Scanner
def port_scanner(target, ports, log):
    log.insert(tk.END, f"Scanning target: {target}\n")
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((target, port)) == 0:
                    open_ports.append(port)
                    log.insert(tk.END, f"Port {port} is open.\n")
        except Exception as e:
            log.insert(tk.END, f"Error scanning port {port}: {e}\n")
    return open_ports

# Module 2: Basic Web Vulnerability Check
def check_sql_injection(url, log):
    test_payload = "' OR '1'='1"  # Basic SQL injection payload
    try:
        response = requests.get(url, params={"id": test_payload}, timeout=5)
        if "SQL syntax" in response.text or "mysql" in response.text:
            log.insert(tk.END, "Possible SQL Injection vulnerability detected.\n")
            return True
        else:
            log.insert(tk.END, "No SQL Injection vulnerability detected.\n")
            return False
    except Exception as e:
        log.insert(tk.END, f"Error checking SQL Injection: {e}\n")
        return False

# Module 3: XSS Check
def check_xss(url, log):
    xss_payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url, params={"q": xss_payload}, timeout=5)
        if xss_payload in response.text:
            log.insert(tk.END, "Possible XSS vulnerability detected.\n")
            return True
        else:
            log.insert(tk.END, "No XSS vulnerability detected.\n")
            return False
    except Exception as e:
        log.insert(tk.END, f"Error checking XSS: {e}\n")
        return False

# Module 4: Generate Report
def generate_report(open_ports, url, sql_vuln, xss_vuln, log):
    report = {
        "Target": url,
        "Open Ports": open_ports,
        "SQL Injection": "Detected" if sql_vuln else "Not Detected",
        "XSS": "Detected" if xss_vuln else "Not Detected"
    }
    log.insert(tk.END, "--- Vulnerability Report ---\n")
    for key, value in report.items():
        log.insert(tk.END, f"{key}: {value}\n")
    return report

# GUI Functionality
def scan():
    def perform_scan():
        target_url = url_entry.get()
        log.insert(tk.END, f"Resolving IP for {target_url}...\n")
        try:
            target_ip = socket.gethostbyname(target_url)
            log.insert(tk.END, f"Resolved IP: {target_ip}\n")
        except socket.gaierror:
            log.insert(tk.END, "Invalid URL\n")
            messagebox.showerror("Error", "Invalid URL")
            return

        ports_to_scan = range(1, 1025)  # First 1024 ports
        log.insert(tk.END, "Starting port scan...\n")
        open_ports = port_scanner(target_ip, ports_to_scan, log)

        log.insert(tk.END, "Checking for SQL Injection vulnerabilities...\n")
        sql_vuln = check_sql_injection(target_url, log)

        log.insert(tk.END, "Checking for XSS vulnerabilities...\n")
        xss_vuln = check_xss(target_url, log)

        log.insert(tk.END, "Generating report...\n")
        generate_report(open_ports, target_url, sql_vuln, xss_vuln, log)
        log.insert(tk.END, "Scan completed.\n")

    threading.Thread(target=perform_scan).start()

# GUI Setup
root = tk.Tk()
root.title("Cybersecurity Tool")
root.geometry("600x400")

url_label = tk.Label(root, text="Enter Target URL:")
url_label.pack(pady=10)

url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=5)

scan_button = tk.Button(root, text="Scan", command=scan)
scan_button.pack(pady=10)

log = scrolledtext.ScrolledText(root, width=70, height=15, state="normal")
log.pack(pady=10)
log.insert(tk.END, "Welcome to the Cybersecurity Tool!\n")

root.mainloop()

# requirements.txt
# requests==2.31.0
# beautifulsoup4==4.12.2
