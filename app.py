"""
SecuriTool — Cybersecurity Analysis Platform
Flask backend with REST API for security scanning.
"""
import uuid
import threading
import time
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from scanners import port_scanner, header_scanner, ssl_scanner, dns_scanner, tech_detector, vuln_scanner

app = Flask(__name__)
CORS(app)

# In-memory scan storage
scans = {}

# Module mapping
MODULES = {
    "ports": {"name": "Port Scanner", "scanner": port_scanner},
    "headers": {"name": "Security Headers", "scanner": header_scanner},
    "ssl": {"name": "SSL/TLS Analysis", "scanner": ssl_scanner},
    "dns": {"name": "DNS Enumeration", "scanner": dns_scanner},
    "tech": {"name": "Technology Detection", "scanner": tech_detector},
    "vulns": {"name": "Vulnerability Scanner", "scanner": vuln_scanner},
}


@app.route("/")
def index():
    """Serve the main dashboard."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Start a new security scan."""
    data = request.get_json()
    target = data.get("target", "").strip()
    modules = data.get("modules", list(MODULES.keys()))
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    # Clean target
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    scan_id = str(uuid.uuid4())[:8]
    
    scans[scan_id] = {
        "id": scan_id,
        "target": target,
        "status": "running",
        "progress": 0,
        "current_module": "",
        "modules_requested": modules,
        "modules_completed": [],
        "results": {},
        "started_at": time.time()
    }
    
    # Run scan in background
    thread = threading.Thread(target=_run_scan, args=(scan_id, target, modules))
    thread.daemon = True
    thread.start()
    
    return jsonify({"scan_id": scan_id, "status": "started"})


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    """Get scan status and results."""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    return jsonify(scan)


@app.route("/api/scan/<scan_id>/module/<module_name>", methods=["GET"])  
def get_module_result(scan_id, module_name):
    """Get results for a specific module."""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    result = scan["results"].get(module_name)
    if result is None:
        return jsonify({"error": "Module not yet completed"}), 404
    
    return jsonify(result)


def _run_scan(scan_id: str, target: str, modules: list):
    """Execute all requested scan modules."""
    scan = scans[scan_id]
    total_modules = len(modules)
    
    for i, module_key in enumerate(modules):
        if module_key not in MODULES:
            continue
        
        module_info = MODULES[module_key]
        scan["current_module"] = module_info["name"]
        base_progress = int((i / total_modules) * 100)
        
        def make_callback(base, total):
            def callback(pct, msg):
                scan["progress"] = base + int((pct / 100) * (100 / total))
                scan["current_module"] = f"{module_info['name']}: {msg}"
            return callback
        
        try:
            result = module_info["scanner"].scan(
                target, 
                callback=make_callback(base_progress, total_modules)
            )
            scan["results"][module_key] = result
        except Exception as e:
            scan["results"][module_key] = {"error": str(e)}
        
        scan["modules_completed"].append(module_key)
    
    scan["status"] = "completed"
    scan["progress"] = 100
    scan["current_module"] = "Scan complete"
    scan["elapsed"] = round(time.time() - scan["started_at"], 1)


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  🛡️  SecuriTool — Cybersecurity Analysis Platform")
    print("  📡  Running at: http://localhost:5000")
    print("="*60 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
