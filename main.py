from fastapi import FastAPI
from datetime import datetime
import uuid

app = FastAPI(
    title="VULKN",
    description="AI-Powered Web Application Security Scanner",
    version="0.1.0"
)

# ✅ storage
scans = {}

# ── Health Check ──────────────────────────────────────
@app.get("/health")
def health_check():
    return {
        "status": "online",
        "service": "VULKN API",
        "timestamp": datetime.now().isoformat()
    }

# ── Scan Submission ───────────────────────────────────
@app.post("/scan")
def submit_scan(url: str):
    scan_id = str(uuid.uuid4())

    scans[scan_id] = {
        "target": url,
        "status": "queued"
    }

    return {
        "scan_id": scan_id,
        "target": url,
        "status": "queued"
    }

# ── Get Scan Status ───────────────────────────────────
@app.get("/scan/{scan_id}")
def get_scan_status(scan_id: str):
    return scans.get(scan_id, {"error": "Scan not found"})

# ── Get Scan Results ──────────────────────────────────
@app.get("/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
    if scan_id not in scans:
        return {"error": "Scan not found"}

    return {
        "scan_id": scan_id,
        "findings": [
            {"vuln_type": "SQL Injection", "severity": "Critical"},
            {"vuln_type": "XSS", "severity": "High"}
        ]
    }