from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from routers.dummy_report import router as dummy_router

app = FastAPI(
    title="VULKN",
    description="AI-Powered Web Application Security Scanner",
    version="0.1.0"
)
app.include_router(dummy_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    return {
        "scan_id": "abc123",       # hardcoded for now
        "target": url,
        "status": "queued",
        "message": f"Scan queued for {url}"
    }

# ── Get Scan Status ───────────────────────────────────
@app.get("/scan/{scan_id}")
def get_scan_status(scan_id: str):
    return {
        "scan_id": scan_id,
        "status": "running",
        "progress": "2/6 scanners complete"
    }

# ── Get Scan Results ──────────────────────────────────
@app.get("/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
    return {
        "scan_id": scan_id,
        "findings": [
            {
                "vuln_type": "SQL Injection",
                "severity": "Critical",
                "description": "Login form vulnerable to SQLi",
                "evidence": "' OR 1=1-- returned 200 OK",
                "confidence": 0.97
            },
            {
                "vuln_type": "XSS",
                "severity": "High",
                "description": "Search field reflects unsanitized input",
                "evidence": "<script>alert(1)</script> executed",
                "confidence": 0.89
            }
        ]
    }
