# tasks.py
from celery import Celery
import datetime
import inspect

# --- Database & Models ---
from database import SessionLocal, findings_collection
import models

# --- Scanners ---
from scanners.sqli_scan import run_sqli_scan
from scanners.xss_scan import run_xss_scan
from scanners.port_scan import run_port_scan
from scanners.dir_traversal import run_dir_traversal_scan
from scanners.csrf_scan import run_csrf_scan
from scanners.headers_scan import run_headers_scan

# 1. Initialize Celery & Connect to your Docker Redis
celery_app = Celery(
    "vulkn_tasks",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

# Global DVWA Cookies
dvwa_cookies = {
    "PHPSESSID": "cm83rkmq2qv9mt5rkgmmuu9j43", # Keep your current cookie here
    "security": "low"
}

# 2. Tell Celery this is a background task
@celery_app.task(name="run_all_scanners")
def run_all_scanners(scan_id: str, url: str):
    db = SessionLocal()
    try:
        task = db.query(models.ScanTask).filter(models.ScanTask.scan_id == scan_id).first()
        if task:
            task.status = "Running"
            db.commit()

        findings = []
        scanners = [
            run_sqli_scan,
            run_xss_scan,
            run_port_scan,
            run_dir_traversal_scan,
            run_csrf_scan,
            run_headers_scan,
        ]
        
        for scanner in scanners:
            try:
                sig = inspect.signature(scanner)
                if 'cookies' in sig.parameters:
                    result = scanner(url, cookies=dvwa_cookies)
                else:
                    result = scanner(url)
                    
                if result.get("vulnerabilities_found", 0) > 0:
                    findings.extend(result.get("details", []))
                    
            except Exception as e:
                findings.append({
                    "type": "Scanner Error",
                    "severity": "Info",
                    "description": f"Error running {scanner.__name__}: {str(e)}"
                })

        mongo_document = {
            "scan_id": scan_id,
            "target_url": url,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "findings": findings
        }
        findings_collection.insert_one(mongo_document)

        if task:
            task.status = "Completed"
            task.completed_at = datetime.datetime.utcnow()
            db.commit()
            
    except Exception as e:
        if task:
            task.status = "Failed"
            db.commit()
        print(f"[!] Scan {scan_id} failed: {e}")
    finally:
        db.close()