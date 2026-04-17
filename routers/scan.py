# routers/scan.py
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import uuid
import datetime

# --- Database & Models ---
from database import get_db, SessionLocal, findings_collection
import models

# --- Scanners ---
from scanners.sqli_scan import run_sqli_scan
from scanners.xss_scan import run_xss_scan
from scanners.port_scan import run_port_scan
from scanners.dir_traversal import run_dir_traversal_scan
from scanners.csrf_scan import run_csrf_scan
from scanners.headers_scan import run_headers_scan

router = APIRouter()

class ScanRequest(BaseModel):
    url: str

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


@router.post("/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    url = request.url 
    scan_id = str(uuid.uuid4())[:8]
    
    # 1. Save the new task to PostgreSQL
    new_task = models.ScanTask(
        scan_id=scan_id,
        target_url=url,
        status="Queued"
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    
    # 2. Trigger the background scan
    background_tasks.add_task(run_all_scanners, scan_id, url)
    
    return {
        "scan_id": scan_id,
        "target": url,
        "status": "Queued",
        "message": f"Scan queued for {url}",
    }


@router.get("/scan/{scan_id}")
def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    task = db.query(models.ScanTask).filter(models.ScanTask.scan_id == scan_id).first()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan ID not found")
        
    return {
        "scan_id": task.scan_id,
        "target": task.target_url,
        "status": task.status,
        "created_at": task.created_at
    }


@router.get("/scan/{scan_id}/results")
def get_scan_results(scan_id: str, db: Session = Depends(get_db)):
    # 1. First check PostgreSQL to ensure the scan actually finished
    task = db.query(models.ScanTask).filter(models.ScanTask.scan_id == scan_id).first()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan ID not found")
        
    if task.status != "Completed":
        return {"message": f"Scan is currently {task.status}. Check back later."}

    # 2. Query MongoDB for the heavy findings payload
    # Note: {"_id": 0} hides the internal Mongo ObjectId so it doesn't break FastAPI's JSON parser
    report = findings_collection.find_one({"scan_id": scan_id}, {"_id": 0})
    
    if not report:
        raise HTTPException(status_code=404, detail="Results not found in MongoDB")
        
    return report