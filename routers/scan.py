# routers/scan.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import uuid

# --- Database & Models ---
from database import get_db, findings_collection
import models

# --- Import the Celery Task ---
from tasks import run_all_scanners 

router = APIRouter()

class ScanRequest(BaseModel):
    url: str

@router.post("/scan")
def start_scan(request: ScanRequest, db: Session = Depends(get_db)):
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
    
    # 2. FIRE AND FORGET: Hand the job to Redis/Celery!
    # The .delay() method is Celery's magic command to queue it in the background
    run_all_scanners.delay(scan_id, url)
    
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
    task = db.query(models.ScanTask).filter(models.ScanTask.scan_id == scan_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Scan ID not found")
        
    if task.status != "Completed":
        return {"message": f"Scan is currently {task.status}. Check back later."}

    report = findings_collection.find_one({"scan_id": scan_id}, {"_id": 0})
    if not report:
        raise HTTPException(status_code=404, detail="Results not found in MongoDB")
        
    return report