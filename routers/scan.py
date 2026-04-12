from fastapi import APIRouter, BackgroundTasks
import uuid

from scanners.sqli_scan import run_sqli_scan
from scanners.xss_scan import run_xss_scan
from scanners.port_scan import run_port_scan
from scanners.dir_traversal import run_dir_traversal_scan
from scanners.csrf_scan import run_csrf_scan
from scanners.headers_scan import run_headers_scan


router = APIRouter()
scan_results = {}


def run_all_scanners(scan_id: str, url: str):
	scan_results[scan_id]["status"] = "Running"

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
			findings.append(
				{
					"type": "Scanner Error",
					"severity": "Info",
					"description": f"Error running {scanner.__name__}: {str(e)}",
				}
			)

	scan_results[scan_id]["status"] = "Completed"
	scan_results[scan_id]["findings"] = findings


@router.post("/scan")
def start_scan(url: str, background_tasks: BackgroundTasks):
	scan_id = str(uuid.uuid4())[:8]
	scan_results[scan_id] = {
		"scan_id": scan_id,
		"target": url,
		"status": "queued",
		"findings": [],
	}
	background_tasks.add_task(run_all_scanners, scan_id, url)
	return {
		"scan_id": scan_id,
		"target": url,
		"status": "queued",
		"message": f"Scan queued for {url}",
	}


@router.get("/scan/{scan_id}")
def get_scan_status(scan_id: str):
	if scan_id not in scan_results:
		return {"error": "Scan ID not found"}
	result = scan_results.get(scan_id)
	return {
		"scan_id": scan_id,
		"target": result["target"],
		"status": result["status"],
		"findings": result.get("findings", []),
	}


@router.get("/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
	if scan_id not in scan_results:
		return {"error": "Scan ID not found"}
	return scan_results[scan_id]
