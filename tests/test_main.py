# tests/test_main.py
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_submit_scan():
    response = client.post("/scan?url=http://localhost:80")
    assert response.status_code == 200
    assert response.json()["status"] == "queued"

def test_get_scan_status():
    response = client.get("/scan/abc123")
    assert response.status_code == 200
    assert "scan_id" in response.json()

def test_get_scan_results():
    response = client.get("/scan/abc123/results")
    assert response.status_code == 200
    assert "findings" in response.json()