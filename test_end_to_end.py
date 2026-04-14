"""
VULKN — test_end_to_end.py
Day 25: end-to-end test for /classify + /score

Document says: Test /classify + /score end to end 3 times
This script calls all 3 AI endpoints in the exact order a scanner would:
  Step 1: POST /classify      — Isolation Forest on request features
  Step 2: POST /classify-response — Rules on server response body
  Step 3: POST /score         — Severity scoring

Run with: python test_end_to_end.py
Server must be running: uvicorn ai_service.main:app --reload --port 8001
"""

import requests
import json

BASE_URL = "http://localhost:8001"


def test_round(round_number: int, vuln_type: str, response_body: str,
               status_code: int, expected_severity: str):
    """
    Runs one complete end-to-end test round.
    Calls /classify → /classify-response → /score in sequence.
    """
    print(f"\n{'=' * 55}")
    print(f"ROUND {round_number}  —  Testing: {vuln_type}")
    print("=" * 55)

    # ── Step 1: POST /classify (Isolation Forest) ──────────────────────
    print(f"\nStep 1: POST /classify (Isolation Forest)")
    r1 = requests.post(f"{BASE_URL}/classify", json={
        "request_length": 195,
        "method_encoded": 1,
        "num_parameters": 5,
        "body_length":    146
    })
    assert r1.status_code == 200, f"FAIL: /classify returned {r1.status_code}"
    d1 = r1.json()
    print(f"  anomaly_score : {d1['anomaly_score']}")
    print(f"  ai_label      : {d1['ai_label']}")
    assert d1['ai_label'] == 'anomalous', \
        f"FAIL: expected anomalous, got {d1['ai_label']}"
    print(f"  PASS ✓")

    # ── Step 2: POST /classify-response (rule-based) ───────────────────
    print(f"\nStep 2: POST /classify-response (rule-based)")
    r2 = requests.post(f"{BASE_URL}/classify-response", json={
        "response_body": response_body,
        "status_code":   status_code,
        "vuln_type":     vuln_type
    })
    assert r2.status_code == 200, f"FAIL: /classify-response returned {r2.status_code}"
    d2 = r2.json()
    print(f"  label      : {d2['label']}")
    print(f"  confidence : {d2['confidence']}")
    print(f"  signals    : {d2['details']['signals']}")
    assert d2['label'] == 'attack', \
        f"FAIL: expected attack, got {d2['label']}"
    print(f"  PASS ✓")

    # ── Step 3: POST /score (severity rules) ──────────────────────────
    print(f"\nStep 3: POST /score (severity rules)")
    r3 = requests.post(f"{BASE_URL}/score", json={
        "vuln_type":            vuln_type,
        "confidence":           d2['confidence'],
        "confirmed_vulnerable": True,
        "error_keywords_found": len(d2['details']['signals']) > 0
    })
    assert r3.status_code == 200, f"FAIL: /score returned {r3.status_code}"
    d3 = r3.json()
    print(f"  severity   : {d3['severity']}")
    print(f"  cvss_score : {d3['cvss_score']}")
    print(f"  reasoning  : {d3['reasoning'][0]}")
    assert d3['severity'] in ['Critical', 'High', 'Medium', 'Low'], \
        f"FAIL: unexpected severity {d3['severity']}"
    print(f"  PASS ✓")

    print(f"\nROUND {round_number} COMPLETE — {vuln_type}: "
          f"IF={d1['ai_label']} → "
          f"response={d2['label']} ({d2['confidence']}) → "
          f"severity={d3['severity']}")


if __name__ == "__main__":

    print("VULKN AI SERVICE — END-TO-END TEST")
    print("Server must be running on port 8001")
    print()

    # ── Check server is running ─────────────────────────────────────────
    try:
        health = requests.get(f"{BASE_URL}/health")
        h = health.json()
        print(f"Server: {h['status']}")
        print(f"IF model loaded: {h['if_loaded']}")
        print(f"LR model loaded: {h['lr_loaded']}")
        assert h['if_loaded'], "FAIL: Isolation Forest not loaded"
    except requests.exceptions.ConnectionError:
        print("ERROR: Server not running.")
        print("Start it with: uvicorn ai_service.main:app --reload --port 8001")
        exit(1)

    # ── Run 3 rounds ────────────────────────────────────────────────────
    test_round(
        round_number=1,
        vuln_type="SQLi",
        response_body="Welcome admin! SQL syntax error near OR in your query",
        status_code=200,
        expected_severity="Critical"
    )

    test_round(
    round_number=2,
    vuln_type="SQLi",
    response_body="Fatal error: mysql_fetch_array() expects parameter 1 to be resource",
    status_code=500,
    expected_severity="Medium"   
    )

    test_round(
    round_number=3,
    vuln_type="XSS",
    response_body='<script>alert(1)</script> reflected in search results page',  
    status_code=200,
    expected_severity="Medium"   
    )

    print(f"\n{'=' * 55}")
    print("ALL 3 ROUNDS PASSED")
    print("ai_service is ready for the Week 5 demo")
    print("=" * 55)