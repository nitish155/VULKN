"""
VULKN - MongoDB Seed Script
Run this to insert sample scan_results documents for development.
Usage: python infra/seed_mongo.py
Requires MongoDB running (via docker-compose up)
"""

from datetime import datetime, timezone
import json

SAMPLE_DOCUMENTS = [
    {
        "scan_id": "550e8400-e29b-41d4-a716-446655440000",
        "vuln_type": "SQLi",
        "scanner_version": "1.0.0",
        "target_url": "http://testphp.vulnweb.com/login.php",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "payloads": [
            "' OR 1=1--",
            "' AND 1=2--",
            "' UNION SELECT NULL--"
        ],
        "responses": [
            {
                "payload": "' OR 1=1--",
                "status_code": 200,
                "response_time": 4823.5,
                "body_snippet": "Welcome admin!",
                "body_length": 8192,
                "error_found": True,
                "error_message": "SQL syntax error near OR"
            },
            {
                "payload": "' AND 1=2--",
                "status_code": 500,
                "response_time": 201.4,
                "body_snippet": "mysql_fetch_array() error",
                "body_length": 3200,
                "error_found": True,
                "error_message": "mysql_fetch_array() expects resource"
            },
            {
                "payload": "' UNION SELECT NULL--",
                "status_code": 200,
                "response_time": 189.0,
                "body_snippet": "Invalid credentials",
                "body_length": 512,
                "error_found": False,
                "error_message": None
            }
        ],
        "ai_analysis": {
            "anomaly_score": -0.6497,
            "ai_label": "anomalous",
            "contamination": 0.10,
            "features_used": {
                "request_length": 195,
                "method_encoded": 1,
                "num_parameters": 5,
                "body_length": 146
            },
            "confidence": 0.89
        },
        "confirmed_vulnerable": True,
        "evidence_summary": (
            "SQL injection confirmed. ' OR 1=1-- returned admin "
            "session. SQL error exposed in 500 response."
        )
    },
    {
        "scan_id": "660f9511-f30c-52e5-b827-557766551111",
        "vuln_type": "XSS",
        "scanner_version": "1.0.0",
        "target_url": "http://testphp.vulnweb.com/search.php",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "payloads": [
            "",
            "",
            "javascript:alert(1)"
        ],
        "responses": [
            {
                "payload": "",
                "status_code": 200,
                "response_time": 98.3,
                "body_snippet": " reflected in page",
                "body_length": 4096,
                "error_found": True,
                "error_message": "Script tag reflected unescaped"
            },
            {
                "payload": "",
                "status_code": 200,
                "response_time": 102.1,
                "body_snippet": " in response",
                "body_length": 4150,
                "error_found": True,
                "error_message": "onerror handler reflected"
            },
            {
                "payload": "javascript:alert(1)",
                "status_code": 200,
                "response_time": 95.7,
                "body_snippet": "No reflection detected",
                "body_length": 3900,
                "error_found": False,
                "error_message": None
            }
        ],
        "ai_analysis": {
            "anomaly_score": -0.6424,
            "ai_label": "anomalous",
            "contamination": 0.10,
            "features_used": {
                "request_length": 126,
                "method_encoded": 0,
                "num_parameters": 5,
                "body_length": 0
            },
            "confidence": 0.84
        },
        "confirmed_vulnerable": True,
        "evidence_summary": (
            "Reflected XSS confirmed. Script tag reflected "
            "unescaped in search results page."
        )
    },
    {
        "scan_id": "770a0622-g41d-63f6-c938-668877662222",
        "vuln_type": "SQLi",
        "scanner_version": "1.0.0",
        "target_url": "http://safe-target.com/login",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "payloads": [
            "' OR 1=1--",
            "' AND 1=2--"
        ],
        "responses": [
            {
                "payload": "' OR 1=1--",
                "status_code": 200,
                "response_time": 142.0,
                "body_snippet": "Invalid credentials. Please try again.",
                "body_length": 512,
                "error_found": False,
                "error_message": None
            },
            {
                "payload": "' AND 1=2--",
                "status_code": 200,
                "response_time": 138.0,
                "body_snippet": "Invalid credentials. Please try again.",
                "body_length": 512,
                "error_found": False,
                "error_message": None
            }
        ],
        "ai_analysis": {
            "anomaly_score": -0.5239,
            "ai_label": "normal",
            "contamination": 0.10,
            "features_used": {
                "request_length": 48,
                "method_encoded": 1,
                "num_parameters": 0,
                "body_length": 25
            },
            "confidence": 0.72
        },
        "confirmed_vulnerable": False,
        "evidence_summary": (
            "No SQL injection found. All responses consistent "
            "with normal credential rejection."
        )
    }
]


def seed_without_mongo():
    """
    Preview the documents without needing MongoDB installed.
    MongoDB will be available via docker-compose in Week 4.
    """
    print("=" * 55)
    print("VULKN MongoDB Seed Preview")
    print("=" * 55)
    print(f"\n{len(SAMPLE_DOCUMENTS)} documents ready to insert")
    print("into collection: vulkn_db.scan_results")
    print()
    for i, doc in enumerate(SAMPLE_DOCUMENTS, 1):
        print(f"Document {i}:")
        print(f"  scan_id    : {doc['scan_id']}")
        print(f"  vuln_type  : {doc['vuln_type']}")
        print(f"  target_url : {doc['target_url']}")
        print(f"  payloads   : {len(doc['payloads'])} tried")
        print(f"  ai_label   : {doc['ai_analysis']['ai_label']}")
        print(f"  ai_score   : {doc['ai_analysis']['anomaly_score']}")
        print(f"  vulnerable : {doc['confirmed_vulnerable']}")
        print()

    print("NOTE: MongoDB not connected yet.")
    print("Real insertion happens in Week 4 when docker-compose")
    print("starts MongoDB. This script will then call:")
    print("  from pymongo import MongoClient")
    print("  client = MongoClient('mongodb://localhost:27017/')")
    print("  db = client['vulkn_db']")
    print("  db.scan_results.insert_many(SAMPLE_DOCUMENTS)")


if __name__ == "__main__":
    seed_without_mongo()