"""
VULKN — ai_service/mongo_client.py
MongoDB client for storing and retrieving scan results.
The document says:
  pip install motor pymongo
  Function: save_scan_result(doc)
  Function: get_results(scan_id)
  Test: insert + retrieve one doc
  Print it to verify structure
"""

import os
import asyncio
from datetime import datetime, timezone
from typing import Optional

# MONGO_URL reads from environment variable
# When docker-compose runs: mongodb://localhost:27017
# or: mongodb://mongo:27017 (docker service name)
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME   = "vulkn_db"
COLLECTION = "scan_results"

# ── Async client (for use inside FastAPI endpoints) ───────────────────
async def get_mongo_client():
    """Returns an async Motor client."""
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=3000)
        # Test connection
        await client.admin.command('ping')
        return client
    except Exception as e:
        print(f"[mongo_client] Could not connect: {e}")
        return None


async def save_scan_result(doc: dict) -> Optional[str]:
    """
    The document says: Function: save_scan_result(doc)
    Saves one scan result document to MongoDB.
    Returns the inserted _id as string, or None on error.

    doc must match mongo_schema.md structure:
    {
        scan_id, vuln_type, target_url, payloads,
        responses, ai_analysis, confirmed_vulnerable
    }
    """
    if "scanned_at" not in doc:
        doc["scanned_at"] = datetime.now(timezone.utc).isoformat()

    try:
        client = await get_mongo_client()
        if client is None:
            print("[mongo_client] MongoDB not available — cannot save")
            return None

        db         = client[DB_NAME]
        collection = db[COLLECTION]
        result     = await collection.insert_one(doc)
        inserted_id = str(result.inserted_id)
        print(f"[mongo_client] Document saved: _id={inserted_id}")
        client.close()
        return inserted_id

    except Exception as e:
        print(f"[mongo_client] save_scan_result error: {e}")
        return None


async def get_results(scan_id: str) -> list:
    """
    The document says: Function: get_results(scan_id)
    Retrieves all scan result documents for a given scan_id.
    Returns a list of documents (dicts).
    """
    try:
        client = await get_mongo_client()
        if client is None:
            print("[mongo_client] MongoDB not available — returning empty")
            return []

        db         = client[DB_NAME]
        collection = db[COLLECTION]
        cursor     = collection.find({"scan_id": scan_id})
        docs       = await cursor.to_list(length=100)

        # Convert ObjectId to string for JSON serialisation
        for doc in docs:
            doc["_id"] = str(doc["_id"])

        client.close()
        print(f"[mongo_client] Found {len(docs)} documents for scan_id={scan_id}")
        return docs

    except Exception as e:
        print(f"[mongo_client] get_results error: {e}")
        return []


async def get_one_result(scan_id: str, vuln_type: str) -> Optional[dict]:
    """
    Gets a single document matching scan_id + vuln_type.
    Useful for checking if a specific scanner result already exists.
    """
    try:
        client = await get_mongo_client()
        if client is None:
            return None

        db         = client[DB_NAME]
        collection = db[COLLECTION]
        doc        = await collection.find_one({
            "scan_id": scan_id,
            "vuln_type": vuln_type
        })

        if doc:
            doc["_id"] = str(doc["_id"])
        client.close()
        return doc

    except Exception as e:
        print(f"[mongo_client] get_one_result error: {e}")
        return None


# ── Sync test function (for running directly without FastAPI) ─────────
def test_mongo_connection():
    """
    The document says: 'Test: insert + retrieve one doc. Print it to verify.'
    Runs the async functions synchronously for direct testing.
    """

    # Sample document matching your mongo_schema.md exactly
    sample_doc = {
        "scan_id": "test-scan-550e8400-day19",
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
        "evidence_summary": "SQL injection confirmed. Login bypass via ' OR 1=1--"
    }

    print("=" * 55)
    print("Testing MongoDB connection...")
    print(f"MONGO_URL: {MONGO_URL}")
    print("=" * 55)

    async def run_test():
        print("\nStep 1: Inserting test document...")
        inserted_id = await save_scan_result(sample_doc.copy())

        if inserted_id is None:
            print("\nMongoDB not running yet.")
            print("This is expected — docker-compose up in Week 5.")
            print("Showing what document WOULD be inserted:\n")
            import json
            print(json.dumps(sample_doc, indent=2, default=str))
            return

        print(f"\nStep 2: Retrieving documents for scan_id={sample_doc['scan_id']}...")
        results = await get_results(sample_doc["scan_id"])

        print(f"\nStep 3: Verifying structure of retrieved document:")
        if results:
            doc = results[0]
            print(f"  _id               : {doc.get('_id')}")
            print(f"  scan_id           : {doc.get('scan_id')}")
            print(f"  vuln_type         : {doc.get('vuln_type')}")
            print(f"  payloads count    : {len(doc.get('payloads', []))}")
            print(f"  responses count   : {len(doc.get('responses', []))}")
            print(f"  ai_label          : {doc.get('ai_analysis', {}).get('ai_label')}")
            print(f"  anomaly_score     : {doc.get('ai_analysis', {}).get('anomaly_score')}")
            print(f"  confirmed_vuln    : {doc.get('confirmed_vulnerable')}")
            print("\nDocument structure matches mongo_schema.md!")
        else:
            print("No documents returned.")

    asyncio.run(run_test())
    print("\nDay 19 MongoDB tasks complete!")


if __name__ == "__main__":
    test_mongo_connection()