"""
VULKN — ai_service/main.py
AI-powered anomaly detection service.
Day 10: built with hardcoded thresholds.
Day 18: upgraded to use real trained Isolation Forest model.
"""

import os
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone

app = FastAPI(
    title="VULKN AI Service",
    description="ML-powered anomaly detection for web application scanning",
    version="0.2.0"
)

# ── Load the trained model at startup ────────────────────────────────
# Model was trained on Day 13/14 using Isolation Forest
# contamination=0.10, trained on 36,000 normal HTTP requests
# Threshold = -0.6004

MODEL_PATH = os.getenv(
    "MODEL_PATH",
    "datasets/isolation_forest_final.joblib"
)

model = None

def load_model():
    global model
    try:
        model = joblib.load(MODEL_PATH)
        print(f"[ai_service] Model loaded from {MODEL_PATH}")
        print(f"[ai_service] contamination={model.contamination}")
        print(f"[ai_service] threshold={model.offset_:.4f}")
        return True
    except FileNotFoundError:
        print(f"[ai_service] WARNING: Model file not found at {MODEL_PATH}")
        print("[ai_service] Running in fallback mode (threshold-based)")
        return False
    except Exception as e:
        print(f"[ai_service] ERROR loading model: {e}")
        return False

# Load model when service starts
load_model()

FEATURES = ['request_length', 'method_encoded', 'num_parameters', 'body_length']

# ── Pydantic input/output models ─────────────────────────────────────
class ClassifyInput(BaseModel):
    request_length: int
    method_encoded: int   # GET=0, POST=1, PUT=2
    num_parameters: int
    body_length: int

class ClassifyResult(BaseModel):
    request_length: int
    method_encoded: int
    num_parameters: int
    body_length: int
    anomaly_score: float
    ai_label: str         # 'anomalous' or 'normal'
    confidence: float
    model_version: str

class SeverityInput(BaseModel):
    vuln_type: str        # SQLi, XSS, CSRF, PathTraversal, OpenPort
    anomaly_score: float
    confirmed_vulnerable: bool

# ── Helper: run model prediction ─────────────────────────────────────
def predict(features: dict) -> dict:
    """
    Runs Isolation Forest prediction.
    Falls back to threshold-based if model not loaded.
    """
    X = pd.DataFrame([features])[FEATURES]

    if model is not None:
        # Real trained model
        pred  = model.predict(X)[0]      # 1=normal, -1=anomalous
        score = model.score_samples(X)[0]
        label = "anomalous" if pred == -1 else "normal"
        # Confidence: how far score is from threshold
        distance = abs(score - model.offset_)
        confidence = min(round(distance * 5, 2), 1.0)
    else:
        # Fallback: hardcoded threshold from Day 10
        score = -0.55  # default estimate
        label = "anomalous" if features['body_length'] > 200 or \
                features['request_length'] > 150 else "normal"
        confidence = 0.5

    return {
        "anomaly_score": round(score, 4),
        "ai_label": label,
        "confidence": confidence
    }

# ── Endpoints ─────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "service": "VULKN AI Service",
        "status": "running",
        "version": "0.2.0",
        "model_loaded": model is not None,
        "model_threshold": round(model.offset_, 4) if model else None
    }

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ai_service",
        "model_loaded": model is not None,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.post("/classify", response_model=ClassifyResult)
def classify(data: ClassifyInput):
    """
    Main endpoint — takes 4 HTTP request features, returns anomaly score.
    Called by every scanner after finding a potential vulnerability.
    """
    features = {
        "request_length": data.request_length,
        "method_encoded": data.method_encoded,
        "num_parameters": data.num_parameters,
        "body_length": data.body_length
    }
    result = predict(features)

    return ClassifyResult(
        request_length=data.request_length,
        method_encoded=data.method_encoded,
        num_parameters=data.num_parameters,
        body_length=data.body_length,
        anomaly_score=result["anomaly_score"],
        ai_label=result["ai_label"],
        confidence=result["confidence"],
        model_version="IsolationForest-v1-c0.10"
    )

@app.post("/severity")
def get_severity(data: SeverityInput):
    """
    Returns CVSS-inspired severity score and label.
    Combines vuln_type with AI anomaly confirmation.
    """
    # Base CVSS scores per vuln type (Day 13 plan)
    cvss_base = {
        "SQLi":          9.8,
        "XSS_stored":    8.8,
        "XSS_reflected": 6.1,
        "XSS":           7.0,
        "OpenPort":      5.3,
        "PathTraversal": 7.5,
        "DirTraversal":  7.5,
        "CSRF":          6.5
    }

    base_score = cvss_base.get(data.vuln_type, 5.0)

    # Boost score if AI also flagged as anomalous
    if data.confirmed_vulnerable and data.anomaly_score < -0.60:
        final_score = min(base_score * 1.1, 10.0)
    elif data.confirmed_vulnerable:
        final_score = base_score
    else:
        final_score = base_score * 0.7

    if final_score >= 9.0:
        severity = "Critical"
    elif final_score >= 7.0:
        severity = "High"
    elif final_score >= 4.0:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "vuln_type": data.vuln_type,
        "base_cvss": base_score,
        "final_score": round(final_score, 1),
        "severity": severity,
        "ai_confirmed": data.anomaly_score < -0.60
    }

@app.get("/model-info")
def model_info():
    """Returns info about the loaded model."""
    if model is None:
        return {"error": "Model not loaded"}
    return {
        "algorithm": "IsolationForest",
        "contamination": model.contamination,
        "n_estimators": model.n_estimators,
        "threshold": round(model.offset_, 4),
        "features": FEATURES,
        "trained_on": "CSIC 2010 — 36,000 normal HTTP requests",
        "recall_at_c010": "30.8%",
        "precision_at_c010": "68.4%"
    }

@app.get("/threshold-info")
def threshold_info():
    """Legacy endpoint from Day 10 — kept for compatibility."""
    threshold = model.offset_ if model else -0.6004
    return {
        "threshold": round(threshold, 4),
        "contamination": model.contamination if model else 0.10,
        "interpretation": {
            "score_below_threshold": "anomalous",
            "score_above_threshold": "normal"
        }
    }