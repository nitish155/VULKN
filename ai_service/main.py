"""
VULKN — ai_service/main.py
AI-powered anomaly detection service.

Day 10: built with hardcoded thresholds.
Day 18: upgraded to use real trained Isolation Forest model.
Day 23: added LR model + /classify-response + /score endpoints.
Day 23 FIX: /classify-response now uses rule-based pattern matching
            instead of LR model (LR trained on payloads, not responses).

Current endpoints:
  GET  /                  — service status (both models)
  GET  /health            — health check
  GET  /model-info        — info on all models
  GET  /threshold-info    — legacy IF threshold info
  POST /classify          — Isolation Forest: 4 request features → anomaly score
  POST /classify-response — Rule-based: response body + status code → attack label
  POST /severity          — CVSS severity from vuln_type + anomaly score
  POST /score             — Day 24 rules: confidence + vuln_type → severity
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime, timezone

app = FastAPI(
    title="VULKN AI Service",
    description="ML-powered anomaly detection for web application scanning",
    version="0.3.0"
)

# ─────────────────────────────────────────────────────────────────────
# ISOLATION FOREST MODEL (Day 18)
# ─────────────────────────────────────────────────────────────────────
MODEL_PATH = os.getenv("MODEL_PATH", "datasets/isolation_forest_final.joblib")
model = None

def load_model():
    global model
    try:
        model = joblib.load(MODEL_PATH)
        print(f"[ai_service] IF model loaded from {MODEL_PATH}")
        print(f"[ai_service] contamination={model.contamination}")
        print(f"[ai_service] threshold={model.offset_:.4f}")
        return True
    except FileNotFoundError:
        print(f"[ai_service] WARNING: IF model not found at {MODEL_PATH}")
        return False
    except Exception as e:
        print(f"[ai_service] ERROR loading IF model: {e}")
        return False

load_model()

# ─────────────────────────────────────────────────────────────────────
# LOGISTIC REGRESSION MODEL (Day 22/23)
# NOTE: Used for payload text only — NOT for response body classification
# ─────────────────────────────────────────────────────────────────────

# --- OLD (V1) Logistic Regression model paths [Deprecated] ---
# Used in earlier version (Day 22–23)
# Keeping for reference / rollback if needed
# LR_MODEL_PATH  = os.getenv("LR_MODEL_PATH",  "datasets/logistic_regression_payload.joblib")
# LR_CONFIG_PATH = os.getenv("LR_CONFIG_PATH", "datasets/lr_classifier_config.json")

# --- ACTIVE CONFIG (V2 - Current)(Day 26) ---
# Improved Logistic Regression model with enhanced features (Day 26)
# Used for payload classification with better accuracy and performance
LR_MODEL_PATH  = os.getenv("LR_MODEL_PATH",  "datasets/logistic_regression_v2.joblib")
LR_CONFIG_PATH = os.getenv("LR_CONFIG_PATH", "datasets/lr_v2_config.json")

lr_model  = None
lr_config = {}

def load_lr_model():
    global lr_model, lr_config
    try:
        lr_model = joblib.load(LR_MODEL_PATH)
        with open(LR_CONFIG_PATH, 'r') as f:
            lr_config = json.load(f)
        print(f"[ai_service] LR model loaded: accuracy={lr_config.get('accuracy')}%")
        return True
    except FileNotFoundError:
        print(f"[ai_service] WARNING: LR model not found at {LR_MODEL_PATH}")
        return False
    except Exception as e:
        print(f"[ai_service] ERROR loading LR model: {e}")
        return False

load_lr_model()

# Feature list for Isolation Forest — do not change this name
IF_FEATURES = ['request_length', 'method_encoded', 'num_parameters', 'body_length']

# ─────────────────────────────────────────────────────────────────────
# RULE-BASED RESPONSE PATTERN LISTS (Day 23 FIX)
#
# WHY rules and NOT the LR model for response body?
# The LR model was trained on ATTACK PAYLOAD text (e.g. ' OR 1=1--)
# The /classify-response endpoint receives SERVER RESPONSE text
# (e.g. "mysql_fetch_array() error"). These are completely different.
# SQL error messages in responses are not in the LR training data,
# so the model returns near-zero probability for them. That is not
# a model failure — it is using the wrong tool for the job.
# Pattern matching is the correct and reliable approach here.
# ─────────────────────────────────────────────────────────────────────

SQL_ERROR_PATTERNS = [
    'sql syntax', 'syntax error near', 'mysql_fetch', 'mysql_num_rows',
    'mysql_query', 'pg_query', 'ora-', 'microsoft ole db',
    'odbc drivers', 'sql server', 'unclosed quotation mark',
    'invalid column name', 'division by zero', 'supplied argument is not',
    'table or view does not exist', 'psycopg2', 'sqlite3.operationalerror',
    'you have an error in your sql', 'warning: mysql',
    'mysqli_fetch', 'pdo exception', 'sqlstate',
    'error in your sql syntax', 'mysql_real_escape',
    'sql error', 'database error',
]

XSS_REFLECTION_PATTERNS = [
    'onerror=', 'onmouseover=', 'onload=', 'onclick=', 'onfocus=',
    'onblur=', 'onpointer', 'autofocus', 'alert(', 'alert (',
    'javascript:', '<script', '</script>', '<img src=x',
    'expression(', 'document.cookie', 'window.location',
    '<svg', 'ondeactivate', 'ondragenter', '<tt onmouseover',
]

AUTH_BYPASS_PATTERNS = [
    'welcome admin', 'logged in as admin', 'admin panel',
    'you are logged in', 'login successful', 'access granted',
    'authentication successful',
]

INFO_LEAK_PATTERNS = [
    'root:x:0:0', 'uid=0', '/etc/passwd', '/etc/shadow',
    'aws_access_key', 'api_key=', 'secret_key',
    'stack trace', 'traceback (most recent', 'exception in thread',
]


def classify_response_rules(body: str, status_code: int) -> dict:
    """
    Rule-based classifier for HTTP response bodies.
    Checks for SQL error strings, XSS reflection, auth bypass,
    and information leakage. Returns confidence + signals.
    """
    bl     = body.lower()
    score  = 0.0
    signals     = []
    attack_type = "unknown"

    sql_matches  = [p for p in SQL_ERROR_PATTERNS  if p in bl]
    xss_matches  = [p for p in XSS_REFLECTION_PATTERNS if p in bl]
    auth_matches = [p for p in AUTH_BYPASS_PATTERNS if p in bl]
    info_matches = [p for p in INFO_LEAK_PATTERNS   if p in bl]

    if sql_matches:
        score      += 0.6
        attack_type = "SQLi"
        signals.append(f"SQL error patterns: {sql_matches[:3]}")

    if xss_matches:
        score      += 0.5
        attack_type = "XSS"
        signals.append(f"XSS patterns reflected: {xss_matches[:3]}")

    if auth_matches:
        score      += 0.4
        attack_type = "SQLi"
        signals.append(f"Auth bypass indicators: {auth_matches[:2]}")

    if info_matches:
        score += 0.5
        signals.append(f"Information leak: {info_matches[:2]}")

    # Status code adjustments
    if status_code == 500 and sql_matches:
        score += 0.3
        signals.append("HTTP 500 + SQL error = strong SQLi evidence")
    elif status_code == 500:
        score += 0.1
        signals.append("HTTP 500 = server error (possible attack)")
    elif status_code == 200 and (sql_matches or xss_matches or auth_matches):
        signals.append("HTTP 200 + attack pattern = potential injection success")
    elif status_code in [401, 403] and not auth_matches:
        score -= 0.2
        signals.append("HTTP 401/403 = server rejected (less likely vulnerable)")

    final_confidence = min(max(score, 0.0), 1.0)
    # 0.3 threshold: security context — better to flag than miss
    final_label = "attack" if final_confidence > 0.3 else "benign"

    return {
        "confidence": round(final_confidence, 3),
        "label":      final_label,
        "signals":    signals,
        "attack_type": attack_type if final_label == "attack" else "none"
    }


# ─────────────────────────────────────────────────────────────────────
# PYDANTIC MODELS
# ─────────────────────────────────────────────────────────────────────

class ClassifyInput(BaseModel):
    request_length: int
    method_encoded: int
    num_parameters: int
    body_length:    int

class ClassifyResult(BaseModel):
    request_length: int
    method_encoded: int
    num_parameters: int
    body_length:    int
    anomaly_score:  float
    ai_label:       str
    confidence:     float
    model_version:  str

class SeverityInput(BaseModel):
    vuln_type:            str
    anomaly_score:        float
    confirmed_vulnerable: bool

class ResponseClassifyInput(BaseModel):
    response_body: str
    status_code:   int
    scan_id:       str = ""
    vuln_type:     str = ""

class ScoreInput(BaseModel):
    vuln_type:            str
    confidence:           float
    confirmed_vulnerable: bool
    error_keywords_found: bool = False


# ─────────────────────────────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────────────────────────────

def predict_if(features: dict) -> dict:
    X = pd.DataFrame([features])[IF_FEATURES]
    if model is not None:
        pred       = model.predict(X)[0]
        score      = model.score_samples(X)[0]
        label      = "anomalous" if pred == -1 else "normal"
        distance   = abs(score - model.offset_)
        confidence = min(round(distance * 5, 2), 1.0)
    else:
        score      = -0.55
        label      = "anomalous" if features['body_length'] > 200 or \
                     features['request_length'] > 150 else "normal"
        confidence = 0.5
    return {"anomaly_score": round(score, 4), "ai_label": label, "confidence": confidence}


# ─────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service": "VULKN AI Service", "status": "running", "version": "0.3.0",
        "models": {
            "isolation_forest":    model is not None,
            "logistic_regression": lr_model is not None,
            "response_classifier": "rule-based (always active)"
        }
    }


@app.get("/health")
def health():
    return {
        "status": "ok", "service": "ai_service",
        "if_loaded": model is not None, "lr_loaded": lr_model is not None,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/classify", response_model=ClassifyResult)
def classify(data: ClassifyInput):
    """
    Isolation Forest endpoint.
    Input:  { request_length, method_encoded, num_parameters, body_length }
    Output: { anomaly_score, ai_label, confidence }
    """
    features = {
        "request_length": data.request_length, "method_encoded": data.method_encoded,
        "num_parameters": data.num_parameters,  "body_length": data.body_length
    }
    result = predict_if(features)
    return ClassifyResult(
        request_length=data.request_length, method_encoded=data.method_encoded,
        num_parameters=data.num_parameters,  body_length=data.body_length,
        anomaly_score=result["anomaly_score"], ai_label=result["ai_label"],
        confidence=result["confidence"], model_version="IsolationForest-v1-c0.10"
    )


@app.post("/classify-response")
def classify_response_body(data: ResponseClassifyInput):
    """
    Rule-based response body classifier. (Day 23)
    Input:  { response_body, status_code }
    Output: { label, confidence, details }

    Uses SQL error pattern matching, XSS reflection detection,
    auth bypass detection, and status code analysis.
    NOT the LR model — see WHY in module comments above.
    """
    result = classify_response_rules(data.response_body, data.status_code)
    return {
        "label":      result["label"],
        "confidence": result["confidence"],
        "details": {
            "attack_type": result["attack_type"],
            "signals":     result["signals"],
            "status_code": data.status_code,
            "body_length": len(data.response_body),
            "classifier":  "rule-based-pattern-matching"
        }
    }


@app.post("/severity")
def get_severity(data: SeverityInput):
    """CVSS-inspired severity from vuln_type + anomaly score."""
    cvss_base = {
        "SQLi": 9.8, "XSS_stored": 8.8, "XSS_reflected": 6.1, "XSS": 7.0,
        "OpenPort": 5.3, "PathTraversal": 7.5, "DirTraversal": 7.5, "CSRF": 6.5
    }
    base_score  = cvss_base.get(data.vuln_type, 5.0)
    final_score = min(base_score * 1.1, 10.0) if data.confirmed_vulnerable and \
                  data.anomaly_score < -0.60 else \
                  base_score if data.confirmed_vulnerable else base_score * 0.7
    severity    = "Critical" if final_score >= 9.0 else "High" if final_score >= 7.0 \
                  else "Medium" if final_score >= 4.0 else "Low"
    return {
        "vuln_type": data.vuln_type, "base_cvss": base_score,
        "final_score": round(final_score, 1), "severity": severity,
        "ai_confirmed": data.anomaly_score < -0.60
    }


@app.post("/score")
def score_finding(data: ScoreInput):
    """
    Day 24 severity rules.
    Rule 1: SQLi + confidence > 0.9 = Critical
    Rule 2: XSS  + confidence > 0.8 = High
    Rule 3: error keywords found    = Medium
    Rule 4: confirmed               = standard CVSS
    Rule 5: not confirmed           = Low
    """
    cvss_base  = {
        "SQLi": 9.8, "XSS_stored": 8.8, "XSS_reflected": 6.1, "XSS": 7.0,
        "OpenPort": 5.3, "PathTraversal": 7.5, "DirTraversal": 7.5, "CSRF": 6.5
    }
    base_score = cvss_base.get(data.vuln_type, 5.0)
    confidence = data.confidence
    vuln       = data.vuln_type
    reasoning  = []

    if vuln == "SQLi" and confidence > 0.9 and data.confirmed_vulnerable:
        final_score = 9.8;  severity = "Critical"
        reasoning.append(f"Rule 1: SQLi + conf={confidence:.2f} > 0.9 → Critical (9.8)")
    elif vuln in ("XSS", "XSS_stored", "XSS_reflected") and \
         confidence > 0.8 and data.confirmed_vulnerable:
        final_score = 8.0;  severity = "High"
        reasoning.append(f"Rule 2: XSS + conf={confidence:.2f} > 0.8 → High (8.0)")
    elif data.error_keywords_found:
        final_score = 5.5;  severity = "Medium"
        reasoning.append("Rule 3: Error keywords = info disclosure → Medium (5.5)")
    elif data.confirmed_vulnerable:
        final_score = base_score
        severity    = "Critical" if final_score >= 9.0 else "High" if final_score >= 7.0 \
                      else "Medium" if final_score >= 4.0 else "Low"
        reasoning.append(f"Rule 4: Confirmed, CVSS={base_score} → {severity}")
    else:
        final_score = base_score * 0.5;  severity = "Low"
        reasoning.append(f"Rule 5: Not confirmed → Low ({final_score:.1f})")

    return {
        "vuln_type": vuln, "severity": severity,
        "cvss_score": round(final_score, 1), "confidence": round(confidence, 3),
        "reasoning": reasoning, "model_used": "severity-rules-v1"
    }


@app.get("/model-info")
def model_info():
    """Returns info about all models and classifiers."""
    return {
        "isolation_forest": {
            "loaded": model is not None, "algorithm": "IsolationForest",
            "contamination": model.contamination if model else None,
            "threshold": round(model.offset_, 4) if model else None,
            "n_estimators": model.n_estimators if model else None,
            "trained_on": "CSIC 2010 — 36,000 normal HTTP requests",
            "endpoint": "POST /classify",
            "input": "request_length, method_encoded, num_parameters, body_length",
            "recall": "30.8%", "precision": "68.4%"
        },
        "logistic_regression": {
            "loaded": lr_model is not None, "algorithm": "LogisticRegression",
            "accuracy": lr_config.get("accuracy"), "trained_on": lr_config.get("trained_on"),
            "note": "Payload classification only — not used for response body",
            "features": lr_config.get("features")
        },
        "response_classifier": {
            "loaded": True, "algorithm": "Rule-based pattern matching",
            "endpoint": "POST /classify-response", "input": "response_body, status_code",
            "pattern_counts": {
                "sql_errors": len(SQL_ERROR_PATTERNS),
                "xss_patterns": len(XSS_REFLECTION_PATTERNS),
                "auth_bypass": len(AUTH_BYPASS_PATTERNS),
                "info_leak": len(INFO_LEAK_PATTERNS)
            },
            "why_not_lr": "LR trained on attack payloads — not server response text"
        }
    }


@app.get("/threshold-info")
def threshold_info():
    """Legacy endpoint from Day 10."""
    threshold = model.offset_ if model else -0.6004
    return {
        "threshold": round(threshold, 4),
        "contamination": model.contamination if model else 0.10,
        "interpretation": {
            "score_below_threshold": "anomalous",
            "score_above_threshold": "normal"
        }
    }
