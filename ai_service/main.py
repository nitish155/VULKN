from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np

app = FastAPI(
    title="VULKN AI Service",
    description="ML-powered anomaly detection for web application scanning",
    version="0.1.0"
)

class ScoreInput(BaseModel):
    score: float

class ClassifyResult(BaseModel):
    input_score: float
    prediction: str
    confidence: str
    message: str

@app.get("/")
def root():
    return {"service": "VULKN AI Service", "status": "running", "version": "0.1.0"}

@app.get("/health")
def health():
    return {"status": "ok", "service": "ai_service"}

@app.get("/classify")
def classify_by_query(score: float):
    if score < -0.1:
        prediction = "anomalous"
        confidence = "high" if score < -0.3 else "medium"
    else:
        prediction = "normal"
        confidence = "high" if score > 0.05 else "medium"

    return {
        "input_score": score,
        "prediction": prediction,
        "confidence": confidence,
        "message": f"Score {score:.4f} classified as {prediction} with {confidence} confidence"
    }

@app.post("/classify")
def classify_by_body(data: ScoreInput):
    score = data.score

    if score < -0.1:
        prediction = "anomalous"
        confidence = "high" if score < -0.3 else "medium"
    else:
        prediction = "normal"
        confidence = "high" if score > 0.05 else "medium"

    return ClassifyResult(
        input_score=score,
        prediction=prediction,
        confidence=confidence,
        message=f"Score {score:.4f} is {prediction}"
    )

@app.get("/threshold-info")
def threshold_info():
    return {
        "thresholds": {
            "anomalous_high":   "score < -0.30",
            "anomalous_medium": "-0.30 <= score < -0.10",
            "normal_medium":    "-0.10 <= score < 0.05",
            "normal_high":      "score >= 0.05"
        },
        "note": "Thresholds will be replaced with trained Isolation Forest model in Week 4"
    }