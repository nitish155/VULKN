from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from routers.scan import router as scan_router

app = FastAPI(
    title="VULKN",
    description="AI-Powered Web Application Security Scanner",
    version="0.1.0"
)
app.include_router(scan_router)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  
    allow_methods=["*"],
    allow_headers=["*"],
)
    
@app.get("/health")
def health():
    return {
        "status": "online",
        "service": "VULKN API",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }