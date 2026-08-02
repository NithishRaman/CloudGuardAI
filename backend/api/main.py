from fastapi import FastAPI
from backend.services.scan_service import run_full_scan


app = FastAPI(
    title="CloudGuardAI API",
    version="2.0.0",
    description="AI-powered AWS Cloud Security Monitoring Platform",
)


@app.get("/")
def root():
    return {
        "project": "CloudGuardAI",
        "version": "2.0.0",
        "status": "running",
    }


@app.get("/api")
def api_root():
    return {
        "project": "CloudGuardAI",
        "version": "2.0.0",
        "status": "running",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }


@app.get("/api/health")
def api_health():
    return {
        "status": "healthy",
    }


@app.post("/scan")
def scan():
    return run_full_scan()


@app.post("/api/scan")
def api_scan():
    return run_full_scan()
