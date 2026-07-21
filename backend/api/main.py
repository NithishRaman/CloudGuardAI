from fastapi import FastAPI
from backend.services.scan_service import run_full_scan


app = FastAPI(
    title="CloudGuardAI API",
    version="2.0.0",
    description="AI-powered AWS Cloud Security Monitoring Platform"
)


@app.get("/")
def root():

    return {
        "project": "CloudGuardAI",
        "version": "2.0.0",
        "status": "running"
    }


@app.get("/health")
def health():

    return {
        "status": "healthy"
    }


@app.post("/scan")
def scan():

    result = run_full_scan()

    return result
