from fastapi import FastAPI
from backend.services.scan_service import run_full_scan


# ============================================================
# CLOUDGUARDAI API
# ============================================================

app = FastAPI(
    title="CloudGuardAI API",
    version="2.0.0",
    description="AI-powered AWS Cloud Security Monitoring Platform",
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "project": "CloudGuardAI",
        "version": "2.0.0",
        "status": "running",
        "message": "CloudGuardAI API is online",
    }


# ============================================================
# API ROOT
# ============================================================

@app.get("/api")
def api_root():
    return {
        "project": "CloudGuardAI",
        "version": "2.0.0",
        "status": "running",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

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


# ============================================================
# SECURITY SCAN
# ============================================================

@app.post("/scan")
def scan():
    result = run_full_scan()
    return result


@app.post("/api/scan")
def api_scan():
    result = run_full_scan()
    return result
