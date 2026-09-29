"""
FastAPI Application Entry Point
-------------------------------
Phishing URL Detection System - Machine Learning Backend
Static URL Analysis Engine
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.api.endpoints import router as api_router
from app.ml.predictor import get_predictor

# Configure secure logging (no sensitive user data logged)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phishing_detection_api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Warm up ML model on startup to ensure instant zero-latency inference."""
    logger.info("Initializing static ML prediction engine...")
    try:
        predictor = get_predictor()
        logger.info(f"Loaded trained model: {predictor.model_metrics.get('selected_model', 'scikit-learn')}")
    except Exception as e:
        logger.error(f"Failed to load ML model artifact: {e}")
    yield
    logger.info("Shutting down Phishing URL Detection API...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Production-grade Machine Learning API for Static Phishing URL Detection. "
        "Strictly performs static lexical and structural analysis without executing or visiting target destinations."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Configuration
# Prevents arbitrary origin access in production; allows configured dashboard origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add defense-in-depth HTTP security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Static-Inspection-Only"] = "true"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception at {request.url.path}: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred during static URL analysis."}
    )


# Register API routes under /api
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["Root"])
def root_status():
    return {
        "service": settings.PROJECT_NAME,
        "status": "online",
        "analysis_type": "static_url_only",
        "docs_url": "/docs",
    }
