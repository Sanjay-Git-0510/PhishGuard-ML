"""
TRUSTLENS — FastAPI Application Entry Point
---------------------------------------------
Phishing, Impersonation and Social Engineering Detection System
Extends the original Phishing URL Detection backend.

Analysis type: Static only — no outbound requests, no URL visits.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.api.endpoints import router as url_router
from app.api.message_routes import router as message_router
from app.api.feedback_routes import router as feedback_router
from app.ml.predictor import get_predictor
from app.modules.message_analysis.predictor import get_message_predictor

# Configure secure logging — no sensitive user data logged
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("trustlens_api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Warm up ML models on startup for zero-latency inference."""
    logger.info("Initializing TRUSTLENS static analysis engine...")

    # Load existing URL model
    try:
        url_predictor = get_predictor()
        logger.info(f"URL model loaded: {url_predictor.model_metrics.get('selected_model', 'scikit-learn')}")
    except Exception as e:
        logger.error(f"Failed to load URL model: {e}")

    # Load message model (graceful if not yet trained)
    try:
        msg_predictor = get_message_predictor()
        if msg_predictor.model_available:
            logger.info("Message classification model loaded successfully.")
        else:
            logger.warning(
                "Message model not found. ML classification will use rule-based fallback. "
                "Run backend/ml/train_message_model.py to enable genuine ML classification."
            )
    except Exception as e:
        logger.error(f"Message model initialization error: {e}")

    logger.info("TRUSTLENS is ready.")
    yield
    logger.info("Shutting down TRUSTLENS API...")


app = FastAPI(
    title="TRUSTLENS",
    description=(
        "Phishing, Impersonation and Social Engineering Detection System. "
        "Performs static security analysis. Does not open submitted links, "
        "send messages, or perform actions on behalf of users."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# CORS Configuration
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
    logger.error(f"Unhandled exception at {request.url.path}: {type(exc).__name__}")
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred during analysis."}
    )


# Register all API routes under /api
app.include_router(url_router, prefix=settings.API_V1_STR)
app.include_router(message_router, prefix=settings.API_V1_STR)
app.include_router(feedback_router, prefix=settings.API_V1_STR)


@app.get("/", tags=["Root"])
def root_status():
    return {
        "service": "TRUSTLENS",
        "version": "2.0.0",
        "status": "online",
        "description": "Phishing, Impersonation and Social Engineering Detection System",
        "analysis_type": "static_only",
        "privacy_notice": (
            "TRUSTLENS performs static security analysis. "
            "It does not open submitted links, send messages or perform actions on your behalf."
        ),
        "docs_url": "/docs",
    }
