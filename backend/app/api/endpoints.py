"""
FastAPI Route Handlers and Endpoints
-----------------------------------
- GET  /api/health
- POST /api/predict
- GET  /api/model-info
- POST /api/batch-predict
- GET  /api/history
"""

import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db, Base, engine
from app.core.config import settings
from app.models.db_models import ScanRecord
from app.schemas.schemas import (
    UrlAnalysisRequest,
    UrlAnalysisResponse,
    BatchAnalysisRequest,
    BatchAnalysisResponse,
    HealthResponse,
    ModelInfoResponse,
    ScanHistoryItem,
)
from app.ml.predictor import get_predictor, PhishingPredictor

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["System Health"])
def health_check(db: Session = Depends(get_db)):
    """System health check and ML model readiness inspection."""
    predictor = get_predictor()
    model_loaded = predictor.model is not None
    selected_model = predictor.model_metrics.get("selected_model", "Unknown")

    # Verify DB connectivity
    db_status = "connected"
    try:
        db.execute(ScanRecord.__table__.select().limit(1))
    except Exception as e:
        db_status = f"degraded: {str(e)}"

    return HealthResponse(
        status="healthy" if model_loaded else "unhealthy",
        model_loaded=model_loaded,
        selected_model=selected_model,
        features_count=len(predictor.feature_names),
        database_status=db_status,
        environment=settings.ENVIRONMENT,
    )


@router.post("/predict", response_model=UrlAnalysisResponse, tags=["Threat Analysis"])
def analyze_url(request: UrlAnalysisRequest, db: Session = Depends(get_db)):
    """
    Perform static lexical and structural phishing analysis on a submitted URL.
    Does NOT visit, execute, or send requests to the target destination.
    """
    predictor = get_predictor()
    try:
        result = predictor.predict(request.url)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error during feature extraction or model prediction: {str(e)}"
        )

    # Persist scan event in database
    try:
        record = ScanRecord(
            url=result["url"],
            prediction=result["prediction"],
            probability=result["probability"],
            risk_level=result["risk_level"],
            features_json=json.dumps(result["features"]),
            reasons_json=json.dumps(result["reasons"]),
        )
        db.add(record)
        db.commit()
    except Exception:
        db.rollback()  # Silently maintain response even if audit logging fails

    return UrlAnalysisResponse(**result)


@router.post("/batch-predict", response_model=BatchAnalysisResponse, tags=["Threat Analysis"])
def analyze_batch(request: BatchAnalysisRequest, db: Session = Depends(get_db)):
    """Analyze up to 50 URLs in a single batch."""
    predictor = get_predictor()
    results = []

    for raw_url in request.urls:
        url = raw_url.strip()
        if not url:
            continue
        try:
            res = predictor.predict(url)
            results.append(UrlAnalysisResponse(**res))
            # Persist
            record = ScanRecord(
                url=res["url"],
                prediction=res["prediction"],
                probability=res["probability"],
                risk_level=res["risk_level"],
                features_json=json.dumps(res["features"]),
                reasons_json=json.dumps(res["reasons"]),
            )
            db.add(record)
        except Exception:
            continue

    try:
        db.commit()
    except Exception:
        db.rollback()

    return BatchAnalysisResponse(total=len(results), results=results)


@router.get("/model-info", response_model=ModelInfoResponse, tags=["Model Diagnostics"])
def get_model_diagnostics():
    """Return trained scikit-learn model metadata, confusion matrix, and feature importances."""
    predictor = get_predictor()
    metrics = predictor.model_metrics
    if not metrics:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model metrics metadata not found. Train the model to generate diagnostics."
        )

    return ModelInfoResponse(
        selected_model=metrics.get("selected_model", "Unknown"),
        trained_at=metrics.get("trained_at", ""),
        dataset_samples=metrics.get("dataset_samples", 0),
        train_samples=metrics.get("train_samples", 0),
        test_samples=metrics.get("test_samples", 0),
        best_metrics=metrics.get("best_metrics", {}),
        all_models_benchmark=metrics.get("all_models_benchmark", []),
        feature_importance=metrics.get("feature_importance", {}),
    )


@router.get("/history", response_model=List[ScanHistoryItem], tags=["Telemetry Feed"])
def get_scan_history(limit: int = 25, db: Session = Depends(get_db)):
    """Retrieve recent static analysis logs for the SOC telemetry feed."""
    records = db.query(ScanRecord).order_by(ScanRecord.id.desc()).limit(min(limit, 100)).all()
    history = []
    for r in records:
        reasons = []
        try:
            reasons = json.loads(r.reasons_json)
        except Exception:
            reasons = []

        history.append(ScanHistoryItem(
            id=r.id,
            url=r.url,
            prediction=r.prediction,
            probability=r.probability,
            risk_level=r.risk_level,
            reasons=reasons,
            scanned_at=r.scanned_at.isoformat(),
        ))
    return history
