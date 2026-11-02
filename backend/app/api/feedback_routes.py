"""
Feedback API Routes
--------------------
POST /api/feedback         — Submit analysis feedback
GET  /api/feedback/summary — Get feedback summary (admin)
"""

import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from sqlalchemy import text
from app.core.database import get_db, Base, engine
from app.models.db_models import FeedbackRecord
from app.schemas.message_schema import (
    FeedbackRequest,
    FeedbackResponse,
    FeedbackSummaryResponse,
)

logger = logging.getLogger("trustlens.feedback_routes")

# Ensure table exists
Base.metadata.create_all(bind=engine)


def _ensure_feedback_columns():
    """Add columns introduced after the table was first created (SQLite)."""
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("PRAGMA table_info(feedback_records)")).fetchall()
            names = {row[1] for row in rows}
            statements = []
            if "language" not in names:
                statements.append("ALTER TABLE feedback_records ADD COLUMN language VARCHAR(16)")
            if "message_text" not in names:
                statements.append("ALTER TABLE feedback_records ADD COLUMN message_text TEXT")
            if "used_for_retraining" not in names:
                statements.append(
                    "ALTER TABLE feedback_records ADD COLUMN used_for_retraining INTEGER DEFAULT 0"
                )
            for stmt in statements:
                conn.execute(text(stmt))
            if statements:
                conn.commit()
    except Exception as e:
        logger.warning(f"Feedback schema check skipped: {e}")


_ensure_feedback_columns()

router = APIRouter()


@router.post("/feedback", response_model=FeedbackResponse, tags=["Feedback"])
def submit_feedback(request: FeedbackRequest, db: Session = Depends(get_db)):
    """
    Submit user feedback on an analysis result.
    When the user challenges a false positive (marks a result as legitimate/benign)
    and includes the original message, the sample is added to the training pool
    and the message model is retrained immediately.
    """
    try:
        message_text = (request.message_text or "").strip() or None
        record = FeedbackRecord(
            analysis_id=request.analysis_id,
            channel=request.channel,
            language=request.language,
            original_risk_level=request.get_prediction(),
            original_prediction=request.get_prediction(),
            user_feedback=request.user_feedback,
            feedback_reason=request.feedback_reason[:1000] if request.feedback_reason else None,
            message_text=message_text,
            used_for_retraining=0,
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        retrained = False
        retrain_status = None
        if message_text:
            from app.modules.message_analysis.retrainer import append_feedback_sample, retrain_model

            appended = append_feedback_sample(
                message=message_text,
                corrected_label=request.user_feedback,
                channel=request.channel or "unknown",
                language=request.language or "english",
            )
            if appended:
                retrain_status = retrain_model()
                retrained = retrain_status.get("status") == "success"
                if retrained:
                    record.used_for_retraining = 1
                    db.commit()

        message = "Feedback recorded. Thank you for helping improve TRUSTLENS."
        if retrained:
            message = (
                "Feedback recorded and the message model was retrained. "
                "Analyze the same message again to see the updated result."
            )
        elif message_text:
            message = (
                "Feedback recorded. Retraining could not complete; "
                "the correction is stored and will be applied on re-analysis."
            )

        return FeedbackResponse(
            feedback_id=record.id,
            analysis_id=record.analysis_id,
            original_prediction=record.original_prediction,
            user_feedback=record.user_feedback,
            created_at=record.created_at.isoformat(),
            retrained=retrained,
            message=message,
        )
    except Exception as e:
        db.rollback()
        logger.error(f"Feedback submission error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record feedback. Please try again.",
        )


@router.get("/feedback/summary", response_model=FeedbackSummaryResponse, tags=["Feedback"])
def get_feedback_summary(limit: int = 50, db: Session = Depends(get_db)):
    """
    Retrieve a summary of recent feedback submissions.
    Intended for internal review and model curation, not public display.
    """
    try:
        records = (
            db.query(FeedbackRecord)
            .order_by(FeedbackRecord.id.desc())
            .limit(min(limit, 200))
            .all()
        )

        legitimate_count = sum(1 for r in records if r.user_feedback == "legitimate")
        suspicious_count = sum(1 for r in records if r.user_feedback in ("suspicious", "still_suspicious"))

        items = [
            {
                "feedback_id": r.id,
                "analysis_id": r.analysis_id,
                "original_prediction": r.original_prediction,
                "user_feedback": r.user_feedback,
                "feedback_reason": r.feedback_reason,
                "created_at": r.created_at.isoformat(),
            }
            for r in records
        ]

        return FeedbackSummaryResponse(
            total_feedback=len(records),
            legitimate_count=legitimate_count,
            suspicious_count=suspicious_count,
            feedback_items=items,
        )
    except Exception as e:
        logger.error(f"Feedback summary error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load feedback summary.",
        )

