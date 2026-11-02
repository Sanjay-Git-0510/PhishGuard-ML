"""
Database ORM Models
-------------------
Stores URL scan records and message analysis feedback.
Supports PostgreSQL (or SQLite local fallback).
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Text, DateTime
from app.core.database import Base


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), nullable=False, index=True)
    prediction = Column(String(32), nullable=False) # 'legitimate' or 'phishing'
    probability = Column(Float, nullable=False)
    risk_level = Column(String(32), nullable=False) # 'low', 'medium', 'high'
    features_json = Column(Text, nullable=False)    # JSON string of extracted features
    reasons_json = Column(Text, nullable=False)     # JSON string of observed indicators
    scanned_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class FeedbackRecord(Base):
    """
    Stores user feedback on analysis results for model improvement.
    When the user consents, the message text is stored for retraining.
    """
    __tablename__ = "feedback_records"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(64), nullable=False, index=True)
    channel = Column(String(16), nullable=True)          # 'email' or 'sms'
    language = Column(String(16), nullable=True)          # 'english', 'kannada', 'hindi', 'code-mixed'
    original_risk_level = Column(String(32), nullable=False)
    original_prediction = Column(String(32), nullable=False)
    user_feedback = Column(String(32), nullable=False)   # 'legitimate' or 'suspicious'/'still_suspicious'
    feedback_reason = Column(Text, nullable=True)        # optional reason (max 1000 chars)
    message_text = Column(Text, nullable=True)           # original message for retraining (user consent)
    used_for_retraining = Column(Integer, default=0)     # 0=pending, 1=used
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
