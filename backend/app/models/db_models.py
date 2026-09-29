"""
Database ORM Models for Static URL Scan History
-----------------------------------------------
Stores static analysis records in PostgreSQL (or SQLite local fallback).
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
