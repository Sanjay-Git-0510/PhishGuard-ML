"""
Pydantic Schemas for Request Validation and Response Serialization
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from urllib.parse import urlparse


class UrlAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="Target URL for static phishing inspection")

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("URL cannot be empty or whitespace.")

        # Ensure scheme is supported
        if not (clean.startswith("http://") or clean.startswith("https://")):
            # Auto-prepend http:// if missing scheme for parsing
            clean = "http://" + clean

        parsed = urlparse(clean)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Only http:// and https:// URL protocols are supported.")

        if not parsed.netloc and not parsed.path:
            raise ValueError("Malformed URL: Missing valid domain or host authority.")

        return clean


class BatchAnalysisRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=50, description="List of up to 50 URLs to inspect")


class UrlAnalysisResponse(BaseModel):
    url: str
    prediction: str # "legitimate" or "phishing"
    probability: float
    risk_level: str # "low", "medium", "high"
    features: Dict[str, float]
    reasons: List[str]
    static_analysis_notice: str = "Static URL analysis only — the submitted website is not visited by this application."
    timestamp: str


class BatchAnalysisResponse(BaseModel):
    total: int
    results: List[UrlAnalysisResponse]


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    selected_model: str
    features_count: int
    database_status: str
    environment: str
    version: str = "1.0.0"


class ModelInfoResponse(BaseModel):
    selected_model: str
    trained_at: str
    dataset_samples: int
    train_samples: int
    test_samples: int
    best_metrics: Dict[str, Any]
    all_models_benchmark: List[Dict[str, Any]]
    feature_importance: Dict[str, float]
    static_analysis_assurance: str = "Static URL analysis only — no outbound requests, DNS execution, or target visits."


class ScanHistoryItem(BaseModel):
    id: int
    url: str
    prediction: str
    probability: float
    risk_level: str
    reasons: List[str]
    scanned_at: str
