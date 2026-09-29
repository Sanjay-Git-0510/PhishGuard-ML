"""
Configuration settings for the Phishing Detection Backend.
Loads environment variables safely with robust defaults.
"""

import os
from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Phishing URL Detection System"
    API_V1_STR: str = "/api"
    ENVIRONMENT: str = "development"

    # CORS origins: explicitly configurable via env, no wildcard in production
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
    ]

    # Database connection URL (PostgreSQL by default, falls back to SQLite for local ease)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./scans.db"
    )

    # Artifact paths
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    MODEL_PATH: str = os.path.join(BASE_DIR, "models", "phishing_model.joblib")
    FEATURE_NAMES_PATH: str = os.path.join(BASE_DIR, "models", "feature_names.json")
    METRICS_PATH: str = os.path.join(BASE_DIR, "models", "model_metrics.json")

    model_config = {
        "case_sensitive": True,
        "env_file": ".env",
        "extra": "ignore",
    }


settings = Settings()
