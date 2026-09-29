"""
Integration tests for FastAPI endpoints
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["analysis_type"] == "static_url_only"


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert data["features_count"] == 24


def test_predict_benign_url():
    response = client.post("/api/predict", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "legitimate"
    assert "probability" in data
    assert data["risk_level"] in ("low", "medium", "high")
    assert "features" in data
    assert "reasons" in data


def test_predict_phishing_url():
    response = client.post(
        "/api/predict",
        json={"url": "http://192.168.1.100/paypal/login.php?update_account=true"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "phishing"
    assert data["probability"] >= 0.5
    assert data["risk_level"] == "high"
    assert len(data["reasons"]) > 0


def test_predict_malformed_url():
    # Empty string should fail validation
    response = client.post("/api/predict", json={"url": ""})
    assert response.status_code == 422


def test_model_info_endpoint():
    response = client.get("/api/model-info")
    assert response.status_code == 200
    data = response.json()
    assert "selected_model" in data
    assert "best_metrics" in data
    assert "feature_importance" in data
    assert "confusion_matrix" in data["best_metrics"]


def test_batch_predict():
    payload = {
        "urls": [
            "https://wikipedia.org",
            "http://account-apple-update.top/auth/index.html"
        ]
    }
    response = client.post("/api/batch-predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["results"]) == 2
