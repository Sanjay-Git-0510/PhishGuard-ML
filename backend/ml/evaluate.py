"""
Model Evaluation and Diagnostics Module
---------------------------------------
Loads the trained model and computes detailed metrics, classification reports,
and confusion matrix diagnostics against test or external validation sets.
"""

import os
import sys
import json
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(CURRENT_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.ml.feature_extractor import extract_feature_vector

MODEL_PATH = os.path.join(BACKEND_DIR, "models", "phishing_model.joblib")
METRICS_PATH = os.path.join(BACKEND_DIR, "models", "model_metrics.json")


def load_model_and_metrics():
    """Load the persisted model artifact and metrics metadata."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Run train.py first.")
    model = joblib.load(MODEL_PATH)
    metrics = {}
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, "r") as f:
            metrics = json.load(f)
    return model, metrics


def evaluate_sample_batch(urls, true_labels=None):
    """Predict for a batch of URLs and display diagnostic summary."""
    model, _ = load_model_and_metrics()
    vectors = [extract_feature_vector(u) for u in urls]
    preds = model.predict(vectors)
    probs = model.predict_proba(vectors)[:, 1] if hasattr(model, "predict_proba") else [None] * len(urls)

    results = []
    for u, p, pr in zip(urls, preds, probs):
        results.append({
            "url": u,
            "prediction": "phishing" if p == 1 else "legitimate",
            "probability": round(float(pr), 4) if pr is not None else None,
        })
    return results


if __name__ == "__main__":
    _, meta = load_model_and_metrics()
    print(json.dumps(meta, indent=2))
