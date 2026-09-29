"""
Inference Engine and Model Predictor
------------------------------------
Loads the pre-trained scikit-learn model serialized via joblib.
Performs genuine supervised ML prediction and feature-driven transparent explanations.
Never retrains model during server execution.
"""

import os
import json
import joblib
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from app.core.config import settings
from app.ml.feature_extractor import (
    FEATURE_NAMES,
    extract_features,
    extract_feature_vector,
    get_observed_indicators,
)


class PhishingPredictor:
    _instance: Optional["PhishingPredictor"] = None

    def __init__(self):
        self.model = None
        self.feature_names = FEATURE_NAMES
        self.model_metrics = {}
        self.load_artifacts()

    @classmethod
    def get_instance(cls) -> "PhishingPredictor":
        if cls._instance is None:
            cls._instance = PhishingPredictor()
        return cls._instance

    def load_artifacts(self):
        """Load joblib model and JSON metadata from disk."""
        if not os.path.exists(settings.MODEL_PATH):
            raise FileNotFoundError(
                f"Model file not found at {settings.MODEL_PATH}. "
                "Please run 'python backend/ml/train.py' before starting the server."
            )

        self.model = joblib.load(settings.MODEL_PATH)

        if os.path.exists(settings.FEATURE_NAMES_PATH):
            with open(settings.FEATURE_NAMES_PATH, "r") as f:
                self.feature_names = json.load(f)

        if os.path.exists(settings.METRICS_PATH):
            with open(settings.METRICS_PATH, "r") as f:
                self.model_metrics = json.load(f)

    def predict(self, url: str) -> Dict[str, Any]:
        """
        Execute static ML prediction pipeline:
        1. Extract static features
        2. Format feature vector
        3. Model predict_proba
        4. Derive risk level and observed security indicators
        """
        if self.model is None:
            self.load_artifacts()

        # 1. Feature extraction
        features = extract_features(url)
        vector = [features[name] for name in self.feature_names]

        # 2. scikit-learn model inference
        pred_label = int(self.model.predict([vector])[0])

        # Genuine prediction probability for phishing (class 1)
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba([vector])[0]
            phishing_prob = float(probs[1])
        else:
            # Fallback for models without predict_proba
            phishing_prob = 1.0 if pred_label == 1 else 0.0

        phishing_prob = round(phishing_prob, 4)

        # 3. Risk Level Determination (baseline from ML model)
        if phishing_prob >= 0.70 or pred_label == 1:
            risk_level = "high"
            prediction = "phishing"
        elif phishing_prob >= 0.35:
            risk_level = "medium"
            prediction = "phishing" if pred_label == 1 else "legitimate"
        else:
            risk_level = "low"
            prediction = "legitimate"

        # 3b. SAFETY OVERRIDE: Rule-based override for clear typosquat attacks.
        # Even if the ML model is uncertain (e.g., training data gap), a domain
        # with confirmed digit-for-letter substitution (paypa1.com, g00gle.com)
        # or a brand doppelganger (1-2 char edit distance from known brand) is
        # definitively a phishing vector and must be caught. Defense in depth.
        digit_sub = features.get("has_digit_substitution", 0)
        doppelganger = features.get("brand_doppelganger", 0)
        if digit_sub == 1 or doppelganger == 1:
            prediction = "phishing"
            risk_level = "high"
            # Boost probability to reflect certainty of this detection
            phishing_prob = max(phishing_prob, 0.92)

        # 4. Observed URL indicators (static explainability)
        indicators = get_observed_indicators(features, url)

        # Add ML-based contextual note if indicators were scarce but probability was elevated
        if pred_label == 1 and not indicators:
            indicators.append("Lexical pattern matches known malicious structural fingerprints.")

        return {
            "url": url,
            "prediction": prediction,
            "probability": phishing_prob,
            "risk_level": risk_level,
            "features": features,
            "reasons": indicators,
            "static_analysis_notice": "Static URL analysis only — the submitted website is not visited by this application.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Global predictor accessor
def get_predictor() -> PhishingPredictor:
    return PhishingPredictor.get_instance()
