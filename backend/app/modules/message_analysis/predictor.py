"""
Message ML Predictor
---------------------
Loads the trained message classification model (message_model.joblib)
and provides prediction for email/SMS messages.

Falls back gracefully if the model has not been trained yet.
"""

import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Model path
_BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
MESSAGE_MODEL_PATH = os.path.join(_BASE_DIR, "models", "message_model.joblib")
MESSAGE_MODEL_METADATA_PATH = os.path.join(_BASE_DIR, "models", "message_model_metadata.json")


class MessagePredictor:
    _instance: Optional["MessagePredictor"] = None

    def __init__(self):
        self.model = None
        self.metadata = {}
        self._model_available = False
        self._load()

    @classmethod
    def get_instance(cls) -> "MessagePredictor":
        if cls._instance is None:
            cls._instance = MessagePredictor()
        return cls._instance

    @classmethod
    def reload_instance(cls) -> "MessagePredictor":
        """Reload the model from disk after retraining."""
        if cls._instance is None:
            cls._instance = MessagePredictor()
        else:
            cls._instance._load()
        return cls._instance

    def _load(self):
        """Load the message model. Fails gracefully if not yet trained."""
        if not os.path.exists(MESSAGE_MODEL_PATH):
            logger.warning(
                f"Message model not found at {MESSAGE_MODEL_PATH}. "
                "Run backend/ml/train_message_model.py to generate it. "
                "Message ML classification will use rule-based fallback until the model is trained."
            )
            self._model_available = False
            return

        try:
            import joblib
            self.model = joblib.load(MESSAGE_MODEL_PATH)
            self._model_available = True
            logger.info("Message classification model loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load message model: {e}")
            self._model_available = False

        if os.path.exists(MESSAGE_MODEL_METADATA_PATH):
            try:
                import json
                with open(MESSAGE_MODEL_METADATA_PATH, "r") as f:
                    self.metadata = json.load(f)
            except Exception:
                self.metadata = {}

    @property
    def model_available(self) -> bool:
        return self._model_available

    def predict(self, text: str, channel: str = "email", language: str = "english") -> Dict[str, Any]:
        """
        Predict whether a message is suspicious.

        Returns:
            {
                "label": "suspicious" | "benign",
                "confidence": float (0.0–1.0),
                "method": "ml_model" | "rule_based_fallback",
                "model_available": bool,
                "note": str
            }
        """
        if not self._model_available or self.model is None:
            return self._fallback_predict(text)

        try:
            # The model pipeline expects a list of texts
            prob_array = self.model.predict_proba([text])[0]
            classes = [str(c).lower() for c in getattr(self.model, "classes_", [0, 1])]
            suspicious_idx = None
            for candidate in ("suspicious", "1", "phishing"):
                if candidate in classes:
                    suspicious_idx = classes.index(candidate)
                    break
            if suspicious_idx is None:
                # Binary 0/1 encoding from the original trainer: class 1 = suspicious
                suspicious_idx = 1 if len(prob_array) > 1 else 0
            suspicious_prob = float(prob_array[suspicious_idx])
            label = "suspicious" if suspicious_prob >= 0.5 else "benign"

            return {
                "label": label,
                "confidence": round(suspicious_prob if label == "suspicious" else (1.0 - suspicious_prob), 4),
                "suspicious_probability": round(suspicious_prob, 4),
                "method": "ml_model",
                "model_available": True,
                "note": (
                    "ML classification score. This is a statistical estimate, "
                    "not proof of malicious intent."
                ),
                "model_info": {
                    "algorithm": self.metadata.get("selected_model", "unknown"),
                    "trained_at": self.metadata.get("trained_at", "unknown"),
                }
            }
        except Exception as e:
            logger.error(f"Message model prediction error: {e}")
            return self._fallback_predict(text)

    def _fallback_predict(self, text: str) -> Dict[str, Any]:
        """
        Rule-based fallback when the ML model is not available.
        Uses simple English and Hindi heuristics — NOT a substitute for genuine ML classification.
        """
        import re
        text_lower = text.lower() if text else ""
        original = text or ""

        # Simple heuristic signal count (English + Hindi)
        signals = 0
        if re.search(r"\botp\b|\bone[- ]time\s+password\b|ओटीपी", text_lower):
            signals += 3
        if re.search(r"\b(?:password|pin|upi\s*pin)\b.{0,30}(?:share|enter|provide|send)", text_lower):
            signals += 3
        if re.search(r"पासवर्ड.{0,20}(?:दर्ज|भेजें|बताएं)|पिन.{0,20}(?:दर्ज|भेजें|बताएं)", original):
            signals += 3
        if re.search(r"\b(?:account|wallet)\s+(?:blocked|suspended|frozen)\b", text_lower):
            signals += 2
        if re.search(r"खाता\s*(?:बंद|ब्लॉक|निलंबित|निष्क्रिय)", original):
            signals += 2
        if re.search(r"\bclick\s+(?:here|link|below)\b", text_lower):
            signals += 1
        if re.search(r"लिंक\s*(?:पर\s*)?(?:क्लिक|टैप)", original):
            signals += 1
        if re.search(r"\burgent(?:ly)?\b|\bimmediately\b|\bact\s+now\b", text_lower):
            signals += 1
        if re.search(r"तुरंत|तत्काल|अभी\s*कार्रवाई", original):
            signals += 1
        if re.search(r"\b(?:won|winning|winner|prize|lottery|reward)\b", text_lower):
            signals += 2
        if re.search(r"इनाम|लॉटरी|पुरस्कार", original):
            signals += 2

        if signals >= 4:
            label = "suspicious"
            conf = 0.65
        elif signals >= 2:
            label = "suspicious"
            conf = 0.45
        else:
            label = "benign"
            conf = 0.60

        return {
            "label": label,
            "confidence": conf,
            "suspicious_probability": conf if label == "suspicious" else (1.0 - conf),
            "method": "rule_based_fallback",
            "model_available": False,
            "note": (
                "Message ML model is not yet trained. This result uses basic rule-based heuristics "
                "and should not be treated as an ML classification. "
                "Run backend/ml/train_message_model.py to enable genuine ML classification."
            ),
        }


def get_message_predictor() -> MessagePredictor:
    return MessagePredictor.get_instance()

