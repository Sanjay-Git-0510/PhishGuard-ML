"""
Feedback-Driven Model Retrainer
---------------------------------
Collects user feedback with message text, merges it with the existing
training data, and retrains the message classification model.

When a user reports a false positive (says a message is 'legitimate' when
the model predicted 'suspicious', or vice versa), the corrected sample is
appended to the feedback training pool.  After each feedback submission
that includes message text, the model is retrained on the combined dataset
(original synthetic data + all accumulated feedback corrections).

The retrained model is saved to the same path as the original, so the
predictor singleton picks it up on reload.
"""

import os
import csv
import logging
import threading
import unicodedata
from typing import Optional

import pandas as pd
import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

logger = logging.getLogger("trustlens.retrainer")

_BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
MODEL_PATH = os.path.join(_BASE_DIR, "models", "message_model.joblib")
METADATA_PATH = os.path.join(_BASE_DIR, "models", "message_model_metadata.json")
SYNTHETIC_CSV = os.path.join(_BASE_DIR, "datasets", "synthetic", "trustlens_synthetic_dataset.csv")
FEEDBACK_CSV = os.path.join(_BASE_DIR, "datasets", "feedback", "feedback_training_data.csv")

# Lock to prevent concurrent retraining
_retrain_lock = threading.Lock()


def _ensure_feedback_dir():
    """Create the feedback dataset directory if it does not exist."""
    feedback_dir = os.path.dirname(FEEDBACK_CSV)
    os.makedirs(feedback_dir, exist_ok=True)


def append_feedback_sample(
    message: str,
    corrected_label: str,
    channel: str = "unknown",
    language: str = "english",
) -> bool:
    """
    Append a single feedback-corrected sample to the feedback CSV.

    Args:
        message: The original message text.
        corrected_label: The user's corrected label — 'benign' or 'suspicious'.
        channel: 'email' or 'sms'.
        language: 'english', 'kannada', 'hindi', or 'code-mixed'.

    Returns:
        True if the sample was appended successfully.
    """
    _ensure_feedback_dir()

    # Normalize label
    if corrected_label in ("legitimate", "benign"):
        normalized = "benign"
    elif corrected_label in ("suspicious", "still_suspicious", "phishing"):
        normalized = "suspicious"
    else:
        logger.warning(f"Unknown feedback label '{corrected_label}', skipping.")
        return False

    # Append to CSV
    file_exists = os.path.exists(FEEDBACK_CSV)
    try:
        with open(FEEDBACK_CSV, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["message", "normalized_label", "channel", "language", "source"])
            writer.writerow([message, normalized, channel, language, "user_feedback"])
        logger.info(f"Feedback sample appended: label={normalized}, lang={language}")
        return True
    except Exception as e:
        logger.error(f"Failed to append feedback sample: {e}")
        return False


def _normalize_match_key(text: str) -> str:
    """Unicode-normalize and collapse whitespace for reliable message matching."""
    normalized = unicodedata.normalize("NFC", str(text or ""))
    return " ".join(normalized.split())


def lookup_user_correction(message: str) -> Optional[str]:
    """
    Return the latest user-corrected label for a message match.
    Used so a challenged false positive is respected on re-analysis.
    """
    if not message or not os.path.exists(FEEDBACK_CSV):
        return None
    try:
        df = pd.read_csv(FEEDBACK_CSV, encoding="utf-8")
        if "message" not in df.columns or "normalized_label" not in df.columns:
            return None
        needle = _normalize_match_key(message)
        if not needle:
            return None
        labels = []
        for _, row in df.iterrows():
            candidate = _normalize_match_key(row["message"])
            if candidate == needle:
                labels.append(str(row["normalized_label"]).lower())
        if not labels:
            return None
        last = labels[-1]
        if last in ("benign", "legitimate"):
            return "benign"
        if last in ("suspicious", "still_suspicious", "phishing"):
            return "suspicious"
        return None
    except Exception as e:
        logger.warning(f"Feedback lookup failed: {e}")
        return None


def get_feedback_count() -> int:
    """Return the number of accumulated feedback samples."""
    if not os.path.exists(FEEDBACK_CSV):
        return 0
    try:
        df = pd.read_csv(FEEDBACK_CSV)
        return len(df)
    except Exception:
        return 0


def retrain_model() -> dict:
    """
    Retrain the message classification model using:
      1. The original synthetic training data
      2. All accumulated user feedback corrections

    Returns a dict with training results (accuracy, sample counts, etc.).

    Thread-safe: only one retraining runs at a time.
    """
    if not _retrain_lock.acquire(blocking=False):
        logger.warning("Retraining already in progress, skipping.")
        return {"status": "skipped", "reason": "retraining_in_progress"}

    try:
        return _do_retrain()
    finally:
        _retrain_lock.release()


def _do_retrain() -> dict:
    """Internal retraining logic."""
    logger.info("Starting feedback-driven model retraining...")

    frames = []

    # Load original synthetic data
    if os.path.exists(SYNTHETIC_CSV):
        syn_df = pd.read_csv(SYNTHETIC_CSV)
        if "message" in syn_df.columns and "normalized_label" in syn_df.columns:
            frames.append(syn_df[["message", "normalized_label"]].copy())
            logger.info(f"  Synthetic data: {len(syn_df)} samples")

    # Load processed real datasets if available
    processed_dir = os.path.join(_BASE_DIR, "datasets", "processed")
    combined_path = os.path.join(processed_dir, "combined_processed.csv")
    if os.path.exists(combined_path):
        real_df = pd.read_csv(combined_path)
        if "message" in real_df.columns and "normalized_label" in real_df.columns:
            # Map real dataset labels: phishing → suspicious, legitimate → benign
            label_map = {"phishing": "suspicious", "legitimate": "benign"}
            real_df["normalized_label"] = real_df["normalized_label"].map(
                lambda x: label_map.get(x, x)
            )
            frames.append(real_df[["message", "normalized_label"]].copy())
            logger.info(f"  Real processed data: {len(real_df)} samples")

    # Load feedback corrections
    feedback_count = 0
    if os.path.exists(FEEDBACK_CSV):
        fb_df = pd.read_csv(FEEDBACK_CSV)
        if "message" in fb_df.columns and "normalized_label" in fb_df.columns:
            frames.append(fb_df[["message", "normalized_label"]].copy())
            feedback_count = len(fb_df)
            logger.info(f"  Feedback corrections: {feedback_count} samples")

    if not frames:
        logger.error("No training data available.")
        return {"status": "error", "reason": "no_training_data"}

    # Combine all data. Keep feedback last so drop_duplicates retains the user correction.
    df = pd.concat(frames, ignore_index=True)
    df = df.dropna(subset=["message", "normalized_label"])
    df["message"] = df["message"].astype(str)
    df = df[df["message"].str.strip().str.len() > 5]
    df["normalized_label"] = df["normalized_label"].map(
        lambda x: "benign" if str(x).lower() in ("benign", "legitimate", "0") else (
            "suspicious" if str(x).lower() in ("suspicious", "phishing", "spam", "1", "still_suspicious") else str(x).lower()
        )
    )
    df = df[df["normalized_label"].isin(["benign", "suspicious"])]
    df = df.drop_duplicates(subset="message", keep="last").reset_index(drop=True)

    # Repeat user corrections so they actually move the decision boundary.
    if feedback_count > 0 and os.path.exists(FEEDBACK_CSV):
        fb_weight = pd.read_csv(FEEDBACK_CSV, encoding="utf-8")
        if "message" in fb_weight.columns and "normalized_label" in fb_weight.columns:
            fb_weight = fb_weight[["message", "normalized_label"]].copy()
            fb_weight["normalized_label"] = fb_weight["normalized_label"].map(
                lambda x: "benign" if str(x).lower() in ("benign", "legitimate") else "suspicious"
            )
            weighted = pd.concat([fb_weight] * 8, ignore_index=True)
            df = pd.concat([df, weighted], ignore_index=True)

    logger.info(f"  Combined training set: {len(df)} samples")
    logger.info(f"  Label distribution:\n{df['normalized_label'].value_counts().to_string()}")

    if len(df) < 10:
        logger.error("Insufficient training data (< 10 samples).")
        return {"status": "error", "reason": "insufficient_data", "sample_count": len(df)}

    # Split using the same 0/1 encoding as train_message_model.py
    X = df["message"].tolist()
    y = (df["normalized_label"] == "suspicious").astype(int).tolist()

    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, random_state=42, stratify=y
        )
    except ValueError:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.15, random_state=42
        )

    # Train the same pipeline type as the original
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(2, 5),
            max_features=50000,
            min_df=1,
            sublinear_tf=True,
            strip_accents=None,
        )),
        ("clf", SGDClassifier(
            loss="modified_huber",
            max_iter=1000,
            random_state=42,
            class_weight="balanced",
        )),
    ])

    pipeline.fit(X_train, y_train)

    # Evaluate
    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    logger.info(f"  Retrained model accuracy: {accuracy:.4f}")

    # Save the model
    joblib.dump(pipeline, MODEL_PATH)
    logger.info(f"  Model saved to {MODEL_PATH}")

    # Save metadata
    import json
    from datetime import datetime, timezone

    metadata = {
        "selected_model": "Linear SVM (char TF-IDF) — feedback-retrained",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(df),
        "feedback_samples": feedback_count,
        "test_accuracy": round(accuracy, 4),
        "retrained": True,
    }
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # Reload the predictor singleton with the new model
    try:
        from app.modules.message_analysis.predictor import MessagePredictor
        predictor = MessagePredictor.reload_instance()
        logger.info(f"  Predictor reloaded: model_available={predictor.model_available}")
    except Exception as e:
        logger.warning(f"  Could not reload predictor singleton: {e}")

    return {
        "status": "success",
        "total_samples": len(df),
        "feedback_samples": feedback_count,
        "accuracy": round(accuracy, 4),
        "retrained": True,
    }

