"""
evaluate_message_model.py — TRUSTLENS Message Model Evaluation
----------------------------------------------------------------
Loads the trained message_model.joblib and evaluates it on a held-out
portion of either the processed real datasets (preferred) or the
synthetic dataset as a fallback.

Reports:
  - Overall accuracy, precision, recall, F1, AUC-ROC
  - Per-class metrics
  - Confusion matrix
  - Evaluation by channel (email / sms)
  - Evaluation by language (english / kannada / code-mixed)

Run from the project root:
    python backend/ml/evaluate_message_model.py [path/to/dataset.csv]
"""

import os
import sys
import json
import logging

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
import joblib

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
MODEL_PATH = os.path.join(PROJECT_ROOT, "backend", "models", "message_model.joblib")
COMBINED_PROC = os.path.join(PROJECT_ROOT, "backend", "datasets", "processed", "combined_processed.csv")
SYNTHETIC_PATH = os.path.join(
    PROJECT_ROOT, "backend", "datasets", "synthetic", "trustlens_synthetic_dataset.csv"
)
REPORTS_DIR = os.path.join(PROJECT_ROOT, "backend", "datasets", "reports")


def load_model():
    if not os.path.exists(MODEL_PATH):
        logger.error(f"Model not found: {MODEL_PATH}")
        logger.error("Run backend/ml/train_message_model.py first.")
        sys.exit(1)
    logger.info(f"Loading model from {MODEL_PATH}")
    return joblib.load(MODEL_PATH)


def load_dataset(path: str | None = None) -> pd.DataFrame:
    """Load dataset, preferring combined processed; falling back to synthetic."""
    if path and os.path.exists(path):
        logger.info(f"Using specified dataset: {path}")
        return pd.read_csv(path, low_memory=False)
    if os.path.exists(COMBINED_PROC):
        logger.info(f"Using combined processed dataset: {COMBINED_PROC}")
        return pd.read_csv(COMBINED_PROC, low_memory=False)
    if os.path.exists(SYNTHETIC_PATH):
        logger.warning(
            "Real processed datasets not found. Evaluating on synthetic data only.\n"
            "Download real datasets (see DATASET_DOWNLOADS.md) for meaningful metrics."
        )
        return pd.read_csv(SYNTHETIC_PATH, low_memory=False)
    logger.error("No dataset available for evaluation.")
    sys.exit(1)


def evaluate(model, df: pd.DataFrame) -> dict:
    """
    Run evaluation and return a metrics dictionary.
    """
    if "message" not in df.columns or "normalized_label" not in df.columns:
        logger.error("Dataset must have 'message' and 'normalized_label' columns.")
        sys.exit(1)

    df = df.dropna(subset=["message", "normalized_label"])
    df = df[df["message"].str.len() > 5]

    # Stratified split — use 20 % as test set
    try:
        _, test_df = train_test_split(
            df, test_size=0.2, random_state=42, stratify=df["normalized_label"]
        )
    except ValueError:
        # Stratification fails if a class has too few samples
        _, test_df = train_test_split(df, test_size=0.2, random_state=42)

    logger.info(f"Test set size: {len(test_df)}")

    X_test = test_df["message"].tolist()
    y_test = test_df["normalized_label"].tolist()

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    classes = list(model.classes_)

    # ── Overall metrics ──────────────────────────────────────────────
    acc = accuracy_score(y_test, y_pred)
    logger.info(f"\nOverall Accuracy: {acc:.4f}")
    logger.info(f"\nClassification Report:\n{classification_report(y_test, y_pred, zero_division=0)}")

    cm = confusion_matrix(y_test, y_pred, labels=classes)
    logger.info(f"Confusion Matrix (labels={classes}):\n{cm}")

    # AUC-ROC (binary or multi-class one-vs-rest)
    try:
        if len(classes) == 2:
            phishing_idx = classes.index("phishing") if "phishing" in classes else 1
            auc = roc_auc_score(
                [1 if y == "phishing" else 0 for y in y_test],
                y_proba[:, phishing_idx],
            )
        else:
            auc = roc_auc_score(
                pd.get_dummies(y_test).values,
                y_proba,
                multi_class="ovr",
                average="weighted",
            )
        logger.info(f"AUC-ROC: {auc:.4f}")
    except Exception as exc:
        logger.warning(f"Could not compute AUC-ROC: {exc}")
        auc = None

    # ── Per-subset metrics ───────────────────────────────────────────
    subset_results = {}
    for col in ("channel", "language"):
        if col not in test_df.columns:
            continue
        for val in test_df[col].unique():
            mask = test_df[col] == val
            sub_X = test_df.loc[mask, "message"].tolist()
            sub_y = test_df.loc[mask, "normalized_label"].tolist()
            if len(sub_y) < 2:
                continue
            sub_pred = model.predict(sub_X)
            sub_acc = accuracy_score(sub_y, sub_pred)
            subset_results[f"{col}={val}"] = {
                "n": len(sub_y),
                "accuracy": round(sub_acc, 4),
            }
            logger.info(f"  Subset {col}={val}  n={len(sub_y)}  accuracy={sub_acc:.4f}")

    metrics = {
        "test_set_size": len(test_df),
        "accuracy": round(acc, 4),
        "auc_roc": round(auc, 4) if auc is not None else None,
        "classes": classes,
        "confusion_matrix": cm.tolist(),
        "subset_results": subset_results,
    }

    return metrics


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None

    model = load_model()
    df = load_dataset(path)
    metrics = evaluate(model, df)

    # Save report
    os.makedirs(REPORTS_DIR, exist_ok=True)
    report_path = os.path.join(REPORTS_DIR, "evaluation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"\nEvaluation report saved: {report_path}")


if __name__ == "__main__":
    main()

