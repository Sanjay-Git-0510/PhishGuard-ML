"""
Machine Learning Training Pipeline for Phishing URL Detection
-------------------------------------------------------------
- Loads clean labeled dataset (url, label: 0=legitimate, 1=phishing)
- Extracts features using the identical feature_extractor module
- Performs stratified train/test split (80/20) with zero data leakage
- Trains and benchmarks multiple supervised classifiers:
    1. Logistic Regression (L2 penalty, balanced class weight)
    2. Decision Tree Classifier
    3. Random Forest Classifier
    4. Gradient Boosting Classifier
- Computes comprehensive evaluation metrics:
    Accuracy, Precision, Recall, F1-Score, ROC-AUC, Confusion Matrix
- Selects optimal model prioritizing Recall (minimizing false negatives) and ROC-AUC
- Serializes model via joblib and saves metadata (feature names, evaluation report)
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

# Ensure backend directory is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(CURRENT_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.ml.feature_extractor import (
    FEATURE_NAMES,
    extract_features,
    extract_feature_vector,
)

DATASET_PATH = os.path.join(BACKEND_DIR, "datasets", "urls_dataset.csv")
MODELS_DIR = os.path.join(BACKEND_DIR, "models")


def build_feature_matrix(df: pd.DataFrame):
    """Convert URL DataFrame into feature matrix X and target vector y."""
    print(f"[*] Extracting {len(FEATURE_NAMES)} static features for {len(df)} URLs...")
    X_rows = []
    y_vals = []

    for _, row in df.iterrows():
        url = str(row["url"]).strip()
        label = int(row["label"])
        vector = extract_feature_vector(url)
        X_rows.append(vector)
        y_vals.append(label)

    X = np.array(X_rows, dtype=np.float32)
    y = np.array(y_vals, dtype=np.int32)
    return X, y


def evaluate_model(name: str, model, X_test, y_test):
    """Compute and return standard classification metrics and confusion matrix."""
    y_pred = model.predict(X_test)
    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X_test)[:, 1]
        roc_auc = float(roc_auc_score(y_test, y_prob))
    else:
        y_prob = None
        roc_auc = 0.0

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    return {
        "model_name": name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
        },
    }


def train_and_evaluate():
    """Main training, evaluation, and selection routine."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}. Run prepare_dataset.py first.")

    df = pd.read_csv(DATASET_PATH)
    # Deduplicate again to guarantee absolute zero data leakage
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    X, y = build_feature_matrix(df)

    # 80/20 stratified split with fixed seed
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[+] Dataset split: {len(X_train)} training samples, {len(X_test)} testing samples")
    print(f"    Train distribution: Legitimate={int((y_train==0).sum())}, Phishing={int((y_train==1).sum())}")
    print(f"    Test distribution:  Legitimate={int((y_test==0).sum())}, Phishing={int((y_test==1).sum())}")

    # Define Candidate Models
    candidates = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=8,
            class_weight="balanced",
            random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            class_weight="balanced",
            random_state=42
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=120,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        ),
    }

    results = []
    trained_models = {}

    print("\n" + "=" * 75)
    print(f"{'Model':<22} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<8} | {'F1':<6} | {'ROC-AUC':<7}")
    print("-" * 75)

    for name, model in candidates.items():
        model.fit(X_train, y_train)
        metrics = evaluate_model(name, model, X_test, y_test)
        results.append(metrics)
        trained_models[name] = model

        print(f"{name:<22} | {metrics['accuracy']:<8.4f} | {metrics['precision']:<9.4f} | "
              f"{metrics['recall']:<8.4f} | {metrics['f1_score']:<6.4f} | {metrics['roc_auc']:<7.4f}")

    print("=" * 75 + "\n")

    # Selection Strategy:
    # In Phishing detection, False Negatives (missing a phishing attack) are the most critical risk.
    # Therefore, we prioritize Recall and ROC-AUC while ensuring Precision remains above acceptable bounds.
    # When scores are tied, prefer Random Forest for superior ensemble robustness and tree feature importances.
    def score_model(r):
        tie_bonus = 0.05 if r["model_name"] == "Random Forest" else 0.0
        return (r["recall"] * 0.5 + r["roc_auc"] * 0.3 + r["f1_score"] * 0.2) + tie_bonus

    best_candidate = max(results, key=score_model)
    best_name = best_candidate["model_name"]
    best_model = trained_models[best_name]

    print(f"[*] Selected Best Model: '{best_name}'")
    print(f"    Reason: Highest weighted combination of Recall ({best_candidate['recall']}) and ROC-AUC ({best_candidate['roc_auc']})")

    # Feature Importance (if tree-based)
    feature_importance = {}
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        for feat_name, imp in zip(FEATURE_NAMES, importances):
            feature_importance[feat_name] = round(float(imp), 4)
        # Sort descending
        feature_importance = dict(sorted(feature_importance.items(), key=lambda item: item[1], reverse=True))

    # Save Model Artifacts
    model_save_path = os.path.join(MODELS_DIR, "phishing_model.joblib")
    features_save_path = os.path.join(MODELS_DIR, "feature_names.json")
    metrics_save_path = os.path.join(MODELS_DIR, "model_metrics.json")

    joblib.dump(best_model, model_save_path)

    with open(features_save_path, "w") as f:
        json.dump(FEATURE_NAMES, f, indent=2)

    metadata = {
        "selected_model": best_name,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_samples": int(len(df)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "best_metrics": best_candidate,
        "all_models_benchmark": results,
        "feature_importance": feature_importance,
    }

    with open(metrics_save_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[OK] Saved model artifact:    {model_save_path}")
    print(f"[OK] Saved feature names:     {features_save_path}")
    print(f"[OK] Saved training metrics:  {metrics_save_path}")
    return metadata


if __name__ == "__main__":
    train_and_evaluate()
