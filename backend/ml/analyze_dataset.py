"""
analyze_dataset.py — TRUSTLENS Dataset Analysis & Reporting
-------------------------------------------------------------
Produces a comprehensive HTML and JSON report for any TRUSTLENS dataset CSV.

Analysed metrics:
  - Shape, column types, memory usage
  - Label distribution with balance ratio
  - Per-channel, per-language, per-source distributions
  - Message length statistics (min / max / mean / median / p5 / p95)
  - Character-set analysis (Latin, Kannada, Devanagari, mixed)
  - Vocabulary size and average token count
  - Exact-duplicate count
  - Near-duplicate estimate (Jaccard similarity sampling)
  - Top n-grams per label class

Run from the project root:
    python backend/ml/analyze_dataset.py [path/to/dataset.csv]

If no path is given, the synthetic dataset is analysed by default.
Reports are written to backend/datasets/reports/.
"""

import os
import sys
import json
import logging
import unicodedata
from collections import Counter
from datetime import datetime, timezone

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
SYNTHETIC_PATH = os.path.join(
    PROJECT_ROOT, "backend", "datasets", "synthetic", "trustlens_synthetic_dataset.csv"
)
REPORTS_DIR = os.path.join(PROJECT_ROOT, "backend", "datasets", "reports")


# ── Helpers ──────────────────────────────────────────────────────────

def detect_script(text: str) -> str:
    """Detect dominant script in a text string."""
    if not isinstance(text, str) or len(text) == 0:
        return "empty"
    has_kannada = any("\u0c80" <= ch <= "\u0cff" for ch in text)
    has_latin = any(ch.isascii() and ch.isalpha() for ch in text)
    has_devanagari = any("\u0900" <= ch <= "\u097f" for ch in text)
    scripts = []
    if has_kannada:
        scripts.append("kannada")
    if has_devanagari:
        scripts.append("devanagari")
    if has_latin:
        scripts.append("latin")
    if len(scripts) > 1:
        return "mixed(" + "+".join(scripts) + ")"
    if len(scripts) == 1:
        return scripts[0]
    return "other"


def jaccard(a: str, b: str) -> float:
    """Jaccard similarity between word sets."""
    sa = set(a.lower().split())
    sb = set(b.lower().split())
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)


def top_ngrams(texts, n=2, top_k=15):
    """Extract top-k character n-grams from a list of texts."""
    counter = Counter()
    for text in texts:
        if not isinstance(text, str):
            continue
        text_lower = text.lower()
        for i in range(len(text_lower) - n + 1):
            gram = text_lower[i:i + n]
            if gram.strip():
                counter[gram] += 1
    return counter.most_common(top_k)


# ── Main Analysis ────────────────────────────────────────────────────

def analyze(path: str) -> dict:
    """Run full analysis on a dataset CSV and return a report dict."""
    logger.info(f"Analysing: {path}")

    df = pd.read_csv(path, low_memory=False)
    report = {
        "dataset_path": path,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # ── Basic shape ──────────────────────────────────────────────────
    report["shape"] = {"rows": int(df.shape[0]), "columns": int(df.shape[1])}
    report["columns"] = list(df.columns)
    report["dtypes"] = {col: str(dtype) for col, dtype in df.dtypes.items()}
    report["memory_usage_kb"] = round(df.memory_usage(deep=True).sum() / 1024, 1)
    report["null_counts"] = {col: int(v) for col, v in df.isnull().sum().items() if v > 0}

    logger.info(f"Shape: {df.shape[0]} rows × {df.shape[1]} columns")

    # ── Label distribution ───────────────────────────────────────────
    if "normalized_label" in df.columns:
        label_counts = df["normalized_label"].value_counts().to_dict()
        report["label_distribution"] = {str(k): int(v) for k, v in label_counts.items()}
        vals = list(label_counts.values())
        report["class_balance_ratio"] = round(min(vals) / max(vals), 4) if max(vals) > 0 else 0
    else:
        report["label_distribution"] = "column 'normalized_label' not found"
        report["class_balance_ratio"] = None

    # ── Channel & language distributions ─────────────────────────────
    for col in ("channel", "language", "source"):
        if col in df.columns:
            report[f"{col}_distribution"] = {
                str(k): int(v) for k, v in df[col].value_counts().items()
            }

    # ── Message length statistics ────────────────────────────────────
    if "message" in df.columns:
        lengths = df["message"].fillna("").str.len()
        report["message_length"] = {
            "min": int(lengths.min()),
            "max": int(lengths.max()),
            "mean": round(float(lengths.mean()), 1),
            "median": round(float(lengths.median()), 1),
            "p5": int(np.percentile(lengths, 5)),
            "p95": int(np.percentile(lengths, 95)),
            "std": round(float(lengths.std()), 1),
        }

        # Token counts
        token_counts = df["message"].fillna("").str.split().str.len()
        report["token_count"] = {
            "min": int(token_counts.min()),
            "max": int(token_counts.max()),
            "mean": round(float(token_counts.mean()), 1),
            "median": round(float(token_counts.median()), 1),
        }

        # Vocabulary
        all_tokens = []
        for text in df["message"].fillna(""):
            all_tokens.extend(text.lower().split())
        report["vocabulary_size"] = len(set(all_tokens))
        report["total_tokens"] = len(all_tokens)

        # Script detection
        scripts = df["message"].fillna("").apply(detect_script)
        report["script_distribution"] = {
            str(k): int(v) for k, v in scripts.value_counts().items()
        }

        # Very short messages
        report["messages_under_10_chars"] = int((lengths < 10).sum())
        report["messages_under_20_chars"] = int((lengths < 20).sum())

        # Exact duplicates
        dup_count = df.duplicated(subset="message").sum()
        report["exact_duplicates"] = int(dup_count)

        # Near-duplicate sampling
        messages = df["message"].fillna("").tolist()
        sample_size = min(300, len(messages))
        sample = messages[:sample_size]
        near_dup_pairs = 0
        for i in range(len(sample)):
            for j in range(i + 1, len(sample)):
                if jaccard(sample[i], sample[j]) >= 0.85:
                    near_dup_pairs += 1
        report["near_duplicate_pairs_in_sample"] = near_dup_pairs
        report["near_duplicate_sample_size"] = sample_size

        # Top bigrams per label
        if "normalized_label" in df.columns:
            report["top_bigrams_per_label"] = {}
            for label in df["normalized_label"].dropna().unique():
                label_texts = df.loc[df["normalized_label"] == label, "message"].fillna("").tolist()
                grams = top_ngrams(label_texts, n=2, top_k=15)
                report["top_bigrams_per_label"][str(label)] = [
                    {"ngram": g, "count": c} for g, c in grams
                ]
    else:
        report["message_length"] = "column 'message' not found"

    # ── Cross-tabulations ────────────────────────────────────────────
    for row_col, col_col in [("channel", "normalized_label"), ("language", "normalized_label")]:
        if row_col in df.columns and col_col in df.columns:
            ct = pd.crosstab(df[row_col], df[col_col])
            report[f"crosstab_{row_col}_x_{col_col}"] = {
                str(idx): {str(c): int(v) for c, v in row.items()}
                for idx, row in ct.iterrows()
            }

    return report


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else SYNTHETIC_PATH

    if not os.path.exists(path):
        logger.error(f"File not found: {path}")
        sys.exit(1)

    report = analyze(path)

    # Save JSON report
    os.makedirs(REPORTS_DIR, exist_ok=True)
    basename = os.path.splitext(os.path.basename(path))[0]
    json_path = os.path.join(REPORTS_DIR, f"analysis_{basename}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info(f"JSON report saved: {json_path}")

    # Print summary to console
    print("\n" + "=" * 60)
    print(f"DATASET ANALYSIS REPORT")
    print(f"Dataset: {path}")
    print(f"Shape: {report['shape']['rows']} rows × {report['shape']['columns']} columns")
    print(f"Memory: {report['memory_usage_kb']} KB")
    if isinstance(report.get("label_distribution"), dict):
        print(f"\nLabel distribution:")
        for label, count in report["label_distribution"].items():
            print(f"  {label}: {count}")
        print(f"Class balance ratio: {report['class_balance_ratio']}")
    if isinstance(report.get("message_length"), dict):
        ml = report["message_length"]
        print(f"\nMessage length: min={ml['min']}  max={ml['max']}  mean={ml['mean']}  median={ml['median']}")
    if "vocabulary_size" in report:
        print(f"Vocabulary: {report['vocabulary_size']} unique tokens, {report['total_tokens']} total")
    print(f"Exact duplicates: {report.get('exact_duplicates', 'N/A')}")
    print(f"Near-duplicate pairs (sample): {report.get('near_duplicate_pairs_in_sample', 'N/A')}")
    if isinstance(report.get("script_distribution"), dict):
        print(f"\nScript distribution:")
        for script, count in report["script_distribution"].items():
            print(f"  {script}: {count}")
    print("=" * 60)


if __name__ == "__main__":
    main()

