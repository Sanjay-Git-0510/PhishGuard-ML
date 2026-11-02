"""
validate_dataset.py — TRUSTLENS Dataset Validation
----------------------------------------------------
Validates processed and synthetic datasets for:
  - Required column presence
  - Null / missing values
  - Label distribution balance
  - Duplicate messages
  - Near-duplicate detection (Jaccard similarity of word sets)
  - Minimum sample counts per category

Run from the project root:
    python backend/ml/validate_dataset.py [path/to/dataset.csv]

If no path is provided, the synthetic dataset is validated by default.
"""

import os
import sys
import logging
import unicodedata
from collections import Counter

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
SYNTHETIC_PATH = os.path.join(
    PROJECT_ROOT, "backend", "datasets", "synthetic", "trustlens_synthetic_dataset.csv"
)

REQUIRED_COLUMNS = {"message", "normalized_label"}
MIN_SAMPLES_PER_LABEL = 30
NEAR_DUP_THRESHOLD = 0.85  # Jaccard similarity above this → near-duplicate


def jaccard(a: str, b: str) -> float:
    """Compute Jaccard similarity between word sets of two strings."""
    sa = set(a.lower().split())
    sb = set(b.lower().split())
    if not sa and not sb:
        return 1.0
    return len(sa & sb) / len(sa | sb)


def validate(path: str) -> bool:
    """
    Validate a dataset CSV file.  Returns True if all checks pass.
    """
    logger.info(f"Validating: {path}")

    if not os.path.exists(path):
        logger.error(f"File not found: {path}")
        return False

    df = pd.read_csv(path, low_memory=False)
    logger.info(f"Shape: {df.shape}")

    all_ok = True

    # ── Check 1: Required columns ───────────────────────────────────
    missing_cols = REQUIRED_COLUMNS - set(df.columns)
    if missing_cols:
        logger.error(f"Missing required columns: {missing_cols}")
        all_ok = False
    else:
        logger.info("✓ Required columns present")

    if not all_ok:
        return False  # Cannot continue without required columns

    # ── Check 2: Null values ────────────────────────────────────────
    null_counts = df[list(REQUIRED_COLUMNS)].isnull().sum()
    if null_counts.any():
        logger.error(f"Null values detected:\n{null_counts[null_counts > 0].to_string()}")
        all_ok = False
    else:
        logger.info("✓ No null values in required columns")

    # ── Check 3: Label distribution ─────────────────────────────────
    label_dist = df["normalized_label"].value_counts()
    logger.info(f"Label distribution:\n{label_dist.to_string()}")
    for label, count in label_dist.items():
        if count < MIN_SAMPLES_PER_LABEL:
            logger.warning(
                f"  Label '{label}' has only {count} samples "
                f"(minimum recommended: {MIN_SAMPLES_PER_LABEL})"
            )
    ratio = label_dist.min() / label_dist.max() if label_dist.max() > 0 else 0
    if ratio < 0.5:
        logger.warning(
            f"  Class imbalance detected (minority/majority ratio = {ratio:.2f}). "
            "Consider balancing before training."
        )
    else:
        logger.info(f"✓ Class balance ratio: {ratio:.2f}")

    # ── Check 4: Exact duplicates ───────────────────────────────────
    dup_count = df.duplicated(subset="message").sum()
    if dup_count > 0:
        logger.warning(f"  {dup_count} exact duplicate messages found — drop them before training.")
    else:
        logger.info("✓ No exact duplicate messages")

    # ── Check 5: Near-duplicates (sample-based for performance) ─────
    messages = df["message"].fillna("").astype(str).tolist()
    sample_size = min(500, len(messages))
    sample = messages[:sample_size]
    near_dup_pairs = 0
    for i in range(len(sample)):
        for j in range(i + 1, len(sample)):
            if jaccard(sample[i], sample[j]) >= NEAR_DUP_THRESHOLD:
                near_dup_pairs += 1

    if near_dup_pairs > 0:
        logger.warning(
            f"  {near_dup_pairs} near-duplicate pairs found in first {sample_size} rows "
            f"(Jaccard ≥ {NEAR_DUP_THRESHOLD}). Review for template-generated data."
        )
    else:
        logger.info(f"✓ No near-duplicates detected in first {sample_size} rows")

    # ── Check 6: Message length distribution ────────────────────────
    df["_msg_len"] = df["message"].str.len()
    length_stats = df["_msg_len"].describe()
    logger.info(
        f"Message length stats:\n"
        f"  min={length_stats['min']:.0f}  max={length_stats['max']:.0f}  "
        f"mean={length_stats['mean']:.0f}  median={df['_msg_len'].median():.0f}"
    )
    very_short = (df["_msg_len"] < 10).sum()
    if very_short:
        logger.warning(f"  {very_short} messages shorter than 10 characters — possible garbage rows.")

    # ── Check 7: Optional columns ───────────────────────────────────
    optional = {"channel", "language", "source"}
    present_optional = optional & set(df.columns)
    if present_optional:
        for col in sorted(present_optional):
            logger.info(f"  Column '{col}' distribution:\n{df[col].value_counts().to_string()}")

    # ── Summary ─────────────────────────────────────────────────────
    if all_ok:
        logger.info("\n✅ Dataset validation PASSED")
    else:
        logger.error("\n❌ Dataset validation FAILED — fix issues listed above before training.")

    return all_ok


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else SYNTHETIC_PATH
    ok = validate(path)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

