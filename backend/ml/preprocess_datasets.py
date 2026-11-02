"""
preprocess_datasets.py — TRUSTLENS Dataset Preprocessing
---------------------------------------------------------
Reads raw downloaded datasets from backend/datasets/raw/ and produces
cleaned, normalised CSV files in backend/datasets/processed/.

Run from the project root:
    python backend/ml/preprocess_datasets.py

Expected raw files (see DATASET_DOWNLOADS.md for download instructions):
    backend/datasets/raw/phishing_email.csv    — Kaggle: naserabdullahalam/phishing-email-dataset
    backend/datasets/raw/kannada_sms.csv       — IEEE DataPort DOI 10.21227/dcym-pd69
    backend/datasets/raw/sms_spam.csv          — UCI SMS Spam Collection (tab-separated)
"""

import os
import sys
import logging
import unicodedata

import pandas as pd

# ── Resolve paths ────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))
RAW_DIR = os.path.join(PROJECT_ROOT, "backend", "datasets", "raw")
PROC_DIR = os.path.join(PROJECT_ROOT, "backend", "datasets", "processed")

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def nfc(text: str) -> str:
    """Apply Unicode NFC normalisation and strip leading/trailing whitespace."""
    if not isinstance(text, str):
        return ""
    return unicodedata.normalize("NFC", text).strip()


# ── Dataset 1: Phishing Email (Kaggle) ──────────────────────────────
def preprocess_email_dataset() -> pd.DataFrame | None:
    """
    Preprocess the Naser Abdullah Alam phishing email dataset.

    The dataset contains emails from multiple sources (Enron, Ling, CEAS,
    Nazario, Nigerian Fraud, SpamAssassin).  Actual column names are inspected
    at runtime; common variants are tried before failing gracefully.
    """
    path = os.path.join(RAW_DIR, "phishing_email.csv")
    if not os.path.exists(path):
        logger.warning("phishing_email.csv not found — skipping (see DATASET_DOWNLOADS.md).")
        return None

    logger.info("Loading phishing email dataset …")
    df = pd.read_csv(path, low_memory=False)
    logger.info(f"  Raw shape: {df.shape}   Columns: {list(df.columns)}")

    # Detect text and label columns by inspecting column names
    col_lower = {c: c.lower() for c in df.columns}
    text_col = next(
        (c for c in df.columns if col_lower[c] in {"email text", "text", "body", "email_text", "message"}),
        None,
    )
    label_col = next(
        (c for c in df.columns if col_lower[c] in {"email type", "label", "class", "type", "email_type"}),
        None,
    )

    if text_col is None or label_col is None:
        logger.error(
            f"  Could not detect required columns.  Found: {list(df.columns)}\n"
            "  Edit the column-name detection logic in preprocess_datasets.py to match."
        )
        return None

    logger.info(f"  Using text column='{text_col}', label column='{label_col}'")

    # Build normalised dataframe
    out = pd.DataFrame()
    out["message"] = df[text_col].astype(str).apply(nfc)
    out["channel"] = "email"
    out["language"] = "english"
    out["source"] = "kaggle_phishing_email"

    # Map labels → phishing / legitimate
    raw_labels = df[label_col].astype(str).str.lower().str.strip()
    label_map = {
        "phishing email": "phishing",
        "phishing": "phishing",
        "spam": "phishing",      # treat spam as suspicious
        "safe email": "legitimate",
        "safe": "legitimate",
        "ham": "legitimate",
        "legitimate": "legitimate",
        "benign": "legitimate",
    }
    out["normalized_label"] = raw_labels.map(label_map)
    unknown_mask = out["normalized_label"].isna()
    if unknown_mask.any():
        logger.warning(
            f"  {unknown_mask.sum()} rows have unmapped labels: "
            f"{raw_labels[unknown_mask].unique()[:10]}. These will be dropped."
        )
        out = out[~unknown_mask]

    # Drop empty messages
    out = out[out["message"].str.len() > 10]
    # Drop duplicates
    before = len(out)
    out = out.drop_duplicates(subset="message")
    logger.info(f"  After dedup: {len(out)} rows (removed {before - len(out)} duplicates)")

    logger.info(f"  Label distribution:\n{out['normalized_label'].value_counts().to_string()}")
    return out


# ── Dataset 2: Dravidian/Kannada SMS (IEEE DataPort) ────────────────
def preprocess_kannada_sms_dataset() -> pd.DataFrame | None:
    """
    Preprocess the Dravidian Spam SMS dataset.

    Select only Kannada and English samples.  Preserve original Unicode text.
    Column name variants are tried at runtime.
    """
    path = os.path.join(RAW_DIR, "kannada_sms.csv")
    if not os.path.exists(path):
        logger.warning("kannada_sms.csv not found — skipping (see DATASET_DOWNLOADS.md).")
        return None

    logger.info("Loading Kannada SMS dataset …")
    try:
        df = pd.read_csv(path, low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(path, encoding="utf-8-sig", low_memory=False)

    logger.info(f"  Raw shape: {df.shape}   Columns: {list(df.columns)}")

    col_lower = {c: c.lower().strip() for c in df.columns}
    text_col = next(
        (c for c in df.columns if col_lower[c] in {"text", "message", "sms", "content", "sms text"}),
        None,
    )
    label_col = next(
        (c for c in df.columns if col_lower[c] in {"label", "class", "category", "type"}),
        None,
    )
    lang_col = next(
        (c for c in df.columns if col_lower[c] in {"language", "lang"}),
        None,
    )

    if text_col is None or label_col is None:
        logger.error(
            f"  Could not detect required columns.  Found: {list(df.columns)}\n"
            "  Update the column detection in preprocess_datasets.py."
        )
        return None

    logger.info(f"  text='{text_col}', label='{label_col}', language='{lang_col}'")

    # Filter to Kannada and English only when a language column exists
    if lang_col:
        lang_vals = df[lang_col].astype(str).str.lower()
        df = df[lang_vals.isin({"kannada", "english", "en", "kn"})]
        logger.info(f"  After language filter (Kannada/English): {len(df)} rows")

    out = pd.DataFrame()
    out["message"] = df[text_col].astype(str).apply(nfc)
    out["channel"] = "sms"
    out["source"] = "ieee_dravidian_sms"

    # Detect language per row
    def _detect_lang(text: str) -> str:
        # Kannada Unicode range: U+0C80–U+0CFF
        has_kannada = any("\u0c80" <= ch <= "\u0cff" for ch in text)
        has_latin = any(ch.isascii() and ch.isalpha() for ch in text)
        if has_kannada and has_latin:
            return "code-mixed"
        if has_kannada:
            return "kannada"
        return "english"

    out["language"] = out["message"].apply(_detect_lang)

    # Map labels
    raw_labels = df[label_col].astype(str).str.lower().str.strip()
    label_map = {
        "spam": "phishing",
        "phishing": "phishing",
        "ham": "legitimate",
        "legitimate": "legitimate",
        "safe": "legitimate",
        "benign": "legitimate",
        "not spam": "legitimate",
    }
    out["normalized_label"] = raw_labels.map(label_map)
    out = out[out["normalized_label"].notna()]
    out = out[out["message"].str.len() > 5]
    before = len(out)
    out = out.drop_duplicates(subset="message")
    logger.info(f"  After dedup: {len(out)} rows (removed {before - len(out)} duplicates)")
    logger.info(f"  Label distribution:\n{out['normalized_label'].value_counts().to_string()}")
    return out


# ── Dataset 3: UCI SMS Spam Collection ──────────────────────────────
def preprocess_uci_sms_dataset() -> pd.DataFrame | None:
    """
    Preprocess the UCI SMS Spam Collection.

    The file is tab-separated with two columns: label and message.
    Column names may or may not be present in the header.
    """
    path = os.path.join(RAW_DIR, "sms_spam.csv")
    if not os.path.exists(path):
        logger.warning("sms_spam.csv not found — skipping (see DATASET_DOWNLOADS.md).")
        return None

    logger.info("Loading UCI SMS Spam Collection …")
    # Try with and without a header line
    try:
        df = pd.read_csv(path, sep="\t", header=None, names=["label", "message"], encoding="latin-1")
        # If first row is a header, drop it
        if df.iloc[0]["label"].lower() in {"label", "v1", "class"}:
            df = df.iloc[1:].reset_index(drop=True)
    except Exception:
        df = pd.read_csv(path, sep="\t", encoding="latin-1")
        # Guess columns
        if "label" not in df.columns or "message" not in df.columns:
            df.columns = ["label", "message"] + list(df.columns[2:])

    logger.info(f"  Raw shape: {df.shape}")

    out = pd.DataFrame()
    out["message"] = df["message"].astype(str).apply(nfc)
    out["channel"] = "sms"
    out["language"] = "english"
    out["source"] = "uci_sms_spam"

    raw_labels = df["label"].astype(str).str.lower().str.strip()
    label_map = {"ham": "legitimate", "spam": "phishing"}
    out["normalized_label"] = raw_labels.map(label_map)
    out = out[out["normalized_label"].notna()]
    out = out[out["message"].str.len() > 5]
    before = len(out)
    out = out.drop_duplicates(subset="message")
    logger.info(f"  After dedup: {len(out)} rows (removed {before - len(out)} duplicates)")
    logger.info(f"  Label distribution:\n{out['normalized_label'].value_counts().to_string()}")
    return out


# ── Main ─────────────────────────────────────────────────────────────
def main():
    os.makedirs(PROC_DIR, exist_ok=True)

    frames = []

    email_df = preprocess_email_dataset()
    if email_df is not None:
        out_path = os.path.join(PROC_DIR, "email_processed.csv")
        email_df.to_csv(out_path, index=False)
        logger.info(f"Saved: {out_path}")
        frames.append(email_df)

    kannada_df = preprocess_kannada_sms_dataset()
    if kannada_df is not None:
        out_path = os.path.join(PROC_DIR, "kannada_sms_processed.csv")
        kannada_df.to_csv(out_path, index=False)
        logger.info(f"Saved: {out_path}")
        frames.append(kannada_df)

    uci_df = preprocess_uci_sms_dataset()
    if uci_df is not None:
        out_path = os.path.join(PROC_DIR, "uci_sms_processed.csv")
        uci_df.to_csv(out_path, index=False)
        logger.info(f"Saved: {out_path}")
        frames.append(uci_df)

    if not frames:
        logger.warning(
            "No datasets were processed. Download the raw files first — see DATASET_DOWNLOADS.md."
        )
        sys.exit(0)

    # Merge all into a single combined file
    combined = pd.concat(frames, ignore_index=True)
    combined = combined.drop_duplicates(subset="message").reset_index(drop=True)
    combined_path = os.path.join(PROC_DIR, "combined_processed.csv")
    combined.to_csv(combined_path, index=False)
    logger.info(
        f"\nCombined dataset saved: {combined_path}\n"
        f"Total rows: {len(combined)}\n"
        f"Label distribution:\n{combined['normalized_label'].value_counts().to_string()}"
    )


if __name__ == "__main__":
    main()

