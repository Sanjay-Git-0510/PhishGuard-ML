"""
Dataset Download Instructions and Loaders
-------------------------------------------
Public dataset loaders for TRUSTLENS.
Each dataset requires manual download (see DATASET_DOWNLOADS.md).
"""

import os
import sys
import json
import pandas as pd
from typing import Optional, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(CURRENT_DIR)
RAW_DIR = os.path.join(BACKEND_DIR, "datasets", "raw")
PROCESSED_DIR = os.path.join(BACKEND_DIR, "datasets", "processed")
REPORTS_DIR = os.path.join(BACKEND_DIR, "datasets", "reports")


def _ensure_dirs():
    for d in (RAW_DIR, PROCESSED_DIR, REPORTS_DIR):
        os.makedirs(d, exist_ok=True)


def load_phishing_email_dataset(filename: str = "phishing_email.csv") -> Optional[pd.DataFrame]:
    """
    Load Phishing Email Dataset by Naser Abdullah Alam.
    Source: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
    Expected file: backend/datasets/raw/phishing_email.csv

    Column mapping (inspect actual file):
      - text_combined / body / text: message text
      - label / Email Type: 0=legitimate, 1=phishing (or similar)
    """
    fpath = os.path.join(RAW_DIR, filename)
    if not os.path.exists(fpath):
        print(f"[!] Phishing Email Dataset not found at {fpath}")
        print("    Download from: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset")
        print("    Place the CSV file at: backend/datasets/raw/phishing_email.csv")
        return None

    try:
        df = pd.read_csv(fpath, encoding="utf-8", on_bad_lines="skip")
        print(f"[+] Loaded phishing email dataset: {len(df)} rows, columns: {list(df.columns)}")

        # Try to detect the text column
        text_col = None
        for col in ["text_combined", "body", "text", "message", "Email Text", "email_text"]:
            if col in df.columns:
                text_col = col
                break

        # Try to detect the label column
        label_col = None
        for col in ["label", "Label", "Email Type", "email_type", "class", "phishing"]:
            if col in df.columns:
                label_col = col
                break

        if not text_col or not label_col:
            print(f"[!] Could not auto-detect columns. Found: {list(df.columns)}")
            print("    Please inspect the file and update load_phishing_email_dataset().")
            return None

        df_out = pd.DataFrame()
        df_out["message"] = df[text_col].astype(str)
        df_out["subject"] = ""
        df_out["channel"] = "email"
        df_out["language"] = "english"

        # Normalize labels — preserve original, map to normalized
        original_labels = df[label_col]
        df_out["original_label"] = original_labels.astype(str)

        # Map: phishing/spam=suspicious, ham/legitimate=benign
        def map_label(v):
            v_str = str(v).lower().strip()
            if v_str in ("1", "phishing", "spam", "phishing email"):
                return "suspicious"
            elif v_str in ("0", "ham", "legitimate", "safe email"):
                return "benign"
            else:
                return "unknown"

        df_out["normalized_label"] = original_labels.apply(map_label)
        df_out = df_out[df_out["normalized_label"] != "unknown"]
        df_out["source_dataset"] = "phishing_email_alam_kaggle"
        df_out["attack_type"] = df_out["normalized_label"].apply(
            lambda x: "phishing" if x == "suspicious" else "benign_notification"
        )
        df_out["sender_name"] = ""
        df_out["sender_address"] = ""
        df_out["reply_to"] = ""
        df_out["sender_id"] = ""
        df_out["claimed_identity"] = ""
        df_out["scenario_id"] = "PUBLIC_EMAIL_ALAM"

        print(f"[+] Phishing email dataset processed: {len(df_out)} valid rows")
        print(f"    Benign: {(df_out['normalized_label']=='benign').sum()}")
        print(f"    Suspicious: {(df_out['normalized_label']=='suspicious').sum()}")
        return df_out

    except Exception as e:
        print(f"[!] Error loading phishing email dataset: {e}")
        return None


def load_uci_sms_dataset(filename: str = "sms_spam.csv") -> Optional[pd.DataFrame]:
    """
    Load UCI SMS Spam Collection.
    Source: https://archive.ics.uci.edu/dataset/228/sms+spam+collection
    Expected file: backend/datasets/raw/sms_spam.csv
    Columns: v1 (ham/spam), v2 (message text)
    """
    fpath = os.path.join(RAW_DIR, filename)
    if not os.path.exists(fpath):
        print(f"[!] UCI SMS Dataset not found at {fpath}")
        print("    Download from: https://archive.ics.uci.edu/dataset/228/sms+spam+collection")
        print("    Place SMSSpamCollection (renamed to sms_spam.csv) at: backend/datasets/raw/sms_spam.csv")
        return None

    try:
        # UCI SMS is tab-separated with no header
        df = pd.read_csv(fpath, sep="\t", header=None, names=["label", "message"],
                         encoding="latin-1", on_bad_lines="skip")
        print(f"[+] UCI SMS dataset loaded: {len(df)} rows")

        df_out = pd.DataFrame()
        df_out["message"] = df["message"].astype(str)
        df_out["subject"] = ""
        df_out["channel"] = "sms"
        df_out["language"] = "english"
        df_out["original_label"] = df["label"].astype(str)
        df_out["normalized_label"] = df["label"].apply(
            lambda x: "suspicious" if str(x).lower() == "spam" else "benign"
        )
        df_out["source_dataset"] = "uci_sms_spam_collection"
        df_out["attack_type"] = df_out["normalized_label"].apply(
            lambda x: "suspicious_link" if x == "suspicious" else "benign_notification"
        )
        df_out["sender_name"] = ""
        df_out["sender_address"] = ""
        df_out["reply_to"] = ""
        df_out["sender_id"] = ""
        df_out["claimed_identity"] = ""
        df_out["scenario_id"] = "PUBLIC_SMS_UCI"

        print(f"[+] UCI SMS processed: {len(df_out)} rows")
        print(f"    Ham (benign): {(df_out['normalized_label']=='benign').sum()}")
        print(f"    Spam (suspicious): {(df_out['normalized_label']=='suspicious').sum()}")
        return df_out

    except Exception as e:
        print(f"[!] Error loading UCI SMS dataset: {e}")
        return None


def load_dravidian_sms_dataset(filename_kn: str = "kannada_sms.csv") -> Optional[pd.DataFrame]:
    """
    Load Dravidian Spam SMS Dataset (Kannada portion).
    Source: https://doi.org/10.21227/dcym-pd69 (IEEE DataPort)
    Expected file: backend/datasets/raw/kannada_sms.csv

    Note: Only Kannada language samples are loaded here.
    English samples from this dataset overlap with UCI SMS.
    """
    fpath = os.path.join(RAW_DIR, filename_kn)
    if not os.path.exists(fpath):
        print(f"[!] Dravidian SMS Dataset (Kannada) not found at {fpath}")
        print("    Download from: https://doi.org/10.21227/dcym-pd69")
        print("    Place the Kannada CSV at: backend/datasets/raw/kannada_sms.csv")
        return None

    try:
        df = pd.read_csv(fpath, encoding="utf-8", on_bad_lines="skip")
        print(f"[+] Dravidian SMS (Kannada) loaded: {len(df)} rows, columns: {list(df.columns)}")

        # Try to detect columns
        text_col = None
        label_col = None
        for col in df.columns:
            col_lower = col.lower()
            if "text" in col_lower or "message" in col_lower or "sms" in col_lower:
                text_col = col
            if "label" in col_lower or "class" in col_lower or "category" in col_lower:
                label_col = col

        if not text_col or not label_col:
            print(f"[!] Could not auto-detect columns: {list(df.columns)}")
            return None

        df_out = pd.DataFrame()
        df_out["message"] = df[text_col].astype(str)
        df_out["subject"] = ""
        df_out["channel"] = "sms"
        df_out["language"] = "kannada"
        df_out["original_label"] = df[label_col].astype(str)

        def map_label_kn(v):
            v_str = str(v).lower().strip()
            if v_str in ("spam", "1", "phishing", "suspicious"):
                return "suspicious"
            elif v_str in ("ham", "0", "legitimate", "benign", "not spam"):
                return "benign"
            return "unknown"

        df_out["normalized_label"] = df[label_col].apply(map_label_kn)
        df_out = df_out[df_out["normalized_label"] != "unknown"]
        df_out["source_dataset"] = "dravidian_sms_ieee_dataport"
        df_out["attack_type"] = "suspicious_link"
        df_out["sender_name"] = ""
        df_out["sender_address"] = ""
        df_out["reply_to"] = ""
        df_out["sender_id"] = ""
        df_out["claimed_identity"] = ""
        df_out["scenario_id"] = "PUBLIC_KN_SMS_DRAVIDIAN"

        print(f"[+] Dravidian Kannada SMS processed: {len(df_out)} rows")
        return df_out

    except Exception as e:
        print(f"[!] Error loading Dravidian dataset: {e}")
        return None


def load_all_datasets() -> dict:
    """
    Attempt to load all public datasets and return status report.
    Saves processed files for use by train_message_model.py.
    """
    _ensure_dirs()
    report = {"loaded": [], "missing": [], "errors": []}

    email_df = load_phishing_email_dataset()
    if email_df is not None:
        out = os.path.join(PROCESSED_DIR, "processed_email.csv")
        email_df.to_csv(out, index=False, encoding="utf-8")
        report["loaded"].append({"dataset": "phishing_email_alam", "samples": len(email_df), "output": out})
        print(f"[OK] Saved processed email dataset: {out}")
    else:
        report["missing"].append("phishing_email_alam_kaggle")

    sms_df = load_uci_sms_dataset()
    if sms_df is not None:
        out = os.path.join(PROCESSED_DIR, "processed_sms.csv")
        sms_df.to_csv(out, index=False, encoding="utf-8")
        report["loaded"].append({"dataset": "uci_sms_spam", "samples": len(sms_df), "output": out})
        print(f"[OK] Saved processed SMS dataset: {out}")
    else:
        report["missing"].append("uci_sms_spam_collection")

    kn_df = load_dravidian_sms_dataset()
    if kn_df is not None:
        out = os.path.join(PROCESSED_DIR, "processed_kannada_sms.csv")
        kn_df.to_csv(out, index=False, encoding="utf-8")
        report["loaded"].append({"dataset": "dravidian_sms_kannada", "samples": len(kn_df), "output": out})
        print(f"[OK] Saved Kannada SMS dataset: {out}")
    else:
        report["missing"].append("dravidian_sms_ieee_dataport")

    report_path = os.path.join(REPORTS_DIR, "dataset_load_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[OK] Dataset load report: {report_path}")

    if report["missing"]:
        print(f"\n[!] Missing datasets: {report['missing']}")
        print("    See DATASET_DOWNLOADS.md for download instructions.")
        print("    Training will proceed with synthetic dataset only.")

    return report


if __name__ == "__main__":
    load_all_datasets()

