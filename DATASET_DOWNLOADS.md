# DATASET_DOWNLOADS.md — TRUSTLENS Dataset Sources & Download Instructions

All analysis in TRUSTLENS uses traditional machine learning trained on the following
public datasets. The datasets are **not bundled** with this repository. Download them
manually and place the files in `backend/datasets/raw/` before running the preprocessing
and training scripts.

---

## Dataset 1 — Phishing Email Dataset (Kaggle)

| Field | Value |
|-------|-------|
| **Name** | Phishing Email Dataset |
| **Author** | Naser Abdullah Alam |
| **Kaggle identifier** | `naserabdullahalam/phishing-email-dataset` |
| **URL** | <https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset> |
| **Purpose** | English email classification (phishing / legitimate) |
| **Expected raw file** | `backend/datasets/raw/phishing_email.csv` |
| **License** | [Kaggle dataset-specific terms](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) |

### Contents

Email records collected from multiple sources:

- **Enron email dataset** — legitimate corporate emails
- **Ling-spam corpus** — spam/ham emails
- **CEAS 2008** — spam challenge dataset
- **Nazario phishing corpus** — confirmed phishing emails
- **Nigerian Fraud / 419 corpus** — advance-fee fraud
- **SpamAssassin** — mixed spam/ham

> **Important:** Not all "spam" rows are confirmed phishing. The preprocessing
> script (`backend/ml/preprocess_datasets.py`) maps labels consistently. Review
> the label mapping if you require a stricter phishing-only definition.

### Download Instructions

**Method A — Kaggle CLI (recommended)**

```bash
# 1. Install the Kaggle CLI (inside your project venv)
pip install kaggle

# 2. Place your API token at %USERPROFILE%\.kaggle\kaggle.json  (Windows)
#    Get it from: https://www.kaggle.com/settings → API → Create New Token

# 3. Download and extract
kaggle datasets download -d naserabdullahalam/phishing-email-dataset -p backend/datasets/raw/ --unzip
```

**Method B — Manual browser download**

1. Log in to [kaggle.com](https://www.kaggle.com).
2. Go to <https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset>.
3. Click **Download** (top-right).
4. Extract the ZIP file.
5. Rename the main CSV file to `phishing_email.csv`.
6. Place it at `backend/datasets/raw/phishing_email.csv`.

---

## Dataset 2 — Spam SMS in Dravidian Languages (IEEE DataPort)

| Field | Value |
|-------|-------|
| **Name** | Spam SMS in Dravidian Languages |
| **DOI** | [10.21227/dcym-pd69](https://doi.org/10.21227/dcym-pd69) |
| **URL** | <https://ieee-dataport.org/documents/spam-sms-dravidian-languages> |
| **Purpose** | Kannada and English SMS spam/ham classification |
| **Languages used** | English, Kannada (Tamil, Telugu, Malayalam available but not required) |
| **Expected raw file** | `backend/datasets/raw/kannada_sms.csv` |
| **License** | [Creative Commons Attribution 4.0 (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/) |

### Download Instructions

IEEE DataPort requires a free account.

1. Create or log in at [ieee-dataport.org](https://ieee-dataport.org).
2. Navigate to <https://doi.org/10.21227/dcym-pd69>.
3. Click **Download** to get the dataset archive.
4. Extract the archive.
5. Locate the Kannada SMS CSV file (usually named `Kannada_sms.csv` or similar).
6. Rename it to `kannada_sms.csv`.
7. Place it at `backend/datasets/raw/kannada_sms.csv`.

> **Unicode preservation:** The preprocessing script reads the file with `utf-8`
> or `utf-8-sig` encoding to preserve Kannada Unicode characters (U+0C80–U+0CFF).
> Do not convert the file to ASCII or Latin-1.

### Attribution

If you use this dataset in publications, cite:

> Kalaivani, S., Thenmozhi, D., et al., *"Spam SMS in Dravidian Languages"*,
> IEEE DataPort, DOI: 10.21227/dcym-pd69.

---

## Dataset 3 — SMS Spam Collection (UCI Machine Learning Repository)

| Field | Value |
|-------|-------|
| **Name** | SMS Spam Collection |
| **Dataset ID** | 228 |
| **URL** | <https://archive.ics.uci.edu/dataset/228/sms+spam+collection> |
| **Purpose** | Additional English SMS ham/spam examples |
| **Expected raw file** | `backend/datasets/raw/sms_spam.csv` |
| **Format** | Tab-separated (TSV), two columns: label (`ham`/`spam`), message |
| **License** | Creative Commons Attribution 4.0 (CC BY 4.0) |

### Download Instructions

1. Go to <https://archive.ics.uci.edu/dataset/228/sms+spam+collection>.
2. Click **Download** to get the ZIP archive.
3. Extract `SMSSpamCollection` (no extension — it is a tab-separated text file).
4. Rename it to `sms_spam.csv`.
5. Place it at `backend/datasets/raw/sms_spam.csv`.

The file has no header row. Columns are: `label` (ham/spam) and `message`.
The preprocessing script handles this format automatically.

### Attribution

> Almeida, T. A., Gómez Hidalgo, J. M., & Yamakami, A. (2011).
> *"Contributions to the Study of SMS Spam Filtering: New Collection and Methods"*.
> Proceedings of the 2011 ACM Symposium on Document Engineering.

---

## File Layout After Download

```
backend/
└── datasets/
    └── raw/
        ├── phishing_email.csv       ← Dataset 1 (Kaggle)
        ├── kannada_sms.csv          ← Dataset 2 (IEEE DataPort)
        └── sms_spam.csv             ← Dataset 3 (UCI)
```

---

## Preprocessing & Training

After downloading, run in order:

```powershell
# 1. Preprocess all three datasets
python backend/ml/preprocess_datasets.py

# 2. Validate the processed data
python backend/ml/validate_dataset.py backend/datasets/processed/combined_processed.csv

# 3. Retrain the message classifier on real data
python backend/ml/train_message_model.py

# 4. Evaluate the model
python backend/ml/evaluate_message_model.py
```

The preprocessing script will skip any file that is not present and log a warning,
so you can proceed with partial downloads.

---

## Synthetic Dataset (Fallback)

`backend/datasets/synthetic/trustlens_synthetic_dataset.csv` is included in this
repository as a training fallback when the real datasets are unavailable.

> **Warning:** The synthetic dataset was designed for initial system validation only.
> It is small (400 samples) and homogeneous. Real-world performance will be significantly
> better when the model is trained on the actual public datasets above.

---

## Privacy & Data Handling

- Raw dataset files are listed in `.gitignore` and are **not committed** to this repository.
- The preprocessing script never modifies the original raw files.
- Processed files contain only normalised message text, labels, channel, language and source.
- No personal information from the original datasets is stored or transmitted.

