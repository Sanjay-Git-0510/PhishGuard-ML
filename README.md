# AegisThreat — Machine Learning Static Phishing URL Detection & SOC Threat Feed

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.2+-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4+-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![Vite](https://img.shields.io/badge/Vite-8.3+-646CFF?logo=vite&logoColor=white)](https://vite.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A high-performance cybersecurity intelligence platform engineered to detect malicious phishing URLs using **static lexical feature extraction** and **supervised machine learning**.

Built with an **Airgap Safe-Mode** architecture, AegisThreat **never** connects to target URLs, performs zero DNS resolutions, and executes no remote scripts—completely eliminating secondary infection and drive-by download risks during threat triage.

---

## Table of Contents

- [Project Description](#project-description)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [20 Extracted Static Feature Vectors](#20-extracted-static-feature-vectors)
- [Machine Learning Benchmark](#machine-learning-benchmark)
- [Quick Start Guide](#quick-start-guide)
  - [Prerequisites](#prerequisites)
  - [Environment Setup (`.env`)](#environment-setup-env)
  - [Option 1: One-Click Launch (Windows)](#option-1-one-click-launch-windows)
  - [Option 2: Manual Launch (Windows / Linux / macOS)](#option-2-manual-launch-windows--linux--macos)
- [Pushing to GitHub Guide](#pushing-to-github-guide)
- [API Reference](#api-reference)
- [Dataset Curation & Model Retraining](#dataset-curation--model-retraining)
- [Automated Testing](#automated-testing)
- [Project Directory Structure](#project-directory-structure)
- [Security Disclaimer & License](#security-disclaimer--license)

---

## Project Description

Modern phishing campaigns employ sophisticated evasion techniques, including fast-flux DNS, credential-harvesting subdomains, homograph spoofing, brand impersonation, and obfuscated payload parameters. Traditional security solutions that ping or fetch suspicious URLs risk alerting threat actors, triggering payload delivery, or suffering credential compromises.

**AegisThreat** solves this challenge through pure **static URL forensic analysis**:
1. **Airgap Safety**: Evaluates URLs purely by decomposing their string structure, syntactic characteristics, lexical entropy, and keyword distributions. No network packets are ever sent to the examined URL.
2. **Deterministic & Probabilistic Hybrid**: Combines deterministic security rules (IP-as-host, known high-abuse TLDs, keyword lures, brand spoofs) with an ensemble Machine Learning classifier (Random Forest) trained to recognize complex non-linear combinations of attack signals.
3. **Enterprise SOC Triage**: Ships with a dark-mode Security Operations Center (SOC) dashboard that delivers instantaneous risk scores, vulnerability classifications, multi-URL batch ingestion, model explainability metrics, and persistent audit logs.

---

## Key Features

- **Airgap Safe-Mode Static Inspection**: 
  Zero HTTP/HTTPS requests, zero DNS lookups, zero remote code execution. Complete isolation during threat inspection.
- **24-Vector Lexical & Entropy Extractor**: 
  Measures Shannon entropy ($H = -\sum p_i \log_2 p_i$), symbol density, subdomain hierarchy depth, credential lures, URL shorteners, abuse TLDs, digit substitutions (`paypa1`), brand typosquatting, IDN homoglyphs, and path mismatches.
- **High-Recall Machine Learning Core**: 
  Trained and cross-validated with 100% recall on evaluation holdout sets to virtually eliminate False Negatives (missed phishing attacks).
- **Interactive SOC Threat Feed Dashboard**:
  - Live radial probability gauges with contextual risk tiers (`LOW`, `MEDIUM`, `HIGH`).
  - Interactive **24-Vector Feature Breakdown** table with cybersecurity rationale for each detected signal.
  - Dynamic **Vulnerability Matrix** and recommended SOC containment actions.
  - **Batch Scanner** for multi-URL threat ingestion (up to 50 URLs in one batch).
  - **Live Model Intelligence Tab** showing confusion matrix, ROC-AUC score, and top feature importances.
  - **Scan Audit Trail** backed by SQLite or PostgreSQL for historical incident analysis.
- **Production-Ready FastAPI REST API**: 
  Full OpenAPI (Swagger) documentation, structured Pydantic data validation, and configurable CORS security.

---

## System Architecture

```mermaid
graph TD
    User([SOC Analyst / Incident Responder]) -->|Web Browser| Frontend[Vite + React 19 SOC Dashboard]
    Frontend -->|Reverse Proxy /api| Backend[FastAPI REST API Server]
    Backend --> Extractor[Static 24-Vector Feature Extractor]
    Extractor -->|Lexical & Entropy Vectors| Model[Random Forest Classifier (.joblib)]
    Model -->|Phishing Probability & Class| Backend
    Backend -->|Audit Log Ingestion| DB[(Database: SQLite / PostgreSQL)]
    Backend -->|JSON Threat Intelligence| Frontend
    Frontend --> View1[Threat Risk Gauge & Triage Guidance]
    Frontend --> View2[24-Vector Feature Table & Radar Heatmap]
    Frontend --> View3[Batch URL Multi-Scan Results]
```

---

## 24 Extracted Static Feature Vectors

| # | Vector Name | Description | Threat Rationale |
| :-: | :--- | :--- | :--- |
| 1 | `url_length` | Total character count | Long URLs obscure malicious targets or embed serialized payload tokens |
| 2 | `hostname_length` | Length of FQDN hostname | Oversized hostnames commonly impersonate enterprise domains |
| 3 | `path_length` | Length of resource path | Deep paths mimic legitimate enterprise directory structures |
| 4 | `query_length` | Length of query string | Attackers inject payload flags, base64 payloads, or tracking params |
| 5 | `num_dots` | Period (`.`) count | Excessive dots indicate complex subdomain spoofing |
| 6 | `num_hyphens` | Hyphen (`-`) count | Frequently used to stitch target brand names (`apple-id-login`) |
| 7 | `num_underscores` | Underscore (`_`) count | Syntactic anomaly frequently seen in credential harvesting scripts |
| 8 | `num_slashes` | Forward slash (`/`) count | Deep path traversal mimicry |
| 9 | `num_question_marks`| Question mark (`?`) count | Query delimiter manipulation |
| 10 | `num_equal_signs` | Equal sign (`=`) count | High query parameter count used for telemetry tracking |
| 11 | `num_at_symbols` | `@` symbol count | Legacy HTTP authority disguise trick (`victim@malicious.com`) |
| 12 | `num_digits` | Numeric digit count | Dense numbers correlate with unmapped, dynamic disposable campaigns |
| 13 | `digit_ratio` | Digits / Total URL length | Measures numeric concentration across the entire string |
| 14 | `num_subdomains` | Subdomain hierarchy depth | Multi-level chains (`login.verify.bank.fake.com`) indicate mimicry |
| 15 | `is_ip_address` | Host is literal IPv4 / IPv6 | Bypasses DNS registration; strong indicator of malicious C2/hosts |
| 16 | `is_https` | HTTPS connection scheme | Plaintext HTTP flags lack of encrypted transport |
| 17 | `has_suspicious_keywords` | Matches credential keywords | Detects keywords (`login`, `verify`, `account`, `banking`, `secure`, etc.) |
| 18 | `is_shortened` | Hostname matches URL shortener | Obfuscates destination domain (`bit.ly`, `tinyurl.com`, `t.co`, etc.) |
| 19 | `suspicious_tld` | Hostname ends in high-abuse TLD | Disposable TLDs favored by threat actors (`.xyz`, `.top`, `.tk`, `.buzz`, etc.) |
| 20 | `url_entropy` | Shannon Entropy ($H$) | Measures character randomness and algorithmic obfuscation |
| 21 | `has_digit_substitution` | Digits substituting letters | Flags leetspeak spoofing (`paypa1`, `g00gle`, `m1crosoft`) |
| 22 | `brand_doppelganger` | Levenshtein typosquatting | Flags domains with edit distance $\le 2$ from top brands |
| 23 | `has_punycode_idn` | Punycode (`xn--`) domain encoding | Detects internationalized homoglyph spoofing attacks |
| 24 | `path_has_brand_mismatch`| Brand token in path mismatch | Flags domains using trusted brand in URI path while hosted elsewhere |


---

## Machine Learning Benchmark

The model evaluation pipeline evaluates 4 supervised classifiers on stratified 80/20 train-test splits:

| Classifier | Accuracy | Precision | Recall (Sensitivity) | F1-Score | ROC-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Selected)** | **100.0%** | **100.0%** | **100.0%** | **1.0000** | **1.0000** |
| Gradient Boosting | 100.0% | 100.0% | 100.0% | 1.0000 | 1.0000 |
| Decision Tree | 98.57% | 96.55% | 100.0% | 0.9825 | 0.9881 |
| Logistic Regression | 94.29% | 90.00% | 96.43% | 0.9310 | 0.9855 |

> **Selection Criteria**: In threat triage, **Recall** is prioritized over all metrics to ensure true phishing attempts are never classified as benign (minimizing False Negatives).

---

## Quick Start Guide

### Prerequisites

Ensure you have the following installed:
- **Python**: Version `3.10` or higher (`3.11`, `3.12`, or `3.14`)
- **Node.js**: Version `18.x` or higher (with `npm`)
- **Git**

---

### Environment Setup (`.env`)

The project uses `.env` files for configuration. A template file [`backend/.env.example`](backend/.env.example) is included in the repository.

1. Navigate to the `backend` directory and create your `.env` from the template:
   - **Windows (Command Prompt / PowerShell)**:
     ```cmd
     copy backend\.env.example backend\.env
     ```
   - **Linux / macOS**:
     ```bash
     cp backend/.env.example backend/.env
     ```

2. Review [`backend/.env`](backend/.env):
   ```env
   ENVIRONMENT=development
   PROJECT_NAME="AegisThreat - Phishing URL Detection System"
   DATABASE_URL=sqlite:///./scans.db
   BACKEND_CORS_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173","http://localhost:3000","http://127.0.0.1:3000","http://localhost:8080"]
   ```

> [!NOTE]
> `.env` files and SQLite databases (`*.db`) are ignored in [`.gitignore`](.gitignore) to prevent leaking local settings or audit logs to GitHub.

---

### Option 1: One-Click Launch (Windows)

Simply double-click [`start_all.bat`](start_all.bat) or run from your terminal:
```cmd
start_all.bat
```
This script will:
1. Verify Python and Node.js environments.
2. Launch the FastAPI backend on `http://127.0.0.1:8000`.
3. Launch the Vite React frontend on `http://localhost:5173`.

---

### Option 2: Manual Launch (Windows / Linux / macOS)

#### 1. Setup & Launch Backend
```bash
# Navigate to backend directory
cd backend

# Create and activate virtual environment
# Windows:
python -m venv ..\venv
..\venv\Scripts\activate
# Linux / macOS:
python3 -m venv ../venv
source ../venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- Interactive API Documentation (Swagger): `http://127.0.0.1:8000/docs`
- Backend Health Check: `http://127.0.0.1:8000/api/health`

#### 2. Setup & Launch Frontend
```bash
# In a new terminal, navigate to frontend directory
cd frontend

# Install npm packages
npm install

# Start Vite development server
npm run dev
```
- Open `http://localhost:5173` in your browser.

---

## Pushing to GitHub Guide

Follow these steps to push this project cleanly to your GitHub profile without committing local databases or temporary files:

### 1. Initialize Git & Check Status
```bash
git status
```
Verify that `.gitignore` is present and that sensitive files (`backend/.env`, `scans.db`, `venv/`, `node_modules/`, `__pycache__/`) are **not** listed under untracked files.

### 2. Stage All Clean Files
```bash
git add .
```

### 3. Commit the Changes
```bash
git commit -m "feat: initial commit - AegisThreat phishing URL detection platform"
```

### 4. Create a New GitHub Repository
1. Go to [GitHub](https://github.com/new).
2. Create a new repository named `Phishing-URL-Detection` (or your preferred name).
3. Do **not** check "Initialize this repository with a README" (the repository already contains a full README).

### 5. Link Remote and Push
```bash
# Rename default branch to main
git branch -M main

# Link your remote repository (replace with your GitHub username)
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/Phishing-URL-Detection.git

# Push code to GitHub
git push -u origin main
```

---

## API Reference

### Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | API status and root metadata |
| `GET` | `/api/health` | Health check, model readiness, database state |
| `POST`| `/api/predict` | Single URL static analysis and risk classification |
| `POST`| `/api/batch-predict` | Batch URL static analysis (up to 50 URLs per request) |
| `GET` | `/api/model-info` | Classifier metrics, confusion matrix, and feature importances |
| `GET` | `/api/history` | Historical audit logs of scanned URLs |

### Sample Single URL Analysis

**Request:**
```bash
curl -X POST "http://127.0.0.1:8000/api/predict" \
     -H "Content-Type: application/json" \
     -d '{"url": "http://192.168.1.100/paypal/login.php?verify=1"}'
```

**Response:**
```json
{
  "url": "http://192.168.1.100/paypal/login.php?verify=1",
  "prediction": "phishing",
  "probability": 0.9933,
  "risk_level": "high",
  "features": {
    "url_length": 46.0,
    "hostname_length": 13.0,
    "path_length": 17.0,
    "query_length": 8.0,
    "num_dots": 4.0,
    "num_hyphens": 0.0,
    "num_underscores": 0.0,
    "num_slashes": 4.0,
    "num_question_marks": 1.0,
    "num_equal_signs": 1.0,
    "num_at_symbols": 0.0,
    "num_digits": 11.0,
    "digit_ratio": 0.2391,
    "num_subdomains": 0.0,
    "is_ip_address": 1.0,
    "is_https": 0.0,
    "has_suspicious_keywords": 1.0,
    "is_shortened": 0.0,
    "suspicious_tld": 0.0,
    "url_entropy": 4.3666
  },
  "reasons": [
    "IP address used directly as hostname (bypasses domain registration)",
    "Contains high-risk security/credential keywords (e.g. login, verify, account, secure)",
    "Unencrypted connection scheme (HTTP instead of HTTPS)",
    "High numeric density (23.9% digits)"
  ],
  "static_analysis_notice": "Static URL analysis only — the submitted website is not visited by this application.",
  "timestamp": "2026-09-29T10:00:00.000000+00:00"
}
```

---

## Dataset Curation & Model Retraining

To expand the training dataset with new threat feeds or update the scikit-learn models:

```bash
# 1. Regenerate curated dataset
python backend/datasets/prepare_dataset.py

# 2. Retrain and benchmark all classifiers
python backend/ml/train.py

# 3. (Optional) Run standalone model evaluation metrics
python backend/ml/evaluate.py
```
This updates the serialized artifacts in `backend/models/`:
- `phishing_model.joblib`: Serialized Random Forest classifier
- `feature_names.json`: Ordered list of 20 feature vector names
- `model_metrics.json`: Accuracy, precision, recall, F1, and confusion matrix data

---

## Automated Testing

Run the full end-to-end test suite (14 backend integration/unit tests + frontend linter + build verification):

- **Windows One-Click Test Suite**:
  ```cmd
  run_tests.bat
  ```

- **Backend Pytest Only**:
  ```bash
  pytest backend/tests/
  ```

- **Frontend Linter & Build Verification**:
  ```bash
  cd frontend
  npm run lint
  npm run build
  ```

---

## Project Directory Structure

```text
Phissing_Detection/
├── .gitignore                   # Global Git ignore rules (credentials, DBs, cache, node_modules)
├── README.md                    # Master project documentation
├── pytest.ini                   # Pytest configuration
├── run_tests.bat                # Windows end-to-end test suite launcher
├── start_all.bat                # One-click launcher for backend & frontend
├── start_backend.bat            # Windows launcher for FastAPI server
├── start_frontend.bat           # Windows launcher for Vite dev server
├── backend/
│   ├── app/
│   │   ├── api/                 # API routers (endpoints: health, predict, history, etc.)
│   │   ├── core/                # App config, database session manager
│   │   ├── ml/                  # Feature extractor engine & model predictor
│   │   ├── models/              # SQLAlchemy database models (ScanRecord)
│   │   ├── schemas/             # Pydantic validation schemas
│   │   └── main.py              # FastAPI entry point & CORS configuration
│   ├── datasets/                # Dataset generation script & labeled CSVs
│   ├── ml/                      # Supervised training & benchmark evaluation scripts
│   ├── models/                  # Serialized .joblib model & metrics JSON
│   ├── tests/                   # Pytest unit & integration test suite
│   ├── .env.example             # Backend environment template (safe for Git)
│   ├── pytest.ini               # Backend test runner configuration
│   └── requirements.txt         # Backend Python dependencies
└── frontend/
    ├── src/
    │   ├── assets/              # Static branding and icons
    │   ├── components/          # React components (Scanner, Heatmap, Batch, Telemetry, Feed)
    │   ├── services/            # Axios/Fetch API client
    │   ├── App.jsx              # Main dashboard application logic
    │   ├── index.css            # Dark-mode glassmorphic SOC design system
    │   └── main.jsx             # React DOM root entry
    ├── public/                  # Public static assets & favicon
    ├── package.json             # React 19, Vite, Lucide dependencies
    └── vite.config.js           # Vite dev server and backend proxy config
```

---

## Security Disclaimer & License

### Security Notice
AegisThreat is designed specifically for security analysis, education, and incident triage. It operates entirely on static lexical analysis and does not visit or execute remote code from submitted URLs. Always handle untrusted URLs with appropriate operational security protocols.

### License
This project is licensed under the [MIT License](LICENSE).
