"""
URL Predictor — Reuses Existing Phishing URL Model
----------------------------------------------------
Wraps the existing PhishingPredictor singleton to analyze
URLs extracted from email/SMS messages.
Does NOT replace or modify the existing URL model.
"""

from typing import List, Dict, Any
from app.ml.predictor import get_predictor
from app.modules.url_analysis.url_extractor import extract_urls, classify_url_metadata


def analyze_urls_in_message(message_text: str) -> Dict[str, Any]:
    """
    Extract all URLs from a message and run them through the existing
    phishing URL detection model.

    Returns:
        {
          "urls_found": [...],
          "url_count": int,
          "results": [ { url, prediction, probability, risk_level, reasons, metadata } ],
          "any_high_risk": bool,
          "any_phishing": bool,
          "highest_risk": "low"/"medium"/"high",
        }
    """
    urls = extract_urls(message_text)

    if not urls:
        return {
            "urls_found": [],
            "url_count": 0,
            "results": [],
            "any_high_risk": False,
            "any_phishing": False,
            "highest_risk": "none",
            "static_analysis_notice": (
                "No URLs were found in the message. "
                "Static URL analysis only — submitted links are never visited."
            ),
        }

    predictor = get_predictor()
    results = []
    any_high = False
    any_phishing = False
    highest = "none"
    risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3}

    for url in urls:
        try:
            pred = predictor.predict(url)
            meta = classify_url_metadata(url)
            combined = {
                "url": url,
                "prediction": pred["prediction"],
                "probability": pred["probability"],
                "risk_level": pred["risk_level"],
                "reasons": pred["reasons"],
                "metadata": meta,
            }
            results.append(combined)

            if pred["risk_level"] == "high":
                any_high = True
            if pred["prediction"] == "phishing":
                any_phishing = True
            if risk_order.get(pred["risk_level"], 0) > risk_order.get(highest, 0):
                highest = pred["risk_level"]

        except Exception as e:
            results.append({
                "url": url,
                "prediction": "error",
                "probability": 0.0,
                "risk_level": "unknown",
                "reasons": [f"URL analysis error: {str(e)}"],
                "metadata": classify_url_metadata(url),
            })

    return {
        "urls_found": urls,
        "url_count": len(urls),
        "results": results,
        "any_high_risk": any_high,
        "any_phishing": any_phishing,
        "highest_risk": highest,
        "static_analysis_notice": (
            "Static URL analysis only — submitted links are never visited or followed."
        ),
    }


def analyze_single_url(url: str) -> Dict[str, Any]:
    """
    Analyze a single URL using the existing phishing model.
    Returns the predictor result plus URL metadata.
    """
    predictor = get_predictor()
    try:
        pred = predictor.predict(url)
        meta = classify_url_metadata(url)
        return {**pred, "metadata": meta}
    except Exception as e:
        return {
            "url": url,
            "prediction": "error",
            "probability": 0.0,
            "risk_level": "unknown",
            "reasons": [f"Analysis error: {str(e)}"],
            "metadata": classify_url_metadata(url),
        }

