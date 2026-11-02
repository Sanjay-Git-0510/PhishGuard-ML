"""
Message Analysis API Routes
-----------------------------
POST /api/analyze-message  — Analyze an email or SMS message
"""

import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, status
from app.schemas.message_schema import (
    EmailAnalysisRequest,
    SmsAnalysisRequest,
    MessageAnalysisResponse,
    RiskAssessmentResult,
    MLClassificationResult,
    UrlAnalysisResult,
    UrlResultItem,
    IdentityAnalysisResult,
    SocialEngineeringResult,
    EvidenceItem,
)
from app.modules.message_analysis.preprocessing import preprocess_message
from app.modules.message_analysis.predictor import get_message_predictor
from app.modules.identity_analysis.sender_checker import (
    check_sender_name_consistency,
    check_reply_to_mismatch,
    check_sms_sender_id,
)
from app.modules.identity_analysis.domain_checker import run_full_domain_analysis
from app.modules.social_engineering.detector import detect_social_engineering
from app.modules.url_analysis.url_predictor import analyze_urls_in_message
from app.modules.evidence.evidence_extractor import extract_all_evidence
from app.modules.risk_engine.assessment import assess_risk, generate_recommendations
from app.modules.message_analysis.retrainer import lookup_user_correction

logger = logging.getLogger("trustlens.message_routes")

router = APIRouter()


def _build_identity_result_email(
    sender_name: str,
    sender_email: str,
    reply_to: str,
    claimed_org: str,
) -> Dict[str, Any]:
    """Run identity checks for an email submission."""
    name_check = check_sender_name_consistency(sender_name or "", claimed_org or "")
    reply_to_check = check_reply_to_mismatch(sender_email or "", reply_to or "")
    domain_analysis = run_full_domain_analysis(
        sender_email or "", claimed_org or "", reply_to or ""
    )

    # Compute overall identity status
    indicators = domain_analysis.get("domain_indicators", [])
    reply_mismatch = reply_to_check.get("status") == "mismatch"
    name_mismatch = name_check.get("status") in ("inconsistent", "mismatch")

    if "domain_mismatch" in indicators or "lookalike_domain" in indicators or "punycode_domain" in indicators:
        if reply_mismatch or name_mismatch:
            overall = "suspicious"
        else:
            overall = "inconsistent"
    elif reply_mismatch or "free_provider" in indicators:
        overall = "inconsistent"
    elif not sender_email:
        overall = "unknown"
    else:
        overall = "plausible"

    identity_indicators = []
    if reply_mismatch:
        identity_indicators.append("reply_to_mismatch")
    if name_mismatch:
        identity_indicators.append("display_name_mismatch")
    identity_indicators.extend(indicators)

    return {
        "name_check": name_check,
        "reply_to_check": reply_to_check,
        "domain_analysis": domain_analysis,
        "sms_sender_check": None,
        "overall_identity_status": overall,
        "identity_indicators": identity_indicators,
    }


def _build_identity_result_sms(
    sender_id: str,
    claimed_org: str,
) -> Dict[str, Any]:
    """Run identity checks for an SMS submission."""
    sms_check = check_sms_sender_id(sender_id or "", claimed_org or "")

    overall = "unknown"
    if sms_check.get("status") == "registry_match":
        overall = "plausible"
    elif sms_check.get("status") == "mismatch":
        overall = "suspicious"

    indicators = []
    if sms_check.get("status") == "mismatch":
        indicators.append("sms_sender_mismatch")

    return {
        "name_check": {"status": "not_applicable", "note": "Display name check not applicable for SMS."},
        "reply_to_check": {"status": "not_applicable", "note": "Reply-To not applicable for SMS."},
        "domain_analysis": {
            "domain_trust": {"status": "not_applicable"},
            "domain_similarity": {"status": "not_applicable"},
            "punycode_check": {"status": "not_applicable"},
            "domain_indicators": [],
        },
        "sms_sender_check": sms_check,
        "overall_identity_status": overall,
        "identity_indicators": indicators,
    }


@router.post("/analyze-message", response_model=MessageAnalysisResponse, tags=["Message Analysis"])
def analyze_message(request: EmailAnalysisRequest):
    """
    Analyze an email message for phishing, impersonation, and social engineering signals.
    Static analysis only — no outbound network requests.
    """
    try:
        return _run_analysis(
            channel="email",
            message=request.message,
            language=request.language,
            subject=request.subject or "",
            sender_name=request.sender_name or "",
            sender_email=request.sender_email or "",
            reply_to=request.reply_to or "",
            claimed_org=request.claimed_org or "",
            sender_id="",
        )
    except Exception as e:
        logger.error(f"Message analysis error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during message analysis. Please try again.",
        )


@router.post("/analyze-sms", response_model=MessageAnalysisResponse, tags=["Message Analysis"])
def analyze_sms(request: SmsAnalysisRequest):
    """
    Analyze an SMS message for phishing, impersonation, and social engineering signals.
    Static analysis only — no outbound network requests.
    """
    try:
        return _run_analysis(
            channel="sms",
            message=request.message,
            language=request.language,
            subject="",
            sender_name="",
            sender_email="",
            reply_to="",
            claimed_org=request.claimed_org or "",
            sender_id=request.sender_id or "",
        )
    except Exception as e:
        logger.error(f"SMS analysis error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during SMS analysis. Please try again.",
        )


def _run_analysis(
    channel: str,
    message: str,
    language: str,
    subject: str,
    sender_name: str,
    sender_email: str,
    reply_to: str,
    claimed_org: str,
    sender_id: str,
) -> MessageAnalysisResponse:
    """Core analysis pipeline."""
    analysis_id = str(uuid.uuid4())[:16]

    # 1. Preprocessing
    preprocessed = preprocess_message(message, subject, channel, language)
    normalized_text = preprocessed["normalized_text"]
    combined_text = preprocessed["combined_text"]

    # 2. ML message classification
    predictor = get_message_predictor()
    ml_raw = predictor.predict(normalized_text, channel, language)
    user_correction = (
        lookup_user_correction(message)
        or lookup_user_correction(combined_text)
        or lookup_user_correction(normalized_text)
    )
    if user_correction == "benign":
        ml_raw = {
            **ml_raw,
            "label": "benign",
            "confidence": 0.99,
            "suspicious_probability": 0.01,
            "note": (
                "User correction applied: this message was previously challenged as legitimate "
                "and the classifier was retrained with that label."
            ),
        }
    elif user_correction == "suspicious":
        ml_raw = {
            **ml_raw,
            "label": "suspicious",
            "confidence": max(float(ml_raw.get("confidence") or 0), 0.8),
            "suspicious_probability": max(float(ml_raw.get("suspicious_probability") or 0), 0.8),
            "note": (
                "User correction applied: this message was previously reported as still suspicious."
            ),
        }
    ml_result = MLClassificationResult(**ml_raw)

    # 3. URL extraction and analysis
    url_raw = analyze_urls_in_message(combined_text)
    url_results_items = [UrlResultItem(**r) for r in url_raw.get("results", [])]
    url_analysis = UrlAnalysisResult(
        urls_found=url_raw.get("urls_found", []),
        url_count=url_raw.get("url_count", 0),
        results=url_results_items,
        any_high_risk=url_raw.get("any_high_risk", False),
        any_phishing=url_raw.get("any_phishing", False),
        highest_risk=url_raw.get("highest_risk", "none"),
        static_analysis_notice=url_raw.get("static_analysis_notice", ""),
    )

    # 4. Identity analysis
    if channel == "email":
        identity_raw = _build_identity_result_email(
            sender_name, sender_email, reply_to, claimed_org
        )
    else:
        identity_raw = _build_identity_result_sms(sender_id, claimed_org)

    identity_result = IdentityAnalysisResult(**identity_raw)

    # 5. Social engineering detection
    se_raw = detect_social_engineering(combined_text, language)
    se_result = SocialEngineeringResult(**se_raw)

    # 6. Evidence extraction
    evidence_raw = extract_all_evidence(
        original_text=message,
        subject=subject,
        claimed_org=claimed_org,
        se_results=se_raw,
        identity_result=identity_raw,
        url_analysis=url_raw,
    )
    evidence_items = [EvidenceItem(**e) for e in evidence_raw]

    # 7. Risk assessment
    risk_raw = assess_risk(
        ml_result=ml_raw,
        url_analysis=url_raw,
        identity_result=identity_raw,
        se_results=se_raw,
        evidence_list=evidence_raw,
        channel=channel,
        user_correction=user_correction,
    )
    risk_result = RiskAssessmentResult(**risk_raw)

    # 8. Recommendations
    recommendations = generate_recommendations(
        risk_level=risk_raw["risk_level"],
        se_results=se_raw,
        url_analysis=url_raw,
        identity_result=identity_raw,
        channel=channel,
    )

    return MessageAnalysisResponse(
        analysis_id=analysis_id,
        channel=channel,
        language=language,
        risk_assessment=risk_result,
        ml_classification=ml_result,
        url_analysis=url_analysis,
        identity_analysis=identity_result,
        social_engineering=se_result,
        evidence=evidence_items,
        recommendations=recommendations,
        user_correction_applied=user_correction,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

