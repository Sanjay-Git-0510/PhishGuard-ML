"""
Hybrid Risk Assessment Engine
------------------------------
Combines signals from all detection modules into a final risk tier.

Risk Tiers:
    HIGH   — Multiple independent strong indicators or a particularly serious combination
    MEDIUM — Suspicious patterns, inconclusive evidence, unknown provenance
    LOW    — No significant suspicious indicators detected

IMPORTANT:
- An unknown sender alone does NOT produce HIGH risk.
- A suspicious keyword alone does NOT produce HIGH risk.
- A model score is NOT treated as proof of phishing.
- Risk rules are configurable and explainable.

All reasoning is documented in the returned explanation.
"""

from typing import Dict, Any, List, Optional


def _count_high_evidence(evidence_list: List[Dict]) -> int:
    return sum(1 for e in evidence_list if e.get("severity") == "high")


def _count_medium_evidence(evidence_list: List[Dict]) -> int:
    return sum(1 for e in evidence_list if e.get("severity") == "medium")


def _has_credential_request(se_results: Dict) -> bool:
    return bool(se_results.get("has_credential_request", False))


def _has_url_phishing(url_analysis: Dict) -> bool:
    return url_analysis.get("any_phishing", False)


def _has_url_high_risk(url_analysis: Dict) -> bool:
    return url_analysis.get("any_high_risk", False)


def _has_identity_mismatch(identity_result: Dict) -> bool:
    indicators = identity_result.get("domain_analysis", {}).get("domain_indicators", [])
    return "domain_mismatch" in indicators or "lookalike_domain" in indicators or "punycode_domain" in indicators


def _has_reply_to_mismatch(identity_result: Dict) -> bool:
    return identity_result.get("reply_to_check", {}).get("status") == "mismatch"


def _message_ml_is_suspicious(ml_result: Dict) -> bool:
    return ml_result.get("label") == "suspicious" and ml_result.get("suspicious_probability", 0) >= 0.6


def assess_risk(
    ml_result: Dict[str, Any],
    url_analysis: Dict[str, Any],
    identity_result: Dict[str, Any],
    se_results: Dict[str, Any],
    evidence_list: List[Dict[str, Any]],
    channel: str = "email",
    user_correction: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compute the overall risk tier and provide a human-readable explanation.

    Returns:
        {
            "risk_level": "high" | "medium" | "low",
            "risk_score": int (0-100, indicative only),
            "triggered_rules": List[str],
            "explanation": str,
            "contributing_factors": List[str],
        }
    """
    triggered_rules: List[str] = []
    contributing_factors: List[str] = []
    high_count = _count_high_evidence(evidence_list)
    medium_count = _count_medium_evidence(evidence_list)

    # ─────────────────────────────────────────────
    # HIGH RISK RULES
    # ─────────────────────────────────────────────

    # Rule H1: Credential request + identity mismatch
    if _has_credential_request(se_results) and _has_identity_mismatch(identity_result):
        triggered_rules.append("H1")
        contributing_factors.append(
            "A credential request (OTP, password, PIN) was detected combined with sender identity inconsistencies."
        )

    # Rule H2: Credential request + suspicious URL
    if _has_credential_request(se_results) and _has_url_phishing(url_analysis):
        triggered_rules.append("H2")
        contributing_factors.append(
            "A credential request was detected in a message that also contains a suspicious link."
        )

    # Rule H3: Financial request + suspicious URL
    if se_results.get("has_financial", False) and _has_url_phishing(url_analysis):
        triggered_rules.append("H3")
        contributing_factors.append(
            "A financial request was detected in a message containing a suspicious URL."
        )

    # Rule H4: Reply-To mismatch + fear/threat language
    if _has_reply_to_mismatch(identity_result) and se_results.get("has_fear", False):
        triggered_rules.append("H4")
        contributing_factors.append(
            "Reply-To address differs from the sender domain and the message contains threat language."
        )

    # Rule H5: Lookalike/punycode domain + any suspicious signals
    if _has_identity_mismatch(identity_result) and (
        se_results.get("has_credential_request", False)
        or se_results.get("has_fear", False)
        or _has_url_phishing(url_analysis)
    ):
        triggered_rules.append("H5")
        contributing_factors.append(
            "A domain impersonation indicator (lookalike domain or punycode) was combined with additional suspicious signals."
        )

    # Rule H6: Three or more distinct high-severity evidence items from independent sources
    high_sources = set(e["source"] for e in evidence_list if e.get("severity") == "high")
    if len(high_sources) >= 2 and high_count >= 3:
        triggered_rules.append("H6")
        contributing_factors.append(
            f"Multiple high-severity signals detected across {len(high_sources)} independent sources "
            f"({', '.join(high_sources)})."
        )

    # ─────────────────────────────────────────────
    # MEDIUM RISK RULES
    # ─────────────────────────────────────────────

    # Rule M1: ML model flags suspicious + any corroborating indicator
    if _message_ml_is_suspicious(ml_result) and (
        se_results.get("total_signals", 0) > 0
        or _has_url_high_risk(url_analysis)
        or _has_identity_mismatch(identity_result)
    ):
        triggered_rules.append("M1")
        contributing_factors.append(
            f"Message ML classifier flagged this as suspicious "
            f"(probability: {ml_result.get('suspicious_probability', 0):.1%}) "
            "with at least one corroborating security indicator."
        )

    # Rule M2: Credential request alone (without identity mismatch)
    if _has_credential_request(se_results) and not any(
        r in triggered_rules for r in ("H1", "H2")
    ):
        triggered_rules.append("M2")
        contributing_factors.append(
            "The message requests sensitive information (OTP, password, PIN) "
            "but no sender identity mismatch was detected."
        )

    # Rule M3: Unknown/free-provider sender + financial content
    domain_status = identity_result.get("domain_analysis", {}).get("domain_trust", {}).get("status", "")
    if domain_status in ("free_provider", "unregistered_org") and se_results.get("has_financial", False):
        triggered_rules.append("M3")
        contributing_factors.append(
            "A message containing financial content came from an unregistered or free email domain."
        )

    # Rule M4: URL found with medium risk or shortener
    if url_analysis.get("url_count", 0) > 0 and not _has_url_phishing(url_analysis):
        shorteners = [
            r for r in url_analysis.get("results", [])
            if r.get("metadata", {}).get("is_shortener")
        ]
        if shorteners:
            triggered_rules.append("M4")
            contributing_factors.append(
                "The message contains a URL shortener link, which masks the actual destination."
            )

    # Rule M5: Urgency + impersonation (without credentials)
    if se_results.get("has_urgency", False) and se_results.get("has_impersonation", False) \
            and not _has_credential_request(se_results):
        triggered_rules.append("M5")
        contributing_factors.append(
            "The message combines urgency with a claim to represent a known organization."
        )

    # Rule M6: Multiple medium evidence items
    if medium_count >= 3 and not triggered_rules:
        triggered_rules.append("M6")
        contributing_factors.append(
            f"Multiple suspicious indicators detected ({medium_count} medium-severity signals)."
        )

    # ─────────────────────────────────────────────
    # DETERMINE FINAL RISK LEVEL
    # ─────────────────────────────────────────────

    high_rules = [r for r in triggered_rules if r.startswith("H")]
    medium_rules = [r for r in triggered_rules if r.startswith("M")]

    if high_rules:
        risk_level = "high"
        risk_score = min(90 + len(high_rules) * 2, 98)
    elif medium_rules:
        risk_level = "medium"
        risk_score = 40 + len(medium_rules) * 8
        risk_score = min(risk_score, 74)
    else:
        risk_level = "low"
        risk_score = max(5, high_count * 3 + medium_count * 2)
        risk_score = min(risk_score, 30)

    # User challenged a false positive: honor that correction on re-analysis.
    if user_correction == "benign":
        triggered_rules.append("U1")
        contributing_factors.append(
            "A user correction marked this exact message as legitimate. "
            "The previous classification was treated as a false positive."
        )
        risk_level = "low"
        risk_score = min(risk_score, 18)
    elif user_correction == "suspicious" and risk_level == "low":
        triggered_rules.append("U2")
        contributing_factors.append(
            "A user correction marked this exact message as still suspicious."
        )
        risk_level = "medium"
        risk_score = max(risk_score, 45)

    # ─────────────────────────────────────────────
    # EXPLANATION
    # ─────────────────────────────────────────────

    if user_correction == "benign":
        explanation = (
            "This message was previously challenged as legitimate/benign. "
            "The classifier was retrained with that correction, so this analysis "
            "treats the prior flag as a false positive. Still verify unexpected "
            "requests through a known official channel."
        )
    elif risk_level == "high":
        explanation = (
            "Multiple independent high-confidence indicators were detected. "
            "This message exhibits characteristics strongly associated with phishing, "
            "impersonation, or social engineering attacks."
        )
    elif risk_level == "medium":
        explanation = (
            "Suspicious patterns were detected but there is insufficient certainty for a HIGH classification. "
            "The message warrants independent verification before taking any action."
        )
    else:
        explanation = (
            "No significant suspicious indicators were detected. "
            "The message does not exhibit strong signals of phishing or social engineering. "
            "Continue to exercise caution with unexpected requests involving sensitive information."
        )

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "triggered_rules": triggered_rules,
        "explanation": explanation,
        "contributing_factors": contributing_factors,
        "signal_summary": {
            "high_severity_evidence": high_count,
            "medium_severity_evidence": medium_count,
            "se_signals_total": se_results.get("total_signals", 0),
            "urls_analyzed": url_analysis.get("url_count", 0),
            "urls_phishing": len([r for r in url_analysis.get("results", []) if r.get("prediction") == "phishing"]),
        },
        "risk_note": (
            "Risk levels are computed from security indicators and are not proof of malicious intent. "
            "A LOW result does not guarantee a message is safe. "
            "Always verify unexpected requests through official communication channels."
        ),
    }


def generate_recommendations(
    risk_level: str,
    se_results: Dict[str, Any],
    url_analysis: Dict[str, Any],
    identity_result: Dict[str, Any],
    channel: str = "email",
) -> List[str]:
    """
    Generate contextual safe-verification recommendations based on detected signals.
    """
    recs = [
        "Verify this request through a known official channel: open the organization's "
        "app or website yourself, or call a number you already trust (for example, the "
        "number printed on your bank card or a previous genuine statement). Do not use "
        "links, phone numbers, or reply addresses supplied in this message."
    ]

    if risk_level == "high":
        recs.append("Do not click any links in this message.")
        if se_results.get("has_credential_request"):
            recs.append(
                "Do not share any OTPs, passwords, PINs, or banking credentials — "
                "no legitimate organization will ever ask for these via message."
            )
        if url_analysis.get("any_phishing"):
            recs.append(
                "The URLs in this message were flagged as suspicious. "
                "Do not visit them."
            )
        recs.append(
            "Open the organization's official mobile application or website independently "
            "(type the address manually — do not copy it from this message)."
        )
        recs.append(
            "Contact the organization only through a phone number or email address you find "
            "on their official website or on the back of your bank card — "
            "never use contact details supplied in the suspicious message."
        )
        recs.append(
            "If you suspect fraud, report this message to your bank's fraud helpline "
            "or to the national cybercrime portal (cybercrime.gov.in for India)."
        )

    elif risk_level == "medium":
        recs.append("Verify the sender independently before responding.")
        recs.append(
            "If the message claims to be from an organization, check the organization's official "
            "website for the correct contact details and verify with them directly."
        )
        recs.append("Avoid providing personal or financial information based solely on this message.")
        if url_analysis.get("url_count", 0) > 0:
            recs.append(
                "If you need to visit a linked website, type the official address manually "
                "rather than clicking the link in this message."
            )
        if _has_reply_to_mismatch(identity_result):
            recs.append(
                "The Reply-To address differs from the sender's domain. "
                "Do not rely on the supplied contact information in this message."
            )

    else:  # LOW
        recs.append(
            "No significant suspicious indicators were detected in this message."
        )
        recs.append(
            "Even for messages that appear legitimate, always verify unexpected requests "
            "involving sensitive information or financial transactions through official channels."
        )

    return recs

