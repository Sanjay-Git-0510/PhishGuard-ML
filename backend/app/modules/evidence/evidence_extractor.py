"""
Evidence Extraction Engine
---------------------------
Extracts verifiable, quoted textual evidence from submitted messages
and metadata fields.

CRITICAL: Every textual evidence excerpt MUST correspond to an actual substring
of the submitted original message or metadata. No fabricated evidence.

Evidence items have the structure:
{
    "signal": str,           # signal type identifier
    "severity": str,         # "high", "medium", "low", "info"
    "source": str,           # "message", "subject", "sender", "reply_to", "url", "identity"
    "evidence": str,         # exact quoted substring from the source
    "explanation": str,      # plain-language explanation of the risk
}
"""

import re
from typing import List, Dict, Any, Optional


def _excerpt(text: str, match_str: str, window: int = 60) -> str:
    """
    Find match_str in text and return a surrounding excerpt.
    Falls back to the match itself if not found in text.
    """
    if not text or not match_str:
        return match_str or ""

    idx = text.lower().find(match_str.lower())
    if idx == -1:
        # Try partial match
        for i in range(len(match_str), 3, -1):
            idx = text.lower().find(match_str.lower()[:i])
            if idx != -1:
                break

    if idx == -1:
        # Return truncated match string as fallback
        return match_str[:100]

    start = max(0, idx - 10)
    end = min(len(text), idx + len(match_str) + 10)
    excerpt = text[start:end].strip()
    return excerpt


def _signal_key(signal_name: str) -> str:
    """Normalize English/Hindi/Kannada signal ids so severity is language-agnostic."""
    name = (signal_name or "").lower()
    for suffix in ("_hi", "_kn"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    aliases = {
        "password": "password_request",
        "pin_request": "password_request",
        "otp_in_msg": "otp_request",
        "account_issue": "account_blocked",
        "prize_won": "prize_claim",
        "amount_transfer": "fund_transfer_request",
        "upi_pin": "cvv_request",
        "aadhaar": "card_details",
        "bank_details": "banking_credentials",
        "cvv_request": "cvv_request",
    }
    return aliases.get(name, name)


def extract_evidence_from_se_signals(
    original_text: str,
    se_results: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Convert social engineering detection results into verifiable evidence items.
    Only includes items that are verifiable against the original text.
    """
    evidence = []
    source = "message"

    # URGENCY signals
    for signal in se_results.get("urgency", []):
        raw = signal.get("evidence", "") or signal.get("full_match", "")
        if raw and raw in original_text:
            evidence.append({
                "signal": f"urgency/{signal['signal']}",
                "severity": "medium",
                "source": source,
                "evidence": raw,
                "explanation": (
                    "The message creates time pressure or urgency. "
                    "Legitimate organizations typically allow reasonable time to respond. "
                    "Urgency alone does not indicate a phishing attempt."
                ),
            })

    # FEAR / THREAT signals
    for signal in se_results.get("fear", []):
        raw = signal.get("evidence", "") or signal.get("full_match", "")
        if raw and raw in original_text:
            severity = "high" if _signal_key(signal["signal"]) in (
                "account_blocked", "legal_action", "criminal_charges", "data_breach"
            ) else "medium"
            evidence.append({
                "signal": f"fear/{signal['signal']}",
                "severity": severity,
                "source": source,
                "evidence": raw,
                "explanation": (
                    "The message uses fear or threat language (account blocking, legal action, breach notification). "
                    "Scammers commonly use threats to pressure victims into acting without verification."
                ),
            })

    # CREDENTIAL REQUEST signals
    for signal in se_results.get("credential_request", []):
        raw = signal.get("evidence", "") or signal.get("full_match", "")
        if raw and raw in original_text:
            severity = "high" if _signal_key(signal["signal"]) in (
                "otp_request", "password_request", "banking_credentials",
                "card_details", "cvv_request"
            ) else "medium"
            evidence.append({
                "signal": f"credential/{signal['signal']}",
                "severity": severity,
                "source": source,
                "evidence": raw,
                "explanation": (
                    "The message requests sensitive authentication information. "
                    "Legitimate banks, universities and government agencies never ask for OTPs, "
                    "passwords, PINs or CVV numbers via message."
                ),
            })

    # FINANCIAL MANIPULATION signals
    for signal in se_results.get("financial", []):
        raw = signal.get("evidence", "") or signal.get("full_match", "")
        if raw and raw in original_text:
            severity = "high" if _signal_key(signal["signal"]) in (
                "fund_transfer_request", "payment_demand", "prize_claim"
            ) else "medium"
            evidence.append({
                "signal": f"financial/{signal['signal']}",
                "severity": severity,
                "source": source,
                "evidence": raw,
                "explanation": (
                    "The message involves financial content (payment demand, refund claim, prize offer). "
                    "Unexpected financial requests require independent verification through official channels."
                ),
            })

    # IMPERSONATION signals
    for signal in se_results.get("impersonation", []):
        raw = signal.get("evidence", "") or signal.get("full_match", "")
        if raw and raw in original_text:
            evidence.append({
                "signal": f"impersonation/{signal['signal']}",
                "severity": "medium",
                "source": source,
                "evidence": raw,
                "explanation": (
                    "The message references or claims to be from a bank, government body, "
                    "university, or other trusted organization. "
                    "Always verify the sender's actual email domain or phone number independently."
                ),
            })

    return evidence


def extract_identity_evidence(
    identity_result: Dict[str, Any],
    claimed_org: str,
) -> List[Dict[str, Any]]:
    """
    Convert identity analysis results into evidence items.
    """
    evidence = []

    # Domain trust check
    domain_trust = identity_result.get("domain_analysis", {}).get("domain_trust", {})
    if domain_trust.get("status") == "mismatch":
        sender_domain = domain_trust.get("sender_domain", "")
        expected = ", ".join(domain_trust.get("expected_domains", []))
        evidence.append({
            "signal": "identity/domain_mismatch",
            "severity": "high",
            "source": "sender",
            "evidence": f"Sender domain: {sender_domain}",
            "explanation": (
                f"The sender's email domain '{sender_domain}' does not match the expected "
                f"domain(s) for '{claimed_org}': {expected}. "
                "This is a strong indicator that the sender may not be who they claim to be."
            ),
        })

    if domain_trust.get("status") == "free_provider":
        sender_domain = domain_trust.get("sender_domain", "")
        evidence.append({
            "signal": "identity/free_email_provider",
            "severity": "medium",
            "source": "sender",
            "evidence": f"Sender domain: {sender_domain}",
            "explanation": (
                f"The message appears to come from a free email provider ({sender_domain}) "
                f"while claiming to represent '{claimed_org}'. "
                "Legitimate organizations typically use their own domain name for official communications."
            ),
        })

    # Lookalike domain
    similarity = identity_result.get("domain_analysis", {}).get("domain_similarity", {})
    if similarity.get("status") == "suspicious_similarity":
        evidence.append({
            "signal": "identity/lookalike_domain",
            "severity": "high",
            "source": "sender",
            "evidence": f"Sender domain: {similarity.get('sender_domain', '')}",
            "explanation": (
                f"The sender domain is very similar to '{similarity.get('similar_to', '')}' "
                f"(edit distance: {similarity.get('edit_distance', '?')}). "
                "This may be a lookalike or typosquat domain designed to appear legitimate."
            ),
        })

    # Punycode
    punycode = identity_result.get("domain_analysis", {}).get("punycode_check", {})
    if punycode.get("status") == "punycode_detected":
        evidence.append({
            "signal": "identity/punycode_domain",
            "severity": "high",
            "source": "sender",
            "evidence": f"Domain: {punycode.get('domain', '')}",
            "explanation": (
                "The sender's domain uses punycode encoding (xn--), which can make a fake domain "
                "appear identical to a legitimate one in many email clients."
            ),
        })

    # Reply-To mismatch
    reply_to_check = identity_result.get("reply_to_check", {})
    if reply_to_check.get("status") == "mismatch":
        evidence.append({
            "signal": "identity/reply_to_mismatch",
            "severity": "high",
            "source": "reply_to",
            "evidence": (
                f"Sender domain: {reply_to_check.get('sender_domain', '')} | "
                f"Reply-To domain: {reply_to_check.get('reply_to_domain', '')}"
            ),
            "explanation": (
                "The Reply-To address points to a different domain than the sender. "
                "This means your reply will go to a different organization than the apparent sender. "
                "This is a common phishing technique to intercept your response."
            ),
        })

    # Sender name mismatch
    name_check = identity_result.get("name_check", {})
    if name_check.get("status") in ("inconsistent", "mismatch"):
        evidence.append({
            "signal": "identity/display_name_mismatch",
            "severity": "medium",
            "source": "sender",
            "evidence": f"Display name: {name_check.get('sender_name', '')}",
            "explanation": (
                f"The sender's display name does not match known names for '{claimed_org}'. "
                "The display name in an email can be set to anything and does not verify identity."
            ),
        })

    # SMS sender ID mismatch
    sms_check = identity_result.get("sms_sender_check") or {}
    if sms_check.get("status") == "mismatch":
        evidence.append({
            "signal": "identity/sms_sender_mismatch",
            "severity": "high",
            "source": "sender",
            "evidence": f"SMS Sender ID: {sms_check.get('sender_id', '')}",
            "explanation": (
                f"The SMS sender ID does not match known IDs for '{claimed_org}'. "
                f"Expected: {', '.join(sms_check.get('known_sender_ids', []))}. "
                "Note: SMS sender IDs can be spoofed; even a matching ID does not guarantee authenticity."
            ),
        })

    return evidence


def extract_url_evidence(url_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert URL analysis results into evidence items.
    """
    evidence = []

    for url_result in url_analysis.get("results", []):
        url = url_result.get("url", "")
        prediction = url_result.get("prediction", "")
        risk_level = url_result.get("risk_level", "")

        if prediction == "phishing" or risk_level in ("high", "medium"):
            severity = "high" if risk_level == "high" else "medium"
            reasons_text = "; ".join(url_result.get("reasons", []))
            evidence.append({
                "signal": "url/phishing_detected",
                "severity": severity,
                "source": "url",
                "evidence": url,
                "explanation": (
                    f"URL analysis flagged this link as suspicious (risk: {risk_level}). "
                    f"Indicators: {reasons_text}. "
                    "The URL is shown as plain text and was NOT visited."
                ),
            })
        elif url_result.get("metadata", {}).get("is_shortener"):
            evidence.append({
                "signal": "url/shortener_detected",
                "severity": "medium",
                "source": "url",
                "evidence": url,
                "explanation": (
                    "This URL uses a link shortening service, which hides the actual destination. "
                    "Shortened URLs are not inherently malicious but obscure the target domain. "
                    "Verify the organization through official channels before clicking."
                ),
            })

    return evidence


def extract_all_evidence(
    original_text: str,
    subject: str,
    claimed_org: str,
    se_results: Dict[str, Any],
    identity_result: Dict[str, Any],
    url_analysis: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Consolidate all evidence from all modules into a single list.
    Orders evidence by severity (high first).
    """
    all_evidence = []

    # Combine subject and body for SE evidence
    combined_text = f"{subject}\n{original_text}".strip() if subject else original_text

    se_evidence = extract_evidence_from_se_signals(combined_text, se_results)
    identity_evidence = extract_identity_evidence(identity_result, claimed_org)
    url_evidence = extract_url_evidence(url_analysis)

    all_evidence.extend(se_evidence)
    all_evidence.extend(identity_evidence)
    all_evidence.extend(url_evidence)

    # Sort by severity
    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    all_evidence.sort(key=lambda e: severity_order.get(e.get("severity", "info"), 4))

    return all_evidence

