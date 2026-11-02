"""
Social Engineering Detection — Kannada Language Rules
------------------------------------------------------
Pattern-based detection of social engineering signals in Kannada (Unicode) text.
Also handles Kannada-English code-mixed text by combining signals.

IMPORTANT: These patterns are SECURITY INDICATORS, not proof of malicious intent.
Signals are combined by the risk engine, not treated individually as proof.
"""

import re
from typing import List, Dict, Any


# ─────────────────────────────────────────────
# A. URGENCY — Kannada
# ─────────────────────────────────────────────
# Common Kannada urgency words and phrases
URGENCY_KN_PATTERNS = [
    (re.compile(r"ತಕ್ಷಣ"), "immediate_kn"),               # Immediately
    (re.compile(r"ಈಗಲೇ"), "right_now_kn"),                # Right now
    (re.compile(r"ತ್ವರಿತ(?:ವಾಗಿ)?"), "quickly_kn"),       # Quickly/urgently
    (re.compile(r"ಇಂದು\s*ಕೊನೆ(?:ಯ\s*ದಿನ)?"), "last_day_today_kn"),  # Today is the last day
    (re.compile(r"ಅವಧಿ\s*ಮೀರಿದೆ"), "expired_kn"),         # Deadline expired
    (re.compile(r"ಕೊನೆಯ\s*ದಿನ"), "last_day_kn"),          # Last day
    (re.compile(r"ಅಂತಿಮ\s*(?:ಎಚ್ಚರಿಕೆ|ನೋಟಿಸ್|ಅವಕಾಶ)"), "final_notice_kn"),  # Final warning/notice
    (re.compile(r"ಸಮಯ\s*ಮೀರಿದೆ"), "time_over_kn"),        # Time is up
    (re.compile(r"(?:\d+)\s*(?:ಗಂಟೆ|ನಿಮಿಷ|ದಿನ)\s*(?:ಒಳಗೆ|ಮುಂಚೆ)"), "time_window_kn"),  # Within N hours/minutes/days
    (re.compile(r"ತಡ\s*ಮಾಡಬೇಡಿ"), "do_not_delay_kn"),   # Don't delay
    (re.compile(r"ಶೀಘ್ರವಾಗಿ"), "soon_kn"),                # Soon / rapidly
]

# ─────────────────────────────────────────────
# B. FEAR / THREATS — Kannada
# ─────────────────────────────────────────────
FEAR_KN_PATTERNS = [
    (re.compile(r"ಖಾತೆ\s*(?:ನಿರ್ಬಂಧ|ಸ್ಥಗಿತ|ರದ್ದು|ಮುಚ್ಚಲಾಗಿದೆ|ಬ್ಲಾಕ್)"), "account_blocked_kn"),  # Account blocked/suspended
    (re.compile(r"ಕಾನೂನು\s*ಕ್ರಮ"), "legal_action_kn"),    # Legal action
    (re.compile(r"ದಂಡ"), "penalty_kn"),                    # Fine/penalty
    (re.compile(r"ಪೊಲೀಸ್|ಸಿಬಿಐ|ಜಾರಿ\s*ನಿರ್ದೇಶನಾಲಯ"), "police_kn"),  # Police/CBI/ED
    (re.compile(r"ವಂಚನೆ\s*ಪತ್ತೆ"), "fraud_detected_kn"),  # Fraud detected
    (re.compile(r"ಅನಧಿಕೃತ\s*(?:ಪ್ರವೇಶ|ವ್ಯವಹಾರ)"), "unauthorized_kn"),  # Unauthorized access/transaction
    (re.compile(r"ಡೇಟಾ\s*ಉಲ್ಲಂಘನೆ"), "data_breach_kn"),   # Data breach
    (re.compile(r"ಕೆವೈಸಿ\s*(?:ನವೀಕರಿಸಿ|ಅವಧಿ\s*ಮೀರಿದೆ|ಪೂರ್ಣಗೊಳಿಸಿ)"), "kyc_kn"),  # KYC update/expired
    (re.compile(r"ಖಾತೆ\s*(?:ಅಮಾನ್ಯ|ಅಡಚಣೆ)"), "account_issue_kn"),  # Account invalid/problem
    (re.compile(r"ಸಾಲ\s*(?:ಬಾಕಿ|ಮರುಪಾವತಿ\s*ವಿಫಲ)"), "loan_overdue_kn"),  # Loan overdue/repayment failed
]

# ─────────────────────────────────────────────
# C. CREDENTIAL HARVESTING — Kannada
# ─────────────────────────────────────────────
CREDENTIAL_KN_PATTERNS = [
    (re.compile(r"OTP\s*(?:ಹಂಚಿಕೊಳ್ಳಿ|ನೀಡಿ|ಕಳುಹಿಸಿ|ಶೇರ್\s*ಮಾಡಿ)"), "otp_request_kn"),  # Share OTP
    (re.compile(r"(?:OTP|ಒಟಿಪಿ)\s*(?:ಅನ್ನು|:)\s*\d{4,8}"), "otp_in_msg_kn"),   # OTP in message
    (re.compile(r"ಪಾಸ್ ?ವರ್ಡ್|ಪಿನ್\s*(?:ಹಂಚಿಕೊಳ್ಳಿ|ನೀಡಿ|ಕಳುಹಿಸಿ)"), "password_kn"),  # Password/PIN request
    (re.compile(r"ಬ್ಯಾಂಕ್\s*(?:ವಿವರ|ಖಾತೆ\s*ನಂಬರ್|ವ್ಯವಹಾರ\s*ವಿವರ)"), "bank_details_kn"),  # Bank details
    (re.compile(r"ಆಧಾರ್?\s*(?:ನಂಬರ್|ಕಾರ್ಡ್)"), "aadhaar_kn"),  # Aadhaar number
    (re.compile(r"PAN\s*(?:ನಂಬರ್|ಕಾರ್ಡ್)|ಪ್ಯಾನ್\s*ನಂಬರ್"), "pan_kn"),  # PAN number
    (re.compile(r"ಯುಪಿಐ\s*ಪಿನ್|UPI\s*PIN"), "upi_pin_kn"),    # UPI PIN
    (re.compile(r"ಖಾತೆ\s*(?:ಪರಿಶೀಲಿಸಿ|ದೃಢೀಕರಿಸಿ|ಪ್ರಮಾಣೀಕರಿಸಿ)"), "account_verify_kn"),  # Verify account
    (re.compile(r"ಲಿಂಕ್\s*(?:ಕ್ಲಿಕ್|ಒತ್ತಿ)\s*(?:ಮಾಡಿ|ಪರಿಶೀಲಿಸಿ)"), "click_link_kn"),  # Click link
]

# ─────────────────────────────────────────────
# D. FINANCIAL MANIPULATION — Kannada
# ─────────────────────────────────────────────
FINANCIAL_KN_PATTERNS = [
    (re.compile(r"(?:ರೂ\.?|₹)\s*[\d,]+\s*(?:ಹಣ|ಮೊತ್ತ|ವರ್ಗಾವಣೆ)"), "amount_transfer_kn"),  # Amount transfer
    (re.compile(r"ಬಹುಮಾನ|ಇನಾಮು|ಪ್ರಶಸ್ತಿ\s*(?:ಗೆದ್ದಿದ್ದೀರಿ|ಗೆದ್ದಿದ್ದೀರ)"), "prize_won_kn"),  # Won prize
    (re.compile(r"ಹಿಂದಿರುಗಿಸು(?:ವ)?|ರಿಫಂಡ್"), "refund_kn"),  # Refund
    (re.compile(r"ಉಚಿತ\s*(?:ಕೊಡುಗೆ|ಬಹುಮಾನ|ಹಣ|ರಿಚಾರ್ಜ್)"), "free_gift_kn"),  # Free gift/money
    (re.compile(r"ಕ್ಯಾಶ್?ಬ್ಯಾಕ್|ಕ್ಯಾಶ್\s*ಬ್ಯಾಕ್"), "cashback_kn"),  # Cashback
    (re.compile(r"ಸಾಲ\s*(?:ಅನುಮೋದನೆ|ಅರ್ಜಿ|ಪ್ರಸ್ತಾಪ)"), "loan_offer_kn"),  # Loan approved/offer
    (re.compile(r"(?:ಇಎಂಐ|EMI)\s*(?:ವಿಫಲ|ಬಾಕಿ|ಮೀರಿದ)"), "emi_failed_kn"),  # EMI failed/overdue
    (re.compile(r"ಹೂಡಿಕೆ.{0,20}(?:\d+%|\d+\s*ಶೇಕಡಾ)\s*ಲಾಭ"), "investment_kn"),  # Investment returns
]

# ─────────────────────────────────────────────
# E. IMPERSONATION — Kannada
# ─────────────────────────────────────────────
IMPERSONATION_KN_PATTERNS = [
    (re.compile(r"(?:ಬ್ಯಾಂಕ್|ಸ್ಟೇಟ್\s*ಬ್ಯಾಂಕ್|ಎಸ್‌ಬಿಐ|ಎಚ್‌ಡಿಎಫ್‌ಸಿ)"), "bank_kn"),  # Bank names
    (re.compile(r"(?:ಆರ್‌ಬಿಐ|ರಿಸರ್ವ್\s*ಬ್ಯಾಂಕ್)"), "rbi_kn"),  # RBI
    (re.compile(r"(?:ಆದಾಯ\s*ತೆರಿಗೆ|ಜಿಎಸ್‌ಟಿ|ಕಸ್ಟಮ್ಸ್)"), "tax_dept_kn"),  # Income Tax/GST
    (re.compile(r"(?:ಪೊಲೀಸ್|ಸಿಬಿಐ|ನ್ಯಾಯಾಲಯ)"), "authority_kn"),  # Police/CBI/Court
    (re.compile(r"(?:ವಿಶ್ವವಿದ್ಯಾಲಯ|ಕಾಲೇಜು).{0,20}(?:ಶುಲ್ಕ|ಪ್ರವೇಶ|ಪರೀಕ್ಷೆ)"), "university_kn"),  # University fees/exam
    (re.compile(r"ಗ್ರಾಹಕ\s*(?:ಸೇವೆ|ಸಹಾಯ|ಕೇಂದ್ರ)"), "customer_service_kn"),  # Customer service
    (re.compile(r"(?:ಅಮೇಜಾನ್|ಫ್ಲಿಪ್ ?ಕಾರ್ಟ್|ಸ್ವಿಗ್ಗಿ|ಜೊಮ್ಯಾಟೊ).{0,20}(?:ಡೆಲಿವರಿ|ಆರ್ಡರ್)"), "ecommerce_kn"),  # E-commerce delivery
]


def _find_all_matches_kn(text: str, patterns: List) -> List[Dict[str, Any]]:
    """Find all matching Kannada patterns and return structured signals."""
    found = []
    seen_signals = set()
    for pattern, signal_name in patterns:
        if signal_name in seen_signals:
            continue
        match = pattern.search(text)
        if match:
            start = max(0, match.start() - 10)
            end = min(len(text), match.end() + 10)
            excerpt = text[start:end].strip()
            found.append({
                "signal": signal_name,
                "evidence": excerpt,
                "full_match": text[match.start():match.end()].strip(),
            })
            seen_signals.add(signal_name)
    return found


def detect_kannada_signals(text: str) -> Dict[str, Any]:
    """
    Detect social-engineering signals in Kannada text (Unicode).
    Also works on code-mixed Kannada-English text.
    Returns a structured dictionary of detected categories and their evidence.
    """
    if not text or not text.strip():
        return {
            "urgency": [],
            "fear": [],
            "credential_request": [],
            "financial": [],
            "impersonation": [],
            "total_signals": 0,
        }

    urgency = _find_all_matches_kn(text, URGENCY_KN_PATTERNS)
    fear = _find_all_matches_kn(text, FEAR_KN_PATTERNS)
    cred = _find_all_matches_kn(text, CREDENTIAL_KN_PATTERNS)
    financial = _find_all_matches_kn(text, FINANCIAL_KN_PATTERNS)
    impersonation = _find_all_matches_kn(text, IMPERSONATION_KN_PATTERNS)

    total = len(urgency) + len(fear) + len(cred) + len(financial) + len(impersonation)

    return {
        "urgency": urgency,
        "fear": fear,
        "credential_request": cred,
        "financial": financial,
        "impersonation": impersonation,
        "total_signals": total,
    }

