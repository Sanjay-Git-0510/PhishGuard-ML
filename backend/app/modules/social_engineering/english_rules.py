"""
Social Engineering Detection — English Language Rules
------------------------------------------------------
Pattern-based detection of social engineering signals in English text.
Returns structured signal objects with exact evidence excerpts.

IMPORTANT: These patterns are SECURITY INDICATORS, not proof of malicious intent.
A legitimate message may contain urgency or payment-related language.
Signals are combined by the risk engine, not treated individually as proof.
"""

import re
from typing import List, Dict, Any

# ─────────────────────────────────────────────
# A. URGENCY MANIPULATION
# ─────────────────────────────────────────────
URGENCY_PATTERNS = [
    (re.compile(r"\bact\s+(?:now|immediately|urgently|at\s+once)\b", re.I), "act_now"),
    (re.compile(r"\burgent(?:ly)?\s+(?:action|verification|update|response|attention)\b", re.I), "urgent_action"),
    (re.compile(r"\bimmediate(?:ly)?\s+(?:action|verification|update|response|attention)\b", re.I), "immediate_action"),
    (re.compile(r"\bwithin\s+(?:\d+\s+)?(?:hour|hours|minute|minutes|day|days)\b", re.I), "time_window"),
    (re.compile(r"\blast\s+(?:day|chance|opportunity|notice)\b", re.I), "last_chance"),
    (re.compile(r"\bexpires?\s+(?:today|soon|in\s+\d+\s+(?:hour|day|minute))\b", re.I), "expiry_pressure"),
    (re.compile(r"\bdeadline\s+(?:is|has\s+passed|approaching)\b", re.I), "deadline"),
    (re.compile(r"\bfinal\s+(?:notice|warning|reminder|opportunity)\b", re.I), "final_notice"),
    (re.compile(r"\btime[- ]sensitive\b", re.I), "time_sensitive"),
    (re.compile(r"\bdo\s+not\s+(?:delay|ignore|miss)\b", re.I), "do_not_delay"),
    (re.compile(r"\bresponse\s+(?:required|needed)\s+(?:immediately|urgently|within)\b", re.I), "response_required"),
    (re.compile(r"\byour\s+account\s+will\s+(?:be\s+)?(?:closed|blocked|suspended|terminated|deleted)\b", re.I), "account_closure_threat"),
]

# ─────────────────────────────────────────────
# B. FEAR AND THREATS
# ─────────────────────────────────────────────
FEAR_PATTERNS = [
    (re.compile(r"\baccount\s+(?:has\s+been\s+|is\s+)?(?:blocked|suspended|disabled|locked|frozen|terminated)\b", re.I), "account_blocked"),
    (re.compile(r"\bsuspended\b", re.I), "suspended"),
    (re.compile(r"\blegal\s+action\b", re.I), "legal_action"),
    (re.compile(r"\blaw(?:suit|yer|enforcement)?\b.{0,30}\b(?:taken|filed|initiated|proceed)\b", re.I), "lawsuit"),
    (re.compile(r"\bcriminal\s+(?:charges|complaint|action|proceeding)\b", re.I), "criminal_charges"),
    (re.compile(r"\bpenalty\b|\bpenalties\b", re.I), "penalty"),
    (re.compile(r"\bfine\s+of\s+(?:Rs\.?|INR|USD|\$|£|€)?\s*[\d,]+\b", re.I), "fine"),
    (re.compile(r"\byour\s+(?:data|information|account|access)\s+(?:has\s+been\s+)?(?:compromised|breached|stolen|exposed)\b", re.I), "data_breach"),
    (re.compile(r"\bunauthorized\s+(?:access|login|activity|transaction)\b", re.I), "unauthorized_access"),
    (re.compile(r"\bsuspicious\s+(?:activity|login|transaction|access)\s+detected\b", re.I), "suspicious_activity"),
    (re.compile(r"\bwe\s+have\s+detected\s+(?:unusual|suspicious|unauthorized)\b", re.I), "detected_activity"),
    (re.compile(r"\byour\s+(?:KYC|account)\s+(?:has\s+)?(?:expired|is\s+invalid|needs?\s+update)\b", re.I), "kyc_expired"),
    (re.compile(r"\bwarrant\b|\bpolice\b|\bCBI\b|\bED\b|\bIncome\s+Tax\b.{0,30}\bnotice\b", re.I), "authority_threat"),
]

# ─────────────────────────────────────────────
# C. CREDENTIAL HARVESTING
# ─────────────────────────────────────────────
CREDENTIAL_PATTERNS = [
    (re.compile(r"\b(?:share|enter|provide|submit|send|confirm|disclose)\b.{0,40}\b(?:OTP|one[- ]time\s+password)\b", re.I), "otp_request"),
    (re.compile(r"\b(?:your\s+)?OTP\s+(?:is|:)\s*\d{4,8}\b", re.I), "otp_in_message"),
    (re.compile(r"\b(?:share|enter|provide|confirm)\b.{0,40}\b(?:password|passcode|PIN|MPIN|UPIN|UPI\s+PIN)\b", re.I), "password_request"),
    (re.compile(r"\b(?:banking|net\s*banking|login)\s+(?:credentials|details|password|username)\b", re.I), "banking_credentials"),
    (re.compile(r"\bcard\s+(?:number|details|PIN|CVV|expiry)\b", re.I), "card_details"),
    (re.compile(r"\bCVV\b|\bCVV2\b", re.I), "cvv_request"),
    (re.compile(r"\bverif(?:y|ication)\s+(?:your\s+)?(?:identity|account|details|credentials)\b", re.I), "identity_verification"),
    (re.compile(r"\b(?:click|tap|follow)\b.{0,30}\blink\b.{0,30}\b(?:verify|confirm|update|validate)\b", re.I), "link_verification"),
    (re.compile(r"\bupdate\s+your\s+(?:KYC|profile|credentials|banking\s+details|personal\s+details)\b", re.I), "kyc_update"),
    (re.compile(r"\bregister(?:ed)?\s+(?:mobile|phone|number)\b.{0,30}\b(?:verify|confirm|update)\b", re.I), "mobile_verification"),
    (re.compile(r"\b2FA\b|\btwo[- ]factor\b", re.I), "2fa_mention"),
    (re.compile(r"\bsecret\s+(?:question|answer|key)\b", re.I), "secret_question"),
]

# ─────────────────────────────────────────────
# D. FINANCIAL MANIPULATION
# ─────────────────────────────────────────────
FINANCIAL_PATTERNS = [
    (re.compile(r"\btr(?:ansfer|x)\s+(?:Rs\.?|INR|USD|\$|£|€)?\s*[\d,]+\b", re.I), "fund_transfer_request"),
    (re.compile(r"\bpay(?:ment)?\s+(?:of\s+)?(?:Rs\.?|INR|USD|\$|£|€)?\s*[\d,]+\b", re.I), "payment_demand"),
    (re.compile(r"\brefund\s+(?:of\s+)?(?:Rs\.?|INR|USD|\$|£|€)?\s*[\d,]+\b", re.I), "refund_claim"),
    (re.compile(r"\b(?:won|win|winner|winning|congratulations)\b.{0,60}\b(?:prize|lottery|reward|gift|cash|amount)\b", re.I), "prize_claim"),
    (re.compile(r"\bcashback\s+(?:of\s+)?(?:Rs\.?|INR|USD|\$|£|€)?\s*[\d,]+\b", re.I), "cashback_offer"),
    (re.compile(r"\bfree\s+(?:gift|reward|money|cash|prize)\b", re.I), "free_reward"),
    (re.compile(r"\bclaim\s+(?:your\s+)?(?:reward|prize|refund|cashback|bonus)\b", re.I), "claim_reward"),
    (re.compile(r"\bbonus\s+(?:of\s+)?(?:Rs\.?|INR|USD|\$|£|€)?\s*[\d,]+\b", re.I), "bonus_offer"),
    (re.compile(r"\bEMI\s+(?:bounce|fail|overdue|pending)\b", re.I), "emi_overdue"),
    (re.compile(r"\bloan\s+(?:approved|offer|pre-?approved)\b", re.I), "loan_offer"),
    (re.compile(r"\b(?:investment|profit|return)\s+(?:of\s+)?(?:\d+%|\d+\s+percent)\b", re.I), "investment_scheme"),
    (re.compile(r"\bGST\s+(?:pending|due|refund|notice)\b", re.I), "gst_notice"),
]

# ─────────────────────────────────────────────
# E. IMPERSONATION
# ─────────────────────────────────────────────
IMPERSONATION_PATTERNS = [
    (re.compile(r"\b(?:State\s+Bank|SBI|HDFC|ICICI|Axis|Kotak|PNB|Bank\s+of\s+Baroda|Canara|Federal|IDBI)\b", re.I), "bank_impersonation"),
    (re.compile(r"\b(?:NPCI|UPI|BHIM|PhonePe|Google\s+Pay|Paytm|Amazon\s+Pay|WhatsApp\s+Pay)\b", re.I), "payment_provider_impersonation"),
    (re.compile(r"\b(?:RBI|Reserve\s+Bank|SEBI|IRDAI|TRAI)\b", re.I), "regulator_impersonation"),
    (re.compile(r"\b(?:IT\s+Department|Income\s+Tax|GST\s+Department|Customs)\b", re.I), "govt_dept_impersonation"),
    (re.compile(r"\b(?:police|CBI|ED|Enforcement\s+Directorate)\b", re.I), "law_enforcement_impersonation"),
    (re.compile(r"\b(?:university|college|institute|IIT|IIM|AIIMS)\b.{0,20}\b(?:fees?|admission|exam|result)\b", re.I), "university_impersonation"),
    (re.compile(r"\b(?:Amazon|Flipkart|Swiggy|Zomato|Ola|Uber|Meesho|Myntra)\b.{0,30}\b(?:delivery|order|refund|customer\s+care)\b", re.I), "ecommerce_impersonation"),
    (re.compile(r"\bcustomer\s+(?:care|service|support)\s+(?:team|department)\b", re.I), "customer_support_claim"),
    (re.compile(r"\bofficial\s+representative\b|\bauthorized\s+(?:agent|representative)\b", re.I), "authority_claim"),
    (re.compile(r"\bwe\s+are\s+(?:from|calling\s+from|writing\s+from)\b.{0,30}\b(?:bank|government|RBI|TRAI)\b", re.I), "direct_impersonation"),
]


def _find_first_match(text: str, patterns: List) -> Dict[str, Any]:
    """Find the first matching pattern in text and return signal + evidence."""
    for pattern, signal_name in patterns:
        match = pattern.search(text)
        if match:
            # Extract a context window around the match
            start = max(0, match.start() - 15)
            end = min(len(text), match.end() + 15)
            excerpt = text[start:end].strip()
            return {"matched": True, "signal": signal_name, "evidence": excerpt, "span": (match.start(), match.end())}
    return {"matched": False}


def _find_all_matches(text: str, patterns: List) -> List[Dict[str, Any]]:
    """Find all matching patterns in text and return list of signals."""
    found = []
    seen_signals = set()
    for pattern, signal_name in patterns:
        if signal_name in seen_signals:
            continue
        match = pattern.search(text)
        if match:
            start = max(0, match.start() - 15)
            end = min(len(text), match.end() + 15)
            excerpt = text[start:end].strip()
            found.append({
                "signal": signal_name,
                "evidence": excerpt,
                "full_match": text[match.start():match.end()].strip(),
            })
            seen_signals.add(signal_name)
    return found


def detect_english_signals(text: str) -> Dict[str, Any]:
    """
    Detect social-engineering signals in English text.
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

    urgency_matches = _find_all_matches(text, URGENCY_PATTERNS)
    fear_matches = _find_all_matches(text, FEAR_PATTERNS)
    cred_matches = _find_all_matches(text, CREDENTIAL_PATTERNS)
    financial_matches = _find_all_matches(text, FINANCIAL_PATTERNS)
    impersonation_matches = _find_all_matches(text, IMPERSONATION_PATTERNS)

    total = (
        len(urgency_matches) + len(fear_matches) + len(cred_matches)
        + len(financial_matches) + len(impersonation_matches)
    )

    return {
        "urgency": urgency_matches,
        "fear": fear_matches,
        "credential_request": cred_matches,
        "financial": financial_matches,
        "impersonation": impersonation_matches,
        "total_signals": total,
    }

