"""
Social Engineering Detection — Hindi Language Rules
-----------------------------------------------------
Pattern-based detection of social engineering signals in Hindi (Devanagari Unicode) text.
Also handles Hindi-English code-mixed text by combining signals.

IMPORTANT: These patterns are SECURITY INDICATORS, not proof of malicious intent.
Signals are combined by the risk engine, not treated individually as proof.
"""

import re
from typing import List, Dict, Any


# ─────────────────────────────────────────────
# A. URGENCY — Hindi
# ─────────────────────────────────────────────
# Common Hindi urgency words and phrases
# Verbs used when asking the user to hand over secrets (not "never asks for OTP")
_HI_REQUEST_VERB = (
    r"(?:साझा|शेयर|share|भेज(?:ें|ो|िए)?|बता(?:एं|ओ|इए)?|"
    r"दर्ज|डाल(?:ें|ो|िए)?|लिख(?:ें|ो)?|दीजिए|दें)"
)

URGENCY_HI_PATTERNS = [
    (re.compile(r"तुरंत"), "immediate_hi"),
    (re.compile(r"अभी\s*(?:ही|क्लिक|करें|कार्रवाई|सत्यापित|डाल|भेज|दर्ज)"), "right_now_hi"),
    (re.compile(r"जल्दी(?:\s*से\s*जल्दी)?"), "quickly_hi"),
    (re.compile(r"आज\s*ही"), "today_only_hi"),
    (re.compile(r"समय\s*सीमा"), "deadline_hi"),
    (re.compile(r"अंतिम\s*चेतावनी"), "final_warning_hi"),
    (re.compile(r"अंतिम\s*(?:अवसर|मौका|सूचना|नोटिस)"), "last_chance_hi"),
    (re.compile(r"देर\s*(?:न|ना|मत)\s*करें"), "do_not_delay_hi"),
    (re.compile(r"शीघ्र(?:\s*ही)?"), "soon_hi"),
    (re.compile(r"(?:\d+)\s*(?:घंटे|मिनट|दिन(?:ों)?)\s*(?:में|के\s*अंदर|के\s*भीतर)"), "time_window_hi"),
    (re.compile(r"तत्काल"), "urgent_hi"),
    (re.compile(r"फ़ौरन|फौरन"), "at_once_hi"),
]

# ─────────────────────────────────────────────
# B. FEAR / THREATS — Hindi
# ─────────────────────────────────────────────
FEAR_HI_PATTERNS = [
    (re.compile(r"खाता.{0,24}(?:बंद|ब्लॉक|निष्क्रिय|स्थगित|सस्पेंड|निलंबित|अमान्य)"), "account_blocked_hi"),
    (re.compile(r"कानूनी\s*कार्रवाई"), "legal_action_hi"),
    (re.compile(r"जुर्माना|दंड"), "penalty_hi"),
    (re.compile(r"पुलिस|सीबीआई|ईडी"), "police_hi"),
    (re.compile(r"धोखाधड़ी"), "fraud_detected_hi"),
    (re.compile(r"अनधिकृत\s*(?:लेनदेन|प्रवेश|गतिविधि)"), "unauthorized_hi"),
    (re.compile(r"डेटा\s*उल्लंघन"), "data_breach_hi"),
    (re.compile(r"(?:केवाईसी|KYC)\s*(?:अपडेट|समाप्त|अधूरा|पूरा\s*करें|नवीनीकरण)"), "kyc_hi"),
    (re.compile(r"ऋण\s*(?:बकाया|अतिदेय|चूक)"), "loan_overdue_hi"),
    (re.compile(r"गिरफ़्तार(?:ी)?|गिरफ्तार(?:ी)?"), "arrest_threat_hi"),
    (re.compile(r"स्थायी\s*रूप\s*से\s*बंद"), "account_blocked_hi"),
]

# ─────────────────────────────────────────────
# C. CREDENTIAL HARVESTING — Hindi
# ─────────────────────────────────────────────
CREDENTIAL_HI_PATTERNS = [
    (re.compile(rf"(?:OTP|ओटीपी).{{0,40}}{_HI_REQUEST_VERB}"), "otp_request_hi"),
    (re.compile(rf"{_HI_REQUEST_VERB}.{{0,40}}(?:OTP|ओटीपी)"), "otp_request_hi"),
    (re.compile(r"(?:OTP|ओटीपी)\s*(?:है|:)\s*\d{4,8}"), "otp_in_msg_hi"),
    (re.compile(rf"पासवर्ड.{{0,30}}{_HI_REQUEST_VERB}"), "password_request_hi"),
    (re.compile(rf"{_HI_REQUEST_VERB}.{{0,30}}पासवर्ड"), "password_request_hi"),
    (re.compile(rf"(?:पिन|PIN|यूपीआई\s*पिन|UPI\s*PIN).{{0,25}}{_HI_REQUEST_VERB}"), "pin_request_hi"),
    (re.compile(rf"{_HI_REQUEST_VERB}.{{0,25}}(?:पिन|PIN|UPI\s*PIN)"), "pin_request_hi"),
    (re.compile(r"बैंक\s*(?:विवरण|खाता\s*(?:नंबर|संख्या)|डिटेल)"), "bank_details_hi"),
    (re.compile(r"आधार\s*(?:नंबर|संख्या|कार्ड)"), "aadhaar_hi"),
    (re.compile(r"(?:PAN|पैन)\s*(?:नंबर|कार्ड|संख्या)"), "pan_hi"),
    (re.compile(r"खाता\s*(?:सत्यापित|प्रमाणित|वेरिफ़ाई|वेरिफाई)\s*करें?"), "account_verify_hi"),
    (re.compile(r"(?:लिंक|link).{0,25}(?:क्लिक|टैप|खोल|दबा|जाएँ|जाएं)"), "click_link_hi"),
    (re.compile(r"(?:क्लिक|टैप|खोल).{0,25}(?:लिंक|link)"), "click_link_hi"),
    (re.compile(r"(?:क्रेडिट|डेबिट)\s*कार्ड\s*(?:नंबर|संख्या|विवरण|CVV|सीवीवी)"), "card_details_hi"),
    (re.compile(r"(?:CVV|सीवीवी)"), "cvv_request_hi"),
]

# ─────────────────────────────────────────────
# D. FINANCIAL MANIPULATION — Hindi
# ─────────────────────────────────────────────
FINANCIAL_HI_PATTERNS = [
    (re.compile(r"(?:रु\.?|₹)\s*[\d,]+\s*(?:ट्रांसफर\s*करें|भेजें)"), "fund_transfer_request_hi"),
    (re.compile(r"(?:इनाम|पुरस्कार|लॉटरी).{0,20}(?:जीता|मिला|जीत)"), "prize_claim_hi"),
    (re.compile(r"रिफ(?:ं|न)ड.{0,20}(?:विफल|दर्ज|क्लिक|लिंक)"), "refund_hi"),
    (re.compile(r"(?:मुफ़्त|मुफ्त|निशुल्क)\s*(?:उपहार|गिफ्ट|रिचार्ज|ऑफर|पैसा)"), "free_gift_hi"),
    (re.compile(r"कैशबैक.{0,20}(?:क्लिक|OTP|ओटीपी|दर्ज|डाल)"), "cashback_hi"),
    (re.compile(r"(?:ऋण|लोन)\s*(?:स्वीकृत|मंजूर|अप्रूव्ड|ऑफर|प्रस्ताव)"), "loan_offer_hi"),
    (re.compile(r"(?:ईएमआई|EMI)\s*(?:विफल|बकाया|अतिदेय|फेल|चूक)"), "emi_failed_hi"),
    (re.compile(r"निवेश.{0,20}(?:\d+%|\d+\s*प्रतिशत)\s*(?:लाभ|रिटर्न|मुनाफ़ा|मुनाफा)"), "investment_hi"),
    (re.compile(r"बोनस\s*(?:राशि|पैसा|प्राप्त)"), "bonus_hi"),
    (re.compile(r"(?:डबल|दोगुना|तिगुना)\s*(?:पैसा|राशि|रिटर्न)"), "doubling_scam_hi"),
]

# ─────────────────────────────────────────────
# E. IMPERSONATION — Hindi
# ─────────────────────────────────────────────
IMPERSONATION_HI_PATTERNS = [
    # Named institutions only — generic "बैंक" matches legitimate statements and causes false positives.
    (re.compile(r"(?:स्टेट\s*बैंक|एसबीआई|एचडीएफसी|आईसीआईसीआई|एक्सिस|कोटक|पीएनबी|केनरा|आईडीबीआई)"), "bank_hi"),
    (re.compile(r"(?:आरबीआई|रिज़र्व\s*बैंक|रिजर्व\s*बैंक)"), "rbi_hi"),
    (re.compile(r"(?:आयकर|जीएसटी|कस्टम्स|इनकम\s*टैक्स)"), "tax_dept_hi"),
    (re.compile(r"(?:पुलिस|सीबीआई|न्यायालय|कोर्ट|अदालत)"), "authority_hi"),
    (re.compile(r"(?:विश्वविद्यालय|कॉलेज|यूनिवर्सिटी).{0,20}(?:शुल्क|प्रवेश|फ़ीस|फीस|परीक्षा)"), "university_hi"),
    (re.compile(r"ग्राहक\s*(?:सेवा|सहायता)\s*(?:टीम|विभाग|केंद्र)"), "customer_service_hi"),
    (re.compile(r"(?:अमेज़न|अमेज़ॉन|फ्लिपकार्ट|स्विगी|ज़ोमैटो|ज़ोमेटो|जोमैटो).{0,20}(?:डिलीवरी|ऑर्डर|शिपमेंट)"), "ecommerce_hi"),
    (re.compile(r"(?:जियो|एयरटेल|वोडाफोन|बीएसएनएल).{0,20}(?:रिचार्ज|प्लान|बिल)"), "telecom_hi"),
    (re.compile(r"सरकार(?:ी)?\s*(?:योजना|सब्सिडी|अनुदान|लाभ)"), "govt_scheme_hi"),
    (re.compile(r"(?:बीमा|इंश्योरेंस)\s*(?:एजेंट|क्लेम)"), "insurance_hi"),
]


def _find_all_matches_hi(text: str, patterns: List) -> List[Dict[str, Any]]:
    """Find all matching Hindi patterns and return structured signals."""
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


def detect_hindi_signals(text: str) -> Dict[str, Any]:
    """
    Detect social-engineering signals in Hindi text (Devanagari Unicode).
    Also works on code-mixed Hindi-English text.
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

    urgency = _find_all_matches_hi(text, URGENCY_HI_PATTERNS)
    fear = _find_all_matches_hi(text, FEAR_HI_PATTERNS)
    cred = _find_all_matches_hi(text, CREDENTIAL_HI_PATTERNS)
    financial = _find_all_matches_hi(text, FINANCIAL_HI_PATTERNS)
    impersonation = _find_all_matches_hi(text, IMPERSONATION_HI_PATTERNS)

    total = len(urgency) + len(fear) + len(cred) + len(financial) + len(impersonation)

    return {
        "urgency": urgency,
        "fear": fear,
        "credential_request": cred,
        "financial": financial,
        "impersonation": impersonation,
        "total_signals": total,
    }
