"""
Message Preprocessing Module
------------------------------
Prepares message text for ML classification.
Handles English, Hindi, Kannada, and code-mixed Indic-English text.

CRITICAL: Preserves original Hindi (Devanagari) and Kannada Unicode characters.
Does NOT aggressively strip text before evidence extraction.
The original text is always preserved separately from the normalized version.
"""

import re
import unicodedata
from typing import Dict, Any


# Kannada Unicode block: U+0C80–U+0CFF
KANNADA_RANGE = re.compile(r"[\u0C80-\u0CFF]")

# Devanagari block (Hindi) — not used for primary classification but detected
DEVANAGARI_RANGE = re.compile(r"[\u0900-\u097F]")

# Regex for URLs — replaced with placeholder during normalization
URL_RE = re.compile(
    r"https?://[^\s]+|www\.[^\s]+",
    re.IGNORECASE
)

# Regex for email addresses
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# Regex for phone numbers (Indian formats)
PHONE_RE = re.compile(r"(?:\+91[-\s]?)?[6-9]\d{9}")

# Excessive whitespace
WHITESPACE_RE = re.compile(r"\s+")


def detect_script(text: str) -> Dict[str, Any]:
    """
    Detect the primary writing script of the text.
    Returns script proportions and a language hint.
    """
    if not text:
        return {
            "primary_script": "unknown",
            "has_kannada": False,
            "has_hindi": False,
            "has_latin": False,
            "is_code_mixed": False,
        }

    total_alpha = sum(1 for c in text if c.isalpha())
    if total_alpha == 0:
        return {
            "primary_script": "unknown",
            "has_kannada": False,
            "has_hindi": False,
            "has_latin": False,
            "is_code_mixed": False,
        }

    kannada_chars = len(KANNADA_RANGE.findall(text))
    hindi_chars = len(DEVANAGARI_RANGE.findall(text))
    latin_chars = sum(1 for c in text if c.isascii() and c.isalpha())

    kn_ratio = kannada_chars / max(total_alpha, 1)
    hi_ratio = hindi_chars / max(total_alpha, 1)
    en_ratio = latin_chars / max(total_alpha, 1)

    has_kannada = kn_ratio > 0.05
    has_hindi = hi_ratio > 0.05
    has_latin = en_ratio > 0.05
    is_code_mixed = has_latin and (has_kannada or has_hindi)

    if kn_ratio > 0.5:
        primary = "kannada"
    elif hi_ratio > 0.5:
        primary = "hindi"
    elif kn_ratio > 0.15 or hi_ratio > 0.15:
        primary = "code_mixed"
    else:
        primary = "latin"

    return {
        "primary_script": primary,
        "kannada_char_ratio": round(kn_ratio, 3),
        "hindi_char_ratio": round(hi_ratio, 3),
        "latin_char_ratio": round(en_ratio, 3),
        "has_kannada": has_kannada,
        "has_hindi": has_hindi,
        "has_latin": has_latin,
        "is_code_mixed": is_code_mixed,
    }


def normalize_for_ml(text: str, language: str = "english") -> str:
    """
    Produce a normalized version of the message suitable for ML classification.

    Processing steps:
    1. Decode/normalize Unicode (NFC normalization)
    2. Replace URLs with placeholder token
    3. Replace emails with placeholder token
    4. Replace phone numbers with placeholder token
    5. Collapse whitespace
    6. Lowercase Latin characters (preserves Hindi/Kannada Unicode)

    This function preserves Hindi and Kannada script characters.
    """
    if not text:
        return ""

    # Unicode NFC normalization (important for Kannada)
    normalized = unicodedata.normalize("NFC", text)

    # Replace URLs
    normalized = URL_RE.sub(" URL_TOKEN ", normalized)

    # Replace email addresses
    normalized = EMAIL_RE.sub(" EMAIL_TOKEN ", normalized)

    # Replace phone numbers
    normalized = PHONE_RE.sub(" PHONE_TOKEN ", normalized)

    # Lowercase only ASCII/Latin characters; preserve Kannada
    result_chars = []
    for char in normalized:
        if char.isascii():
            result_chars.append(char.lower())
        else:
            result_chars.append(char)
    normalized = "".join(result_chars)

    # Collapse whitespace
    normalized = WHITESPACE_RE.sub(" ", normalized).strip()

    return normalized


def extract_text_features(
    message: str,
    subject: str = "",
    channel: str = "email",
    language: str = "english",
) -> Dict[str, Any]:
    """
    Extract structured features from a message for use alongside TF-IDF.
    These complement the text classification features.
    """
    combined_text = f"{subject} {message}".strip() if subject else message

    script_info = detect_script(combined_text)
    word_count = len(combined_text.split())
    char_count = len(combined_text)
    has_url = bool(URL_RE.search(combined_text))
    url_count = len(URL_RE.findall(combined_text))

    # Count exclamation marks (urgency signal)
    exclamation_count = combined_text.count("!")

    # Count question marks
    question_count = combined_text.count("?")

    # Has monetary amount
    has_amount = bool(re.search(
        r"(?:Rs\.?|₹|INR|USD|\$|£|€)\s*[\d,]+|[\d,]+\s*(?:Rs\.?|₹|INR)",
        combined_text
    ))

    # Has OTP (strong indicator)
    has_otp = bool(re.search(
        r"\bOTP\b|\bone[- ]time\s+password\b|ओटीपी",
        combined_text,
        re.I,
    ))

    # Has password/PIN request
    has_password_request = bool(re.search(
        r"\b(?:password|passcode|PIN|MPIN|UPIN|UPI\s+PIN)\b",
        combined_text, re.I
    ))

    # Channel encoding
    channel_is_email = 1 if channel.lower() == "email" else 0
    channel_is_sms = 1 if channel.lower() == "sms" else 0

    # Language encoding
    lang_lower = language.lower()
    lang_is_english = 1 if lang_lower in ("english", "en") else 0
    lang_is_hindi = 1 if lang_lower in ("hindi", "hi") else 0
    lang_is_kannada = 1 if lang_lower in ("kannada", "kn") else 0
    lang_is_mixed = 1 if "mix" in lang_lower or "code" in lang_lower else 0

    return {
        "word_count": word_count,
        "char_count": char_count,
        "has_url": int(has_url),
        "url_count": url_count,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "has_amount": int(has_amount),
        "has_otp": int(has_otp),
        "has_password_request": int(has_password_request),
        "channel_is_email": channel_is_email,
        "channel_is_sms": channel_is_sms,
        "lang_is_english": lang_is_english,
        "lang_is_hindi": lang_is_hindi,
        "lang_is_kannada": lang_is_kannada,
        "lang_is_mixed": lang_is_mixed,
        **script_info,
    }


def preprocess_message(
    message: str,
    subject: str = "",
    channel: str = "email",
    language: str = "english",
) -> Dict[str, Any]:
    """
    Full preprocessing pipeline for a submitted message.

    Returns:
        {
            "original_text": str,   # preserved for evidence extraction
            "normalized_text": str, # used for ML prediction
            "combined_text": str,   # subject + body
            "script_info": dict,
            "structured_features": dict,
        }
    """
    combined = f"{subject}\n{message}".strip() if subject else message
    normalized = normalize_for_ml(combined, language)
    script_info = detect_script(combined)
    structured = extract_text_features(message, subject, channel, language)

    return {
        "original_text": message,
        "original_subject": subject,
        "combined_text": combined,
        "normalized_text": normalized,
        "script_info": script_info,
        "structured_features": structured,
    }

