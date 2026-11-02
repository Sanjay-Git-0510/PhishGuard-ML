"""
Social Engineering Detector
---------------------------
Orchestrates English, Hindi and Kannada signal detection.
For code-mixed text, the relevant detectors are run and results merged.
"""

from typing import Dict, Any, List
from app.modules.social_engineering.english_rules import detect_english_signals
from app.modules.social_engineering.kannada_rules import detect_kannada_signals
from app.modules.social_engineering.hindi_rules import detect_hindi_signals


def _merge_category(a: List[Dict], b: List[Dict]) -> List[Dict]:
    """Merge two signal lists, deduplicating by signal name."""
    seen = set()
    merged = []
    for item in a + b:
        if item["signal"] not in seen:
            seen.add(item["signal"])
            merged.append(item)
    return merged


def detect_social_engineering(text: str, language: str = "english") -> Dict[str, Any]:
    """
    Detect social engineering patterns in message text.

    Args:
        text: The message body (or subject + body combined)
        language: "english", "hindi", "kannada", or "code-mixed"

    Returns:
        Dictionary with category-level signal lists and summary counts.
    """
    lang_lower = language.lower().replace("-", "_").replace(" ", "_")

    has_devanagari = any("\u0900" <= c <= "\u097F" for c in (text or ""))
    has_kannada = any("\u0C80" <= c <= "\u0CFF" for c in (text or ""))

    # Always run English: OTP/PIN/click and code-mixed tokens appear in Indic messages.
    # Also run Hindi/Kannada whenever the script is present, even if the user left
    # the language dropdown on English — so both languages get the same coverage.
    run_hi = has_devanagari or lang_lower in ("hindi", "hi", "code_mixed", "hindi_english")
    run_kn = has_kannada or lang_lower in ("kannada", "kn", "code_mixed", "kannada_english")

    parts = [detect_english_signals(text)]
    if run_hi:
        parts.append(detect_hindi_signals(text))
    if run_kn:
        parts.append(detect_kannada_signals(text))

    result = parts[0]
    for extra in parts[1:]:
        result = {
            "urgency": _merge_category(result["urgency"], extra["urgency"]),
            "fear": _merge_category(result["fear"], extra["fear"]),
            "credential_request": _merge_category(
                result["credential_request"], extra["credential_request"]
            ),
            "financial": _merge_category(result["financial"], extra["financial"]),
            "impersonation": _merge_category(result["impersonation"], extra["impersonation"]),
        }
    result["total_signals"] = sum(
        len(v) for k, v in result.items() if k != "total_signals"
    )

    # Count strong signals
    strong_categories = 0
    if result["credential_request"]:
        strong_categories += 1
    if result["fear"]:
        strong_categories += 1
    if result["financial"] and result["impersonation"]:
        strong_categories += 1

    result["strong_category_count"] = strong_categories
    result["has_credential_request"] = len(result["credential_request"]) > 0
    result["has_urgency"] = len(result["urgency"]) > 0
    result["has_fear"] = len(result["fear"]) > 0
    result["has_financial"] = len(result["financial"]) > 0
    result["has_impersonation"] = len(result["impersonation"]) > 0

    return result

