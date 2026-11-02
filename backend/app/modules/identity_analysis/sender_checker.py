"""
Identity Trust Analysis — Sender Checker
-----------------------------------------
Evaluates sender identity fields (display name, email address, reply-to)
against a trusted organization registry.

IMPORTANT LIMITATIONS:
- This module checks structural consistency of supplied metadata ONLY.
- It does NOT perform SPF, DKIM, or DMARC verification.
- A matching domain does NOT prove the sender is authentic.
- An unknown domain does NOT prove impersonation.
- All unavailable verification information is represented as UNKNOWN.
"""

import re
import json
import os
from typing import Dict, Any, Optional

# Load trusted registry once at module import
_REGISTRY_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "trusted_registry.json"
)

def _load_registry() -> Dict:
    try:
        with open(_REGISTRY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

TRUSTED_REGISTRY = _load_registry()


def extract_email_domain(email_address: str) -> Optional[str]:
    """Extract domain from email address. Returns None if malformed."""
    if not email_address or "@" not in email_address:
        return None
    parts = email_address.strip().split("@")
    if len(parts) != 2 or not parts[1]:
        return None
    return parts[1].strip().lower()


def check_sender_name_consistency(
    sender_name: str,
    claimed_org: str
) -> Dict[str, Any]:
    """
    Check whether the sender display name is consistent with the claimed organization.
    Returns observations, not verdicts.
    """
    if not sender_name and not claimed_org:
        return {"status": "unknown", "note": "No sender name or claimed organization provided."}

    if not sender_name:
        return {"status": "unknown", "note": "Sender display name not provided."}

    if not claimed_org:
        return {
            "status": "unchecked",
            "note": "No claimed organization provided. Cannot assess name consistency.",
            "sender_name": sender_name,
        }

    # Case-insensitive substring match
    name_lower = sender_name.lower()
    org_lower = claimed_org.lower()

    # Check registry for this org
    registry_match = None
    for org_key, org_data in TRUSTED_REGISTRY.items():
        if org_key.lower() == org_lower or any(
            d.lower() == org_lower for d in org_data.get("display_names", [])
        ):
            registry_match = (org_key, org_data)
            break

    if registry_match:
        org_key, org_data = registry_match
        known_names = [n.lower() for n in org_data.get("display_names", [])]
        if name_lower in known_names or any(n in name_lower for n in known_names):
            return {
                "status": "consistent",
                "note": f"Sender name '{sender_name}' is consistent with known display names for {org_key}.",
                "sender_name": sender_name,
                "claimed_org": claimed_org,
            }
        else:
            return {
                "status": "inconsistent",
                "note": (
                    f"Sender name '{sender_name}' does not match any known display name for '{claimed_org}'. "
                    f"Known names: {', '.join(org_data.get('display_names', []))}."
                ),
                "sender_name": sender_name,
                "claimed_org": claimed_org,
                "known_display_names": org_data.get("display_names", []),
            }
    else:
        # Org not in registry — do a basic substring check
        if org_lower in name_lower or name_lower in org_lower:
            return {
                "status": "plausible",
                "note": (
                    f"Sender name '{sender_name}' partially matches claimed organization '{claimed_org}'. "
                    "The organization is not in the trusted registry; no authentication can be performed."
                ),
                "sender_name": sender_name,
                "claimed_org": claimed_org,
            }
        else:
            return {
                "status": "mismatch",
                "note": (
                    f"Sender name '{sender_name}' does not contain or resemble '{claimed_org}'. "
                    "The organization is not in the trusted registry."
                ),
                "sender_name": sender_name,
                "claimed_org": claimed_org,
            }


def check_reply_to_mismatch(
    sender_email: str,
    reply_to: str,
) -> Dict[str, Any]:
    """
    Detect Reply-To address that differs from the sender's domain.
    A mismatch is a suspicious indicator — NOT proof of phishing.
    """
    if not reply_to or not reply_to.strip():
        return {
            "status": "not_provided",
            "note": "No Reply-To address was provided.",
        }

    sender_domain = extract_email_domain(sender_email)
    reply_domain = extract_email_domain(reply_to)

    if not sender_domain:
        return {
            "status": "unknown",
            "note": "Sender email address is missing or malformed; cannot check Reply-To consistency.",
        }

    if not reply_domain:
        return {
            "status": "unknown",
            "note": f"Reply-To address '{reply_to}' appears malformed.",
        }

    if sender_domain == reply_domain:
        return {
            "status": "consistent",
            "note": f"Reply-To domain '{reply_domain}' matches sender domain '{sender_domain}'.",
            "sender_domain": sender_domain,
            "reply_to_domain": reply_domain,
        }
    else:
        return {
            "status": "mismatch",
            "note": (
                f"Reply-To domain '{reply_domain}' differs from sender domain '{sender_domain}'. "
                "Replies to this message will go to a different domain than the sender. "
                "This is a suspicious structural indicator."
            ),
            "sender_domain": sender_domain,
            "reply_to_domain": reply_domain,
        }


def check_sms_sender_id(
    sender_id: str,
    claimed_org: str,
) -> Dict[str, Any]:
    """
    Check whether the SMS sender ID matches the claimed organization in the registry.

    LIMITATION: SMS sender IDs can be spoofed. A matching ID does not prove authenticity.
    """
    if not sender_id and not claimed_org:
        return {"status": "unknown", "note": "No sender ID or claimed organization provided."}

    if not sender_id:
        return {"status": "unknown", "note": "No SMS sender ID provided."}

    if not claimed_org:
        return {
            "status": "unchecked",
            "note": "No claimed organization provided. Cannot assess sender ID.",
            "sender_id": sender_id,
        }

    sender_clean = sender_id.strip().upper()
    org_lower = claimed_org.lower()

    for org_key, org_data in TRUSTED_REGISTRY.items():
        if org_key.lower() == org_lower or any(
            d.lower() == org_lower for d in org_data.get("display_names", [])
        ):
            known_ids = [s.upper() for s in org_data.get("sms_sender_ids", [])]
            if sender_clean in known_ids:
                return {
                    "status": "registry_match",
                    "note": (
                        f"Sender ID '{sender_id}' is in the registry for '{org_key}'. "
                        "Note: SMS sender IDs cannot be cryptographically verified. "
                        "A matching ID does not guarantee authenticity."
                    ),
                    "sender_id": sender_id,
                    "claimed_org": claimed_org,
                    "known_sender_ids": org_data.get("sms_sender_ids", []),
                }
            else:
                return {
                    "status": "mismatch",
                    "note": (
                        f"Sender ID '{sender_id}' is not in the known sender IDs for '{claimed_org}'. "
                        f"Expected one of: {', '.join(org_data.get('sms_sender_ids', []))}. "
                        "This is a suspicious indicator."
                    ),
                    "sender_id": sender_id,
                    "claimed_org": claimed_org,
                    "known_sender_ids": org_data.get("sms_sender_ids", []),
                }

    # Org not in registry
    return {
        "status": "unregistered_org",
        "note": (
            f"The claimed organization '{claimed_org}' is not in the trusted registry. "
            "Cannot verify whether the sender ID '{sender_id}' is legitimate."
        ),
        "sender_id": sender_id,
        "claimed_org": claimed_org,
    }

