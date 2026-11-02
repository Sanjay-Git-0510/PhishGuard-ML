"""
Identity Trust Analysis — Domain Checker
-----------------------------------------
Evaluates sender email domains against a trusted organization registry.
Detects domain mismatches, suspicious similar domains and punycode.

IMPORTANT LIMITATIONS:
- No DNS resolution is performed. All checks are structural/lexical only.
- A domain match does not verify the sender's identity.
- An unknown domain is NOT automatically classified as malicious.
- Representation of unavailable information: UNKNOWN.
"""

import re
from typing import Dict, Any, Optional, List
from app.modules.identity_analysis.sender_checker import (
    TRUSTED_REGISTRY,
    extract_email_domain,
)


PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)

# Common free email providers — their use by organizations is a weak indicator
FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.in", "hotmail.com", "outlook.com",
    "live.com", "rediffmail.com", "protonmail.com", "icloud.com",
    "aol.com", "mail.com", "ymail.com", "zohomail.com",
}


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def check_email_domain_trust(
    sender_email: str,
    claimed_org: str,
) -> Dict[str, Any]:
    """
    Check whether the sender email domain matches expected domains for the claimed organization.

    Returns:
        status: "verified_registry", "mismatch", "free_provider", "unregistered_org", "unknown"
    """
    domain = extract_email_domain(sender_email)

    if not domain:
        return {
            "status": "unknown",
            "note": "Sender email address is missing or malformed.",
            "domain_spf_note": "UNKNOWN — no network authentication performed.",
        }

    org_lower = claimed_org.lower() if claimed_org else ""
    result = {
        "sender_domain": domain,
        "claimed_org": claimed_org,
        "domain_spf_note": "UNKNOWN — no network authentication performed.",
        "dkim_note": "UNKNOWN — header authentication not evaluated.",
    }

    # Check against registry
    for org_key, org_data in TRUSTED_REGISTRY.items():
        if org_key.lower() == org_lower or any(
            d.lower() == org_lower for d in org_data.get("display_names", [])
        ):
            known_domains = [d.lower() for d in org_data.get("email_domains", [])]

            # Check if domain is in known list or is a subdomain of a known domain
            domain_match = False
            for kd in known_domains:
                if domain == kd or domain.endswith("." + kd):
                    domain_match = True
                    break

            if domain_match:
                result.update({
                    "status": "registry_match",
                    "note": (
                        f"Sender domain '{domain}' matches a registered domain for '{org_key}'. "
                        "Note: Domain matching does not constitute cryptographic authentication."
                    ),
                    "expected_domains": known_domains,
                })
            else:
                result.update({
                    "status": "mismatch",
                    "note": (
                        f"Sender domain '{domain}' does not match any registered email domain for '{claimed_org}'. "
                        f"Expected: {', '.join(known_domains)}."
                    ),
                    "expected_domains": known_domains,
                })
            return result

    # Org not in registry — check free provider
    if domain in FREE_EMAIL_PROVIDERS:
        result.update({
            "status": "free_provider",
            "note": (
                f"Sender is using a free email provider ({domain}) while claiming to represent '{claimed_org}'. "
                "Legitimate organizations typically use their own domain for official communications."
            ),
        })
        return result

    # Org unknown
    result.update({
        "status": "unregistered_org",
        "note": (
            f"The claimed organization '{claimed_org}' is not in the trusted registry. "
            f"Domain '{domain}' cannot be verified against known organizational domains."
        ) if claimed_org else (
            f"No claimed organization provided. Cannot assess domain '{domain}'."
        ),
    })
    return result


def check_domain_similarity(sender_email: str, claimed_org: str) -> Dict[str, Any]:
    """
    Check whether the sender domain is suspiciously similar to a registered domain
    (potential lookalike/typosquatting attack).

    Algorithm: Levenshtein distance <= 2 between sender domain root and known registry domains.
    """
    domain = extract_email_domain(sender_email)
    if not domain:
        return {"status": "unknown", "similar_to": None}

    # Remove TLD for comparison
    domain_root = domain.split(".")[0] if "." in domain else domain

    org_lower = claimed_org.lower() if claimed_org else ""

    # Check against ALL registry domains for similarity
    for org_key, org_data in TRUSTED_REGISTRY.items():
        for reg_domain in org_data.get("email_domains", []):
            reg_root = reg_domain.split(".")[0] if "." in reg_domain else reg_domain
            if reg_root == domain_root:
                continue  # exact match — not lookalike
            dist = _levenshtein(domain_root.lower(), reg_root.lower())
            if dist <= 2 and len(reg_root) >= 4:
                return {
                    "status": "suspicious_similarity",
                    "note": (
                        f"Sender domain '{domain}' is very similar to a registered domain "
                        f"'{reg_domain}' (organization: {org_key}). "
                        f"Edit distance: {dist}. This may indicate a lookalike/typosquat domain."
                    ),
                    "sender_domain": domain,
                    "similar_to": reg_domain,
                    "edit_distance": dist,
                }

    return {"status": "no_similarity_detected", "similar_to": None, "sender_domain": domain}


def check_punycode_domain(sender_email: str) -> Dict[str, Any]:
    """
    Detect whether the sender domain uses punycode (xn-- prefix) encoding,
    which may indicate a homoglyph/look-alike character attack.
    """
    domain = extract_email_domain(sender_email)
    if not domain:
        return {"status": "unknown"}

    if PUNYCODE_RE.search(domain):
        return {
            "status": "punycode_detected",
            "note": (
                f"Sender domain '{domain}' uses punycode (xn--) encoding. "
                "This can be used to create look-alike domains using non-ASCII characters "
                "that visually resemble legitimate organizations."
            ),
            "domain": domain,
        }
    return {"status": "no_punycode", "domain": domain}


def run_full_domain_analysis(
    sender_email: str,
    claimed_org: str,
    reply_to: str = "",
) -> Dict[str, Any]:
    """
    Run all domain-level checks and return a consolidated analysis.
    """
    trust_check = check_email_domain_trust(sender_email, claimed_org)
    similarity = check_domain_similarity(sender_email, claimed_org)
    punycode = check_punycode_domain(sender_email)

    indicators = []
    if trust_check.get("status") == "mismatch":
        indicators.append("domain_mismatch")
    if trust_check.get("status") == "free_provider":
        indicators.append("free_email_provider")
    if similarity.get("status") == "suspicious_similarity":
        indicators.append("lookalike_domain")
    if punycode.get("status") == "punycode_detected":
        indicators.append("punycode_domain")

    return {
        "domain_trust": trust_check,
        "domain_similarity": similarity,
        "punycode_check": punycode,
        "domain_indicators": indicators,
    }

