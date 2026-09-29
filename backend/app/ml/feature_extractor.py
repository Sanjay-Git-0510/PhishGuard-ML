"""
Feature Extraction Engine for Phishing URL Detection
---------------------------------------------------
Extracts lexical, structural, and statistical features directly from a URL.
Performs strictly static analysis (no network requests, no DNS resolution, no execution).
Used identically during model training and production inference.

v2 - Added 4 new features for typosquatting, digit-substitution, brand-doppelganger,
and punycode/IDN detection to catch attacks like paypa1.com, g00gle.com, etc.
"""

import math
import re
from urllib.parse import urlparse
from typing import Dict, List, Any, Tuple


# Ordered feature names used for model vector alignment (24 features)
FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equal_signs",
    "num_at_symbols",
    "num_digits",
    "digit_ratio",
    "num_subdomains",
    "is_ip_address",
    "is_https",
    "has_suspicious_keywords",
    "is_shortened",
    "suspicious_tld",
    "url_entropy",
    # NEW FEATURES (v2)
    "has_digit_substitution",   # digits replacing letters (paypa1, g00gle, m1crosoft)
    "brand_doppelganger",       # known brand name with ≤2 char edits (typosquat)
    "has_punycode_idn",         # xn-- encoded internationalized domain (homoglyph)
    "path_has_brand_mismatch",  # brand in path but domain doesn't match (brand in path trick)
]

# Suspicious keywords commonly seen in credential phishing / social engineering
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update", "security",
    "banking", "secure", "ebayisapi", "webscr", "confirm", "wallet", "authenticate",
    "support", "service", "billing", "password", "credential", "recover", "unlock",
    "alert", "suspended", "authorise", "authorize", "token", "validation", "payment",
    "invoice", "refund", "reward", "claim", "bonus", "prize", "winner",
]

# Known URL shorteners often used to mask destination targets
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "tiny.cc", "cutt.ly", "goo.gl", "bit.do", "shorte.st",
    "bc.vc", "adf.ly", "v.gd", "qr.ae", "trib.al", "rb.gy", "shorturl.at",
}

# Top-level domains statistically prevalent in disposable/phishing registrations
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "cf", "gq", "buzz", "fit", "icu",
    "work", "club", "surf", "rest", "live", "monster", "cam", "quest",
    "beauty", "hair", "skin", "sbs", "cfd", "click", "link", "gdn",
    "info", "biz", "ru", "cn", "pw", "cc", "ws", "in", "co",
}

# High-value brands commonly targeted by typosquatting and phishing
# Format: canonical_name -> list of common typosquatting patterns (regex patterns applied to hostname)
BRAND_TARGETS = {
    "paypal":     ["paypa1", "paypai", "paypa-l", "payypal", "ppaypal", "paypaI", "pay-pal", "paypa"],
    "google":     ["g00gle", "gogle", "googel", "gooogle", "g0ogle", "go0gle", "goog1e", "googie"],
    "apple":      ["app1e", "appl3", "appie", "aple", "appple", "ap-ple", "appl-e"],
    "microsoft":  ["m1crosoft", "micros0ft", "microsft", "mircosoft", "micorsoft", "microsoift"],
    "amazon":     ["amaz0n", "amazom", "arnazon", "amazoon", "am4zon", "amaz-on", "arnaz0n"],
    "facebook":   ["faceb00k", "facebok", "facebooks", "facebok", "faceb0ok", "facebbk"],
    "netflix":    ["netfl1x", "netflik", "n3tflix", "netfliix", "netlfix", "netfix"],
    "instagram":  ["1nstagram", "instagramm", "inst4gram", "lnstagram", "instaqram"],
    "twitter":    ["tw1tter", "twittter", "twtter", "tweitter", "tw-itter"],
    "linkedin":   ["linkedln", "linkdin", "linked1n", "linke-din", "linke0in"],
    "chase":      ["ch4se", "chasse", "chas3", "chase-bank"],
    "wellsfargo": ["wellsf4rgo", "well5fargo", "wellsfarg0", "wells-fargo"],
    "bankofamerica": ["bankofamerika", "bankofameric4", "bank0famerica"],
    "citibank":   ["c1tibank", "citibnk", "citi-bank", "c1ti"],
    "paypa":      ["paypa1"],  # catches paypa1.com directly
    "gmail":      ["gmai1", "gma1l", "gmaiI", "gmaii", "g-mail"],
    "outlook":    ["0utlook", "outl00k", "outlok", "outIook"],
    "dropbox":    ["dr0pbox", "droopbox", "dr0pb0x"],
    "coinbase":   ["co1nbase", "coinbse", "coinbase-pro"],
    "binance":    ["b1nance", "binanc3", "binnance"],
    "metamask":   ["metamas-k", "m3tamask", "meta-mask"],
    "ledger":     ["l3dger", "ledg3r", "ledger-io"],
    "trezor":     ["tr3zor", "trez0r", "trezor-io"],
}

# All brand canonical names (for fuzzy matching)
ALL_BRAND_NAMES = list(BRAND_TARGETS.keys()) + [
    "ebay", "twitter", "snapchat", "tiktok", "youtube", "discord",
    "steam", "roblox", "spotify", "adobe", "zoom", "slack", "atlassian",
    "github", "gitlab", "bitbucket", "docker", "aws", "azure", "gcp",
    "usps", "fedex", "ups", "dhl", "irs", "ssn", "medicare", "venmo",
    "zelle", "robinhood", "kraken", "kucoin", "trustwallet", "blockchain",
    "walmart", "target", "bestbuy", "costco", "homedepot", "cvs",
    "statefarm", "geico", "progressive", "allstate", "fidelity", "vanguard",
    "schwab", "etrade", "stripe", "shopify", "squareup",
]

# IPv4 regex with optional port
IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?$")
# IPv6 regex
IPV6_REGEX = re.compile(r"^\[?[a-fA-F0-9:]+\]?(?::\d+)?$")

# Digit-to-letter substitutions used in typosquatting
DIGIT_SUBSTITUTIONS = {
    '0': 'o', '1': 'l', '1': 'i', '3': 'e', '4': 'a',
    '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g',
}

# Regex for detecting punycode/IDN encoded hostnames
PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (measures randomness/obfuscation)."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def normalize_url(url: str) -> str:
    """Normalize URL string without modifying payload integrity."""
    clean_url = url.strip()
    if not clean_url:
        return ""
    # Ensure scheme exists for urlparse consistency
    if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
        clean_url = "http://" + clean_url
    return clean_url


def is_ip_host(hostname: str) -> int:
    """Check whether the hostname is an IPv4 or IPv6 literal."""
    if not hostname:
        return 0
    # Strip port if present
    host = hostname.split(":")[0].strip("[]")
    # Quick numeric test for IPv4
    parts = host.split(".")
    if len(parts) == 4:
        if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            return 1
    if ":" in host and len(host) > 2:
        return 1
    return 0


def count_subdomains(hostname: str) -> int:
    """Count number of subdomains excluding root domain and TLD."""
    if not hostname or is_ip_host(hostname):
        return 0
    # Strip port
    host = hostname.split(":")[0].lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return 0
    two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "com.br", "co.jp", "co.in", "org.in"}
    suffix_2 = ".".join(parts[-2:])
    if suffix_2 in two_part_tlds:
        return max(0, len(parts) - 3)
    return max(0, len(parts) - 2)


def check_suspicious_tld(hostname: str) -> int:
    """Check if the URL hostname uses a high-abuse TLD."""
    if not hostname or is_ip_host(hostname):
        return 0
    host = hostname.split(":")[0].lower()
    tld = host.split(".")[-1]
    return 1 if tld in SUSPICIOUS_TLDS else 0


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


def _get_root_domain(hostname: str) -> str:
    """Extract the root domain name (without TLD and subdomains)."""
    if not hostname or is_ip_host(hostname):
        return hostname
    host = hostname.split(":")[0].lower()
    parts = host.split(".")
    two_part_tlds = {"co.uk", "gov.uk", "ac.uk", "com.au", "net.au", "com.br", "co.jp", "co.in", "org.in"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in two_part_tlds:
        return parts[-3] if len(parts) >= 3 else ""
    return parts[-2] if len(parts) >= 2 else parts[0]


def detect_digit_substitution(hostname: str) -> int:
    """
    Detect if the domain uses digit substitutions to impersonate a brand.
    E.g.: paypa1.com (1→l), g00gle.com (0→o), m1crosoft.com (1→i)
    Returns 1 if the domain contains digits AND when digits are replaced with their
    look-alike letters the resulting string closely matches a known brand.
    """
    root = _get_root_domain(hostname)
    if not root:
        return 0

    # If no digits in root domain, no digit substitution
    if not any(c.isdigit() for c in root):
        return 0

    # Try all digit→letter substitutions and see if result matches a brand
    # Build normalized version replacing digits with common letter look-alikes
    normalized = root
    for digit, letter in DIGIT_SUBSTITUTIONS.items():
        normalized = normalized.replace(digit, letter)

    if normalized == root:
        return 0  # No substitutions changed anything

    # Check if normalized version matches any brand (exact or close)
    for brand in ALL_BRAND_NAMES:
        # Exact match after normalization
        if normalized == brand:
            return 1
        # Within 1 edit distance (handles combined tricks)
        if len(brand) >= 4 and _levenshtein(normalized, brand) <= 1:
            return 1

    # Also check known typosquat patterns explicitly
    for brand, patterns in BRAND_TARGETS.items():
        if root in patterns:
            return 1

    return 0


def detect_brand_doppelganger(hostname: str) -> int:
    """
    Detect typosquatting via Levenshtein edit distance to known brand names.
    Catches: paypa1.com, gooogle.com, microsft.com, amazom.com etc.
    Returns 1 if the root domain is 1-2 edits away from a known brand
    AND the domain is not the actual brand (would be legitimate).
    """
    root = _get_root_domain(hostname)
    if not root or len(root) < 4:
        return 0

    for brand in ALL_BRAND_NAMES:
        # Skip if it IS the brand (it's legitimate)
        if root == brand:
            return 0
        # Flag if it's very close to the brand name
        brand_len = len(brand)
        # Use edit distance threshold scaled to brand length
        max_dist = 1 if brand_len <= 6 else 2
        if abs(len(root) - brand_len) <= max_dist:
            dist = _levenshtein(root, brand)
            if 0 < dist <= max_dist:
                return 1

    # Also check explicit patterns list
    for brand, patterns in BRAND_TARGETS.items():
        if root in patterns:
            return 1

    return 0


def detect_punycode_idn(hostname: str) -> int:
    """
    Detect punycode/IDN encoded domains (xn-- prefix) used for homoglyph attacks.
    E.g.: xn--pypl-ccbc.com (looks like paypal but uses Cyrillic/Greek chars)
    """
    if not hostname:
        return 0
    return 1 if PUNYCODE_RE.search(hostname) else 0


def detect_path_brand_mismatch(hostname: str, path: str) -> int:
    """
    Detect when a known brand name appears in the path/domain but the
    registered domain doesn't match (e.g. evil.com/paypal/login or
    paypal.evil.com where root domain is evil).
    """
    if not hostname or not path:
        return 0

    root = _get_root_domain(hostname)
    combined_path = path.lower()

    for brand in ALL_BRAND_NAMES:
        if brand in combined_path and root != brand:
            # Brand appears in path but domain isn't the brand
            return 1

    # Check if a brand appears in a subdomain of a non-brand domain
    host = hostname.split(":")[0].lower()
    parts = host.split(".")
    if len(parts) > 2:
        subdomains_str = ".".join(parts[:-2])
        for brand in ALL_BRAND_NAMES:
            if brand in subdomains_str:
                root_of_host = parts[-2]
                if root_of_host != brand:
                    return 1
    return 0


def extract_features(url: str) -> Dict[str, float]:
    """
    Extract 24 numerical and boolean features from a URL string.
    Returns a dictionary mapping feature names to their numeric values.
    """
    norm_url = normalize_url(url)
    try:
        parsed = urlparse(norm_url)
    except Exception:
        parsed = urlparse("http://invalid.local")

    scheme = parsed.scheme.lower() if parsed.scheme else "http"
    netloc = parsed.netloc.lower() if parsed.netloc else ""
    path = parsed.path if parsed.path else ""
    query = parsed.query if parsed.query else ""
    hostname = parsed.hostname.lower() if parsed.hostname else netloc.split(":")[0]

    url_str = norm_url
    url_len = len(url_str)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    num_dots = url_str.count(".")
    num_hyphens = url_str.count("-")
    num_underscores = url_str.count("_")
    num_slashes = url_str.count("/")
    num_question_marks = url_str.count("?")
    num_equal_signs = url_str.count("=")
    num_at_symbols = url_str.count("@")

    digits = sum(c.isdigit() for c in url_str)
    digit_ratio = round(digits / max(1, url_len), 4)

    subdomains = count_subdomains(hostname)
    ip_flag = is_ip_host(hostname)
    https_flag = 1 if scheme == "https" else 0

    # Suspicious keywords in path, query, or hostname
    lower_content = f"{hostname} {path} {query}".lower()
    has_keywords = 1 if any(kw in lower_content for kw in SUSPICIOUS_KEYWORDS) else 0

    # URL shortener check
    host_clean = hostname.split(":")[0]
    shortener_flag = 1 if host_clean in SHORTENER_DOMAINS else 0

    # Suspicious TLD check
    tld_flag = check_suspicious_tld(hostname)

    # Shannon Entropy of URL
    entropy = calculate_entropy(url_str)

    # === NEW v2 FEATURES ===
    digit_sub_flag = detect_digit_substitution(hostname)
    doppelganger_flag = detect_brand_doppelganger(hostname)
    punycode_flag = detect_punycode_idn(hostname)
    path_mismatch_flag = detect_path_brand_mismatch(hostname, path)

    features: Dict[str, float] = {
        "url_length": float(url_len),
        "hostname_length": float(host_len),
        "path_length": float(path_len),
        "query_length": float(query_len),
        "num_dots": float(num_dots),
        "num_hyphens": float(num_hyphens),
        "num_underscores": float(num_underscores),
        "num_slashes": float(num_slashes),
        "num_question_marks": float(num_question_marks),
        "num_equal_signs": float(num_equal_signs),
        "num_at_symbols": float(num_at_symbols),
        "num_digits": float(digits),
        "digit_ratio": float(digit_ratio),
        "num_subdomains": float(subdomains),
        "is_ip_address": float(ip_flag),
        "is_https": float(https_flag),
        "has_suspicious_keywords": float(has_keywords),
        "is_shortened": float(shortener_flag),
        "suspicious_tld": float(tld_flag),
        "url_entropy": float(entropy),
        # NEW
        "has_digit_substitution": float(digit_sub_flag),
        "brand_doppelganger": float(doppelganger_flag),
        "has_punycode_idn": float(punycode_flag),
        "path_has_brand_mismatch": float(path_mismatch_flag),
    }

    return features


def extract_feature_vector(url: str) -> List[float]:
    """
    Extract features in strict order corresponding to FEATURE_NAMES.
    Used directly as input vector for scikit-learn models.
    """
    feat_dict = extract_features(url)
    return [feat_dict[name] for name in FEATURE_NAMES]


def get_observed_indicators(features: Dict[str, float], url: str) -> List[str]:
    """
    Derive transparent, observable lexical/structural indicators.
    Clearly represents observable URL characteristics (not fabricated).
    """
    indicators = []

    if features.get("is_ip_address", 0) == 1:
        indicators.append("IP address used directly as hostname (bypasses domain registration)")

    if features.get("num_at_symbols", 0) > 0:
        indicators.append("Contains '@' symbol (credential trickery: browser ignores pre-'@' authority)")

    if features.get("url_length", 0) > 75:
        indicators.append(f"Unusually long URL structure ({int(features['url_length'])} characters)")

    if features.get("num_subdomains", 0) >= 3:
        indicators.append(f"Excessive subdomain depth ({int(features['num_subdomains'])} subdomains)")

    if features.get("suspicious_tld", 0) == 1:
        indicators.append("Registered under a high-risk/frequently abused top-level domain (TLD)")

    if features.get("has_suspicious_keywords", 0) == 1:
        indicators.append("Contains high-risk security/credential keywords (e.g. login, verify, account, secure)")

    if features.get("is_shortened", 0) == 1:
        indicators.append("Uses a known URL shortening service (destination host is masked)")

    if features.get("is_https", 0) == 0:
        indicators.append("Unencrypted connection scheme (HTTP instead of HTTPS)")

    if features.get("digit_ratio", 0) > 0.20:
        indicators.append(f"High numeric density ({round(features['digit_ratio']*100, 1)}% digits)")

    if features.get("num_hyphens", 0) >= 3:
        indicators.append(f"Multiple hyphens in URL structure ({int(features['num_hyphens'])} hyphens)")

    if features.get("url_entropy", 0) > 4.5:
        indicators.append(f"Elevated string entropy ({features['url_entropy']}), indicating randomness or obfuscation")

    # NEW v2 indicators
    if features.get("has_digit_substitution", 0) == 1:
        indicators.append("Digit-for-letter substitution detected in domain (e.g. paypa1, g00gle) — classic typosquatting technique")

    if features.get("brand_doppelganger", 0) == 1:
        indicators.append("Domain name is a near-duplicate of a well-known brand (typosquatting / doppelganger domain)")

    if features.get("has_punycode_idn", 0) == 1:
        indicators.append("Punycode/IDN encoded hostname detected (xn--) — possible homoglyph/look-alike character attack")

    if features.get("path_has_brand_mismatch", 0) == 1:
        indicators.append("Known brand name appears in URL path or subdomain but the registered domain does not match (brand impersonation redirect)")

    return indicators
