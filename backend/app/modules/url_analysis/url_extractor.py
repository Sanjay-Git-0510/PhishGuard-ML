"""
URL Extraction Module
---------------------
Extracts URLs from email/SMS message text using regex-based static parsing.
Does NOT visit, resolve, or follow extracted URLs.
"""

import re
from typing import List
from urllib.parse import urlparse

# Comprehensive URL regex (matches http, https, and bare domains)
URL_REGEX = re.compile(
    r"(?:https?://|www\.)(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)",
    re.IGNORECASE
)

# Bare domain patterns (without scheme) — matches things like "bank-secure.example/login"
BARE_DOMAIN_REGEX = re.compile(
    r"(?<!\w)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"(?:com|net|org|in|io|co|uk|gov|edu|info|biz|xyz|top|tk|ml|cf|gq|ru|cn|click|link|online|site|website|live|shop)\b"
    r"(?:/[^\s]*)?",
    re.IGNORECASE
)

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "tiny.cc", "cutt.ly", "goo.gl", "bit.do", "shorte.st",
    "bc.vc", "adf.ly", "v.gd", "qr.ae", "rb.gy", "shorturl.at",
}


def extract_urls(text: str) -> List[str]:
    """
    Extract all URLs from message text using static regex parsing.
    Returns a deduplicated list of found URL strings.
    Does NOT make network requests or follow redirects.
    """
    if not text:
        return []

    found = set()

    # Match explicit http/https URLs and www. prefixed URLs
    for match in URL_REGEX.finditer(text):
        url = match.group(0).rstrip(".,;:)\"'")  # strip trailing punctuation
        if url:
            # Ensure scheme
            if url.startswith("www."):
                url = "http://" + url
            found.add(url)

    # Match bare domains that might be phishing links without scheme
    for match in BARE_DOMAIN_REGEX.finditer(text):
        candidate = match.group(0).rstrip(".,;:)\"'")
        # Avoid double-counting URLs already found
        already_found = any(candidate in u or u in candidate for u in found)
        if not already_found and len(candidate) > 6:
            # Prefix with http:// for downstream parsing
            if not candidate.startswith("http"):
                candidate = "http://" + candidate
            found.add(candidate)

    return sorted(found)


def classify_url_metadata(url: str) -> dict:
    """
    Extract static metadata about a URL without making any network request.
    """
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        hostname = parsed.hostname or ""
        is_shortener = any(
            hostname == s or hostname.endswith("." + s)
            for s in SHORTENER_DOMAINS
        )
        is_ip = bool(re.match(
            r"^(?:\d{1,3}\.){3}\d{1,3}$",
            hostname
        ))
        has_at = "@" in url
        is_https = url.startswith("https://")

        return {
            "url": url,
            "hostname": hostname,
            "is_shortener": is_shortener,
            "is_ip_address": is_ip,
            "has_at_symbol": has_at,
            "is_https": is_https,
            "path": parsed.path,
        }
    except Exception:
        return {
            "url": url,
            "hostname": "",
            "is_shortener": False,
            "is_ip_address": False,
            "has_at_symbol": False,
            "is_https": False,
            "path": "",
        }

