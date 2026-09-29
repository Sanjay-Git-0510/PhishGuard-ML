"""
Unit tests for URL Feature Extraction Engine
"""

import pytest
from app.ml.feature_extractor import (
    FEATURE_NAMES,
    extract_features,
    extract_feature_vector,
    calculate_entropy,
    is_ip_host,
    count_subdomains,
    get_observed_indicators,
)


def test_feature_count():
    feats = extract_features("https://www.google.com")
    assert len(feats) == len(FEATURE_NAMES)
    assert len(feats) == 24


def test_ip_address_detection():
    ip_url = "http://192.168.1.100/login.php"
    feats = extract_features(ip_url)
    assert feats["is_ip_address"] == 1.0
    assert feats["is_https"] == 0.0

    domain_url = "https://example.com/login"
    feats2 = extract_features(domain_url)
    assert feats2["is_ip_address"] == 0.0
    assert feats2["is_https"] == 1.0


def test_subdomains_count():
    url = "http://login.security.accounts.example.com/auth"
    feats = extract_features(url)
    assert feats["num_subdomains"] >= 2


def test_suspicious_keywords():
    url = "http://bad-host.xyz/banking/verify/account/login.html"
    feats = extract_features(url)
    assert feats["has_suspicious_keywords"] == 1.0


def test_url_shortener():
    url = "https://bit.ly/3xSecLogin"
    feats = extract_features(url)
    assert feats["is_shortened"] == 1.0


def test_entropy():
    # Random characters should yield higher entropy than repeated characters
    low_entropy = calculate_entropy("aaaaaaaaaa")
    high_entropy = calculate_entropy("a89z_q!2#xL9k1")
    assert high_entropy > low_entropy


def test_observed_indicators():
    url = "http://192.168.1.1/login.php?user=test"
    feats = extract_features(url)
    indicators = get_observed_indicators(feats, url)
    assert any("IP address" in ind for ind in indicators)
