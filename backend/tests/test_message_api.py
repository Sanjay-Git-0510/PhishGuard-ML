"""
Integration tests for TRUSTLENS Message Analysis and Feedback API endpoints.

These tests verify:
  - Email analysis (English, Kannada, code-mixed)
  - SMS analysis (English, Kannada)
  - Identity mismatch detection (reply-to, lookalike domain)
  - Social engineering signal detection
  - URL extraction from message bodies
  - Feedback submission and retrieval
  - Input validation and error handling
  - Existing URL detection endpoints remain functional

Run:
    cd backend
    ..\\venv\\Scripts\\pytest.exe tests/test_message_api.py -v
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


# ─────────────────────────────────────────────────────────────
# EMAIL ANALYSIS TESTS
# ─────────────────────────────────────────────────────────────

class TestEmailAnalysis:
    """Tests for POST /api/analyze-message"""

    def test_legitimate_english_email(self):
        """A normal business email should produce LOW risk."""
        payload = {
            "sender_name": "John Smith",
            "sender_email": "john.smith@company.example",
            "reply_to": "",
            "claimed_org": "",
            "subject": "Meeting tomorrow at 10am",
            "message": "Hi team, just a reminder that we have a standup meeting tomorrow at 10am. Please bring your progress updates. Thanks, John",
            "language": "english",
        }
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "analysis_id" in data
        assert data["channel"] == "email"
        assert data["language"] == "english"
        assert data["risk_assessment"]["risk_level"] in ("low", "medium")
        assert data["ml_classification"]["label"] in ("benign", "suspicious")
        assert isinstance(data["evidence"], list)
        assert isinstance(data["recommendations"], list)

    def test_suspicious_english_email(self):
        """A phishing email with credential harvesting language should flag HIGH risk."""
        payload = {
            "sender_name": "Demo Bank Security",
            "sender_email": "security@dem0bank.com",
            "reply_to": "collect@gmail.com",
            "claimed_org": "Demo Bank",
            "subject": "URGENT: Your account has been suspended",
            "message": (
                "Dear Customer, your account has been suspended due to suspicious activity. "
                "Click here to verify: http://dem0bank-verify.tk/login and enter your "
                "password and OTP immediately or your account will be permanently closed."
            ),
            "language": "english",
        }
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_assessment"]["risk_level"] in ("high", "medium")
        # Should detect reply-to mismatch
        identity = data["identity_analysis"]
        assert identity["overall_identity_status"] in ("suspicious", "inconsistent")
        # Should detect social engineering signals
        se = data["social_engineering"]
        assert se["total_signals"] > 0
        assert se["has_credential_request"] is True or se["has_urgency"] is True
        # Should find at least one URL
        assert data["url_analysis"]["url_count"] >= 1
        # Evidence should be non-empty
        assert len(data["evidence"]) > 0

    def test_english_hindi_phishing_same_risk_tier(self):
        """Equivalent English and Hindi phishing emails should both be HIGH with credentials."""
        english = {
            "sender_name": "Demo Bank Security",
            "sender_email": "security@dem0bank.com",
            "reply_to": "collect@gmail.com",
            "claimed_org": "Demo Bank",
            "subject": "URGENT: Your account has been suspended",
            "message": (
                "Dear Customer, your account has been suspended due to suspicious activity. "
                "Click here to verify: http://dem0bank-verify.tk/login and enter your "
                "password and OTP immediately or your account will be permanently closed."
            ),
            "language": "english",
        }
        hindi = {
            "sender_name": "डेमो बैंक सुरक्षा",
            "sender_email": "security@dem0bank.com",
            "reply_to": "collect@gmail.com",
            "claimed_org": "Demo Bank",
            "subject": "तुरंत: आपका खाता निलंबित कर दिया गया है",
            "message": (
                "प्रिय ग्राहक, संदिग्ध गतिविधि के कारण आपका खाता निलंबित कर दिया गया है। "
                "सत्यापित करने के लिए यहाँ क्लिक करें: http://dem0bank-verify.tk/login "
                "और अपना पासवर्ड तथा OTP तुरंत दर्ज करें वरना खाता स्थायी रूप से बंद हो जाएगा।"
            ),
            "language": "hindi",
        }
        en = client.post("/api/analyze-message", json=english).json()
        hi = client.post("/api/analyze-message", json=hindi).json()
        assert en["risk_assessment"]["risk_level"] == "high"
        assert hi["risk_assessment"]["risk_level"] == "high"
        assert en["social_engineering"]["has_credential_request"] is True
        assert hi["social_engineering"]["has_credential_request"] is True
        assert en["ml_classification"]["label"] == hi["ml_classification"]["label"] == "suspicious"

    def test_english_hindi_benign_same_risk_tier(self):
        """Equivalent English and Hindi bank statements should both be LOW."""
        english = {
            "sender_name": "Demo Bank",
            "sender_email": "statements@demobank.example",
            "claimed_org": "Demo Bank",
            "subject": "Account Statement — October 2024",
            "message": (
                "Dear Account Holder, Your account statement for October 2024 is now available. "
                "You can view it by logging into your Demo Bank account at www.demobank.example. "
                "If you notice any discrepancy, please contact our customer care at 1800-000-0001. "
                "Demo Bank will never ask for your OTP or PIN. Thank you."
            ),
            "language": "english",
        }
        hindi = {
            "sender_name": "डेमो बैंक",
            "sender_email": "statements@demobank.example",
            "claimed_org": "Demo Bank",
            "subject": "खाता विवरण — अक्टूबर 2024",
            "message": (
                "प्रिय ग्राहक, अक्टूबर 2024 का आपका डेमो बैंक खाता विवरण अब उपलब्ध है। "
                "www.demobank.example पर लॉगिन करके देखें। किसी भी अंतर के लिए 1800-000-0001 पर कॉल करें। "
                "डेमो बैंक कभी OTP या PIN नहीं माँगता। धन्यवाद।"
            ),
            "language": "hindi",
        }
        en = client.post("/api/analyze-message", json=english).json()
        hi = client.post("/api/analyze-message", json=hindi).json()
        assert en["risk_assessment"]["risk_level"] == "low"
        assert hi["risk_assessment"]["risk_level"] == "low"
        assert en["ml_classification"]["label"] == "benign"
        assert hi["ml_classification"]["label"] == "benign"

    def test_hindi_detected_even_if_language_set_english(self):
        """Pasting Hindi while the language field is still English must still detect phishing."""
        payload = {
            "sender_email": "security@dem0bank.com",
            "reply_to": "collect@gmail.com",
            "claimed_org": "Demo Bank",
            "subject": "खाता निलंबित",
            "message": (
                "आपका खाता निलंबित है। लिंक खोलें http://dem0bank-verify.tk/login "
                "और ओटीपी शेयर करें।"
            ),
            "language": "english",
        }
        data = client.post("/api/analyze-message", json=payload).json()
        assert data["risk_assessment"]["risk_level"] in ("high", "medium")
        assert data["social_engineering"]["has_credential_request"] is True
        assert data["social_engineering"]["total_signals"] > 0

    def test_hindi_email(self):
        """A Hindi phishing email should be processed and flag social-engineering signals."""
        payload = {
            "sender_name": "डेमो बैंक सुरक्षा",
            "sender_email": "security@demobank-verify.xyz",
            "reply_to": "collect@quickmail.example",
            "claimed_org": "Demo Bank",
            "subject": "तुरंत: खाता निलंबित",
            "message": (
                "प्रिय ग्राहक, आपका डेमो बैंक खाता निलंबित कर दिया गया है। "
                "24 घंटे के भीतर OTP और पासवर्ड दर्ज करें: http://demobank-verify.xyz/hi/login "
                "वरना खाता स्थायी रूप से बंद हो जाएगा।"
            ),
            "language": "hindi",
        }
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["language"] == "hindi"
        assert data["risk_assessment"]["risk_level"] in ("high", "medium")
        assert len(data["evidence"]) > 0
        recs = " ".join(data["recommendations"]).lower()
        assert "known" in recs or "official" in recs
        se = data["social_engineering"]
        assert se["total_signals"] > 0

    def test_kannada_email(self):
        """A Kannada email should be processed correctly."""
        payload = {
            "sender_name": "",
            "sender_email": "info@example.com",
            "reply_to": "",
            "claimed_org": "",
            "subject": "ಸಂದೇಶ",
            "message": "ನಿಮ್ಮ ಖಾತೆ ಸ್ಥಗಿತಗೊಂಡಿದೆ. ದಯವಿಟ್ಟು ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ನಮೂದಿಸಿ ಮತ್ತು OTP ದೃಢೀಕರಿಸಿ.",
            "language": "kannada",
        }
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["channel"] == "email"
        assert data["language"] == "kannada"
        assert "risk_assessment" in data
        assert "ml_classification" in data

    def test_code_mixed_email(self):
        """A Kannada-English code-mixed email should be handled."""
        payload = {
            "sender_name": "",
            "sender_email": "alerts@bank.example",
            "reply_to": "",
            "claimed_org": "",
            "subject": "Account Update",
            "message": "Dear user, ನಿಮ್ಮ account verify ಮಾಡಿ. Click this link http://fakebank.tk/verify to update ನಿಮ್ಮ password.",
            "language": "code-mixed",
        }
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["language"] == "code-mixed"
        # Should still detect URLs
        assert data["url_analysis"]["url_count"] >= 1

    def test_reply_to_mismatch(self):
        """Reply-To address on a different domain should be flagged."""
        payload = {
            "sender_name": "Support Team",
            "sender_email": "support@trustedbank.example",
            "reply_to": "scammer@random-domain.xyz",
            "claimed_org": "",
            "subject": "Account review",
            "message": "Please review your account details and let us know if you have questions.",
            "language": "english",
        }
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        identity = data["identity_analysis"]
        # Reply-to check should show mismatch
        reply_check = identity.get("reply_to_check", {})
        assert reply_check.get("status") == "mismatch"

    def test_email_with_url_in_body(self):
        """URLs embedded in the message body should be extracted and analysed."""
        payload = {
            "sender_name": "",
            "sender_email": "noreply@example.com",
            "reply_to": "",
            "claimed_org": "",
            "subject": "Check this out",
            "message": "Visit https://bit.ly/fakelink and also http://192.168.1.1/admin/login.php for details.",
            "language": "english",
        }
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["url_analysis"]["url_count"] >= 2
        results = data["url_analysis"]["results"]
        assert len(results) >= 2

    def test_otp_request_detection(self):
        """A message requesting OTP should trigger credential harvesting signal."""
        payload = {
            "sender_name": "",
            "sender_email": "verify@bank.example",
            "reply_to": "",
            "claimed_org": "",
            "subject": "OTP Verification",
            "message": "Please share your OTP and password to verify your bank account. Enter your PIN and card number to proceed.",
            "language": "english",
        }
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        se = data["social_engineering"]
        assert se["has_credential_request"] is True


# ─────────────────────────────────────────────────────────────
# SMS ANALYSIS TESTS
# ─────────────────────────────────────────────────────────────

class TestSmsAnalysis:
    """Tests for POST /api/analyze-sms"""

    def test_legitimate_english_sms(self):
        """A normal SMS should produce LOW risk."""
        payload = {
            "sender_id": "SCHOOL",
            "claimed_org": "",
            "message": "Reminder: Parent-teacher meeting on Saturday at 3pm. Please confirm attendance.",
            "language": "english",
        }
        resp = client.post("/api/analyze-sms", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["channel"] == "sms"
        assert data["risk_assessment"]["risk_level"] in ("low", "medium")

    def test_suspicious_english_sms(self):
        """A phishing SMS with urgency and link should flag higher risk."""
        payload = {
            "sender_id": "+919876543210",
            "claimed_org": "Demo Bank",
            "message": "URGENT: Your Demo Bank account will be blocked! Click http://dem0bank.tk/verify now to avoid suspension. Enter OTP immediately.",
            "language": "english",
        }
        resp = client.post("/api/analyze-sms", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_assessment"]["risk_level"] in ("high", "medium")
        assert data["url_analysis"]["url_count"] >= 1
        se = data["social_engineering"]
        assert se["total_signals"] > 0

    def test_english_hindi_sms_phishing_same_risk_tier(self):
        """Equivalent English and Hindi phishing SMS should both be HIGH."""
        english = {
            "sender_id": "+919876543210",
            "claimed_org": "Demo Bank",
            "message": (
                "URGENT: Your Demo Bank account will be blocked! "
                "Click http://dem0bank.tk/verify now. Enter OTP immediately."
            ),
            "language": "english",
        }
        hindi = {
            "sender_id": "+919876543210",
            "claimed_org": "Demo Bank",
            "message": (
                "तुरंत: आपका डेमो बैंक खाता ब्लॉक हो जाएगा! "
                "अभी क्लिक करें http://dem0bank.tk/verify OTP डालें।"
            ),
            "language": "hindi",
        }
        en = client.post("/api/analyze-sms", json=english).json()
        hi = client.post("/api/analyze-sms", json=hindi).json()
        assert en["risk_assessment"]["risk_level"] == "high"
        assert hi["risk_assessment"]["risk_level"] == "high"
        assert en["social_engineering"]["has_credential_request"] is True
        assert hi["social_engineering"]["has_credential_request"] is True

    def test_hindi_sms(self):
        """A Hindi phishing SMS should be processed with evidence and known-channel guidance."""
        payload = {
            "sender_id": "DM0BANK",
            "claimed_org": "Demo Bank",
            "message": (
                "तुरंत: डेमो बैंक खाता निलंबित। सत्यापित करें: "
                "http://demobank-verify.xyz/hi OTP और PIN डालें।"
            ),
            "language": "hindi",
        }
        resp = client.post("/api/analyze-sms", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["language"] == "hindi"
        assert data["risk_assessment"]["risk_level"] in ("high", "medium")
        assert len(data["evidence"]) > 0
        recs = " ".join(data["recommendations"]).lower()
        assert "known" in recs or "official" in recs
        assert data["social_engineering"]["total_signals"] > 0

    def test_kannada_sms(self):
        """A Kannada SMS should be processed without errors."""
        payload = {
            "sender_id": "DEMOBNK",
            "claimed_org": "",
            "message": "ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ನಿಷ್ಕ್ರಿಯವಾಗಿದೆ. ಈಗಲೇ OTP ನಮೂದಿಸಿ ಮತ್ತು ಪಾಸ್‌ವರ್ಡ್ ಬದಲಾಯಿಸಿ.",
            "language": "kannada",
        }
        resp = client.post("/api/analyze-sms", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["channel"] == "sms"
        assert data["language"] == "kannada"

    def test_sms_minimal_fields(self):
        """SMS with only required fields (message + language) should work."""
        payload = {
            "message": "Hello, how are you?",
            "language": "english",
        }
        resp = client.post("/api/analyze-sms", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["channel"] == "sms"
        assert data["risk_assessment"]["risk_level"] in ("low", "medium", "high")


# ─────────────────────────────────────────────────────────────
# RESPONSE STRUCTURE VALIDATION
# ─────────────────────────────────────────────────────────────

class TestResponseStructure:
    """Verify the full response schema matches the specification."""

    def _get_analysis(self):
        payload = {
            "sender_name": "Test",
            "sender_email": "test@example.com",
            "message": "This is a test message for structural validation.",
            "language": "english",
        }
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 200
        return resp.json()

    def test_top_level_fields(self):
        data = self._get_analysis()
        required_fields = [
            "analysis_id", "channel", "language",
            "risk_assessment", "ml_classification",
            "url_analysis", "identity_analysis",
            "social_engineering", "evidence",
            "recommendations", "timestamp",
        ]
        for field in required_fields:
            assert field in data, f"Missing top-level field: {field}"

    def test_risk_assessment_fields(self):
        data = self._get_analysis()
        ra = data["risk_assessment"]
        assert ra["risk_level"] in ("high", "medium", "low")
        assert isinstance(ra["risk_score"], int)
        assert isinstance(ra["triggered_rules"], list)
        assert isinstance(ra["explanation"], str)
        assert isinstance(ra["contributing_factors"], list)
        assert isinstance(ra["risk_note"], str)

    def test_ml_classification_fields(self):
        data = self._get_analysis()
        ml = data["ml_classification"]
        assert ml["label"] in ("suspicious", "benign")
        assert isinstance(ml["confidence"], (int, float))
        assert isinstance(ml["suspicious_probability"], (int, float))
        assert ml["method"] in ("ml_model", "rule_based_fallback")
        assert isinstance(ml["model_available"], bool)

    def test_url_analysis_fields(self):
        data = self._get_analysis()
        ua = data["url_analysis"]
        assert isinstance(ua["urls_found"], list)
        assert isinstance(ua["url_count"], int)
        assert isinstance(ua["results"], list)
        assert isinstance(ua["any_phishing"], bool)

    def test_identity_analysis_fields(self):
        data = self._get_analysis()
        ia = data["identity_analysis"]
        assert "name_check" in ia
        assert "reply_to_check" in ia
        assert "domain_analysis" in ia
        assert "overall_identity_status" in ia
        assert isinstance(ia["identity_indicators"], list)

    def test_social_engineering_fields(self):
        data = self._get_analysis()
        se = data["social_engineering"]
        for key in ("urgency", "fear", "credential_request", "financial", "impersonation"):
            assert isinstance(se[key], list), f"SE category '{key}' should be a list"
        assert isinstance(se["total_signals"], int)
        assert isinstance(se["has_credential_request"], bool)

    def test_evidence_items_structure(self):
        """Submit a suspicious message and check evidence item format."""
        payload = {
            "sender_email": "alert@dem0bank.com",
            "reply_to": "scam@gmail.com",
            "claimed_org": "Demo Bank",
            "subject": "Verify now",
            "message": "Enter your password immediately or account will be closed.",
            "language": "english",
        }
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        if len(data["evidence"]) > 0:
            item = data["evidence"][0]
            assert "signal" in item
            assert "severity" in item
            assert item["severity"] in ("high", "medium", "low", "info")
            assert "source" in item
            assert "evidence" in item
            assert "explanation" in item

    def test_privacy_notice_present(self):
        data = self._get_analysis()
        assert "privacy_notice" in data
        assert "static" in data["privacy_notice"].lower()

    def test_known_channel_guidance_present(self):
        data = self._get_analysis()
        recs = " ".join(data["recommendations"]).lower()
        assert "known" in recs or "official" in recs


# ─────────────────────────────────────────────────────────────
# INPUT VALIDATION AND ERROR HANDLING
# ─────────────────────────────────────────────────────────────

class TestInputValidation:
    """Test input validation and error handling."""

    def test_empty_message_rejected(self):
        """Empty message should be rejected with 422."""
        payload = {"message": "", "language": "english"}
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 422

    def test_missing_message_field(self):
        """Request without message field should be rejected."""
        payload = {"language": "english"}
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 422

    def test_invalid_language(self):
        """Invalid language should be rejected."""
        payload = {"message": "Test message", "language": "french"}
        resp = client.post("/api/analyze-message", json=payload)
        assert resp.status_code == 422

    def test_sms_empty_message_rejected(self):
        """SMS with empty message should be rejected."""
        payload = {"message": "", "language": "english"}
        resp = client.post("/api/analyze-sms", json=payload)
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────
# FEEDBACK TESTS
# ─────────────────────────────────────────────────────────────

class TestFeedback:
    """Tests for feedback submission and retrieval."""

    def test_submit_feedback_legitimate(self):
        """Submit 'legitimate' feedback for an analysis."""
        # First, run an analysis to get an analysis_id
        analysis_resp = client.post("/api/analyze-message", json={
            "message": "Your account needs verification. Click http://fake.tk/login.",
            "language": "english",
        })
        assert analysis_resp.status_code == 200
        analysis_id = analysis_resp.json()["analysis_id"]

        # Submit feedback
        feedback_resp = client.post("/api/feedback", json={
            "analysis_id": analysis_id,
            "original_risk_level": "high",
            "user_feedback": "legitimate",
            "feedback_reason": "This is from a known sender.",
        })
        assert feedback_resp.status_code == 200
        fb = feedback_resp.json()
        assert fb["analysis_id"] == analysis_id
        assert fb["user_feedback"] == "legitimate"
        assert "feedback_id" in fb

    def test_submit_feedback_still_suspicious(self):
        """Submit 'still_suspicious' feedback."""
        feedback_resp = client.post("/api/feedback", json={
            "analysis_id": "test-id-001",
            "original_risk_level": "low",
            "user_feedback": "still_suspicious",
        })
        assert feedback_resp.status_code == 200
        fb = feedback_resp.json()
        assert fb["user_feedback"] == "still_suspicious"

    def test_feedback_invalid_type(self):
        """Invalid feedback type should be rejected."""
        resp = client.post("/api/feedback", json={
            "analysis_id": "test-id",
            "original_risk_level": "high",
            "user_feedback": "maybe",
        })
        assert resp.status_code == 422

    def test_false_positive_retrain_then_reanalyze(self):
        """Challenging a result as legitimate retrains the model and changes re-analysis."""
        unique_msg = (
            "Campus newsletter for the robotics club weekly meetup this Friday "
            "in lab 3. Bring your project notes. Reference FP-RETRAIN-UNIQUE-4419."
        )
        payload = {
            "sender_name": "Robotics Club",
            "sender_email": "club@demouniversity.example",
            "subject": "Weekly meetup reminder",
            "message": unique_msg,
            "language": "english",
        }
        first = client.post("/api/analyze-message", json=payload)
        assert first.status_code == 200
        analysis_id = first.json()["analysis_id"]

        fb = client.post("/api/feedback", json={
            "analysis_id": analysis_id,
            "original_risk_level": first.json()["risk_assessment"]["risk_level"],
            "user_feedback": "legitimate",
            "feedback_reason": "Official club mail.",
            "channel": "email",
            "language": "english",
            "message_text": unique_msg,
        })
        assert fb.status_code == 200
        body = fb.json()
        assert body["user_feedback"] == "legitimate"
        assert body.get("retrained") is True or "recorded" in body.get("message", "").lower()

        second = client.post("/api/analyze-message", json=payload)
        assert second.status_code == 200
        data = second.json()
        assert data["ml_classification"]["label"] == "benign"
        assert data["risk_assessment"]["risk_level"] == "low"
        assert data.get("user_correction_applied") == "benign"

    def test_hindi_false_positive_retrain_then_reanalyze(self):
        """Hindi legitimate messages can be challenged and re-analysis must return LOW."""
        unique_msg = (
            "प्रिय विद्यार्थियों, डेमो विश्वविद्यालय रोबोटिक्स क्लब की बैठक शुक्रवार को "
            "प्रयोगशाला 3 में है। परियोजना नोट्स साथ लाएँ। संदर्भ HI-FP-RETRAIN-8821।"
        )
        payload = {
            "sender_name": "रोबोटिक्स क्लब",
            "sender_email": "club@demouniversity.example",
            "subject": "क्लब बैठक",
            "message": unique_msg,
            "language": "hindi",
        }
        first = client.post("/api/analyze-message", json=payload)
        assert first.status_code == 200
        analysis_id = first.json()["analysis_id"]
        recs = " ".join(first.json()["recommendations"]).lower()
        assert "known" in recs or "official" in recs

        fb = client.post("/api/feedback", json={
            "analysis_id": analysis_id,
            "original_risk_level": first.json()["risk_assessment"]["risk_level"],
            "user_feedback": "legitimate",
            "feedback_reason": "आधिकारिक क्लब संदेश।",
            "channel": "email",
            "language": "hindi",
            "message_text": unique_msg,
        })
        assert fb.status_code == 200
        assert fb.json().get("retrained") is True or "recorded" in fb.json().get("message", "").lower()

        second = client.post("/api/analyze-message", json=payload)
        assert second.status_code == 200
        data = second.json()
        assert data["ml_classification"]["label"] == "benign"
        assert data["risk_assessment"]["risk_level"] == "low"
        assert data.get("user_correction_applied") == "benign"

    def test_feedback_summary(self):
        """GET /api/feedback/summary should return a valid summary."""
        resp = client.get("/api/feedback/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_feedback" in data
        assert "legitimate_count" in data
        assert "suspicious_count" in data
        assert isinstance(data["feedback_items"], list)


# ─────────────────────────────────────────────────────────────
# BACKWARD COMPATIBILITY TESTS
# ─────────────────────────────────────────────────────────────

class TestBackwardCompatibility:
    """Verify that existing URL detection endpoints still work."""

    def test_existing_predict_endpoint(self):
        """POST /api/predict must still function for URL analysis."""
        resp = client.post("/api/predict", json={"url": "https://www.google.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert "prediction" in data
        assert data["prediction"] in ("phishing", "legitimate")
        assert "probability" in data
        assert "features" in data

    def test_existing_health_endpoint(self):
        """GET /api/health must still return model status."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["model_loaded"] is True

    def test_existing_model_info_endpoint(self):
        """GET /api/model-info must still work."""
        resp = client.get("/api/model-info")
        assert resp.status_code == 200
        data = resp.json()
        assert "selected_model" in data

    def test_existing_batch_predict(self):
        """POST /api/batch-predict must still work."""
        resp = client.post("/api/batch-predict", json={
            "urls": ["https://www.wikipedia.org", "http://evil.tk/login"]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2

