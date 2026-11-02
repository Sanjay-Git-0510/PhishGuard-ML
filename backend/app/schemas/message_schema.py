"""
Pydantic Schemas for Message Analysis and Feedback
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator


_LANGUAGE_ALIASES = {
    "en": "english",
    "english": "english",
    "hi": "hindi",
    "hindi": "hindi",
    "kn": "kannada",
    "kannada": "kannada",
    "code_mixed": "code-mixed",
    "codemixed": "code-mixed",
    "hindi_english": "code-mixed",
    "kannada_english": "code-mixed",
}


def canonicalize_language(value: str) -> str:
    key = (value or "english").lower().replace(" ", "_").replace("-", "_")
    if key not in _LANGUAGE_ALIASES:
        raise ValueError("Language must be one of: english, hindi, kannada, code-mixed")
    return _LANGUAGE_ALIASES[key]


# ─────────────────────────────────────────────────────────────
# MESSAGE ANALYSIS REQUEST SCHEMAS
# ─────────────────────────────────────────────────────────────

class EmailAnalysisRequest(BaseModel):
    sender_name: Optional[str] = Field(None, max_length=255, description="Sender display name")
    sender_email: Optional[str] = Field(None, max_length=320, description="Sender email address")
    reply_to: Optional[str] = Field(None, max_length=320, description="Reply-To email address")
    claimed_org: Optional[str] = Field(None, max_length=255, description="Claimed organization name")
    subject: Optional[str] = Field(None, max_length=998, description="Email subject line")
    message: str = Field(..., min_length=1, max_length=50000, description="Email message body")
    language: str = Field("english", description="Message language: english, hindi, kannada, or code-mixed")

    @field_validator("language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        return canonicalize_language(v)


class SmsAnalysisRequest(BaseModel):
    sender_id: Optional[str] = Field(None, max_length=20, description="SMS sender ID or phone number")
    claimed_org: Optional[str] = Field(None, max_length=255, description="Claimed organization name")
    message: str = Field(..., min_length=1, max_length=5000, description="SMS message content")
    language: str = Field("english", description="Message language: english, hindi, kannada, or code-mixed")

    @field_validator("language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        return canonicalize_language(v)


# ─────────────────────────────────────────────────────────────
# MESSAGE ANALYSIS RESPONSE SCHEMAS
# ─────────────────────────────────────────────────────────────

class EvidenceItem(BaseModel):
    signal: str
    severity: str           # "high", "medium", "low", "info"
    source: str             # "message", "subject", "sender", "reply_to", "url", "identity"
    evidence: str           # quoted excerpt from the original source
    explanation: str        # plain-language explanation


class UrlResultItem(BaseModel):
    url: str
    prediction: str
    probability: float
    risk_level: str
    reasons: List[str]
    metadata: Dict[str, Any]


class UrlAnalysisResult(BaseModel):
    urls_found: List[str]
    url_count: int
    results: List[UrlResultItem]
    any_high_risk: bool
    any_phishing: bool
    highest_risk: str
    static_analysis_notice: str


class IdentityAnalysisResult(BaseModel):
    name_check: Dict[str, Any]
    reply_to_check: Dict[str, Any]
    domain_analysis: Dict[str, Any]
    sms_sender_check: Optional[Dict[str, Any]] = None
    overall_identity_status: str   # "trusted", "suspicious", "inconsistent", "unknown"
    identity_indicators: List[str]


class SocialEngineeringResult(BaseModel):
    urgency: List[Dict[str, Any]]
    fear: List[Dict[str, Any]]
    credential_request: List[Dict[str, Any]]
    financial: List[Dict[str, Any]]
    impersonation: List[Dict[str, Any]]
    total_signals: int
    has_credential_request: bool
    has_urgency: bool
    has_fear: bool
    has_financial: bool
    has_impersonation: bool
    strong_category_count: int


class MLClassificationResult(BaseModel):
    label: str                      # "suspicious" | "benign"
    confidence: float
    suspicious_probability: float
    method: str                     # "ml_model" | "rule_based_fallback"
    model_available: bool
    note: str
    model_info: Optional[Dict[str, Any]] = None


class RiskAssessmentResult(BaseModel):
    risk_level: str                 # "high" | "medium" | "low"
    risk_score: int
    triggered_rules: List[str]
    explanation: str
    contributing_factors: List[str]
    signal_summary: Dict[str, Any]
    risk_note: str


class MessageAnalysisResponse(BaseModel):
    analysis_id: str
    channel: str
    language: str
    risk_assessment: RiskAssessmentResult
    ml_classification: MLClassificationResult
    url_analysis: UrlAnalysisResult
    identity_analysis: IdentityAnalysisResult
    social_engineering: SocialEngineeringResult
    evidence: List[EvidenceItem]
    recommendations: List[str]
    user_correction_applied: Optional[str] = None
    privacy_notice: str = (
        "TRUSTLENS performs static security analysis. "
        "It does not open submitted links, send messages or perform actions on your behalf."
    )
    timestamp: str


# ─────────────────────────────────────────────────────────────
# FEEDBACK SCHEMAS
# ─────────────────────────────────────────────────────────────

class FeedbackRequest(BaseModel):
    analysis_id: str = Field(..., max_length=64, description="ID of the analysis to provide feedback on")
    original_prediction: Optional[str] = Field(None, max_length=32, description="The original risk level or prediction")
    original_risk_level: Optional[str] = Field(None, max_length=32, description="Alias for original_prediction (frontend compatibility)")
    channel: Optional[str] = Field(None, max_length=16, description="Message channel: email or sms")
    language: Optional[str] = Field(None, max_length=16, description="Message language for retraining")
    user_feedback: str = Field(..., description="User's assessment: 'legitimate' or 'suspicious'")
    feedback_reason: Optional[str] = Field(None, max_length=1000, description="Optional reason for feedback")
    message_text: Optional[str] = Field(None, max_length=50000, description="Original message text for retraining (stored only if user consents)")

    @field_validator("user_feedback")
    @classmethod
    def validate_feedback(cls, v: str) -> str:
        allowed = {"legitimate", "benign", "suspicious", "still_suspicious", "incorrect"}
        if v.lower() not in allowed:
            raise ValueError(f"user_feedback must be one of: {', '.join(allowed)}")
        return v.lower()

    def get_prediction(self) -> str:
        """Return original_prediction, falling back to original_risk_level."""
        return self.original_prediction or self.original_risk_level or "unknown"


class FeedbackResponse(BaseModel):
    feedback_id: int
    analysis_id: str
    original_prediction: Optional[str] = None
    user_feedback: str
    created_at: str
    retrained: bool = False
    message: str = "Feedback recorded. Thank you for helping improve TRUSTLENS."


class FeedbackSummaryResponse(BaseModel):
    total_feedback: int
    legitimate_count: int
    suspicious_count: int
    feedback_items: List[Dict[str, Any]]

