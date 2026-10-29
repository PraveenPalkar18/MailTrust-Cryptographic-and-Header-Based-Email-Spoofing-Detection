"""
Phishing Rules Module for MailTrust
Deterministic, transparent keyword and pattern rules for suspicious email indicators.
Strictly adheres to CNS constraint: NO NLP, NO MACHINE LEARNING, NO HARDCODED VERDICTS.
"""

import re
from typing import Dict, List, Any, Optional

from config import Config


class PhishingIndicator:
    """Represents a matched heuristic security indicator."""

    def __init__(
        self,
        rule_id: str,
        category: str,
        title: str,
        severity: str,  # LOW, MEDIUM, HIGH, CRITICAL
        matched_text: str,
        explanation: str
    ):
        self.rule_id = rule_id
        self.category = category
        self.title = title
        self.severity = severity
        self.matched_text = matched_text
        self.explanation = explanation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "matched_text": self.matched_text,
            "explanation": self.explanation,
        }


class PhishingIndicatorsResult:
    """Aggregated container for content-based heuristic indicators."""

    def __init__(self):
        self.indicators: List[PhishingIndicator] = []
        self.has_urgent_threat: bool = False
        self.has_credential_harvesting: bool = False
        self.has_financial_fraud: bool = False
        self.has_dangerous_attachment: bool = False
        self.has_form_submission_lure: bool = False
        self.has_career_lure: bool = False
        self.total_heuristic_score: int = 0
        self.summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicators_count": len(self.indicators),
            "indicators": [i.to_dict() for i in self.indicators],
            "has_urgent_threat": self.has_urgent_threat,
            "has_credential_harvesting": self.has_credential_harvesting,
            "has_financial_fraud": self.has_financial_fraud,
            "has_dangerous_attachment": self.has_dangerous_attachment,
            "has_form_submission_lure": self.has_form_submission_lure,
            "has_career_lure": self.has_career_lure,
            "total_heuristic_score": self.total_heuristic_score,
            "summary": self.summary,
        }


# Configurable deterministic pattern rules
PHISHING_PATTERNS = [
    # 1. Credential Harvesting & Account Takeover
    {
        "id": "CRED-001",
        "category": "Credential Harvesting",
        "title": "Password / Credential Expiration Lure",
        "severity": "HIGH",
        "weight": 25,
        "pattern": r"\b(password\s+(?:expires|has\s+expired|reset\s+required)|expire(?:s)?\s+in\s+\d+\s+hours?|verify\s+your\s+(?:credentials|password))\b",
        "explanation": "Attempts to induce the user into entering credentials on an external site by claiming password expiration."
    },
    {
        "id": "CRED-002",
        "category": "Credential Harvesting",
        "title": "One-Time Passcode (OTP) / MFA Verification Lure",
        "severity": "HIGH",
        "weight": 25,
        "pattern": r"\b(send\s+(?:us\s+)?(?:the|your)\s+(?:code|otp|passcode|token)|enter\s+the\s+(?:verification|2fa|mfa)\s+code|two-factor\s+authentication\s+code)\b",
        "explanation": "Solicits one-time authentication codes, which adversaries use to bypass multi-factor authentication (MFA)."
    },
    {
        "id": "CRED-003",
        "category": "Credential Harvesting",
        "title": "Urgent Account Verification Call-to-Action",
        "severity": "MEDIUM",
        "weight": 15,
        "pattern": r"\b(verify\s+your\s+account\s+immediately|click\s+here\s+to\s+(?:reactivate|unlock|restore)\s+your\s+account|confirm\s+identity\s+now)\b",
        "explanation": "Pressures recipient to click an unverified verification link under false pretenses of an account freeze."
    },

    # 2. Financial Fraud & Coercion
    {
        "id": "FIN-001",
        "category": "Financial Fraud",
        "title": "Urgent Wire Transfer / Payment Diversion",
        "severity": "HIGH",
        "weight": 30,
        "pattern": r"\b(wire\s+transfer|transfer\s+funds\s+immediately|direct\s+deposit\s+change|send\s+payment\s+urgently|remit\s+the\s+balance)\b",
        "explanation": "Common in Business Email Compromise (BEC) attacks attempting to divert invoices or corporate funds."
    },
    {
        "id": "FIN-002",
        "category": "Financial Fraud",
        "title": "Unconventional Payment Request (Gift Cards / Cryptocurrency)",
        "severity": "CRITICAL",
        "weight": 40,
        "pattern": r"\b((?:gift\s*card|itunes\s*card|steam\s*card|amazon\s*gift\s*card|google\s*play\s*card)|(?:bitcoin|btc|cryptocurrency|crypto\s*wallet|ethereum|usdt)\s+(?:address|payment))\b",
        "explanation": "Legitimate institutions and organizations never request payments in retail gift cards or untraceable cryptocurrency."
    },
    {
        "id": "FIN-003",
        "category": "Financial Fraud",
        "title": "Advance Fee / Inheritance / Prize Scam Lure",
        "severity": "MEDIUM",
        "weight": 20,
        "pattern": r"\b(claim\s+your\s+(?:prize|lottery|inheritance)|compensation\s+fund|consignment\s+box|next\s+of\s+kin|processing\s+fee\s+to\s+release)\b",
        "explanation": "Classic advance-fee fraud (419) soliciting personal details and fees for non-existent disbursements."
    },

    # 3. Urgency and Threat Language
    {
        "id": "URG-001",
        "category": "Urgency & Threats",
        "title": "Severe Time-Pressure Threat (Suspension / Termination)",
        "severity": "MEDIUM",
        "weight": 15,
        "pattern": r"\b(suspended\s+within\s+(?:24|48|12)\s+hours?|immediate\s+action\s+required|failure\s+to\s+respond\s+will\s+result|permanent(?:ly)?\s+delet(?:ed|ion))\b",
        "explanation": "Psychological manipulation designed to bypass cognitive caution through artificial time-pressure."
    },
    {
        "id": "URG-002",
        "category": "Urgency & Threats",
        "title": "Legal Action / Law Enforcement Threat",
        "severity": "HIGH",
        "weight": 25,
        "pattern": r"\b(legal\s+action\s+will\s+be\s+taken|law\s+enforcement\s+agency|court\s+summons|subpoena|warrant\s+for\s+arrest)\b",
        "explanation": "Coercive legal threats intended to intimidate recipients into compliance."
    },

    # 4. External Public Forms & Data Submission
    {
        "id": "FORM-001",
        "category": "External Form Submission",
        "title": "Public Cloud Form Registration Link",
        "severity": "MEDIUM",
        "weight": 15,
        "pattern": r"(?:https?:\/\/)?(?:forms\.gle\/[a-zA-Z0-9_-]+|docs\.google\.com\/forms\/|forms\.office\.com\/[a-zA-Z0-9_-]+)",
        "explanation": "Directs user to register or submit personal/academic details via public cloud forms instead of an authenticated portal."
    },

    # 5. Career & Internship Stipend Solicitations
    {
        "id": "CAREER-001",
        "category": "Recruitment & Training Lure",
        "title": "Stipend / Assessment Readiness Solicitation",
        "severity": "LOW",
        "weight": 10,
        "pattern": r"\b(stipend-based\s+internship|stipend\s+opportunities|career\s+readiness\s+program|training\s+&\s+stipend|national-level\s+corporate\s+assessments?)\b",
        "explanation": "Mentions corporate test preparation or stipend-based internships; verify sender domain credentials."
    },
]


def inspect_phishing_indicators(
    parsed_email: Any
) -> PhishingIndicatorsResult:
    """
    Examines subject, text body, and attachments against deterministic security patterns.
    """
    result = PhishingIndicatorsResult()

    subject = getattr(parsed_email, "subject", "")
    text_body = getattr(parsed_email, "text_body", "")
    html_body = getattr(parsed_email, "html_body", "")
    attachments = getattr(parsed_email, "attachments", [])

    # Combine text for scanning
    full_text = f"Subject: {subject}\n{text_body}\n{html_body}"

    # 1. Pattern checks
    for rule in PHISHING_PATTERNS:
        match = re.search(rule["pattern"], full_text, re.IGNORECASE)
        if match:
            matched_snippet = match.group(0)
            indicator = PhishingIndicator(
                rule_id=rule["id"],
                category=rule["category"],
                title=rule["title"],
                severity=rule["severity"],
                matched_text=matched_snippet,
                explanation=rule["explanation"]
            )
            result.indicators.append(indicator)
            result.total_heuristic_score += rule["weight"]

            if rule["category"] == "Credential Harvesting":
                result.has_credential_harvesting = True
            elif rule["category"] == "Financial Fraud":
                result.has_financial_fraud = True
            elif rule["category"] == "Urgency & Threats":
                result.has_urgent_threat = True
            elif rule["category"] == "External Form Submission":
                result.has_form_submission_lure = True
            elif rule["category"] == "Recruitment & Training Lure":
                result.has_career_lure = True

    # 2. Dangerous Attachments Check
    for att in attachments:
        if att.get("is_dangerous_extension"):
            result.has_dangerous_attachment = True
            ext = att.get("extension", "")
            fn = att.get("filename", "")
            indicator = PhishingIndicator(
                rule_id="MAL-ATT-001",
                category="Malware Delivery",
                title=f"Executable / Dangerous Attachment ('{fn}')",
                severity="CRITICAL",
                matched_text=fn,
                explanation=(
                    f"File extension '{ext}' is classified as high-risk executable code. "
                    "Legitimate email communications rarely transmit executable binaries or scripts."
                )
            )
            result.indicators.append(indicator)
            result.total_heuristic_score += 40

    # Summary
    if not result.indicators:
        result.summary = "No content-based phishing keywords or dangerous attachments detected."
    else:
        result.summary = f"Triggered {len(result.indicators)} content heuristic indicator(s) (Score: {result.total_heuristic_score})."

    return result
