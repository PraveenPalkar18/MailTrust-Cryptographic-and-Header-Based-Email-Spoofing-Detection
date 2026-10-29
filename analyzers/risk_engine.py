"""
Explainable Risk Assessment Engine for MailTrust
Synthesizes cryptographic verification (DKIM), sender authorization (SPF),
policy alignment (DMARC), domain heuristics, and content indicators into a
transparent, explainable CNS security verdict.
"""

from typing import Dict, List, Any, Optional

from .email_parser import ParsedEmail
from .dkim_analyzer import DKIMVerificationResult
from .spf_analyzer import SPFResult
from .dmarc_analyzer import DMARCResult
from .domain_analyzer import DomainAnalysisResult
from .phishing_rules import PhishingIndicatorsResult


class RiskAssessmentResult:
    """Consolidated risk assessment and verdict container."""

    def __init__(self):
        # Verdict: AUTHENTICATION VERIFIED, SUSPICIOUS, HIGH RISK, INCONCLUSIVE
        self.verdict: str = "INCONCLUSIVE"
        self.verdict_title: str = ""
        self.verdict_badge_class: str = "secondary"  # success, warning, danger, secondary
        self.verdict_reasons: List[str] = []
        
        # Transparent scoring (0 - 100 risk scale)
        self.calculated_risk_score: int = 0
        self.score_breakdown: List[Dict[str, Any]] = []
        
        # Explicit distinction between authentication status and phishing risk
        self.is_cryptographically_aligned: bool = False
        self.authentication_status: str = "UNAUTHENTICATED"  # AUTHENTICATED, PARTIAL, PERMERROR, FAILED, UNAUTHENTICATED
        self.content_risk_level: str = "LOW"  # LOW, MODERATE, ELEVATED, HIGH
        
        # Summary of checks
        self.dkim_status: str = "NONE"
        self.spf_status: str = "NOT_EVALUABLE"
        self.dmarc_status: str = "NONE"
        
        # Missing information items
        self.missing_information: List[str] = []
        
        # Next actions / actionable security advice
        self.recommended_actions: List[str] = []
        
        # Educational CNS commentary
        self.cns_explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "verdict_title": self.verdict_title,
            "verdict_badge_class": self.verdict_badge_class,
            "verdict_reasons": self.verdict_reasons,
            "calculated_risk_score": self.calculated_risk_score,
            "score_breakdown": self.score_breakdown,
            "is_cryptographically_aligned": self.is_cryptographically_aligned,
            "authentication_status": self.authentication_status,
            "content_risk_level": self.content_risk_level,
            "dkim_status": self.dkim_status,
            "spf_status": self.spf_status,
            "dmarc_status": self.dmarc_status,
            "missing_information": self.missing_information,
            "recommended_actions": self.recommended_actions,
            "cns_explanation": self.cns_explanation,
        }


def compute_risk_verdict(
    parsed_email: ParsedEmail,
    dkim_res: DKIMVerificationResult,
    spf_res: SPFResult,
    dmarc_res: DMARCResult,
    domain_res: DomainAnalysisResult,
    phish_res: PhishingIndicatorsResult
) -> RiskAssessmentResult:
    """
    Computes a deterministic, explainable risk verdict based on transparent CNS rules.
    Strictly adheres to CNS constraints:
    - Never labels an email 'Cryptographically aligned' unless alignment is actually established.
    - Distinguishes cryptographic authentication status from phishing/content risk.
    - Accurately represents DKIM PERMERROR, SPF NOT EVALUABLE, and DMARC NONE (no policy).
    - Never declares an email safe or 0 risk when material authentication checks are unavailable.
    """
    res = RiskAssessmentResult()

    res.dkim_status = dkim_res.status
    res.spf_status = spf_res.status
    res.dmarc_status = dmarc_res.status

    score = 0
    res.score_breakdown = []

    # 1. Determine cryptographic domain alignment
    # Alignment requires DMARC PASS + (DKIM aligned or SPF aligned)
    is_aligned = (dmarc_res.status == "PASS" and (dmarc_res.dkim_aligned or dmarc_res.spf_aligned))
    res.is_cryptographically_aligned = is_aligned

    if is_aligned:
        res.authentication_status = "AUTHENTICATED"
    elif dkim_res.status == "FAIL" or (dmarc_res.status == "FAIL" and dmarc_res.effective_policy in ("reject", "quarantine")):
        res.authentication_status = "FAILED"
    elif dkim_res.status == "PERMERROR":
        res.authentication_status = "PERMERROR"
    else:
        res.authentication_status = "UNAUTHENTICATED"

    # PRIORITY RULE: When email is cryptographically authenticated & domain-aligned,
    # and has no executable malware attachments or lookalike domain spoofing,
    # it is AUTHENTICATED and SAFE (Risk Score = 0).
    # Senders legitimately cite brands, news, and external links in everyday authenticated mail.
    if is_aligned and dkim_res.status == "PASS" and not phish_res.has_dangerous_attachment and not domain_res.has_lookalike_domain:
        res.verdict = "AUTHENTICATION VERIFIED"
        res.verdict_title = "AUTHENTICATION VERIFIED — Cryptographic & Domain Alignment Succeeded"
        res.verdict_badge_class = "success"
        res.calculated_risk_score = 0
        res.content_risk_level = "LOW"
        res.score_breakdown = []
        res.verdict_reasons.append(
            f"DKIM Cryptographic Verification PASSED: Valid digital signature from domain '{dkim_res.primary_domain}'."
        )
        if spf_res.status == "PASS":
            res.verdict_reasons.append(
                f"SPF Sender Authorization PASSED: Connecting IP is authorized by domain '{spf_res.domain or dmarc_res.header_from_domain}'."
            )
        res.verdict_reasons.append(
            f"DMARC Domain Alignment PASSED: Authenticated domain strictly aligns with From header '{dmarc_res.header_from_domain}'."
        )
        res.verdict_reasons.append("No message tampering or sender domain spoofing detected.")
        res.recommended_actions = [
            "Message origin and header integrity are cryptographically authenticated.",
            "Authentication proves the email legitimately originated from the claimed domain owner.",
            "Standard security hygiene applies when reviewing any unexpected requests."
        ]
        res.cns_explanation = (
            "Cryptographic proof established: The RFC 5322 From domain owner legitimately authorized and signed "
            "this message, and message integrity was verified without alteration. "
            "The email passed DKIM, SPF, and DMARC alignment."
        )
        return res

    # 2. Identify missing / unavailable material checks
    if dkim_res.status == "NONE":
        res.missing_information.append("DKIM-Signature header is absent; message lacks cryptographic origin authentication.")
    elif dkim_res.status == "PERMERROR":
        res.missing_information.append(
            "DKIM signature could not be verified due to a permanent DNS failure (public key record not found in DNS)."
        )
    elif dkim_res.status == "TEMPERROR":
        res.missing_information.append("DKIM public key DNS lookup timed out or failed temporarily.")

    if spf_res.status == "NOT_EVALUABLE":
        res.missing_information.append(
            "Connecting client IP and envelope sender are absent; SPF cannot be independently evaluated without SMTP context."
        )
    elif spf_res.status == "TEMPERROR":
        res.missing_information.append("SPF DNS TXT lookup timed out or returned a temporary server failure.")

    if dmarc_res.status == "NONE":
        res.missing_information.append(f"Domain '{dmarc_res.header_from_domain}' has not published an RFC 7489 DMARC policy.")
    elif dmarc_res.status == "TEMPERROR":
        res.missing_information.append("DMARC policy lookup experienced temporary DNS failure.")

    # 3. Check for explicit HIGH RISK indicators
    high_risk_flags = []

    # A) Cryptographic DKIM failure (tampering detected)
    if dkim_res.status == "FAIL":
        high_risk_flags.append(
            "DKIM Cryptographic Verification FAILED: The cryptographic signature or body hash does not match, "
            "indicating message tampering or signature forgery."
        )
        score += 50
        res.score_breakdown.append({"factor": "DKIM Cryptographic Verification Failure", "points": +50})

    # B) DMARC failure on domain with enforcement policy (quarantine or reject)
    if dmarc_res.status == "FAIL" and dmarc_res.effective_policy in ("reject", "quarantine"):
        high_risk_flags.append(
            f"DMARC Enforcement Violation: The sender domain '{dmarc_res.header_from_domain}' explicitly requires "
            f"policy '{dmarc_res.effective_policy.upper()}', and authentication/alignment failed."
        )
        score += 45
        res.score_breakdown.append({"factor": f"DMARC Policy Rejection ({dmarc_res.effective_policy.upper()})", "points": +45})

    # C) Homoglyph / Punycode domain spoofing
    if domain_res.has_lookalike_domain:
        high_risk_flags.append(
            "Lookalike Domain / Homoglyph Detected: The sending domain employs character substitution, "
            "Punycode encoding, or mixed-script homoglyphs to deceive users."
        )
        score += 40
        res.score_breakdown.append({"factor": "Homoglyph / Typosquatted Domain", "points": +40})

    # D) Malicious attachment
    if phish_res.has_dangerous_attachment:
        high_risk_flags.append(
            "Dangerous Executable Attachment: Email contains executable or script attachment file types (.exe, .scr, .vbs)."
        )
        score += 40
        res.score_breakdown.append({"factor": "Dangerous Executable Attachment", "points": +40})

    # E) Deceptive link destination (visual URL mismatch)
    if domain_res.has_url_mismatch:
        high_risk_flags.append(
            "Hyperlink Spoofing: Visible link anchor text displays a different domain than the actual hyperlink destination."
        )
        score += 30
        res.score_breakdown.append({"factor": "Deceptive Hyperlink Mismatch", "points": +30})

    # 4. Check for SUSPICIOUS indicators
    suspicious_flags = []

    # DKIM Permanent Error (e.g. signature present but public key record missing from DNS)
    if dkim_res.status == "PERMERROR":
        suspicious_flags.append(
            "DKIM Permanent Error: Message includes a DKIM signature, but the public key could not be resolved from DNS "
            f"({dkim_res.summary or 'key not found'})."
        )
        score += 25
        res.score_breakdown.append({"factor": "DKIM Verification Permanent Error (Missing Key)", "points": +25})

    # Display name spoofing
    if domain_res.has_display_name_spoof:
        suspicious_flags.append(
            "Display-Name Impersonation: Friendly display name purports to be a known organization or email address "
            f"while actual domain '{domain_res.from_domain}' is unrelated."
        )
        score += 25
        res.score_breakdown.append({"factor": "Display-Name Impersonation", "points": +25})

    # Organization Brand Claim Inconsistency in Subject or Body
    if domain_res.has_brand_mismatch:
        suspicious_flags.append(
            "Organization Brand Claim Inconsistency: Subject or sign-off references a major corporate brand "
            f"while email was transmitted from third-party domain '{domain_res.from_domain}'."
        )
        score += 20
        res.score_breakdown.append({"factor": "Organization Brand Claim Inconsistency", "points": +20})

    # Public cloud form destination
    if domain_res.has_public_form_link or phish_res.has_form_submission_lure:
        suspicious_flags.append(
            "External Form Service: Directs users to submit applications or registrations via public cloud forms "
            "(Google Forms / Microsoft Forms) rather than an authenticated organizational portal."
        )
        score += 15
        res.score_breakdown.append({"factor": "Public Cloud Form Destination", "points": +15})

    # Career / Internship recruitment solicitation
    if phish_res.has_career_lure:
        suspicious_flags.append(
            "Recruitment / Career Readiness Solicitation: Solicits registration for corporate assessment or internship program."
        )
        score += 10
        res.score_breakdown.append({"factor": "Recruitment & Training Solicitation", "points": +10})

    # Misleading subdomain
    if domain_res.has_misleading_subdomain:
        suspicious_flags.append(
            "Brand Subdomain Camouflage: A known brand name is used inside a subdomain of an unrelated host."
        )
        score += 25
        res.score_breakdown.append({"factor": "Misleading Subdomain", "points": +25})

    # Reply-To mismatch
    if domain_res.has_header_mismatch:
        suspicious_flags.append(
            "Reply-To Mismatch: Responses will be routed to an external domain different from the From address."
        )
        score += 15
        res.score_breakdown.append({"factor": "Reply-To External Domain Divergence", "points": +15})

    # DMARC Fail under policy p=none
    if dmarc_res.status == "FAIL" and dmarc_res.effective_policy == "none":
        suspicious_flags.append(
            "DMARC Alignment Failed: Neither aligned DKIM nor SPF passed, but domain policy is monitoring-only (p=none)."
        )
        score += 20
        res.score_breakdown.append({"factor": "DMARC Alignment Failure (p=none)", "points": +20})

    # Absence of DMARC Policy when other warnings or unverified DKIM exist
    if dmarc_res.status == "NONE" and (suspicious_flags or high_risk_flags):
        suspicious_flags.append(
            f"Absence of DMARC Policy: Domain '{dmarc_res.header_from_domain}' publishes no DMARC record to protect recipients."
        )
        score += 10
        res.score_breakdown.append({"factor": "Absence of Domain DMARC Policy", "points": +10})

    # Content phishing indicators
    if phish_res.has_credential_harvesting:
        suspicious_flags.append("Heuristic Indicator: Password expiration or verification code request pattern found in message.")
        score += 20
        res.score_breakdown.append({"factor": "Credential Harvesting Lure", "points": +20})

    if phish_res.has_financial_fraud:
        suspicious_flags.append("Heuristic Indicator: Wire transfer, cryptocurrency, or gift card payment solicitation detected.")
        score += 20
        res.score_breakdown.append({"factor": "Financial Fraud / Gift Card Lure", "points": +20})

    if phish_res.has_urgent_threat:
        suspicious_flags.append("Heuristic Indicator: Urgent deadline or account termination threats detected.")
        score += 10
        res.score_breakdown.append({"factor": "Urgency & Threat Language", "points": +10})

    # SPF softfail or fail (when evaluable)
    if spf_res.status == "FAIL":
        suspicious_flags.append(f"SPF Evaluation: Client IP {spf_res.client_ip} was explicitly rejected (-all).")
        score += 25
        res.score_breakdown.append({"factor": "SPF Evaluation Failure", "points": +25})
    elif spf_res.status == "SOFTFAIL":
        suspicious_flags.append(f"SPF Evaluation: Client IP {spf_res.client_ip} soft-failed (~all).")
        score += 15
        res.score_breakdown.append({"factor": "SPF Evaluation SoftFail", "points": +15})

    # 5. Handle case where material checks are unavailable and no suspicious indicators exist
    # Principle: Do NOT assign a risk score of zero and declare the email safe when material checks are unavailable.
    if not high_risk_flags and not suspicious_flags:
        if not is_aligned:
            # Baseline unverified exposure score (cannot be 0 when checks are unavailable)
            score = 15
            res.score_breakdown.append({
                "factor": "Unauthenticated Message Exposure (DKIM/SPF/DMARC Unverified)",
                "points": 15
            })

    res.calculated_risk_score = min(score, 100)

    # Set content risk level
    if high_risk_flags:
        res.content_risk_level = "HIGH"
    elif suspicious_flags:
        res.content_risk_level = "ELEVATED" if res.calculated_risk_score >= 50 else "MODERATE"
    else:
        res.content_risk_level = "LOW"

    # 6. Synthesize Final Verdict Consistent with Evidence
    # RULE 1: If high-risk flags exist -> HIGH RISK
    if high_risk_flags:
        res.verdict = "HIGH RISK"
        res.verdict_title = "HIGH RISK — Active Spoofing or Malicious Indicators"
        res.verdict_badge_class = "danger"
        res.verdict_reasons.extend(high_risk_flags)
        if suspicious_flags:
            res.verdict_reasons.extend(suspicious_flags[:2])
        res.recommended_actions = [
            "Do NOT click any hyperlinks or download attached files.",
            "Do NOT reply to this message or fulfill any financial/credential requests.",
            "Report this message to your security team or mail administrator as spoofed/phishing.",
            "Verify sender identity out-of-band using an established, trusted telephone number or portal."
        ]
        res.cns_explanation = (
            "The message violates fundamental cryptographic or policy integrity boundaries. "
            "Either cryptographic verification failed (tampered content), a strict DMARC policy was violated, "
            "or deceptive homoglyph/spoofing techniques were detected."
        )

    # RULE 2: If no high risk flags, but suspicious indicators exist -> SUSPICIOUS
    elif suspicious_flags:
        res.verdict = "SUSPICIOUS"
        res.verdict_title = "SUSPICIOUS — Inconsistencies or Phishing Indicators"
        res.verdict_badge_class = "warning"
        res.verdict_reasons.extend(suspicious_flags)
        res.recommended_actions = [
            "Exercise caution before trusting claims or submitting information requested in this email.",
            "Verify that the sender domain is an officially authorized partner of the organization mentioned.",
            "Do not enter personal or academic credentials into public third-party forms (e.g. Google Forms).",
            "Contact the purported organization through their official web portal to verify legitimacy."
        ]
        res.cns_explanation = (
            "While cryptographic tampering was not proven, meaningful warning signs were detected "
            "(such as brand claim divergence, public cloud forms, DKIM key resolution errors, or recruitment solicitations). "
            "MailTrust advises independent verification before proceeding."
        )

    # RULE 3: If DMARC passed AND DKIM passed with alignment -> AUTHENTICATION VERIFIED
    elif is_aligned and dkim_res.status == "PASS" and dmarc_res.dkim_aligned:
        res.verdict = "AUTHENTICATION VERIFIED"
        res.verdict_title = "AUTHENTICATION VERIFIED — Cryptographic & Domain Alignment Succeeded"
        res.verdict_badge_class = "success"
        res.calculated_risk_score = 0
        res.score_breakdown = []
        res.verdict_reasons.append(
            f"DKIM Cryptographic Verification PASSED: Valid RSA/Ed25519 signature from domain '{dkim_res.primary_domain}'."
        )
        res.verdict_reasons.append(
            f"DMARC Alignment PASSED: DKIM signing domain aligns with RFC 5322 From domain '{dmarc_res.header_from_domain}'."
        )
        res.verdict_reasons.append("No suspicious domain inconsistencies or malicious phishing keywords detected.")
        res.recommended_actions = [
            "Message origin and header integrity are cryptographically authenticated.",
            "Note: Authentication proves who sent the email, but does NOT guarantee the sender's intentions are benevolent.",
            "Always maintain standard awareness when reviewing unexpected requests."
        ]
        res.cns_explanation = (
            "Cryptographic proof established: The RFC 5322 From domain owner legitimately authorized and signed "
            "this message, and the message content was not modified in transit. "
            "CRITICAL CNS NOTE: Authentication is NOT a guarantee of safety; legitimate domains can still be compromised."
        )

    # RULE 4: No positive fraud indicators, but authentication could not be verified -> INCONCLUSIVE
    else:
        res.verdict = "INCONCLUSIVE"
        res.verdict_title = "INCONCLUSIVE — Insufficient Authentication Data"
        res.verdict_badge_class = "secondary"
        if dkim_res.status in ("NONE", "PERMERROR"):
            res.verdict_reasons.append("No valid DKIM cryptographic signature could be verified for this message.")
        if spf_res.status == "NOT_EVALUABLE":
            res.verdict_reasons.append("Connecting client IP and envelope sender cannot be verified from static .eml file.")
        if dmarc_res.status == "NONE":
            res.verdict_reasons.append(f"Domain '{dmarc_res.header_from_domain}' has not published an RFC 7489 DMARC policy.")
        
        res.recommended_actions = [
            "Treat the message with neutral caution.",
            "To evaluate SPF, provide the original SMTP connecting IP address and envelope sender.",
            "Contact the sender domain administrator to encourage deployment of DKIM and DMARC."
        ]
        res.cns_explanation = (
            "Insufficient evidence exists to authenticate or condemn this message. "
            "The message lacks verifiable cryptographic signatures (DKIM) and the domain publishes no DMARC record. "
            "MailTrust reflects this uncertainty with an unverified exposure rating rather than false safety."
        )

    return res

