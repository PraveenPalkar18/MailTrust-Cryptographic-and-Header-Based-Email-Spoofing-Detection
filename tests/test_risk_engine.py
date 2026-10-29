"""
Unit Tests for Explainable Risk Engine
Tests the 4 distinct verdicts: AUTHENTICATION VERIFIED, SUSPICIOUS, HIGH RISK, INCONCLUSIVE.
"""

import pytest
from analyzers.risk_engine import compute_risk_verdict
from analyzers.email_parser import ParsedEmail
from analyzers.dkim_analyzer import DKIMVerificationResult, DKIMSignatureResult
from analyzers.spf_analyzer import SPFResult
from analyzers.dmarc_analyzer import DMARCResult
from analyzers.domain_analyzer import DomainAnalysisResult, DomainFinding
from analyzers.phishing_rules import PhishingIndicatorsResult


def test_verdict_authentication_verified():
    """Valid DKIM + DMARC Alignment with no threat indicators produces AUTHENTICATION VERIFIED."""
    email = ParsedEmail()
    email.from_domain = "example.com"

    dkim_res = DKIMVerificationResult()
    dkim_res.status = "PASS"
    dkim_res.primary_domain = "example.com"
    sig = DKIMSignatureResult()
    sig.status = "PASS"
    sig.signing_domain = "example.com"
    dkim_res.signatures.append(sig)

    spf_res = SPFResult()
    spf_res.status = "NOT_EVALUABLE"

    dmarc_res = DMARCResult()
    dmarc_res.status = "PASS"
    dmarc_res.dkim_aligned = True
    dmarc_res.header_from_domain = "example.com"

    domain_res = DomainAnalysisResult()
    phish_res = PhishingIndicatorsResult()

    verdict_res = compute_risk_verdict(email, dkim_res, spf_res, dmarc_res, domain_res, phish_res)
    assert verdict_res.verdict == "AUTHENTICATION VERIFIED"
    assert verdict_res.verdict_badge_class == "success"


def test_verdict_high_risk_on_crypto_fail():
    """DKIM cryptographic verification failure produces HIGH RISK."""
    email = ParsedEmail()
    dkim_res = DKIMVerificationResult()
    dkim_res.status = "FAIL"  # Tampered body/sig

    spf_res = SPFResult()
    dmarc_res = DMARCResult()
    domain_res = DomainAnalysisResult()
    phish_res = PhishingIndicatorsResult()

    verdict_res = compute_risk_verdict(email, dkim_res, spf_res, dmarc_res, domain_res, phish_res)
    assert verdict_res.verdict == "HIGH RISK"
    assert verdict_res.verdict_badge_class == "danger"
    assert any("Cryptographic Verification FAILED" in r for r in verdict_res.verdict_reasons)


def test_verdict_high_risk_on_dmarc_rejection():
    """DMARC failure on domain enforcing reject policy produces HIGH RISK."""
    email = ParsedEmail()
    dkim_res = DKIMVerificationResult()
    dkim_res.status = "FAIL"

    spf_res = SPFResult()
    spf_res.status = "FAIL"

    dmarc_res = DMARCResult()
    dmarc_res.status = "FAIL"
    dmarc_res.effective_policy = "reject"
    dmarc_res.header_from_domain = "bank.com"

    domain_res = DomainAnalysisResult()
    phish_res = PhishingIndicatorsResult()

    verdict_res = compute_risk_verdict(email, dkim_res, spf_res, dmarc_res, domain_res, phish_res)
    assert verdict_res.verdict == "HIGH RISK"


def test_verdict_suspicious_on_display_spoof():
    """Display name spoofing or Reply-To mismatch produces SUSPICIOUS."""
    email = ParsedEmail()
    dkim_res = DKIMVerificationResult()
    spf_res = SPFResult()
    dmarc_res = DMARCResult()
    dmarc_res.status = "NONE"

    domain_res = DomainAnalysisResult()
    domain_res.has_display_name_spoof = True

    phish_res = PhishingIndicatorsResult()

    verdict_res = compute_risk_verdict(email, dkim_res, spf_res, dmarc_res, domain_res, phish_res)
    assert verdict_res.verdict == "SUSPICIOUS"
    assert verdict_res.verdict_badge_class == "warning"


def test_verdict_inconclusive_on_missing_auth():
    """Plain email lacking DKIM, SPF context, and DMARC with no fraud flags produces INCONCLUSIVE."""
    email = ParsedEmail()
    email.from_domain = "plain-site.org"

    dkim_res = DKIMVerificationResult()
    dkim_res.status = "NONE"

    spf_res = SPFResult()
    spf_res.status = "NOT_EVALUABLE"

    dmarc_res = DMARCResult()
    dmarc_res.status = "NONE"
    dmarc_res.header_from_domain = "plain-site.org"

    domain_res = DomainAnalysisResult()
    phish_res = PhishingIndicatorsResult()

    verdict_res = compute_risk_verdict(email, dkim_res, spf_res, dmarc_res, domain_res, phish_res)
    assert verdict_res.verdict == "INCONCLUSIVE"
    assert verdict_res.verdict_badge_class == "secondary"
    assert len(verdict_res.missing_information) >= 2


def test_verdict_all_three_pass_produces_zero_risk_score():
    """
    When all three protocols pass (DKIM PASS, SPF PASS, DMARC PASS & Aligned),
    the email is AUTHENTICATION VERIFIED with risk score 0.
    Legitimate mentions of third party brands or news headlines in authenticated mail
    must never cause high risk or domain spoofing false alarms.
    """
    email = ParsedEmail()
    email.from_domain = "kletech.ac.in"
    email.subject = "News paper Clippings for the Date: 29-10-2026"
    email.text_body = "Today's newspaper clips covering Tata and Google technology announcements."

    dkim_res = DKIMVerificationResult()
    dkim_res.status = "PASS"
    dkim_res.primary_domain = "kletech.ac.in"
    sig = DKIMSignatureResult()
    sig.status = "PASS"
    sig.signing_domain = "kletech.ac.in"
    dkim_res.signatures.append(sig)

    spf_res = SPFResult()
    spf_res.status = "PASS"
    spf_res.domain = "kletech.ac.in"
    spf_res.client_ip = "209.85.220.69"

    dmarc_res = DMARCResult()
    dmarc_res.status = "PASS"
    dmarc_res.header_from_domain = "kletech.ac.in"
    dmarc_res.dkim_aligned = True
    dmarc_res.spf_aligned = True

    domain_res = DomainAnalysisResult()
    phish_res = PhishingIndicatorsResult()

    verdict_res = compute_risk_verdict(email, dkim_res, spf_res, dmarc_res, domain_res, phish_res)
    assert verdict_res.verdict == "AUTHENTICATION VERIFIED"
    assert verdict_res.verdict_badge_class == "success"
    assert verdict_res.calculated_risk_score == 0
    assert len(verdict_res.score_breakdown) == 0
    assert "No message tampering or sender domain spoofing detected." in verdict_res.verdict_reasons

