"""
Unit Tests for Domain Lookalikes, Homoglyphs, and Heuristic Phishing Rules
"""

import pytest
from analyzers.domain_analyzer import analyze_domains
from analyzers.phishing_rules import inspect_phishing_indicators
from analyzers.email_parser import ParsedEmail


def test_display_name_spoofing():
    """Display name claims brand while domain is unrelated."""
    email = ParsedEmail()
    email.from_header = "\"PayPal Security Center\" <alerts@unrelated-hacker.com>"
    email.from_name = "PayPal Security Center"
    email.from_domain = "unrelated-hacker.com"
    
    result = analyze_domains(email)
    assert result.has_display_name_spoof is True
    assert any("Brand Impersonation in Display Name ('Paypal')" in f.title for f in result.findings)


def test_character_substitution_typosquatting():
    """Character substitution typosquatting (paypa1.com)."""
    email = ParsedEmail()
    email.from_domain = "paypa1.com"
    
    result = analyze_domains(email)
    assert result.has_lookalike_domain is True
    assert any("Character-Substitution" in f.title for f in result.findings)


def test_levenshtein_distance_typosquatting():
    """Single edit distance typosquatting (e.g. netflx.com -> netflix.com)."""
    email = ParsedEmail()
    email.from_domain = "netflx.com"
    
    result = analyze_domains(email)
    assert result.has_lookalike_domain is True
    assert any("netflix" in f.title.lower() for f in result.findings)


def test_punycode_idn_detection():
    """Punycode domain (xn--...) detected."""
    email = ParsedEmail()
    email.from_domain = "xn--pple-43d.com"
    
    result = analyze_domains(email)
    assert result.has_lookalike_domain is True
    assert any("Punycode" in f.category for f in result.findings)


def test_misleading_subdomain():
    """Brand placed in subdomain of unrelated domain."""
    email = ParsedEmail()
    email.from_domain = "paypal.com.account-update.net"
    
    result = analyze_domains(email)
    assert result.has_misleading_subdomain is True
    assert any("Brand Subdomain Camouflage" in f.title for f in result.findings)


def test_phishing_rules_credential_and_crypto():
    """Detect credential lure, gift card / cryptocurrency solicitation."""
    email = ParsedEmail()
    email.subject = "Urgent: Verify your credentials now"
    email.text_body = "Your password has expired. Send payment to Bitcoin address or remit via Amazon gift card."
    
    res = inspect_phishing_indicators(email)
    assert res.has_credential_harvesting is True
    assert res.has_financial_fraud is True
    assert res.total_heuristic_score > 30
