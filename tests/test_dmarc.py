"""
Unit Tests for DMARC Alignment and Policy Evaluation (RFC 7489)
"""

import pytest
from analyzers.dmarc_analyzer import evaluate_dmarc, get_organizational_domain
from analyzers.dkim_analyzer import DKIMVerificationResult, DKIMSignatureResult
from analyzers.spf_analyzer import SPFResult


def test_organizational_domain_extraction():
    """Test Public Suffix List organizational domain resolution."""
    assert get_organizational_domain("mail.example.com") == "example.com"
    assert get_organizational_domain("sub.deep.corp.co.uk") == "corp.co.uk"
    assert get_organizational_domain("paypal.com") == "paypal.com"


def test_dmarc_pass_via_aligned_dkim():
    """DMARC must PASS when aligned DKIM passes, even if SPF is NOT EVALUABLE."""
    # Setup DKIM result
    dkim_res = DKIMVerificationResult()
    dkim_res.status = "PASS"
    sig = DKIMSignatureResult()
    sig.signing_domain = "mail.company.com"
    sig.status = "PASS"
    dkim_res.signatures.append(sig)
    dkim_res.primary_domain = "mail.company.com"

    # Setup SPF result as NOT_EVALUABLE
    spf_res = SPFResult()
    spf_res.status = "NOT_EVALUABLE"

    def mock_dns(domain):
        if domain == "_dmarc.company.com":
            return ["v=DMARC1; p=reject; adkim=r; aspf=r"]
        return []

    res = evaluate_dmarc("company.com", dkim_res, spf_res, dns_query_func=mock_dns)
    assert res.status == "PASS"
    assert res.dkim_aligned is True
    assert res.dkim_authenticated is True
    assert res.policy == "reject"
    assert "DMARC Passed via Aligned DKIM" in res.summary


def test_dmarc_strict_dkim_alignment_failure():
    """In strict mode (adkim=s), subdomain does NOT align with root domain."""
    dkim_res = DKIMVerificationResult()
    dkim_res.status = "PASS"
    sig = DKIMSignatureResult()
    sig.signing_domain = "mail.company.com"  # Subdomain
    sig.status = "PASS"
    dkim_res.signatures.append(sig)

    spf_res = SPFResult()
    spf_res.status = "NONE"

    def mock_dns(domain):
        if domain == "_dmarc.company.com":
            # Strict mode
            return ["v=DMARC1; p=reject; adkim=s; aspf=s"]
        return []

    res = evaluate_dmarc("company.com", dkim_res, spf_res, dns_query_func=mock_dns)
    # Because mode is strict, mail.company.com != company.com -> unaligned -> FAIL
    assert res.status == "FAIL"
    assert res.dkim_aligned is False
    assert res.disposition == "reject"


def test_dmarc_unaligned_third_party_dkim_fails():
    """DKIM passing from unrelated third-party domain must FAIL DMARC alignment."""
    dkim_res = DKIMVerificationResult()
    dkim_res.status = "PASS"
    sig = DKIMSignatureResult()
    sig.signing_domain = "attacker-domain.net"
    sig.status = "PASS"
    dkim_res.signatures.append(sig)
    dkim_res.primary_domain = "attacker-domain.net"

    spf_res = SPFResult()
    spf_res.status = "FAIL"
    spf_res.domain = "attacker-domain.net"

    def mock_dns(domain):
        if domain == "_dmarc.victim-bank.com":
            return ["v=DMARC1; p=quarantine;"]
        return []

    res = evaluate_dmarc("victim-bank.com", dkim_res, spf_res, dns_query_func=mock_dns)
    assert res.status == "FAIL"
    assert res.dkim_aligned is False
    assert res.spf_aligned is False
    assert res.disposition == "quarantine"


def test_dmarc_subdomain_inherits_org_policy():
    """Subdomain without direct policy inherits organizational domain policy."""
    dkim_res = DKIMVerificationResult()
    spf_res = SPFResult()

    def mock_dns(domain):
        # Only org domain has policy
        if domain == "_dmarc.bigcorp.com":
            return ["v=DMARC1; p=reject; sp=quarantine"]
        return []

    res = evaluate_dmarc("marketing.bigcorp.com", dkim_res, spf_res, dns_query_func=mock_dns)
    assert res.is_subdomain is True
    assert res.dmarc_record_domain == "_dmarc.bigcorp.com"
    assert res.policy == "reject"
    assert res.subdomain_policy == "quarantine"
    assert res.effective_policy == "quarantine"


def test_dmarc_no_policy_returns_none():
    """Domain with no published DMARC record returns NONE."""
    def mock_empty_dns(domain):
        return []

    res = evaluate_dmarc("no-dmarc-here.org", None, None, dns_query_func=mock_empty_dns)
    assert res.status == "NONE"
    assert "No DMARC policy published" in res.summary
