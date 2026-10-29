"""
Unit Tests for SPF Evaluation (RFC 7208)
Tests mechanism resolution, qualifiers, lookup limits, recursion limits,
and offline evaluation context handling.
"""

import pytest
from analyzers.spf_analyzer import evaluate_spf, SPFEvaluator
from analyzers.email_parser import ParsedEmail


def test_spf_not_evaluable_when_context_missing():
    """Static .eml without supplied IP must return NOT_EVALUABLE."""
    email = ParsedEmail()
    email.from_domain = "example.com"
    email.return_path_address = "bounce@example.com"
    
    result = evaluate_spf(email, client_ip=None, sender_identity=None)
    assert result.status == "NOT_EVALUABLE"
    assert "Missing required SMTP parameters" in result.summary


def test_spf_ip4_pass():
    """IPv4 CIDR match produces PASS."""
    def mock_dns(domain, qtype):
        if qtype == "TXT" and domain == "example.com":
            return ["v=spf1 ip4:198.51.100.0/24 -all"]
        return []

    evaluator = SPFEvaluator(dns_query_func=mock_dns)
    status, qual, _ = evaluator.evaluate("198.51.100.42", "bounce@example.com", "example.com")
    assert status == "PASS"
    assert qual == "+"


def test_spf_explicit_fail():
    """Non-matching IP falling through to -all produces FAIL."""
    def mock_dns(domain, qtype):
        if qtype == "TXT" and domain == "example.com":
            return ["v=spf1 ip4:198.51.100.0/24 -all"]
        return []

    evaluator = SPFEvaluator(dns_query_func=mock_dns)
    status, qual, _ = evaluator.evaluate("203.0.113.1", "bounce@example.com", "example.com")
    assert status == "FAIL"
    assert qual == "-"


def test_spf_softfail():
    """Non-matching IP falling through to ~all produces SOFTFAIL."""
    def mock_dns(domain, qtype):
        if qtype == "TXT" and domain == "example.com":
            return ["v=spf1 ip4:198.51.100.0/24 ~all"]
        return []

    evaluator = SPFEvaluator(dns_query_func=mock_dns)
    status, qual, _ = evaluator.evaluate("203.0.113.1", "bounce@example.com", "example.com")
    assert status == "SOFTFAIL"
    assert qual == "~"


def test_spf_include_mechanism():
    """Recursive include resolution."""
    def mock_dns(domain, qtype):
        if qtype == "TXT" and domain == "company.com":
            return ["v=spf1 include:_spf.relay.net -all"]
        if qtype == "TXT" and domain == "_spf.relay.net":
            return ["v=spf1 ip4:203.0.113.50 ~all"]
        return []

    evaluator = SPFEvaluator(dns_query_func=mock_dns)
    status, qual, _ = evaluator.evaluate("203.0.113.50", "admin@company.com", "company.com")
    assert status == "PASS"


def test_spf_dns_lookup_limit_exceeded():
    """RFC 7208 requires PERMERROR if > 10 DNS lookups occur."""
    def mock_dns(domain, qtype):
        if domain.startswith("inc") and ".com" in domain:
            idx = int(domain.split(".")[0][3:])
            return [f"v=spf1 include:inc{idx+1}.com -all"]
        return ["v=spf1 include:inc1.com -all"]

    evaluator = SPFEvaluator(dns_query_func=mock_dns)
    status, qual, _ = evaluator.evaluate("1.2.3.4", "test@domain.com", "domain.com")
    assert status == "PERMERROR"
    assert evaluator.dns_lookups > 10


def test_spf_multiple_records_permerror():
    """RFC 7208 Section 3.2: multiple v=spf1 records constitutes a PERMERROR."""
    def mock_dns(domain, qtype):
        return ["v=spf1 ip4:1.1.1.1 -all", "v=spf1 ip4:2.2.2.2 -all"]

    evaluator = SPFEvaluator(dns_query_func=mock_dns)
    status, qual, _ = evaluator.evaluate("1.1.1.1", "test@domain.com", "domain.com")
    assert status == "PERMERROR"


def test_spf_no_record_none():
    """Domain with no SPF record returns NONE."""
    def mock_dns(domain, qtype):
        return ["some other txt record"]

    evaluator = SPFEvaluator(dns_query_func=mock_dns)
    status, qual, _ = evaluator.evaluate("1.1.1.1", "test@domain.com", "domain.com")
    assert status == "NONE"
