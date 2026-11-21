"""
Unit Tests for Cryptographic Hygiene Analysis (RFC 6376, RFC 8301, RFC 8463, NIST SP 800-57).
"""

import pytest
from analyzers.dkim_analyzer import DKIMVerificationResult, DKIMSignatureResult
from analyzers.crypto_hygiene import analyze_dkim_crypto_hygiene


def test_crypto_hygiene_no_signatures():
    """Verify result when no DKIM signatures are present."""
    dkim_res = DKIMVerificationResult()
    dkim_res.has_signatures = False

    hygiene = analyze_dkim_crypto_hygiene(dkim_res)
    assert hygiene.status == "NOT_EVALUABLE"


def test_crypto_hygiene_deprecated_algorithm_rsa_sha1():
    """Verify detection of deprecated rsa-sha1 signature algorithm."""
    dkim_res = DKIMVerificationResult()
    dkim_res.has_signatures = True

    sig = DKIMSignatureResult()
    sig.algorithm = "rsa-sha1"
    sig.raw_header = "v=1; a=rsa-sha1; d=example.com; s=s1; h=from:to:subject; bh=abc; b=xyz;"
    sig.signed_headers = ["from", "to", "subject"]
    dkim_res.signatures = [sig]

    hygiene = analyze_dkim_crypto_hygiene(dkim_res)
    assert hygiene.status in ("FAIL", "HIGH")
    assert any("Deprecated Signature Algorithm" in f.title for f in hygiene.findings)


def test_crypto_hygiene_missing_from_header():
    """Verify critical violation when From header is omitted from signed-header list (RFC 6376 5.4.1)."""
    dkim_res = DKIMVerificationResult()
    dkim_res.has_signatures = True

    sig = DKIMSignatureResult()
    sig.algorithm = "rsa-sha256"
    sig.raw_header = "v=1; a=rsa-sha256; d=example.com; s=s1; h=to:subject; bh=abc; b=xyz;"
    sig.signed_headers = ["to", "subject"]  # 'from' is omitted!
    dkim_res.signatures = [sig]

    hygiene = analyze_dkim_crypto_hygiene(dkim_res)
    assert hygiene.status == "FAIL"
    assert any("Critical Header 'From' Not Signed" in f.title for f in hygiene.findings)


def test_crypto_hygiene_partial_body_length_tag():
    """Verify warning when l= (body length) tag is present."""
    dkim_res = DKIMVerificationResult()
    dkim_res.has_signatures = True

    sig = DKIMSignatureResult()
    sig.algorithm = "rsa-sha256"
    sig.raw_header = "v=1; a=rsa-sha256; d=example.com; s=s1; l=100; h=from:to:subject; bh=abc; b=xyz;"
    sig.signed_headers = ["from", "to", "subject"]
    dkim_res.signatures = [sig]

    hygiene = analyze_dkim_crypto_hygiene(dkim_res)
    assert any("Partial Body Signing" in f.title for f in hygiene.findings)


def test_crypto_hygiene_test_mode_tag():
    """Verify warning when domain publishes t=y (test mode) in DKIM DNS record."""
    dkim_res = DKIMVerificationResult()
    dkim_res.has_signatures = True

    sig = DKIMSignatureResult()
    sig.algorithm = "rsa-sha256"
    sig.raw_header = "v=1; a=rsa-sha256; d=example.com; s=s1; h=from:to:subject; bh=abc; b=xyz;"
    sig.dns_txt_record = "v=DKIM1; k=rsa; t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0..."
    sig.signed_headers = ["from", "to", "subject"]
    dkim_res.signatures = [sig]

    hygiene = analyze_dkim_crypto_hygiene(dkim_res)
    assert any("Test Mode" in f.title for f in hygiene.findings)
