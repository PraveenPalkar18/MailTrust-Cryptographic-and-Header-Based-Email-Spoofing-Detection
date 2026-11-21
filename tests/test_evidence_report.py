"""
Unit Tests for Signed Forensic Evidence Reports and Public Verification (Ed25519 & RFC 8785).
"""

import pytest
from app import app
from database import init_db
from analyzers.evidence_report import (
    create_signed_forensic_report, verify_signed_forensic_report
)


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_signed_forensic_report_lifecycle():
    """Verify end-to-end Ed25519 digital signing, serialization, and verification."""
    mock_analysis = {
        "report_id": "rep-test-12345",
        "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "email": {
            "from": "executive@example.com",
            "sender_domain": "example.com",
            "subject": "Confidential Board Resolution",
            "date": "Mon, 26 Oct 2026 10:00:00 +0000"
        },
        "verdict": {
            "classification": "AUTHENTICATION VERIFIED",
            "score": 0,
            "reasons": ["Valid 2048-bit DKIM signature", "DMARC strict pass"]
        },
        "dkim": {"status": "PASS"},
        "spf": {"status": "pass"},
        "dmarc": {"status": "pass"},
        "smime": {"status": "NOT_PRESENT"},
        "crypto_hygiene": {"status": "PASS"}
    }

    # 1. Sign report
    signed_doc = create_signed_forensic_report(mock_analysis)
    assert "payload" in signed_doc
    assert "signature_block" in signed_doc
    assert signed_doc["signature_block"]["algorithm"] == "Ed25519"

    # 2. Verify authentic document
    result = verify_signed_forensic_report(signed_doc)
    assert result["is_authentic"] is True
    assert result["status"] == "AUTHENTIC"


def test_signed_report_tamper_detection():
    """Verify that any post-export tampering of payload fields is mathematically detected."""
    mock_analysis = {
        "report_id": "rep-tamper-check",
        "file_sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "email": {"from": "innocent@example.com"},
        "verdict": {"classification": "AUTHENTICATION VERIFIED", "score": 0}
    }

    signed_doc = create_signed_forensic_report(mock_analysis)

    # Attacker alters the risk score or verdict in the payload
    signed_doc["payload"]["cryptographic_verdicts"]["risk_score"] = 99

    # Verification must flag tampering
    result = verify_signed_forensic_report(signed_doc)
    assert result["is_authentic"] is False
    assert result["status"] == "TAMPERED"


def test_signed_report_malformed_input():
    """Verify graceful rejection of malformed or non-dictionary reports."""
    assert verify_signed_forensic_report({})["status"] == "MALFORMED"
    assert verify_signed_forensic_report({"payload": {}})["status"] == "MALFORMED"
    assert verify_signed_forensic_report("not a dict")["status"] == "MALFORMED"
