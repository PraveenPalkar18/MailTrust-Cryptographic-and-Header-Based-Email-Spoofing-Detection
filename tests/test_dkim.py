"""
Cryptographic Integration Tests for DKIM Verification
Tests RFC 6376 cryptographic verification using freshly generated RSA key pairs,
message tampering detection, incorrect keys, and missing DNS keys.
"""

import base64
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import dkim

from analyzers.dkim_analyzer import verify_dkim_signatures


@pytest.fixture(scope="module")
def rsa_keypair():
    """Generate fresh 2048-bit RSA test key pair."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    dns_record = f"v=DKIM1; k=rsa; p={pub_b64}".encode("utf-8")
    return priv_pem, dns_record


def test_dkim_valid_signature_passes(rsa_keypair):
    """Demonstrate: A message signed with matching private key verifies with corresponding public key."""
    priv_pem, dns_record = rsa_keypair
    
    raw_message = (
        b"From: test@example.com\r\n"
        b"To: recipient@example.org\r\n"
        b"Subject: Cryptographic Test\r\n"
        b"\r\n"
        b"Authentic payload content."
    )
    
    sig = dkim.sign(
        message=raw_message,
        selector=b"test-sel",
        domain=b"example.com",
        privkey=priv_pem
    )
    signed_email = sig + raw_message

    def mock_dns(name: bytes, timeout: int = 5):
        if b"test-sel._domainkey.example.com" in name.lower():
            return dns_record
        return None

    result = verify_dkim_signatures(signed_email, custom_dnsfunc=mock_dns)
    assert result.status == "PASS"
    assert result.signatures_count == 1
    assert result.primary_domain == "example.com"
    assert result.primary_selector == "test-sel"
    assert result.signatures[0].status == "PASS"
    assert "Cryptographic signature verified successfully" in result.signatures[0].details


def test_dkim_tampered_body_fails(rsa_keypair):
    """Demonstrate: Altering a signed part of message causes cryptographic verification failure."""
    priv_pem, dns_record = rsa_keypair
    
    raw_message = (
        b"From: test@example.com\r\n"
        b"Subject: Integrity Test\r\n"
        b"\r\n"
        b"Original trusted message body."
    )
    
    sig = dkim.sign(
        message=raw_message,
        selector=b"test-sel",
        domain=b"example.com",
        privkey=priv_pem
    )
    # Tamper with body content post-signing
    tampered_email = sig + raw_message.replace(b"Original trusted", b"TAMPERED ADVERSARIAL")

    def mock_dns(name: bytes, timeout: int = 5):
        return dns_record

    result = verify_dkim_signatures(tampered_email, custom_dnsfunc=mock_dns)
    assert result.status == "FAIL"
    assert result.signatures[0].status == "FAIL"


def test_dkim_incorrect_public_key_fails(rsa_keypair):
    """Demonstrate: An incorrect public key in DNS does not produce successful verification."""
    priv_pem, _ = rsa_keypair
    
    raw_message = b"From: test@example.com\r\nSubject: Test\r\n\r\nHello"
    sig = dkim.sign(
        message=raw_message,
        selector=b"test-sel",
        domain=b"example.com",
        privkey=priv_pem
    )
    signed_email = sig + raw_message

    # Generate a DIFFERENT key pair for DNS
    wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    wrong_pub_der = wrong_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    wrong_pub_b64 = base64.b64encode(wrong_pub_der).decode("ascii")
    wrong_dns_record = f"v=DKIM1; k=rsa; p={wrong_pub_b64}".encode("utf-8")

    def mock_wrong_dns(name: bytes, timeout: int = 5):
        return wrong_dns_record

    result = verify_dkim_signatures(signed_email, custom_dnsfunc=mock_wrong_dns)
    assert result.status == "FAIL"
    assert result.signatures[0].status == "FAIL"


def test_dkim_missing_dns_key_reported(rsa_keypair):
    """Demonstrate: A missing DNS public key record is reported correctly as PERMERROR."""
    priv_pem, _ = rsa_keypair
    raw_message = b"From: test@example.com\r\nSubject: Test\r\n\r\nHello"
    sig = dkim.sign(
        message=raw_message,
        selector=b"test-sel",
        domain=b"example.com",
        privkey=priv_pem
    )
    signed_email = sig + raw_message

    def mock_empty_dns(name: bytes, timeout: int = 5):
        return None  # Record not found in DNS

    result = verify_dkim_signatures(signed_email, custom_dnsfunc=mock_empty_dns)
    assert result.status == "PERMERROR"
    assert "public key record not found" in result.signatures[0].details.lower()


def test_dkim_temporary_dns_error(rsa_keypair):
    """Demonstrate: DNS timeout or server failure is reported as TEMPERROR."""
    priv_pem, _ = rsa_keypair
    raw_message = b"From: test@example.com\r\nSubject: Test\r\n\r\nHello"
    sig = dkim.sign(
        message=raw_message,
        selector=b"test-sel",
        domain=b"example.com",
        privkey=priv_pem
    )
    signed_email = sig + raw_message

    def mock_error_dns(name: bytes, timeout: int = 5):
        raise dkim.DnsTimeoutError("Simulated DNS timeout failure")

    result = verify_dkim_signatures(signed_email, custom_dnsfunc=mock_error_dns)
    assert result.status == "TEMPERROR"


def test_dkim_no_signature():
    """Verify that email without DKIM signature returns NONE."""
    raw_message = b"From: test@example.com\r\nSubject: Unsigned\r\n\r\nNo DKIM here"
    result = verify_dkim_signatures(raw_message)
    assert result.status == "NONE"
    assert result.has_signatures is False
