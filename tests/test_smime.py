"""
Unit Tests for S/MIME Digital Signature Forensics (RFC 8551, RFC 5652, RFC 5751).
"""

import datetime
from datetime import timezone
import email
from email.message import Message

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from asn1crypto import cms, util, x509 as asn1_x509

from analyzers.smime_analyzer import verify_smime_signatures, SMIMEResult


def test_smime_not_present():
    """Verify standard RFC 5322 plaintext email is flagged as NOT_PRESENT."""
    raw = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Plain Email\r\n"
        b"\r\n"
        b"This is a standard email with no S/MIME envelope.\r\n"
    )
    result = verify_smime_signatures(raw, from_address="sender@example.com")
    assert result.is_smime is False
    assert result.status == "NOT_PRESENT"


def test_smime_enveloped_data_detection():
    """Verify that encrypted (enveloped-data) messages are safely classified without crashing."""
    raw = (
        b"From: secret@example.com\r\n"
        b"To: agent@example.com\r\n"
        b"Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"MIIBWAYJKoZIhvcNAQcDoIIBTDCCAUgCAQAxggEwMIIBLAIBADB2MGMx..."
    )
    result = verify_smime_signatures(raw, from_address="secret@example.com")
    assert result.is_smime is True
    assert result.status == "ENCRYPTED_NOT_ANALYZABLE"


def test_smime_clear_signed_verification():
    """Verify synthetic valid S/MIME clear-signed multipart/signed message."""
    # 1. Generate RSA key and certificate
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(timezone.utc)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Alice Signer"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, "alice@trusted.example"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name("alice@trusted.example")]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(priv_key, hashes.SHA256())
    )

    cert_der = cert.public_bytes(Encoding.DER)

    # 2. Body to sign
    body_content = b"Content-Type: text/plain; charset=utf-8\r\n\r\nApproved milestone payment.\r\n"

    # Compute digest and signature
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(body_content)
    msg_digest = hasher.finalize()

    # Build signed_attrs
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            'type': cms.CMSAttributeType('content_type'),
            'values': [cms.ContentType('data')]
        }),
        cms.CMSAttribute({
            'type': cms.CMSAttributeType('message_digest'),
            'values': [cms.OctetString(msg_digest)]
        }),
    ])
    
    # Sign DER bytes of signed_attrs with tag replaced by 0x31
    der_attrs = signed_attrs.dump()
    encoded_attrs = b"\x31" + der_attrs[1:]
    sig_bytes = priv_key.sign(encoded_attrs, padding.PKCS1v15(), hashes.SHA256())

    # Build CMS SignedData
    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': asn1_x509.Name.load(cert.issuer.public_bytes()),
                'serial_number': cert.serial_number
            })
        }),
        'digest_algorithm': cms.DigestAlgorithm({'algorithm': 'sha256'}),
        'signed_attrs': signed_attrs,
        'signature_algorithm': cms.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),
        'signature': cms.OctetString(sig_bytes),
    })

    signed_data = cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [cms.DigestAlgorithm({'algorithm': 'sha256'})],
        'encap_content_info': cms.ContentInfo({'content_type': 'data'}),
        'certificates': [cms.CertificateChoices({'certificate': cms.Certificate.load(cert_der)})],
        'signer_infos': cms.SignerInfos([signer_info])
    })

    content_info = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data
    })
    pkcs7_der = content_info.dump()

    # Build full MIME multipart/signed message
    import base64
    b64_sig = base64.encodebytes(pkcs7_der).decode("ascii")

    raw_eml = (
        b'From: Alice Signer <alice@trusted.example>\r\n'
        b'To: Bob <bob@example.com>\r\n'
        b'Subject: Signed Project Milestone\r\n'
        b'Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256; boundary="----boundary123"\r\n'
        b'\r\n'
        b'------boundary123\r\n'
        + body_content +
        b'------boundary123\r\n'
        b'Content-Type: application/pkcs7-signature; name="smime.p7s"\r\n'
        b'Content-Transfer-Encoding: base64\r\n'
        b'\r\n'
        + b64_sig.encode("ascii") +
        b'------boundary123--\r\n'
    )

    result = verify_smime_signatures(raw_eml, from_address="alice@trusted.example")
    assert result.is_smime is True
    assert result.signature_valid is True
    assert result.identity_matches_from is True
    assert result.status == "VALID"
    assert result.signer_email == "alice@trusted.example"
