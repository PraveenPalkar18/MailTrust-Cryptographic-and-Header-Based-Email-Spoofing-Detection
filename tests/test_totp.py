"""
Unit Tests for RFC 6238 TOTP Multi-Factor Authentication,
Secret Encryption, QR Code Generation, and Single-Use Recovery Codes.
"""

import pytest
import pyotp
from app import app
from database import get_db, init_db
from models import User, RecoveryCode
from security.auth import hash_password
from security.totp import (
    generate_totp_secret, encrypt_totp_secret, decrypt_totp_secret,
    get_provisioning_uri, generate_qr_code_data_uri, verify_totp_code,
    generate_recovery_codes, verify_and_consume_recovery_code
)


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_totp_secret_encryption():
    """Verify that TOTP secrets are encrypted at rest using AES-128-CBC + HMAC-SHA256."""
    secret = generate_totp_secret()
    assert len(secret) == 32  # Standard Base32 length

    encrypted = encrypt_totp_secret(secret)
    assert encrypted != secret
    # Encrypted payload should not contain the plaintext secret
    assert secret not in encrypted

    decrypted = decrypt_totp_secret(encrypted)
    assert decrypted == secret


def test_totp_code_verification():
    """Verify accurate generation and validation of 6-digit TOTP codes."""
    secret = generate_totp_secret()
    totp = pyotp.TOTP(secret)

    # Valid current code
    current_code = totp.now()
    assert verify_totp_code(secret, current_code) is True

    # Invalid code
    assert verify_totp_code(secret, "000000" if current_code != "000000" else "111111") is False

    # Malformed inputs
    assert verify_totp_code(secret, "") is False
    assert verify_totp_code(secret, "abcdef") is False
    assert verify_totp_code(secret, "12345") is False  # 5 digits


def test_qr_code_generation():
    """Verify that inline QR code Data URI is properly generated."""
    secret = generate_totp_secret()
    uri = get_provisioning_uri(secret, "user@example.com")
    assert uri.startswith("otpauth://totp/MailTrust:")
    assert f"secret={secret}" in uri

    qr_data = generate_qr_code_data_uri(uri)
    assert qr_data.startswith("data:image/svg+xml;base64,")
    assert len(qr_data) > 100


def test_recovery_codes_generation_and_consumption():
    """Verify single-use recovery code generation, cryptographic hashing, and consumption."""
    import uuid
    uid = uuid.uuid4().hex[:6]
    with get_db() as db:
        user = User(
            username=f"totp_user_{uid}",
            email=f"totp_{uid}@example.com",
            password_hash=hash_password("Pass123456!@#"),
            role="USER"
        )
        db.add(user)
        db.flush()
        user_id = user.id

    # Generate 8 single-use codes
    plain_codes, entities = generate_recovery_codes(user_id, count=8)
    assert len(plain_codes) == 8
    assert len(entities) == 8

    # Store entities in database
    with get_db() as db:
        for ent in entities:
            db.add(ent)

    test_code = plain_codes[0]

    # 1. First consumption succeeds
    consumed = verify_and_consume_recovery_code(user_id, test_code)
    assert consumed is True

    # 2. Re-use attempt is rejected (single-use enforcement)
    reused = verify_and_consume_recovery_code(user_id, test_code)
    assert reused is False

    # 3. Invalid code is rejected
    invalid = verify_and_consume_recovery_code(user_id, "XXXX-YYYY")
    assert invalid is False
