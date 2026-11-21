"""
Unit Tests for MailTrust Authentication, Password Security, Session Tracking,
Rate Limiting, and Role-Based Access Control (RBAC).
"""

import pytest
from datetime import datetime, timezone, timedelta
from app import app
from database import get_db, init_db
from models import User, SessionRecord, utc_now
from security.auth import (
    hash_password, verify_password, validate_password_strength,
    is_rate_limited, record_failed_attempt, clear_failed_attempts,
    create_user_session, revoke_session, generate_session_token, hash_token,
    generate_csrf_token
)


@pytest.fixture(autouse=True)
def setup_database():
    """Ensure database schema exists for testing."""
    init_db()


def test_argon2id_password_hashing():
    """Verify that passwords are securely hashed using Argon2id and verified accurately."""
    plain = "SuperSecur3P@ssw0rd!2026"
    hashed = hash_password(plain)
    
    # Hash must start with argon2id signature
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, plain) is True
    assert verify_password(hashed, "WrongPassword123!") is False
    assert verify_password("", plain) is False


def test_password_strength_validation():
    """Verify CNS password complexity policies."""
    # Too short (< 10 chars)
    valid, reason = validate_password_strength("Short1!")
    assert valid is False
    assert "at least 10 characters" in reason

    # Missing uppercase
    valid, _ = validate_password_strength("lowercase123!@#")
    assert valid is False

    # Missing lowercase
    valid, _ = validate_password_strength("UPPERCASE123!@#")
    assert valid is False

    # Missing number
    valid, _ = validate_password_strength("NoNumbersHere!@#")
    assert valid is False

    # Missing special character
    valid, _ = validate_password_strength("NoSymbols12345")
    assert valid is False

    # Valid strong password
    valid, _ = validate_password_strength("ValidPassword123!@#")
    assert valid is True


def test_rate_limiting_sliding_window():
    """Verify sliding window rate limiting for failed authentication attempts."""
    test_ip = "198.51.100.42"
    clear_failed_attempts(test_ip)

    # Initially not rate limited
    assert is_rate_limited(test_ip) is False

    # Record 4 failed attempts (limit is 5)
    for _ in range(4):
        record_failed_attempt(test_ip)
    assert is_rate_limited(test_ip) is False

    # 5th attempt triggers rate limit
    record_failed_attempt(test_ip)
    assert is_rate_limited(test_ip) is True

    # Clearing attempts resets the limit
    clear_failed_attempts(test_ip)
    assert is_rate_limited(test_ip) is False


def test_session_lifecycle_and_revocation():
    """Verify server-side session token generation, hashing, and revocation."""
    import uuid
    uid_str = uuid.uuid4().hex[:6]
    with app.test_request_context("/"):
        with get_db() as db:
            user = User(
                username=f"test_session_{uid_str}",
                email=f"session_{uid_str}@example.com",
                password_hash=hash_password("Secur3P@ss!2026"),
                role="USER"
            )
            db.add(user)
            db.flush()
            user_id = user.id

        raw_token, csrf_token = create_user_session(user_id)
        assert raw_token is not None
        assert len(raw_token) >= 32
        assert csrf_token is not None

        token_h = hash_token(raw_token)

        with get_db() as db:
            session_rec = db.query(SessionRecord).filter_by(session_token_hash=token_h).first()
            assert session_rec is not None
            assert session_rec.user_id == user_id
            assert session_rec.is_revoked is False

        revoke_session(raw_token)

        with get_db() as db:
            session_rec = db.query(SessionRecord).filter_by(session_token_hash=token_h).first()
            assert session_rec.is_revoked is True


def test_rbac_admin_restriction():
    """Verify that unauthenticated and regular USER users cannot access admin endpoints."""
    with app.test_client() as client:
        # 1. Unauthenticated request to /admin redirects to login
        response = client.get("/admin")
        assert response.status_code == 302
        assert "/login" in response.headers.get("Location", "")

        # 2. Authenticated standard USER request to /admin is denied
        with get_db() as db:
            user = db.query(User).filter_by(username="standard_analyst").first()
            if not user:
                user = User(
                    username="standard_analyst",
                    email="analyst@example.com",
                    password_hash=hash_password("Password123!@#"),
                    role="USER"
                )
                db.add(user)
                db.flush()
            uid = user.id

        with app.test_request_context():
            token, _ = create_user_session(uid)

        client.set_cookie(app.config["SESSION_COOKIE_NAME"], token)
        response = client.get("/admin")
        assert response.status_code == 302
        assert "/dashboard" in response.headers.get("Location", "")
