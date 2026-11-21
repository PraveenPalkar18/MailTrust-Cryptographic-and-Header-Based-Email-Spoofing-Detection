"""
Unit Tests for Tamper-Evident Security Audit Logging,
RFC 8785 JSON Canonicalization, SHA-256 Hash Chaining, and Tamper Detection.
"""

import pytest
import json
from app import app
from database import get_db, init_db
from models import AuditLog
from security.audit_log import (
    log_security_event, verify_audit_log_integrity,
    canonicalize_json, sanitize_metadata, GENESIS_PREV_HASH
)
from security.audit_checkpoint import create_audit_checkpoint, verify_checkpoint_signatures


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_rfc8785_json_canonicalization():
    """Verify deterministic JSON serialization rules: sorted keys, compact separators."""
    data = {
        "z": 1,
        "a": "test",
        "nested": {"b": 2, "a": 1}
    }
    canon = canonicalize_json(data)
    # Keys must be sorted lexicographically: a before nested before z
    assert canon.startswith('{"a":"test","nested":{"a":1,"b":2},"z":1}')
    assert " " not in canon  # No whitespace after commas or colons


def test_sensitive_metadata_sanitization():
    """Ensure sensitive credentials and secrets are stripped from audit log entries."""
    meta = {
        "username": "alice",
        "password": "SecretPassword123!",
        "token": "secret_session_token",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "nested": {
            "key": "private_key_material",
            "safe_attribute": 42
        }
    }
    sanitized = sanitize_metadata(meta)
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["token"] == "[REDACTED]"
    assert sanitized["totp_secret"] == "[REDACTED]"
    assert sanitized["nested"]["key"] == "[REDACTED]"
    assert sanitized["nested"]["safe_attribute"] == 42
    assert sanitized["username"] == "alice"


def test_audit_hash_chain_creation_and_verification():
    """Verify unbroken SHA-256 hash chaining across sequentially recorded events."""
    with get_db() as db:
        db.query(AuditLog).delete()
        db.flush()

        ev1 = log_security_event("LOGIN_SUCCESS", actor_id="user:1", actor_role="USER", outcome="SUCCESS", db=db)
        ev2 = log_security_event("PASSWORD_CHANGE", actor_id="user:1", actor_role="USER", outcome="SUCCESS", db=db)
        ev3 = log_security_event("USER_LOGOUT", actor_id="user:1", actor_role="USER", outcome="SUCCESS", db=db)

        assert ev1.sequence_num == 1
        assert ev1.prev_hash == GENESIS_PREV_HASH
        
        assert ev2.sequence_num == 2
        assert ev2.prev_hash == ev1.current_hash

        assert ev3.sequence_num == 3
        assert ev3.prev_hash == ev2.current_hash

        report = verify_audit_log_integrity(db=db)
        assert report["is_valid"] is True
        assert report["total_records"] == 3
        assert len(report["errors"]) == 0


def test_audit_log_tamper_detection_modified_payload():
    """Verify that altering an audit record's payload invalidates the cryptographic hash."""
    with get_db() as db:
        db.query(AuditLog).delete()
        db.flush()

        log_security_event("EVENT_ONE", actor_id="user:1", outcome="SUCCESS", db=db)
        log_security_event("EVENT_TWO", actor_id="user:1", outcome="SUCCESS", db=db)

        second_log = db.query(AuditLog).filter_by(sequence_num=2).first()
        assert second_log is not None
        second_log.action = "EVENT_TWO_TAMPERED"
        db.flush()

        report = verify_audit_log_integrity(db=db)
        assert report["is_valid"] is False
        assert any(e["error_type"] == "PAYLOAD_TAMPERING" for e in report["errors"])


def test_audit_log_tamper_detection_deleted_record():
    """Verify that deleting an intermediate audit record triggers a sequence gap failure."""
    with get_db() as db:
        db.query(AuditLog).delete()
        db.flush()

        log_security_event("STEP_1", actor_id="user:1", db=db)
        log_security_event("STEP_2", actor_id="user:1", db=db)
        log_security_event("STEP_3", actor_id="user:1", db=db)

        ev2_to_delete = db.query(AuditLog).filter_by(sequence_num=2).first()
        assert ev2_to_delete is not None
        db.delete(ev2_to_delete)
        db.flush()

        report = verify_audit_log_integrity(db=db)
        assert report["is_valid"] is False
        assert any(e["error_type"] == "SEQUENCE_GAP" for e in report["errors"])


def test_ed25519_audit_checkpoints():
    """Verify creating and validating Ed25519 digitally signed audit log checkpoints."""
    from models import AuditCheckpoint
    with get_db() as db:
        db.query(AuditCheckpoint).delete()
        db.query(AuditLog).delete()
        db.flush()

        log_security_event("INIT_EVENT", actor_id="system", outcome="SUCCESS", db=db)
        db.flush()

        cp = create_audit_checkpoint(db=db)
        assert cp is not None
        assert cp.sequence_num == 1
        assert len(cp.signature_b64) > 50

        verification = verify_checkpoint_signatures(db=db)
        assert verification["is_valid"] is True
        assert verification["total_checkpoints"] >= 1
