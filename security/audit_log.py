"""
MailTrust Tamper-Evident Audit Logging Module
Implements SHA-256 hash chaining with RFC 8785 deterministic JSON canonicalization.

Hash Construction:
  H_0 = SHA256(canonicalized Event_0 + 64_zeros)
  H_i = SHA256(canonicalized Event_i + H_{i-1})
"""

import json
import hashlib
import uuid
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy import func

from models import AuditLog, utc_now
from database import get_db

# Genesis hash for the initial event in the chain (64 zeros)
GENESIS_PREV_HASH = "0" * 64

# Sensitive keys that must NEVER be persisted in audit log metadata
SENSITIVE_METADATA_KEYS = {
    "password", "secret", "totp_secret", "token", "session_token",
    "csrf_token", "recovery_code", "raw_email", "email_body",
    "private_key", "key", "authorization"
}


def canonicalize_json(data: Dict[str, Any]) -> str:
    """
    Deterministic JSON canonicalization conforming to RFC 8785 principles:
    Lexicographical key sorting, strict UTF-8, no extraneous whitespace.
    """
    return json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    )


def sanitize_metadata(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Strip any accidental credential or sensitive payload from metadata."""
    if not meta:
        return {}
    sanitized = {}
    for k, v in meta.items():
        if k.lower() in SENSITIVE_METADATA_KEYS:
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_metadata(v)
        else:
            sanitized[k] = v
    return sanitized


def compute_event_hash(canonical_payload: str, prev_hash: str) -> str:
    """
    Compute cryptographic hash chain entry:
    H_i = SHA256(canonical_payload || prev_hash)
    """
    combined = canonical_payload.encode("utf-8") + prev_hash.encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def log_security_event(
    action: str,
    actor_id: Optional[str] = None,
    actor_role: Optional[str] = None,
    outcome: str = "SUCCESS",
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    db = None
) -> AuditLog:
    """
    Atomically append a tamper-evident audit record to the cryptographic hash chain.
    """
    def _do_log(session_db):
        # Query the latest audit record to establish chain continuity
        latest_log = session_db.query(AuditLog).order_by(AuditLog.sequence_num.desc()).first()
        
        if latest_log is None:
            seq_num = 1
            prev_hash = GENESIS_PREV_HASH
        else:
            seq_num = latest_log.sequence_num + 1
            prev_hash = latest_log.current_hash
            
        event_id = str(uuid.uuid4())
        timestamp_str = utc_now().isoformat()
        clean_meta = sanitize_metadata(metadata)
        
        # Build canonical dict representing immutable event contents
        event_dict = {
            "sequence_num": seq_num,
            "event_id": event_id,
            "timestamp_utc": timestamp_str,
            "actor_id": actor_id or "anonymous",
            "actor_role": actor_role or "UNAUTHENTICATED",
            "action": action,
            "resource_type": resource_type or "system",
            "resource_id": resource_id or "none",
            "outcome": outcome,
            "metadata": clean_meta
        }
        
        canonical_str = canonicalize_json(event_dict)
        current_hash = compute_event_hash(canonical_str, prev_hash)
        
        record = AuditLog(
            sequence_num=seq_num,
            event_id=event_id,
            timestamp_utc=timestamp_str,
            actor_id=actor_id or "anonymous",
            actor_role=actor_role or "UNAUTHENTICATED",
            action=action,
            resource_type=resource_type or "system",
            resource_id=resource_id or "none",
            outcome=outcome,
            metadata_json=canonicalize_json(clean_meta),
            prev_hash=prev_hash,
            current_hash=current_hash
        )
        session_db.add(record)
        session_db.flush()
        return record

    if db is not None:
        return _do_log(db)
    else:
        with get_db() as local_db:
            return _do_log(local_db)


def verify_audit_log_integrity(db = None) -> Dict[str, Any]:
    """
    Verify the complete cryptographic hash chain of the audit log.
    Detects any tampering: modified fields, deleted records, or reordered entries.
    """
    def _verify(session_db):
        records = session_db.query(AuditLog).order_by(AuditLog.sequence_num.asc()).all()
        
        if not records:
            return {
                "is_valid": True,
                "total_records": 0,
                "errors": [],
                "last_hash": GENESIS_PREV_HASH
            }
            
        errors = []
        expected_prev_hash = GENESIS_PREV_HASH
        expected_seq = 1
        
        for idx, rec in enumerate(records):
            # 1. Sequence number validation (detect deletions / skips)
            if rec.sequence_num != expected_seq:
                errors.append({
                    "record_id": rec.id,
                    "sequence_num": rec.sequence_num,
                    "error_type": "SEQUENCE_GAP",
                    "details": f"Expected sequence {expected_seq}, found {rec.sequence_num}. Records may have been deleted."
                })
                
            # 2. Previous hash continuity
            if rec.prev_hash != expected_prev_hash:
                errors.append({
                    "record_id": rec.id,
                    "sequence_num": rec.sequence_num,
                    "error_type": "HASH_CHAIN_DISCONTINUITY",
                    "details": f"Previous hash mismatch at sequence {rec.sequence_num}."
                })
                
            # 3. Payload integrity & recomputed hash match
            try:
                meta = json.loads(rec.metadata_json) if rec.metadata_json else {}
            except Exception:
                meta = {}
                
            reconstructed_event = {
                "sequence_num": rec.sequence_num,
                "event_id": rec.event_id,
                "timestamp_utc": rec.timestamp_utc,
                "actor_id": rec.actor_id,
                "actor_role": rec.actor_role,
                "action": rec.action,
                "resource_type": rec.resource_type,
                "resource_id": rec.resource_id,
                "outcome": rec.outcome,
                "metadata": meta
            }
            canonical_str = canonicalize_json(reconstructed_event)
            recomputed_hash = compute_event_hash(canonical_str, rec.prev_hash)
            
            if recomputed_hash != rec.current_hash:
                errors.append({
                    "record_id": rec.id,
                    "sequence_num": rec.sequence_num,
                    "error_type": "PAYLOAD_TAMPERING",
                    "details": f"Cryptographic hash mismatch at sequence {rec.sequence_num}. Stored: {rec.current_hash}, Recomputed: {recomputed_hash}."
                })
                
            # Advance expected chain state
            expected_prev_hash = rec.current_hash
            expected_seq = rec.sequence_num + 1
            
        return {
            "is_valid": len(errors) == 0,
            "total_records": len(records),
            "errors": errors,
            "last_hash": records[-1].current_hash
        }

    if db is not None:
        return _verify(db)
    else:
        with get_db() as local_db:
            return _verify(local_db)
