"""
MailTrust Audit Log Checkpoint & Digital Signature Anchor
Provides external cryptographic anchoring for the audit hash chain using Ed25519.

Security Principle:
A hash chain alone prevents undetectable modification by an unprivileged observer,
but a database administrator could rewrite the entire chain from scratch.
By signing checkpoints with an Ed25519 key (held outside or sealed in configuration),
historical checkpoints cannot be forged even if the database is rewritten.
"""

import base64
from typing import Optional, Dict, Any, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from config import Config
from models import AuditLog, AuditCheckpoint, AppSetting, utc_now
from database import get_db

# Setting key for storing generated Ed25519 keys if not set in environment
CHECKPOINT_KEY_SETTING = "audit_checkpoint_ed25519_key_pair"


def _get_or_create_ed25519_key(db) -> Tuple[ed25519.Ed25519PrivateKey, str]:
    """Retrieve existing Ed25519 signing key or generate and persist a new one."""
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    
    # 1. Check environment variable
    if Config.ED25519_PRIVATE_KEY_B64:
        raw_seed = base64.b64decode(Config.ED25519_PRIVATE_KEY_B64)
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_seed)
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv, base64.b64encode(pub_bytes).decode("utf-8")
        
    # 2. Check AppSetting in DB
    setting = db.query(AppSetting).filter_by(key=CHECKPOINT_KEY_SETTING).first()
    if setting:
        raw_seed = base64.b64decode(setting.value)
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_seed)
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv, base64.b64encode(pub_bytes).decode("utf-8")
        
    # 3. Generate new key
    priv = ed25519.Ed25519PrivateKey.generate()
    raw_seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    
    db.add(AppSetting(
        key=CHECKPOINT_KEY_SETTING,
        value=base64.b64encode(raw_seed).decode("utf-8")
    ))
    db.flush()
    return priv, base64.b64encode(pub_bytes).decode("utf-8")


def create_audit_checkpoint(db = None) -> Optional[AuditCheckpoint]:
    """
    Create a digitally signed Ed25519 checkpoint for the latest audit log entry.
    """
    def _create(session_db):
        latest_log = session_db.query(AuditLog).order_by(AuditLog.sequence_num.desc()).first()
        if not latest_log:
            return None
            
        priv_key, pub_b64 = _get_or_create_ed25519_key(session_db)
        
        # Canonical message: sequence_num:current_hash:timestamp
        ts = utc_now().isoformat()
        message = f"CHECKPOINT:{latest_log.sequence_num}:{latest_log.current_hash}:{ts}".encode("utf-8")
        signature = priv_key.sign(message)
        sig_b64 = base64.b64encode(signature).decode("utf-8")
        
        checkpoint = AuditCheckpoint(
            sequence_num=latest_log.sequence_num,
            checkpoint_hash=latest_log.current_hash,
            timestamp_utc=ts,
            signature_b64=sig_b64,
            public_key_b64=pub_b64
        )
        session_db.add(checkpoint)
        session_db.flush()
        return checkpoint

    if db is not None:
        return _create(db)
    else:
        with get_db() as local_db:
            return _create(local_db)


def verify_checkpoint_signatures(db = None) -> Dict[str, Any]:
    """
    Verify all existing audit checkpoints against their Ed25519 digital signatures
    and verify that their referenced hashes match the actual audit log entries.
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    
    def _verify(session_db):
        checkpoints = session_db.query(AuditCheckpoint).order_by(AuditCheckpoint.sequence_num.asc()).all()
        if not checkpoints:
            return {"total_checkpoints": 0, "is_valid": True, "errors": []}
            
        errors = []
        for cp in checkpoints:
            # 1. Verify Ed25519 cryptographic signature
            try:
                pub_bytes = base64.b64decode(cp.public_key_b64)
                sig_bytes = base64.b64decode(cp.signature_b64)
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                
                message = f"CHECKPOINT:{cp.sequence_num}:{cp.checkpoint_hash}:{cp.timestamp_utc}".encode("utf-8")
                pub_key.verify(sig_bytes, message)
            except Exception as e:
                errors.append({
                    "checkpoint_id": cp.id,
                    "sequence_num": cp.sequence_num,
                    "error": f"Invalid Ed25519 signature: {str(e)}"
                })
                continue
                
            # 2. Verify that audit log entry at sequence_num exists and matches checkpoint_hash
            log_entry = session_db.query(AuditLog).filter_by(sequence_num=cp.sequence_num).first()
            if not log_entry:
                errors.append({
                    "checkpoint_id": cp.id,
                    "sequence_num": cp.sequence_num,
                    "error": f"Referenced audit log sequence {cp.sequence_num} is missing from audit log!"
                })
            elif log_entry.current_hash != cp.checkpoint_hash:
                errors.append({
                    "checkpoint_id": cp.id,
                    "sequence_num": cp.sequence_num,
                    "error": f"Hash divergence! Checkpoint hash {cp.checkpoint_hash} does not match audit log hash {log_entry.current_hash}."
                })
                
        return {
            "total_checkpoints": len(checkpoints),
            "is_valid": len(errors) == 0,
            "errors": errors
        }

    if db is not None:
        return _verify(db)
    else:
        with get_db() as local_db:
            return _verify(local_db)
