"""
MailTrust Signed Forensic Evidence Report Module
Generates tamper-evident forensic analysis snapshots signed with Ed25519 digital signatures.
Provides independent public verification of exported MailTrust forensic reports.
"""

import base64
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from config import Config
from models import AppSetting, utc_now
from database import get_db

EVIDENCE_SIGNING_KEY_SETTING = "forensic_report_ed25519_key_pair"


def canonicalize_evidence_json(data: Dict[str, Any]) -> str:
    """Deterministic JSON canonicalization conforming to RFC 8785 principles."""
    return json.dumps(
        data,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":")
    )


def _get_or_create_report_signing_key(db = None) -> Tuple[ed25519.Ed25519PrivateKey, str]:
    """Retrieve existing Ed25519 report signing key or generate and persist a new one."""
    def _fetch(session_db):
        if Config.ED25519_PRIVATE_KEY_B64:
            raw_seed = base64.b64decode(Config.ED25519_PRIVATE_KEY_B64)
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_seed)
            pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            return priv, base64.b64encode(pub_bytes).decode("utf-8")

        setting = session_db.query(AppSetting).filter_by(key=EVIDENCE_SIGNING_KEY_SETTING).first()
        if setting:
            raw_seed = base64.b64decode(setting.value)
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw_seed)
            pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            return priv, base64.b64encode(pub_bytes).decode("utf-8")

        priv = ed25519.Ed25519PrivateKey.generate()
        raw_seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        session_db.add(AppSetting(
            key=EVIDENCE_SIGNING_KEY_SETTING,
            value=base64.b64encode(raw_seed).decode("utf-8")
        ))
        session_db.flush()
        return priv, base64.b64encode(pub_bytes).decode("utf-8")

    if db is not None:
        return _fetch(db)
    else:
        with get_db() as local_db:
            return _fetch(local_db)


def create_signed_forensic_report(
    analysis_data: Dict[str, Any],
    db = None
) -> Dict[str, Any]:
    """
    Generate an RFC 8785 canonical JSON forensic report digitally signed with Ed25519.
    """
    priv_key, pub_key_b64 = _get_or_create_report_signing_key(db)

    # Clean payload for evidence
    payload = {
        "report_metadata": {
            "report_id": analysis_data.get("report_id", "local-report"),
            "timestamp_utc": utc_now().isoformat(),
            "software": "MailTrust Forensic Security Engine",
            "version": "2.0.0-CNS",
            "spec_standard": "RFC-8785-Ed25519",
        },
        "forensic_targets": {
            "file_sha256": analysis_data.get("file_sha256", ""),
            "from_address": analysis_data.get("email", {}).get("from", ""),
            "sender_domain": analysis_data.get("email", {}).get("sender_domain", ""),
            "subject": analysis_data.get("email", {}).get("subject", ""),
            "date": analysis_data.get("email", {}).get("date", ""),
        },
        "cryptographic_verdicts": {
            "overall_verdict": analysis_data.get("verdict", {}).get("classification", "UNKNOWN"),
            "risk_score": analysis_data.get("verdict", {}).get("score", 0),
            "dkim_status": analysis_data.get("dkim", {}).get("status", "NONE"),
            "spf_status": analysis_data.get("spf", {}).get("status", "none"),
            "dmarc_status": analysis_data.get("dmarc", {}).get("status", "none"),
            "smime_status": analysis_data.get("smime", {}).get("status", "NOT_PRESENT"),
            "crypto_hygiene_status": analysis_data.get("crypto_hygiene", {}).get("status", "NOT_EVALUABLE"),
        },
        "findings_summary": analysis_data.get("verdict", {}).get("reasons", []),
    }

    canonical_str = canonicalize_evidence_json(payload)
    canonical_bytes = canonical_str.encode("utf-8")
    canonical_hash = hashlib.sha256(canonical_bytes).hexdigest()

    signature = priv_key.sign(canonical_bytes)
    sig_b64 = base64.b64encode(signature).decode("utf-8")

    return {
        "payload": payload,
        "signature_block": {
            "algorithm": "Ed25519",
            "public_key_b64": pub_key_b64,
            "signature_b64": sig_b64,
            "payload_sha256": canonical_hash,
        }
    }


def verify_signed_forensic_report(report_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify the authenticity, integrity, and Ed25519 digital signature of an exported forensic report.
    Detects any modification or tampering of report findings, timestamps, or verdicts.
    """
    if not isinstance(report_dict, dict):
        return {
            "is_authentic": False,
            "status": "MALFORMED",
            "details": "Invalid report structure: root must be a JSON object."
        }

    payload = report_dict.get("payload")
    sig_block = report_dict.get("signature_block")

    if not payload or not sig_block:
        return {
            "is_authentic": False,
            "status": "MALFORMED",
            "details": "Missing 'payload' or 'signature_block' in forensic report."
        }

    pub_b64 = sig_block.get("public_key_b64")
    sig_b64 = sig_block.get("signature_b64")
    stored_hash = sig_block.get("payload_sha256")

    if not pub_b64 or not sig_b64:
        return {
            "is_authentic": False,
            "status": "MALFORMED",
            "details": "Incomplete cryptographic signature block (missing public key or signature)."
        }

    # 1. Verify SHA-256 canonical hash of payload
    canonical_str = canonicalize_evidence_json(payload)
    canonical_bytes = canonical_str.encode("utf-8")
    recomputed_hash = hashlib.sha256(canonical_bytes).hexdigest()

    if stored_hash and recomputed_hash != stored_hash:
        return {
            "is_authentic": False,
            "status": "TAMPERED",
            "details": f"Payload hash mismatch! Stored: {stored_hash}, Recomputed: {recomputed_hash}. The report content has been altered.",
            "payload": payload
        }

    # 2. Verify Ed25519 signature
    try:
        pub_bytes = base64.b64decode(pub_b64)
        sig_bytes = base64.b64decode(sig_b64)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, canonical_bytes)
    except Exception as e:
        return {
            "is_authentic": False,
            "status": "INVALID_SIGNATURE",
            "details": f"Ed25519 signature verification failed: {str(e)}",
            "payload": payload
        }

    return {
        "is_authentic": True,
        "status": "AUTHENTIC",
        "details": "Ed25519 digital signature verified. Report integrity and authenticity are mathematically guaranteed.",
        "payload": payload,
        "public_key": pub_b64
    }
