"""
MailTrust MongoDB Database Module
Provides permanent NoSQL persistence in MongoDB Atlas for users, sessions,
audit logs, analysis records, and security settings.
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import pymongo
from pymongo import MongoClient
from pymongo.collection import Collection

logger = logging.getLogger("mailtrust.mongo")

_mongo_client: Optional[MongoClient] = None


def get_mongo_uri() -> str:
    from config import Config
    return getattr(
        Config,
        "MONGODB_URI",
        "mongodb+srv://praveen:prvn2005@cluster0.jpq3ozt.mongodb.net/luxury_travel?retryWrites=true&w=majority&appName=Cluster0"
    )


def get_mongo_client() -> Optional[MongoClient]:
    """Return a thread-safe singleton PyMongo MongoClient."""
    global _mongo_client
    if _mongo_client is None:
        uri = get_mongo_uri()
        if not uri:
            return None
        try:
            _mongo_client = MongoClient(
                uri,
                serverSelectionTimeoutMS=4000,
                connectTimeoutMS=4000,
                socketTimeoutMS=5000,
                maxPoolSize=50,
            )
        except Exception as e:
            logger.warning(f"Could not initialize MongoDB client: {e}")
            return None
    return _mongo_client


def get_mongo_db():
    """Return the active MongoDB database object."""
    client = get_mongo_client()
    if client is None:
        return None
    try:
        from config import Config
        db_name = getattr(Config, "MONGODB_DB_NAME", "luxury_travel")
        return client[db_name]
    except Exception as e:
        logger.warning(f"Could not get MongoDB database: {e}")
        return None


def get_collection(name: str) -> Optional[Collection]:
    """Get a specific collection prefixed with mailtrust_."""
    db = get_mongo_db()
    if db is None:
        return None
    col_name = f"mailtrust_{name}" if not name.startswith("mailtrust_") else name
    return db[col_name]


# ---------------------------------------------------------------------------
# MongoDB Serialization & Persistence Helpers
# ---------------------------------------------------------------------------

def mongo_save_user(user) -> bool:
    """Save or update a User document in MongoDB Atlas."""
    try:
        col = get_collection("users")
        if col is None:
            return False
        
        doc = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "password_hash": user.password_hash,
            "role": user.role,
            "is_active": bool(user.is_active),
            "is_locked": bool(user.is_locked),
            "failed_login_attempts": int(user.failed_login_attempts or 0),
            "locked_until": user.locked_until,
            "totp_enabled": bool(user.totp_enabled),
            "totp_secret_encrypted": user.totp_secret_encrypted,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
            "last_login_at": user.last_login_at,
        }
        col.update_one({"username": user.username}, {"$set": doc}, upsert=True)
        return True
    except Exception as e:
        logger.warning(f"MongoDB save_user error: {e}")
        return False


def mongo_delete_user(user) -> bool:
    """Delete a User document from MongoDB Atlas."""
    try:
        col = get_collection("users")
        if col is None:
            return False
        col.delete_one({"username": user.username})
        return True
    except Exception as e:
        logger.warning(f"MongoDB delete_user error: {e}")
        return False


def mongo_save_session(session_rec) -> bool:
    """Save or update a SessionRecord in MongoDB Atlas."""
    try:
        col = get_collection("sessions")
        if col is None:
            return False
        
        doc = {
            "id": session_rec.id,
            "session_token_hash": session_rec.session_token_hash,
            "user_id": session_rec.user_id,
            "ip_address": session_rec.ip_address,
            "user_agent": session_rec.user_agent,
            "created_at": session_rec.created_at,
            "last_active_at": session_rec.last_active_at,
            "expires_at": session_rec.expires_at,
            "is_revoked": bool(session_rec.is_revoked),
        }
        col.update_one(
            {"session_token_hash": session_rec.session_token_hash},
            {"$set": doc},
            upsert=True
        )
        return True
    except Exception as e:
        logger.warning(f"MongoDB save_session error: {e}")
        return False


def mongo_delete_session(session_rec) -> bool:
    """Delete a SessionRecord from MongoDB Atlas."""
    try:
        col = get_collection("sessions")
        if col is None:
            return False
        col.delete_one({"session_token_hash": session_rec.session_token_hash})
        return True
    except Exception as e:
        logger.warning(f"MongoDB delete_session error: {e}")
        return False


def mongo_save_recovery_code(code_rec) -> bool:
    """Save or update a RecoveryCode in MongoDB Atlas."""
    try:
        col = get_collection("recovery_codes")
        if col is None:
            return False
        
        doc = {
            "id": code_rec.id,
            "user_id": code_rec.user_id,
            "code_hash": code_rec.code_hash,
            "is_used": bool(code_rec.is_used),
            "used_at": code_rec.used_at,
            "created_at": code_rec.created_at,
        }
        col.update_one(
            {"user_id": code_rec.user_id, "code_hash": code_rec.code_hash},
            {"$set": doc},
            upsert=True
        )
        return True
    except Exception as e:
        logger.warning(f"MongoDB save_recovery_code error: {e}")
        return False


def mongo_save_analysis(analysis_rec) -> bool:
    """Save or update an AnalysisRecord in MongoDB Atlas."""
    try:
        col = get_collection("analysis_records")
        if col is None:
            return False
        
        doc = {
            "id": analysis_rec.id,
            "report_id": analysis_rec.report_id,
            "user_id": analysis_rec.user_id,
            "file_sha256": analysis_rec.file_sha256,
            "sender_domain": analysis_rec.sender_domain,
            "from_address": analysis_rec.from_address,
            "subject_preview": analysis_rec.subject_preview,
            "verdict": analysis_rec.verdict,
            "verdict_badge_class": analysis_rec.verdict_badge_class,
            "risk_score": int(analysis_rec.risk_score),
            "dkim_status": analysis_rec.dkim_status,
            "spf_status": analysis_rec.spf_status,
            "dmarc_status": analysis_rec.dmarc_status,
            "smime_status": analysis_rec.smime_status,
            "summary_json": analysis_rec.summary_json,
            "created_at": analysis_rec.created_at,
            "expires_at": analysis_rec.expires_at,
        }
        col.update_one(
            {"report_id": analysis_rec.report_id},
            {"$set": doc},
            upsert=True
        )
        return True
    except Exception as e:
        logger.warning(f"MongoDB save_analysis error: {e}")
        return False


def mongo_save_audit_log(audit_rec) -> bool:
    """Save or update an AuditLog event in MongoDB Atlas."""
    try:
        col = get_collection("audit_logs")
        if col is None:
            return False
        
        doc = {
            "id": audit_rec.id,
            "sequence_num": int(audit_rec.sequence_num),
            "event_id": audit_rec.event_id,
            "timestamp_utc": str(audit_rec.timestamp_utc),
            "actor_id": audit_rec.actor_id,
            "actor_role": audit_rec.actor_role,
            "action": audit_rec.action,
            "resource_type": audit_rec.resource_type,
            "resource_id": audit_rec.resource_id,
            "outcome": audit_rec.outcome,
            "metadata_json": audit_rec.metadata_json,
            "prev_hash": audit_rec.prev_hash,
            "current_hash": audit_rec.current_hash,
        }
        col.update_one(
            {"event_id": audit_rec.event_id},
            {"$set": doc},
            upsert=True
        )
        return True
    except Exception as e:
        logger.warning(f"MongoDB save_audit_log error: {e}")
        return False


def mongo_save_checkpoint(cp_rec) -> bool:
    """Save or update an AuditCheckpoint in MongoDB Atlas."""
    try:
        col = get_collection("audit_checkpoints")
        if col is None:
            return False
        
        doc = {
            "id": cp_rec.id,
            "sequence_num": int(cp_rec.sequence_num),
            "checkpoint_hash": cp_rec.checkpoint_hash,
            "timestamp_utc": str(cp_rec.timestamp_utc),
            "signature_b64": cp_rec.signature_b64,
            "public_key_b64": cp_rec.public_key_b64,
            "created_at": cp_rec.created_at,
        }
        col.update_one(
            {"sequence_num": cp_rec.sequence_num},
            {"$set": doc},
            upsert=True
        )
        return True
    except Exception as e:
        logger.warning(f"MongoDB save_checkpoint error: {e}")
        return False


def mongo_save_setting(setting_rec) -> bool:
    """Save or update an AppSetting in MongoDB Atlas."""
    try:
        col = get_collection("settings")
        if col is None:
            return False
        
        doc = {
            "key": setting_rec.key,
            "value": setting_rec.value,
            "updated_at": setting_rec.updated_at,
        }
        col.update_one({"key": setting_rec.key}, {"$set": doc}, upsert=True)
        return True
    except Exception as e:
        logger.warning(f"MongoDB save_setting error: {e}")
        return False


# ---------------------------------------------------------------------------
# MongoDB Startup Sync & Default Admin Provisioning
# ---------------------------------------------------------------------------

def init_mongodb():
    """
    Ensure MongoDB Atlas collections and indexes exist, sync remote data,
    and provision default admin if needed.
    """
    try:
        db = get_mongo_db()
        if db is None:
            logger.info("MongoDB not connected. Skipping MongoDB initialization.")
            return

        # Create indexes
        col_users = db["mailtrust_users"]
        col_users.create_index("username", unique=True)
        col_users.create_index("email", unique=True)

        col_sessions = db["mailtrust_sessions"]
        col_sessions.create_index("session_token_hash", unique=True)

        col_audit = db["mailtrust_audit_logs"]
        col_audit.create_index("sequence_num", unique=True)
        col_audit.create_index("event_id", unique=True)

        col_analyses = db["mailtrust_analysis_records"]
        col_analyses.create_index("report_id", unique=True)
        col_analyses.create_index("file_sha256")

        # Provision default admin in MongoDB if no admin exists
        admin_doc = col_users.find_one({"role": "ADMIN"})
        if not admin_doc:
            from security.auth import hash_password
            admin_pwd_hash = hash_password("AdminPassword#2026")
            now = datetime.now(timezone.utc)
            default_admin = {
                "id": 1,
                "username": "admin",
                "email": "admin@mailtrust.local",
                "password_hash": admin_pwd_hash,
                "role": "ADMIN",
                "is_active": True,
                "is_locked": False,
                "failed_login_attempts": 0,
                "locked_until": None,
                "totp_enabled": False,
                "totp_secret_encrypted": None,
                "created_at": now,
                "updated_at": now,
                "last_login_at": None,
            }
            col_users.update_one({"username": "admin"}, {"$set": default_admin}, upsert=True)
            logger.info("Default administrator created in MongoDB Atlas: username='admin'")

        logger.info("MongoDB Atlas initialized successfully with database: luxury_travel")
    except Exception as e:
        logger.warning(f"MongoDB initialization warning: {e}")


def sync_from_mongodb_to_sqlite(db_session):
    """
    Synchronize stored entities from MongoDB Atlas to local working SQLite session.
    Guarantees persistence across restarts or container redeployments.
    """
    try:
        db = get_mongo_db()
        if db is None:
            return

        from models import (
            User, SessionRecord, RecoveryCode, AnalysisRecord,
            AuditLog, AuditCheckpoint, AppSetting
        )

        # 1. Sync Users
        col_users = db["mailtrust_users"]
        for udoc in col_users.find():
            existing = db_session.query(User).filter_by(username=udoc["username"]).first()
            if not existing:
                u = User(
                    username=udoc["username"],
                    email=udoc["email"],
                    password_hash=udoc["password_hash"],
                    role=udoc.get("role", "USER"),
                    is_active=udoc.get("is_active", True),
                    is_locked=udoc.get("is_locked", False),
                    failed_login_attempts=udoc.get("failed_login_attempts", 0),
                    locked_until=udoc.get("locked_until"),
                    totp_enabled=udoc.get("totp_enabled", False),
                    totp_secret_encrypted=udoc.get("totp_secret_encrypted"),
                    created_at=udoc.get("created_at", datetime.now(timezone.utc)),
                    updated_at=udoc.get("updated_at", datetime.now(timezone.utc)),
                    last_login_at=udoc.get("last_login_at"),
                )
                db_session.add(u)

        # 2. Sync App Settings
        col_settings = db["mailtrust_settings"]
        for sdoc in col_settings.find():
            existing = db_session.query(AppSetting).filter_by(key=sdoc["key"]).first()
            if not existing:
                s = AppSetting(
                    key=sdoc["key"],
                    value=sdoc["value"],
                    updated_at=sdoc.get("updated_at", datetime.now(timezone.utc)),
                )
                db_session.add(s)

        # 3. Sync Analysis Records
        col_analyses = db["mailtrust_analysis_records"]
        for adoc in col_analyses.find().sort("created_at", -1).limit(500):
            existing = db_session.query(AnalysisRecord).filter_by(report_id=adoc["report_id"]).first()
            if not existing:
                a = AnalysisRecord(
                    report_id=adoc["report_id"],
                    user_id=adoc.get("user_id"),
                    file_sha256=adoc["file_sha256"],
                    sender_domain=adoc.get("sender_domain"),
                    from_address=adoc.get("from_address"),
                    subject_preview=adoc.get("subject_preview"),
                    verdict=adoc["verdict"],
                    verdict_badge_class=adoc.get("verdict_badge_class", "secondary"),
                    risk_score=adoc.get("risk_score", 0),
                    dkim_status=adoc.get("dkim_status"),
                    spf_status=adoc.get("spf_status"),
                    dmarc_status=adoc.get("dmarc_status"),
                    smime_status=adoc.get("smime_status"),
                    summary_json=adoc.get("summary_json", "{}"),
                    created_at=adoc.get("created_at", datetime.now(timezone.utc)),
                    expires_at=adoc.get("expires_at"),
                )
                db_session.add(a)

        # 4. Sync Audit Logs
        col_audit = db["mailtrust_audit_logs"]
        for aud_doc in col_audit.find().sort("sequence_num", 1).limit(1000):
            existing = db_session.query(AuditLog).filter_by(event_id=aud_doc["event_id"]).first()
            if not existing:
                aud = AuditLog(
                    sequence_num=aud_doc["sequence_num"],
                    event_id=aud_doc["event_id"],
                    timestamp_utc=aud_doc["timestamp_utc"],
                    actor_id=aud_doc.get("actor_id"),
                    actor_role=aud_doc.get("actor_role"),
                    action=aud_doc["action"],
                    resource_type=aud_doc.get("resource_type"),
                    resource_id=aud_doc.get("resource_id"),
                    outcome=aud_doc.get("outcome", "SUCCESS"),
                    metadata_json=aud_doc.get("metadata_json", "{}"),
                    prev_hash=aud_doc["prev_hash"],
                    current_hash=aud_doc["current_hash"],
                )
                db_session.add(aud)

        db_session.commit()
    except Exception as e:
        logger.warning(f"MongoDB sync error: {e}")
        db_session.rollback()
