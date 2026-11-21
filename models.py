"""
MailTrust ORM Data Models
Provides structured relational persistence for users, sessions, MFA,
privacy-conscious analysis metadata, tamper-evident audit logs, and settings.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Index
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class User(Base):
    """Registered platform user or administrator account."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="USER")  # "USER", "ADMIN"
    
    is_active = Column(Boolean, nullable=False, default=True)
    is_locked = Column(Boolean, nullable=False, default=False)
    failed_login_attempts = Column(Integer, nullable=False, default=0)
    locked_until = Column(DateTime(timezone=True), nullable=True)
    
    # Multi-Factor Authentication (RFC 6238 TOTP)
    totp_enabled = Column(Boolean, nullable=False, default=False)
    totp_secret_encrypted = Column(Text, nullable=True)  # Authenticated encrypted secret
    
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    sessions = relationship("SessionRecord", back_populates="user", cascade="all, delete-orphan")
    recovery_codes = relationship("RecoveryCode", back_populates="user", cascade="all, delete-orphan")
    analyses = relationship("AnalysisRecord", back_populates="user", cascade="all, delete-orphan")


class SessionRecord(Base):
    """Server-side authenticated session tracking."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_token_hash = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_active_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, nullable=False, default=False)

    user = relationship("User", back_populates="sessions")


class RecoveryCode(Base):
    """Single-use MFA recovery codes."""
    __tablename__ = "recovery_codes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash = Column(String(128), nullable=False)
    
    is_used = Column(Boolean, nullable=False, default=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)

    user = relationship("User", back_populates="recovery_codes")


class AnalysisRecord(Base):
    """
    Privacy-Conscious Analysis Metadata Record.
    STRICT PRIVACY POLICY: NEVER stores raw email body, raw attachments, or full headers.
    Stores only forensic fingerprints, verdicts, and cryptographic audit proofs.
    """
    __tablename__ = "analysis_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String(36), unique=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    
    file_sha256 = Column(String(64), nullable=False, index=True)
    sender_domain = Column(String(255), nullable=True)
    from_address = Column(String(255), nullable=True)
    subject_preview = Column(String(255), nullable=True)
    
    verdict = Column(String(50), nullable=False)
    verdict_badge_class = Column(String(20), nullable=False)
    risk_score = Column(Integer, nullable=False)
    
    # Core Protocol Outcomes
    dkim_status = Column(String(20), nullable=True)
    spf_status = Column(String(20), nullable=True)
    dmarc_status = Column(String(20), nullable=True)
    smime_status = Column(String(30), nullable=True)
    
    # Structured non-sensitive findings and summary JSON
    summary_json = Column(Text, nullable=False)
    
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)

    user = relationship("User", back_populates="analyses")


class AuditLog(Base):
    """
    Tamper-Evident Security Audit Log.
    Uses SHA-256 hash chaining:
    H_0 = SHA256(canonicalized Event_0)
    H_i = SHA256(canonicalized Event_i + H_{i-1})
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sequence_num = Column(Integer, unique=True, nullable=False, index=True)
    event_id = Column(String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    timestamp_utc = Column(String(30), nullable=False)
    
    actor_id = Column(String(64), nullable=True)    # e.g. "user:1", "system", "anonymous"
    actor_role = Column(String(20), nullable=True)  # "ADMIN", "USER", "SYSTEM"
    action = Column(String(64), nullable=False)      # e.g. "USER_LOGIN_SUCCESS", "ROLE_CHANGE"
    resource_type = Column(String(64), nullable=True)
    resource_id = Column(String(128), nullable=True)
    outcome = Column(String(20), nullable=False)    # "SUCCESS", "FAILURE", "BLOCKED"
    
    # Canonical serialized metadata JSON (strictly excludes passwords, keys, and tokens)
    metadata_json = Column(Text, nullable=False, default="{}")
    
    # Cryptographic Hash Chain
    prev_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False, index=True)


class AuditCheckpoint(Base):
    """Periodic Ed25519-signed checkpoints of the audit log hash chain."""
    __tablename__ = "audit_checkpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sequence_num = Column(Integer, nullable=False, index=True)
    checkpoint_hash = Column(String(64), nullable=False)
    timestamp_utc = Column(String(30), nullable=False)
    signature_b64 = Column(String(128), nullable=False)
    public_key_b64 = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)


class AppSetting(Base):
    """Dynamic administrative and security configuration key-values."""
    __tablename__ = "app_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
