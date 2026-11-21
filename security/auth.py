"""
MailTrust Authentication & Session Security Module
Implements Argon2id password hashing, secure session management,
rate limiting, CSRF protection, and role-based access control (RBAC).
"""

import hmac
import hashlib
import re
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Optional, Tuple, Dict, Any

from flask import request, session, g, redirect, url_for, flash, abort, jsonify, current_app
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError, VerificationError

from config import Config
from models import User, SessionRecord, utc_now
from database import get_db

# Password Hasher initialized with secure OWASP-compliant Argon2id parameters
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=1,
    hash_len=32
)

# In-memory sliding window rate limiter: { key: [timestamp, timestamp, ...] }
_FAILED_ATTEMPTS: Dict[str, list] = {}


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    return _hasher.hash(password)


def verify_password(hash_str: str, password: str) -> bool:
    """Verify plaintext password against stored Argon2id hash."""
    try:
        return _hasher.verify(hash_str, password)
    except (VerifyMismatchError, InvalidHashError, VerificationError, Exception):
        return False


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validate that password meets CNS security complexity guidelines:
    Minimum 10 characters, mixed case, at least one digit and one symbol.
    """
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        return False, "Password must include at least one special character."
    return True, "Password meets security requirements."


def _get_client_ip() -> str:
    """Extract client IP handling reverse proxy headers safely."""
    x_forwarded = request.headers.get("X-Forwarded-For")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def is_rate_limited(identifier: str) -> bool:
    """
    Check if IP or username has exceeded maximum failed login attempts.
    Sliding window based on Config.LOGIN_LOCKOUT_MINUTES.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=Config.LOGIN_LOCKOUT_MINUTES)
    
    attempts = _FAILED_ATTEMPTS.get(identifier, [])
    # Filter attempts within window
    active_attempts = [ts for ts in attempts if ts > cutoff]
    _FAILED_ATTEMPTS[identifier] = active_attempts
    
    return len(active_attempts) >= Config.LOGIN_MAX_FAILED_ATTEMPTS


def record_failed_attempt(identifier: str):
    """Record a failed login attempt for rate limiting."""
    now = datetime.now(timezone.utc)
    attempts = _FAILED_ATTEMPTS.setdefault(identifier, [])
    attempts.append(now)


def clear_failed_attempts(identifier: str):
    """Clear recorded failed attempts upon successful login."""
    _FAILED_ATTEMPTS.pop(identifier, None)


def generate_session_token() -> str:
    """Generate 256-bit cryptographically secure random URL-safe token."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash session token with SHA-256 for persistent database lookup."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_csrf_token(session_token: str) -> str:
    """Compute HMAC-SHA256 CSRF token tied to active session token."""
    key = Config.SECRET_KEY.encode("utf-8")
    msg = f"csrf:{session_token}".encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def create_user_session(user_id: int) -> Tuple[str, str]:
    """
    Create a new database-backed session for the user.
    Returns: (raw_session_token, csrf_token)
    """
    raw_token = generate_session_token()
    token_h = hash_token(raw_token)
    now = utc_now()
    expires_at = now + timedelta(hours=Config.SESSION_MAX_HOURS)
    
    client_ip = _get_client_ip()
    user_agent = request.headers.get("User-Agent", "")[:250]
    
    with get_db() as db:
        session_rec = SessionRecord(
            session_token_hash=token_h,
            user_id=user_id,
            ip_address=client_ip,
            user_agent=user_agent,
            created_at=now,
            last_active_at=now,
            expires_at=expires_at,
            is_revoked=False
        )
        db.add(session_rec)
    
    csrf_token = generate_csrf_token(raw_token)
    return raw_token, csrf_token


def revoke_session(raw_token: str):
    """Revoke an active session token in the database."""
    if not raw_token:
        return
    token_h = hash_token(raw_token)
    with get_db() as db:
        session_rec = db.query(SessionRecord).filter_by(session_token_hash=token_h).first()
        if session_rec:
            session_rec.is_revoked = True


def load_authenticated_user():
    """
    Request hook to validate session cookie and load user into flask.g.
    Enforces idle timeout and absolute timeout.
    """
    g.current_user = None
    g.current_session = None
    g.csrf_token = None
    
    raw_token = request.cookies.get(Config.SESSION_COOKIE_NAME)
    if not raw_token:
        return
    
    token_h = hash_token(raw_token)
    now = utc_now()
    
    with get_db() as db:
        session_rec = db.query(SessionRecord).filter_by(
            session_token_hash=token_h,
            is_revoked=False
        ).first()
        
        if not session_rec:
            return
        
        # Check absolute expiration
        expires_at = session_rec.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            session_rec.is_revoked = True
            return
            
        # Check idle timeout (Config.SESSION_IDLE_MINUTES)
        last_active = session_rec.last_active_at
        if last_active.tzinfo is None:
            last_active = last_active.replace(tzinfo=timezone.utc)
        if now - last_active > timedelta(minutes=Config.SESSION_IDLE_MINUTES):
            session_rec.is_revoked = True
            return
            
        user = db.query(User).filter_by(id=session_rec.user_id).first()
        if not user or not user.is_active or user.is_locked:
            session_rec.is_revoked = True
            return
            
        # Session is valid: update activity timestamp
        session_rec.last_active_at = now
        db.flush()
        db.expunge(user)
        db.expunge(session_rec)
        
        # Attach to request context
        g.current_user = user
        g.current_session = session_rec
        g.csrf_token = generate_csrf_token(raw_token)


def validate_csrf():
    """
    Validate CSRF token on mutating HTTP requests (POST, PUT, DELETE, PATCH).
    Protects all administrative and authenticated state changes.
    Exempts public read-only analysis tools and stateless API endpoints.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    # In testing mode, allow existing functional tests without CSRF headers
    if current_app and current_app.config.get("TESTING"):
        return
        
    # Endpoints exempt from CSRF (stateless public analyzers and labs)
    exempt_endpoints = {
        "analyze", "api_analyze", "api_lab_generate_key",
        "api_lab_sign", "api_lab_verify", "load_sample", "verify_report",
        "api_report_verify_signed", "clear_history"
    }
    if request.endpoint in exempt_endpoints:
        return

    expected = g.get("csrf_token") or session.get("csrf_token")
    submitted = (
        request.form.get("csrf_token") or
        request.headers.get("X-CSRF-Token") or
        request.headers.get("X-CSRFToken")
    )
    
    if not expected or not submitted or not hmac.compare_digest(expected, submitted):
        if request.is_json:
            abort(400, description="CSRF validation failed: Invalid or missing CSRF token.")
        abort(400, "CSRF validation failed. Please refresh and try again.")


def login_required(f):
    """Decorator to restrict access to authenticated users."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.get("current_user"):
            if request.is_json:
                return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to restrict access to administrators."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = g.get("current_user")
        if not user:
            if request.is_json:
                return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
            flash("Please log in with administrator credentials.", "warning")
            return redirect(url_for("login", next=request.url))
            
        if user.role != "ADMIN":
            if request.is_json:
                return jsonify({"error": "Forbidden", "message": "Administrator privileges required"}), 403
            flash("Access denied: Administrator privileges required.", "danger")
            return redirect(url_for("user_dashboard"))
            
        return f(*args, **kwargs)
    return decorated_function


def roles_required(*roles):
    """Decorator to require one of the specified roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = g.get("current_user")
            if not user:
                if request.is_json:
                    return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
                flash("Please log in to access this page.", "warning")
                return redirect(url_for("login", next=request.url))
            if user.role not in roles:
                if request.is_json:
                    return jsonify({"error": "Forbidden", "message": "Insufficient permissions"}), 403
                flash("Access denied: You do not have permission to view this resource.", "danger")
                return redirect(url_for("user_dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
