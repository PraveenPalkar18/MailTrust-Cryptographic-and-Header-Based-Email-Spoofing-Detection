"""
MailTrust TOTP Multi-Factor Authentication Module
RFC 6238-compliant TOTP generation, authenticated secret encryption,
inline QR code generation, and single-use recovery codes.
"""

import io
import base64
import hashlib
import secrets
from typing import List, Tuple, Optional

import pyotp
import qrcode
import qrcode.image.svg
from cryptography.fernet import Fernet

from config import Config
from models import RecoveryCode, utc_now
from database import get_db

# Initialize Fernet symmetric encryption cipher
_fernet = Fernet(Config.TOTP_ENCRYPTION_KEY.encode("utf-8") if isinstance(Config.TOTP_ENCRYPTION_KEY, str) else Config.TOTP_ENCRYPTION_KEY)


def encrypt_totp_secret(plaintext_secret: str) -> str:
    """Encrypt a TOTP secret using AES-128-CBC + HMAC-SHA256 (Fernet)."""
    return _fernet.encrypt(plaintext_secret.encode("utf-8")).decode("utf-8")


def decrypt_totp_secret(encrypted_secret: str) -> str:
    """Decrypt an encrypted TOTP secret."""
    return _fernet.decrypt(encrypted_secret.encode("utf-8")).decode("utf-8")


def generate_totp_secret() -> str:
    """Generate a high-entropy 160-bit Base32 secret for RFC 6238 TOTP."""
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, username: str) -> str:
    """Generate RFC 6238 OTPAuth URI compatible with Google Authenticator and Authy."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name="MailTrust")


def generate_qr_code_data_uri(provisioning_uri: str) -> str:
    """
    Generate an inline SVG Data URI containing the TOTP provisioning QR code.
    Pure Python SVG generation that does not require external C imaging libraries.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=2,
        image_factory=qrcode.image.svg.SvgPathImage
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image()
    
    svg_bytes = img.to_string()
    b64_svg = base64.b64encode(svg_bytes).decode("utf-8")
    return f"data:image/svg+xml;base64,{b64_svg}"


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP code against the secret with +/- 1 window drift (30s tolerance).
    """
    if not code or not code.strip().isdigit() or len(code.strip()) != 6:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code.strip(), valid_window=window)


def generate_recovery_codes(user_id: int, count: int = 8) -> Tuple[List[str], List[RecoveryCode]]:
    """
    Generate single-use alphanumeric recovery codes.
    Returns: (plaintext_codes_for_user_display, recovery_code_db_entities)
    """
    plain_codes = []
    db_entities = []
    
    for _ in range(count):
        part1 = secrets.token_hex(2).upper()
        part2 = secrets.token_hex(2).upper()
        code = f"{part1}-{part2}"
        plain_codes.append(code)
        
        # SHA-256 hash before storing
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        entity = RecoveryCode(
            user_id=user_id,
            code_hash=code_hash,
            is_used=False
        )
        db_entities.append(entity)
        
    return plain_codes, db_entities


def verify_and_consume_recovery_code(user_id: int, code: str) -> bool:
    """
    Validate and consume a single-use recovery code.
    Returns True if valid and not previously used; marks code as used.
    """
    if not code:
        return False
        
    clean_code = code.strip().upper()
    code_hash = hashlib.sha256(clean_code.encode("utf-8")).hexdigest()
    
    with get_db() as db:
        rec = db.query(RecoveryCode).filter_by(
            user_id=user_id,
            code_hash=code_hash,
            is_used=False
        ).first()
        
        if rec:
            rec.is_used = True
            rec.used_at = utc_now()
            return True
            
    return False
