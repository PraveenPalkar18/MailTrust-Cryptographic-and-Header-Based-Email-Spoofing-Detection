"""
Authentication Lab Engine for MailTrust
Provides real, reproducible cryptographic key generation, DKIM message signing,
controlled payload tampering, and cryptographic verification for educational demonstrations.
"""

import base64
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import dkim

from .dkim_analyzer import verify_dkim_signatures


def generate_lab_keypair(key_size: int = 2048) -> Tuple[bytes, str, str]:
    """
    Generate an authentic RSA keypair for DKIM signing.
    Returns: (private_key_pem_bytes, public_key_b64_str, dns_txt_record_str)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    dns_txt_record = f"v=DKIM1; k=rsa; p={pub_b64}"
    return priv_pem, pub_b64, dns_txt_record


def sign_lab_email(
    raw_message_str: str,
    selector: str,
    domain: str,
    private_key_pem: bytes
) -> str:
    """
    Cryptographically sign an RFC 5322 email string with a private RSA key.
    Normalizes CRLF line endings per RFC 6376.
    """
    # Ensure CRLF line endings
    normalized = raw_message_str.replace("\r\n", "\n").replace("\n", "\r\n")
    message_bytes = normalized.encode("utf-8")

    sig = dkim.sign(
        message=message_bytes,
        selector=selector.encode("utf-8"),
        domain=domain.encode("utf-8"),
        privkey=private_key_pem
    )
    signed_email_bytes = sig + message_bytes
    return signed_email_bytes.decode("utf-8", errors="replace")


def verify_lab_email(
    signed_message_str: str,
    selector: str,
    domain: str,
    dns_txt_record: str
) -> Dict[str, Any]:
    """
    Cryptographically verify a signed (or tampered) email using the specified DNS TXT record.
    """
    normalized = signed_message_str.replace("\r\n", "\n").replace("\n", "\r\n")
    message_bytes = normalized.encode("utf-8")
    dns_bytes = dns_txt_record.encode("utf-8")

    target_query = f"{selector}._domainkey.{domain}".lower().rstrip(".")

    def mock_dns(name: bytes, timeout: int = 5):
        query_str = name.decode("utf-8", errors="replace").lower().rstrip(".")
        if target_query in query_str or query_str in target_query:
            return dns_bytes
        return None

    res = verify_dkim_signatures(message_bytes, custom_dnsfunc=mock_dns)
    
    sig_info = res.signatures[0] if res.signatures else None
    return {
        "status": res.status,
        "summary": res.summary,
        "signing_domain": sig_info.signing_domain if sig_info else domain,
        "selector": sig_info.selector if sig_info else selector,
        "algorithm": sig_info.algorithm if sig_info else "rsa-sha256",
        "body_hash": sig_info.body_hash if sig_info else "",
        "details": sig_info.details if sig_info else res.summary,
        "explanation": sig_info.cryptographic_explanation if sig_info else "",
    }
