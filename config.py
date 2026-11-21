"""
MailTrust Configuration Module
Cryptography and Network Security (CNS) Email Authenticity System
"""

import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "mailtrust-cns-security-key-2026")
    
    # Input constraints
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB maximum upload
    ALLOWED_EXTENSIONS = {"eml", "txt", "msg"}
    
    # DNS Resolver settings
    DNS_TIMEOUT = 3.0  # seconds per query
    DNS_LIFETIME = 5.0  # total seconds per resolution
    DEFAULT_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]  # Fallback public recursive resolvers
    
    # SPF RFC 7208 constraints
    SPF_MAX_DNS_LOOKUPS = 10
    SPF_MAX_VOID_LOOKUPS = 2
    SPF_MAX_RECURSION_DEPTH = 10
    
    # High-value brand targets for lookalike/homoglyph/typosquatting detection
    TARGET_BRANDS = {
        "paypal": "paypal.com",
        "google": "google.com",
        "microsoft": "microsoft.com",
        "apple": "apple.com",
        "amazon": "amazon.com",
        "netflix": "netflix.com",
        "chase": "chase.com",
        "wellsfargo": "wellsfargo.com",
        "bankofamerica": "bankofamerica.com",
        "citibank": "citi.com",
        "irs": "irs.gov",
        "github": "github.com",
        "dropbox": "dropbox.com",
        "linkedin": "linkedin.com",
        "meta": "meta.com",
        "facebook": "facebook.com",
        "twitter": "x.com",
        "instagram": "instagram.com",
        "dhl": "dhl.com",
        "fedex": "fedex.com",
        "ups": "ups.com",
        "usps": "usps.com",
        # Corporate & IT recruiting targets frequently simulated in training/internship lures
        "tcs": "tcs.com",
        "tata": "tata.com",
        "tata consultancy services": "tcs.com",
        "infosys": "infosys.com",
        "wipro": "wipro.com",
        "cognizant": "cognizant.com",
        "accenture": "accenture.com",
        "hcl": "hcltech.com",
        "tech mahindra": "techmahindra.com",
    }
    
    # Public form / survey hosting domains commonly used in external lures
    PUBLIC_FORM_DOMAINS = {
        "forms.gle",
        "docs.google.com",
        "forms.office.com",
        "typeform.com",
        "surveymonkey.com",
        "jotform.com",
        "airtable.com"
    }

    # Dangerous attachment extensions
    DANGEROUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".ps1", ".msi", ".msp", ".hta", ".cpl", ".jar",
        ".iso", ".img", ".vhd", ".pif", ".reg", ".com"
    }

    # Database Persistence
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATABASE_PATH = os.path.join(BASE_DIR, "mailtrust.db")
    DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{DATABASE_PATH}")

    # MongoDB Atlas Database Persistence (Default permanent cloud store)
    MONGODB_URI = os.environ.get(
        "MONGODB_URI",
        "mongodb+srv://praveen:prvn2005@cluster0.jpq3ozt.mongodb.net/luxury_travel?retryWrites=true&w=majority&appName=Cluster0"
    )
    MONGODB_DB_NAME = os.environ.get("MONGODB_DB_NAME", "luxury_travel")

    # Session & Cookie Security
    # Dedicated auth token cookie, distinct from Flask's internal session cookie
    AUTH_COOKIE_NAME = "mailtrust_auth_token"
    SESSION_COOKIE_NAME = "mailtrust_auth_token"
    FLASK_SESSION_COOKIE_NAME = "mailtrust_flask_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    SESSION_IDLE_MINUTES = int(os.environ.get("SESSION_IDLE_MINUTES", 30))
    SESSION_MAX_HOURS = int(os.environ.get("SESSION_MAX_HOURS", 12))

    # Rate Limiting & Account Lockout
    LOGIN_MAX_FAILED_ATTEMPTS = int(os.environ.get("LOGIN_MAX_FAILED_ATTEMPTS", 5))
    LOGIN_LOCKOUT_MINUTES = int(os.environ.get("LOGIN_LOCKOUT_MINUTES", 15))

    # Cryptographic Keys (Loaded from environment or auto-generated securely)
    # Fernet key must be 32 url-safe base64-encoded bytes
    TOTP_ENCRYPTION_KEY = os.environ.get(
        "TOTP_ENCRYPTION_KEY",
        "k_vQe6f-4rW1T1eR3b4LzJvQxG_mX4v7t_Q9L5oR1gI="  # Default fallback dev key
    )
    # Ed25519 Report & Checkpoint Signing Private Key (Base64 raw 32-byte seed or None for dynamic generation)
    ED25519_PRIVATE_KEY_B64 = os.environ.get("ED25519_PRIVATE_KEY_B64", None)

    # Privacy and Data Retention
    ANALYSIS_RETENTION_DAYS = int(os.environ.get("ANALYSIS_RETENTION_DAYS", 30))
    AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", 90))

    # S/MIME Custom Trust Store Bundle (optional path to PEM file)
    SMIME_TRUSTED_CA_BUNDLE = os.environ.get("SMIME_TRUSTED_CA_BUNDLE", None)

