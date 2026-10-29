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

