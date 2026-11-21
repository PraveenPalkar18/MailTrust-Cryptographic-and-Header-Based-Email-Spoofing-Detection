"""
MailTrust Analyzers Package
CNS-focused modular analyzers for email parsing, DKIM cryptographic verification,
SPF RFC 7208 evaluation, DMARC RFC 7489 alignment, domain heuristics, and risk engine.
"""

from .email_parser import parse_raw_email, ParsedEmail
from .dkim_analyzer import verify_dkim_signatures, DKIMVerificationResult
from .spf_analyzer import evaluate_spf, SPFResult
from .dmarc_analyzer import evaluate_dmarc, DMARCResult
from .domain_analyzer import analyze_domains, DomainAnalysisResult
from .phishing_rules import inspect_phishing_indicators, PhishingIndicatorsResult
from .risk_engine import compute_risk_verdict, RiskAssessmentResult
from .crypto_hygiene import analyze_dkim_crypto_hygiene, CryptoHygieneResult
from .smime_analyzer import verify_smime_signatures, SMIMEResult
from .evidence_report import create_signed_forensic_report, verify_signed_forensic_report
from .header_provenance import analyze_header_provenance, HeaderProvenanceResult
from .attachment_inspector import inspect_attachment, inspect_all_attachments

__all__ = [
    "parse_raw_email",
    "ParsedEmail",
    "verify_dkim_signatures",
    "DKIMVerificationResult",
    "evaluate_spf",
    "SPFResult",
    "evaluate_dmarc",
    "DMARCResult",
    "analyze_domains",
    "DomainAnalysisResult",
    "inspect_phishing_indicators",
    "PhishingIndicatorsResult",
    "compute_risk_verdict",
    "RiskAssessmentResult",
    "analyze_dkim_crypto_hygiene",
    "CryptoHygieneResult",
    "verify_smime_signatures",
    "SMIMEResult",
    "create_signed_forensic_report",
    "verify_signed_forensic_report",
    "analyze_header_provenance",
    "HeaderProvenanceResult",
    "inspect_attachment",
    "inspect_all_attachments",
]
