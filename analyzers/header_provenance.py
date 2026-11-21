"""
MailTrust Header Provenance & Authentication-Results Analyzer
Performs forensic inspection of email header stacks, multi-hop Authentication-Results (RFC 8601),
and envelope identity divergence (Return-Path vs From vs Reply-To).
"""

import re
from typing import Dict, List, Any, Optional, Tuple
import tldextract


class HeaderProvenanceResult:
    """Findings from header chain inspection."""

    def __init__(self):
        self.auth_results_count: int = 0
        self.authserv_ids: List[str] = []
        self.auth_results_chain: List[Dict[str, Any]] = []
        self.identity_alignment: Dict[str, Any] = {}
        self.findings: List[Dict[str, str]] = []
        self.has_anomalies: bool = False
        self.summary: str = "Header provenance verified."

    def add_finding(self, severity: str, title: str, details: str):
        self.findings.append({
            "severity": severity,
            "title": title,
            "details": details
        })
        if severity in ("CRITICAL", "HIGH", "WARNING"):
            self.has_anomalies = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "auth_results_count": self.auth_results_count,
            "authserv_ids": self.authserv_ids,
            "auth_results_chain": self.auth_results_chain,
            "identity_alignment": self.identity_alignment,
            "findings": self.findings,
            "has_anomalies": self.has_anomalies,
            "summary": self.summary,
        }


def _extract_domain(addr: str) -> str:
    """Extract registered domain from an email address or domain string."""
    if not addr:
        return ""
    clean = addr
    if "<" in clean and ">" in clean:
        clean = clean.split("<")[1].split(">")[0]
    if "@" in clean:
        clean = clean.split("@")[-1]
    ext = tldextract.extract(clean.strip().lower())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or clean.strip().lower()


def analyze_header_provenance(raw_headers: List[Tuple[str, str]]) -> HeaderProvenanceResult:
    """
    Forensically inspect email headers for multi-hop provenance and identity spoofing.
    raw_headers is a list of (header_name, header_value) tuples in message order.
    """
    result = HeaderProvenanceResult()

    from_header = ""
    reply_to_header = ""
    return_path_header = ""
    auth_results_list = []

    for name, value in raw_headers:
        n_low = name.strip().lower()
        if n_low == "from" and not from_header:
            from_header = value
        elif n_low == "reply-to" and not reply_to_header:
            reply_to_header = value
        elif n_low == "return-path" and not return_path_header:
            return_path_header = value
        elif n_low == "authentication-results":
            auth_results_list.append(value)

    # 1. Multi-hop Authentication-Results Analysis (RFC 8601)
    result.auth_results_count = len(auth_results_list)
    authserv_ids = []

    for idx, ar in enumerate(auth_results_list):
        # Extract authserv-id (first token before semicolon or whitespace)
        match = re.match(r"^\s*([^\s;]+)", ar)
        authserv_id = match.group(1) if match else f"hop-{idx}"
        authserv_ids.append(authserv_id)

        # Parse methods in header: dkim=pass, spf=pass, etc.
        methods = {}
        for method_match in re.finditer(r"(dkim|spf|dmarc)\s*=\s*([a-zA-Z0-9_-]+)", ar, re.IGNORECASE):
            methods[method_match.group(1).lower()] = method_match.group(2).lower()

        result.auth_results_chain.append({
            "hop_index": idx,
            "is_topmost": (idx == 0),
            "authserv_id": authserv_id,
            "raw_snippet": ar[:120] + "..." if len(ar) > 120 else ar,
            "parsed_methods": methods
        })

    result.authserv_ids = authserv_ids

    # Check for suspicious injected Authentication-Results
    if len(auth_results_list) > 1:
        result.add_finding(
            "INFORMATIONAL",
            f"Multiple Authentication-Results Headers ({len(auth_results_list)} hops)",
            "Email passed through multiple intermediate MTAs or security gateways. The topmost header represents the receiving boundary MTA."
        )

    # 2. Envelope and Header Identity Alignment
    from_domain = _extract_domain(from_header)
    reply_domain = _extract_domain(reply_to_header)
    return_path_domain = _extract_domain(return_path_header)

    result.identity_alignment = {
        "from_domain": from_domain,
        "reply_to_domain": reply_domain,
        "return_path_domain": return_path_domain,
        "reply_to_matches_from": (from_domain == reply_domain) if reply_domain else True,
        "return_path_matches_from": (from_domain == return_path_domain) if return_path_domain else True,
    }

    # Detect Reply-To Mismatch (Common Spearphishing Tactic)
    if reply_domain and from_domain and reply_domain != from_domain:
        result.add_finding(
            "WARNING",
            "Reply-To Domain Mismatch",
            f"Email claims to originate from '{from_domain}', but replies are routed to a different domain: '{reply_domain}'. This is a frequent indicator of executive or invoice impersonation lures."
        )

    # Detect Return-Path Mismatch
    if return_path_domain and from_domain and return_path_domain != from_domain:
        result.add_finding(
            "INFORMATIONAL",
            "Return-Path Domain Divergence",
            f"Return-Path envelope domain '{return_path_domain}' differs from display From domain '{from_domain}'. Common in bulk email services (e.g. SendGrid, Mailchimp) or third-party mailing systems."
        )

    if result.has_anomalies:
        result.summary = "Header provenance inspection detected identity or routing anomalies."
    else:
        result.summary = "Header provenance and identity alignment verified."

    return result
