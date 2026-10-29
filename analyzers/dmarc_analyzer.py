"""
DMARC (Domain-based Message Authentication, Reporting, and Conformance)
RFC 7489 Analyzer for MailTrust.
Implements policy record lookup, organizational domain resolution,
relaxed and strict alignment rules for SPF and DKIM.
"""

import re
from typing import Dict, List, Any, Optional, Tuple, Callable
import dns.resolver
import dns.exception
import tldextract

from config import Config
from .dkim_analyzer import DKIMVerificationResult
from .spf_analyzer import SPFResult


class DMARCResult:
    """Structured container for RFC 7489 DMARC evaluation."""

    def __init__(self):
        # Overall status: PASS, FAIL, NONE, TEMPERROR, PERMERROR
        self.status: str = "NONE"
        self.header_from_domain: str = ""
        self.organizational_domain: str = ""
        self.dmarc_record_domain: str = ""
        self.raw_dmarc_record: str = ""
        self.is_subdomain: bool = False
        
        # Policy tags
        self.policy: str = "none"           # p= (none, quarantine, reject)
        self.subdomain_policy: str = ""     # sp=
        self.effective_policy: str = "none"
        self.adkim: str = "r"               # adkim= (r=relaxed, s=strict)
        self.aspf: str = "r"                # aspf= (r=relaxed, s=strict)
        self.percentage: int = 100          # pct=
        self.rua: str = ""
        self.ruf: str = ""
        
        # Alignment evaluations
        self.dkim_authenticated: bool = False
        self.dkim_aligned: bool = False
        self.dkim_alignment_mode: str = "relaxed"
        self.dkim_signing_domain: str = ""
        self.dkim_alignment_details: str = ""
        
        self.spf_authenticated: bool = False
        self.spf_aligned: bool = False
        self.spf_alignment_mode: str = "relaxed"
        self.spf_domain: str = ""
        self.spf_alignment_details: str = ""

        # Disposition & Guidance
        self.disposition: str = "none" # Action receiver takes per policy if fail
        self.summary: str = ""
        self.explanation: str = ""
        self.cns_security_notes: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "header_from_domain": self.header_from_domain,
            "organizational_domain": self.organizational_domain,
            "dmarc_record_domain": self.dmarc_record_domain,
            "raw_dmarc_record": self.raw_dmarc_record,
            "is_subdomain": self.is_subdomain,
            "policy": self.policy,
            "subdomain_policy": self.subdomain_policy,
            "effective_policy": self.effective_policy,
            "adkim": self.adkim,
            "aspf": self.aspf,
            "percentage": self.percentage,
            "dkim_authenticated": self.dkim_authenticated,
            "dkim_aligned": self.dkim_aligned,
            "dkim_alignment_mode": self.dkim_alignment_mode,
            "dkim_signing_domain": self.dkim_signing_domain,
            "dkim_alignment_details": self.dkim_alignment_details,
            "spf_authenticated": self.spf_authenticated,
            "spf_aligned": self.spf_aligned,
            "spf_alignment_mode": self.spf_alignment_mode,
            "spf_domain": self.spf_domain,
            "spf_alignment_details": self.spf_alignment_details,
            "disposition": self.disposition,
            "summary": self.summary,
            "explanation": self.explanation,
            "cns_security_notes": self.cns_security_notes,
        }


def get_organizational_domain(domain: str) -> str:
    """
    Extract the organizational domain (e.g. 'sub.mail.example.com' -> 'example.com')
    using Public Suffix List resolution via tldextract.
    """
    if not domain:
        return ""
    extracted = tldextract.extract(domain)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return domain.lower()


def _parse_dmarc_tags(record: str) -> Dict[str, str]:
    """Parse tag=value pairs from a DMARC TXT record."""
    tags = {}
    cleaned = record.strip()
    for item in cleaned.split(";"):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            k, v = item.split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()
    return tags


def _default_dmarc_dns_query(domain: str) -> List[str]:
    """Default DNS query for DMARC TXT record."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = Config.DNS_TIMEOUT
    resolver.lifetime = Config.DNS_LIFETIME
    if Config.DEFAULT_NAMESERVERS:
        try:
            resolver.nameservers = Config.DEFAULT_NAMESERVERS
        except Exception:
            pass

    answers = resolver.resolve(domain, "TXT")
    results = []
    for rdata in answers:
        results.append("".join([s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s) for s in rdata.strings]))
    return results


def evaluate_dmarc(
    from_domain: str,
    dkim_result: Optional[DKIMVerificationResult],
    spf_result: Optional[SPFResult],
    dns_query_func: Optional[Callable[[str], List[str]]] = None
) -> DMARCResult:
    """
    Evaluate DMARC per RFC 7489.
    
    Checks DMARC policy for from_domain (or organizational domain).
    Evaluates SPF alignment and DKIM alignment.
    DMARC PASSES if at least one authenticated mechanism passes with alignment.
    """
    result = DMARCResult()
    
    clean_from_domain = (from_domain or "").strip().lower()
    if not clean_from_domain:
        result.status = "NONE"
        result.summary = "No RFC 5322 From domain available for DMARC evaluation."
        return result

    result.header_from_domain = clean_from_domain
    org_domain = get_organizational_domain(clean_from_domain)
    result.organizational_domain = org_domain
    result.is_subdomain = (clean_from_domain != org_domain)

    dns_func = dns_query_func if dns_query_func is not None else _default_dmarc_dns_query

    # 1. Fetch DMARC TXT record: first at _dmarc.<domain>, fallback to _dmarc.<org_domain>
    query_domain = f"_dmarc.{clean_from_domain}"
    raw_record = None
    target_found_domain = query_domain

    try:
        records = dns_func(query_domain)
        dmarc_recs = [r for r in records if r.lower().startswith("v=dmarc1")]
        if dmarc_recs:
            raw_record = dmarc_recs[0]
            target_found_domain = query_domain
    except Exception:
        pass

    # If not found and this is a subdomain, query organizational domain
    if not raw_record and result.is_subdomain:
        org_query_domain = f"_dmarc.{org_domain}"
        try:
            records = dns_func(org_query_domain)
            dmarc_recs = [r for r in records if r.lower().startswith("v=dmarc1")]
            if dmarc_recs:
                raw_record = dmarc_recs[0]
                target_found_domain = org_query_domain
        except Exception:
            pass

    if not raw_record:
        result.status = "NONE"
        result.summary = f"No DMARC policy published for '{clean_from_domain}' or its organizational domain '{org_domain}'."
        result.explanation = (
            "Without a published DMARC record, the domain owner has not declared how receivers "
            "should handle unaligned or spoofed emails claiming to be from this domain."
        )
        result.cns_security_notes.append(
            "RFC 7489 Importance: DMARC closes the gap between transport-level authentication (SPF/DKIM) "
            "and the user-visible RFC 5322 From header. Without DMARC, an attacker can pass SPF or DKIM using "
            "their own domain while displaying a victim's brand in the From header."
        )
        return result

    result.raw_dmarc_record = raw_record
    result.dmarc_record_domain = target_found_domain

    # 2. Parse DMARC tags
    tags = _parse_dmarc_tags(raw_record)
    result.policy = tags.get("p", "none")
    result.subdomain_policy = tags.get("sp", "")
    result.adkim = tags.get("adkim", "r")
    result.aspf = tags.get("aspf", "r")
    try:
        result.percentage = int(tags.get("pct", "100"))
    except ValueError:
        result.percentage = 100
    result.rua = tags.get("rua", "")
    result.ruf = tags.get("ruf", "")

    # Effective policy: use sp if message is from a subdomain and sp is declared
    if result.is_subdomain and result.subdomain_policy:
        result.effective_policy = result.subdomain_policy
    else:
        result.effective_policy = result.policy

    # 3. Evaluate DKIM Alignment
    # DKIM passes DMARC if:
    # a) DKIM cryptographically verified (PASS)
    # b) Signing domain (d=) aligns with RFC 5322 From domain
    result.dkim_alignment_mode = "strict" if result.adkim == "s" else "relaxed"
    dkim_pass_and_aligned = False

    if dkim_result and dkim_result.signatures:
        for sig in dkim_result.signatures:
            sig_domain = sig.signing_domain.lower()
            if not sig_domain:
                continue

            # Check alignment
            is_aligned = False
            if result.adkim == "s":
                # Strict: exact match
                is_aligned = (sig_domain == clean_from_domain)
            else:
                # Relaxed: organizational domains must match
                is_aligned = (get_organizational_domain(sig_domain) == org_domain)

            if is_aligned:
                result.dkim_aligned = True
                result.dkim_signing_domain = sig_domain
                if sig.status == "PASS":
                    result.dkim_authenticated = True
                    dkim_pass_and_aligned = True
                    result.dkim_alignment_details = (
                        f"DKIM Aligned & Verified: Signing domain '{sig_domain}' aligns with From domain "
                        f"'{clean_from_domain}' in {result.dkim_alignment_mode} mode."
                    )
                    break
                else:
                    result.dkim_alignment_details = (
                        f"DKIM Aligned but FAILED crypto: Signing domain '{sig_domain}' matches From domain, "
                        f"but signature verification status is '{sig.status}'."
                    )

        if not result.dkim_aligned and dkim_result.primary_domain:
            result.dkim_signing_domain = dkim_result.primary_domain
            result.dkim_alignment_details = (
                f"DKIM Unaligned: Signing domain '{dkim_result.primary_domain}' does NOT match From domain "
                f"'{clean_from_domain}' (Mode: {result.dkim_alignment_mode})."
            )
    else:
        result.dkim_alignment_details = "No DKIM signatures available to evaluate alignment."

    # 4. Evaluate SPF Alignment
    # SPF passes DMARC if:
    # a) SPF evaluated to PASS
    # b) SPF domain aligns with RFC 5322 From domain
    result.spf_alignment_mode = "strict" if result.aspf == "s" else "relaxed"
    spf_pass_and_aligned = False

    if spf_result and spf_result.domain and spf_result.status != "NOT_EVALUABLE":
        spf_domain = spf_result.domain.lower()
        result.spf_domain = spf_domain
        
        is_spf_aligned = False
        if result.aspf == "s":
            is_spf_aligned = (spf_domain == clean_from_domain)
        else:
            is_spf_aligned = (get_organizational_domain(spf_domain) == org_domain)

        if is_spf_aligned:
            result.spf_aligned = True
            if spf_result.status == "PASS":
                result.spf_authenticated = True
                spf_pass_and_aligned = True
                result.spf_alignment_details = (
                    f"SPF Aligned & Verified: Envelope domain '{spf_domain}' aligns with From domain "
                    f"'{clean_from_domain}' in {result.spf_alignment_mode} mode."
                )
            else:
                result.spf_alignment_details = (
                    f"SPF Aligned but not PASS: Envelope domain '{spf_domain}' aligns with From domain, "
                    f"but SPF status is '{spf_result.status}'."
                )
        else:
            result.spf_alignment_details = (
                f"SPF Unaligned: Envelope domain '{spf_domain}' does NOT align with From domain "
                f"'{clean_from_domain}' (Mode: {result.spf_alignment_mode})."
            )
    else:
        if spf_result and spf_result.status == "NOT_EVALUABLE":
            result.spf_alignment_details = "SPF is NOT EVALUABLE in static .eml (missing connecting IP/envelope context)."
        else:
            result.spf_alignment_details = "No SPF evaluation available."

    # 5. Overall DMARC Decision per RFC 7489 Section 6.6.2
    # "A message satisfies the DMARC check if at least one of the mechanisms (DKIM or SPF) produces:
    #  1) a 'pass' result, and
    #  2) alignment."
    if dkim_pass_and_aligned or spf_pass_and_aligned:
        result.status = "PASS"
        result.disposition = "none"
        pass_mechanisms = []
        if dkim_pass_and_aligned:
            pass_mechanisms.append("Aligned DKIM")
        if spf_pass_and_aligned:
            pass_mechanisms.append("Aligned SPF")
        result.summary = f"DMARC Passed via {', '.join(pass_mechanisms)}."
        result.explanation = (
            f"The message satisfies RFC 7489 DMARC policy for '{clean_from_domain}'. "
            f"At least one authentication mechanism ({' and '.join(pass_mechanisms)}) passed cryptographic "
            f"or authorization checks with proper domain alignment."
        )
    else:
        result.status = "FAIL"
        result.disposition = result.effective_policy
        result.summary = f"DMARC Failed (Policy: p={result.effective_policy})."
        result.explanation = (
            f"Neither DKIM nor SPF produced a passing result with domain alignment to '{clean_from_domain}'. "
            f"Domain owner's published policy disposition is: '{result.effective_policy.upper()}'."
        )

    result.cns_security_notes.append(
        "CNS Alignment Rule: In relaxed mode, subdomains (e.g., mail.company.com) align with the root domain "
        "(company.com). In strict mode, an exact FQDN match is required. DMARC prevents attackers from signing "
        "emails with an unrelated domain's valid DKIM key to bypass spam filters."
    )
    return result
