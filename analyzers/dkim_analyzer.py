"""
DKIM Cryptographic Verification Module for MailTrust
Performs RFC 6376 cryptographic signature verification using dkimpy and dnspython.
"""

import re
from typing import Dict, List, Any, Optional, Callable
import dkim
import dns.resolver
import dns.exception

from config import Config


class DKIMSignatureResult:
    """Detailed result for an individual DKIM-Signature header."""

    def __init__(self):
        self.signature_index: int = 0
        self.raw_header: str = ""
        self.version: str = "1"
        self.signing_domain: str = ""  # d=
        self.selector: str = ""        # s=
        self.algorithm: str = ""       # a= (e.g. rsa-sha256)
        self.canonicalization: str = "" # c= (e.g. relaxed/relaxed)
        self.signed_headers: List[str] = [] # h=
        self.body_hash: str = ""       # bh=
        self.signature_data: str = ""  # b=
        self.dns_query: str = ""       # selector._domainkey.domain
        self.dns_txt_record: str = ""
        self.public_key_k: str = "rsa"
        self.public_key_p: str = ""
        
        # Cryptographic outcome: PASS, FAIL, NONE, TEMPERROR, PERMERROR
        self.status: str = "NONE"
        self.details: str = ""
        self.cryptographic_explanation: str = ""
        self.limitations: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature_index": self.signature_index,
            "version": self.version,
            "signing_domain": self.signing_domain,
            "selector": self.selector,
            "algorithm": self.algorithm,
            "canonicalization": self.canonicalization,
            "signed_headers": self.signed_headers,
            "body_hash": self.body_hash,
            "signature_data": self.signature_data[:30] + "..." if len(self.signature_data) > 30 else self.signature_data,
            "dns_query": self.dns_query,
            "dns_txt_record": self.dns_txt_record,
            "public_key_type": self.public_key_k,
            "status": self.status,
            "details": self.details,
            "cryptographic_explanation": self.cryptographic_explanation,
            "limitations": self.limitations,
        }


class DKIMVerificationResult:
    """Overall DKIM verification result for an email message."""

    def __init__(self):
        self.status: str = "NONE"  # PASS, FAIL, NONE, TEMPERROR, PERMERROR
        self.has_signatures: bool = False
        self.signatures_count: int = 0
        self.signatures: List[DKIMSignatureResult] = []
        self.primary_domain: str = ""
        self.primary_selector: str = ""
        self.summary: str = ""
        self.cns_security_notes: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "has_signatures": self.has_signatures,
            "signatures_count": self.signatures_count,
            "signatures": [s.to_dict() for s in self.signatures],
            "primary_domain": self.primary_domain,
            "primary_selector": self.primary_selector,
            "summary": self.summary,
            "cns_security_notes": self.cns_security_notes,
        }


def _parse_dkim_tags(header_value: str) -> Dict[str, str]:
    """Parse tag=value pairs from a DKIM-Signature header per RFC 6376."""
    tags = {}
    # Remove foldings
    cleaned = re.sub(r"\r?\n[ \t]+", " ", header_value.strip())
    # Strip "DKIM-Signature:" prefix if present
    if cleaned.lower().startswith("dkim-signature:"):
        cleaned = cleaned[len("dkim-signature:"):].strip()
        
    for part in cleaned.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def create_dns_resolver() -> dns.resolver.Resolver:
    """Create a configured dnspython resolver with safe timeouts."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = Config.DNS_TIMEOUT
    resolver.lifetime = Config.DNS_LIFETIME
    # Use system or default nameservers
    if Config.DEFAULT_NAMESERVERS:
        try:
            resolver.nameservers = Config.DEFAULT_NAMESERVERS
        except Exception:
            pass
    return resolver


def default_live_dnsfunc(name: bytes, timeout: int = 5) -> Optional[bytes]:
    """
    Live DNS resolver function for dkimpy.
    Resolves TXT record for selector._domainkey.domain.
    """
    try:
        domain_str = name.decode("utf-8", errors="replace").rstrip(".")
        resolver = create_dns_resolver()
        answers = resolver.resolve(domain_str, "TXT")
        for rdata in answers:
            # dnspython returns rdata.strings as a list of byte chunks
            txt_content = b"".join(rdata.strings)
            return txt_content
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    except dns.exception.Timeout:
        raise dkim.DnsTimeoutError("DNS query timed out")
    except Exception as e:
        raise dns.exception.DNSException(f"DNS lookup error: {str(e)}")
    return None


def verify_dkim_signatures(
    raw_message_bytes: bytes,
    custom_dnsfunc: Optional[Callable[[bytes, int], Optional[bytes]]] = None
) -> DKIMVerificationResult:
    """
    Verify all DKIM signatures in raw email bytes cryptographically.
    Optionally accepts a custom dnsfunc for deterministic unit testing.
    """
    result = DKIMVerificationResult()
    
    if not raw_message_bytes:
        result.status = "NONE"
        result.summary = "No message bytes provided for DKIM verification."
        return result

    # Identify DKIM-Signature headers
    lines = raw_message_bytes.split(b"\n")
    # Quick check for DKIM headers
    has_dkim = any(line.lower().startswith(b"dkim-signature:") for line in lines)
    
    if not has_dkim:
        result.status = "NONE"
        result.summary = "No DKIM-Signature header present in email."
        result.cns_security_notes.append(
            "DKIM provides cryptographic non-repudiation and transit integrity. "
            "Without DKIM, email headers and body cannot be cryptographically verified against sender tampering."
        )
        return result

    result.has_signatures = True

    # Parse headers using dkimpy DKIM object
    try:
        d = dkim.DKIM(raw_message_bytes)
    except Exception as e:
        result.status = "PERMERROR"
        result.summary = f"Malformed email or DKIM header formatting: {str(e)}"
        return result

    # Find DKIM-Signature headers and parse tags
    # Header format in dkim.DKIM: list of (name, value)
    sig_headers = [v for k, v in d.headers if k.lower() == b"dkim-signature"]
    result.signatures_count = len(sig_headers)

    dns_function = custom_dnsfunc if custom_dnsfunc is not None else default_live_dnsfunc

    all_passed = True
    any_passed = False
    temp_error = False
    perm_error = False

    for idx, raw_sig in enumerate(sig_headers):
        sig_str = raw_sig.decode("utf-8", errors="replace")
        tags = _parse_dkim_tags(sig_str)
        
        sig_res = DKIMSignatureResult()
        sig_res.signature_index = idx + 1
        sig_res.raw_header = sig_str
        sig_res.version = tags.get("v", "1")
        sig_res.signing_domain = tags.get("d", "").lower()
        sig_res.selector = tags.get("s", "").lower()
        sig_res.algorithm = tags.get("a", "rsa-sha256").lower()
        sig_res.canonicalization = tags.get("c", "simple/simple")
        sig_res.signed_headers = [h.strip().lower() for h in tags.get("h", "").split(":") if h.strip()]
        sig_res.body_hash = tags.get("bh", "")
        sig_res.signature_data = tags.get("b", "")
        
        if sig_res.selector and sig_res.signing_domain:
            sig_res.dns_query = f"{sig_res.selector}._domainkey.{sig_res.signing_domain}"
        
        # Set primary domain from first signature
        if idx == 0:
            result.primary_domain = sig_res.signing_domain
            result.primary_selector = sig_res.selector

        # Check required tags per RFC 6376
        if not sig_res.signing_domain or not sig_res.selector or not sig_res.signature_data:
            sig_res.status = "PERMERROR"
            sig_res.details = "Missing required DKIM tags (d=, s=, or b=)."
            perm_error = True
            all_passed = False
            result.signatures.append(sig_res)
            continue

        # Fetch DNS TXT record to inspect public key
        txt_record_bytes = None
        try:
            query_bytes = sig_res.dns_query.encode("utf-8")
            txt_record_bytes = dns_function(query_bytes, 5)
        except (dkim.DnsTimeoutError, dns.exception.DNSException) as de:
            sig_res.status = "TEMPERROR"
            sig_res.details = f"DNS resolution failed: {str(de)}"
            temp_error = True
            all_passed = False
            result.signatures.append(sig_res)
            continue
        except Exception as ex:
            sig_res.status = "TEMPERROR"
            sig_res.details = f"DNS query unexpected error: {str(ex)}"
            temp_error = True
            all_passed = False
            result.signatures.append(sig_res)
            continue

        if not txt_record_bytes:
            sig_res.status = "PERMERROR"
            sig_res.details = f"DNS public key record not found for {sig_res.dns_query}."
            perm_error = True
            all_passed = False
            result.signatures.append(sig_res)
            continue

        sig_res.dns_txt_record = txt_record_bytes.decode("utf-8", errors="replace")
        
        # Parse public key tags from TXT record: v=DKIM1; k=rsa; p=MIGf...
        pub_tags = _parse_dkim_tags(sig_res.dns_txt_record)
        sig_res.public_key_k = pub_tags.get("k", "rsa")
        sig_res.public_key_p = pub_tags.get("p", "")

        if not sig_res.public_key_p:
            sig_res.status = "PERMERROR"
            sig_res.details = f"DKIM DNS record found ({sig_res.dns_query}) but public key tag (p=) is missing or revoked."
            perm_error = True
            all_passed = False
            result.signatures.append(sig_res)
            continue

        # Perform actual cryptographic verification for this signature
        try:
            # We use d.verify(idx, dnsfunc) to verify this signature index
            valid = d.verify(idx=idx, dnsfunc=dns_function)
            if valid:
                sig_res.status = "PASS"
                sig_res.details = (
                    f"Cryptographic signature verified successfully. "
                    f"RSA key ({sig_res.public_key_k}) from {sig_res.dns_query} matches signature. "
                    f"Headers and body hash (bh={sig_res.body_hash[:12]}...) are intact."
                )
                sig_res.cryptographic_explanation = (
                    "Integrity Verified: The signed RFC 5322 headers and body hash were unaltered "
                    "since the private key of domain '" + sig_res.signing_domain + "' signed this message."
                )
                sig_res.limitations = (
                    "Important: A valid DKIM signature proves only that the holder of private key for "
                    f"'{sig_res.signing_domain}' signed the message. It does NOT prove the sender is benevolent, "
                    "nor does it prove the visible From address is genuine without DMARC alignment."
                )
                any_passed = True
            else:
                sig_res.status = "FAIL"
                sig_res.details = (
                    "Cryptographic verification failed! Signature data does not match computed "
                    "public-key digest or body hash has been modified in transit."
                )
                all_passed = False
        except dkim.ValidationError as ve:
            sig_res.status = "FAIL"
            sig_res.details = f"DKIM validation error (tampering/hash mismatch): {str(ve)}"
            all_passed = False
        except dkim.KeyFormatError as kfe:
            sig_res.status = "PERMERROR"
            sig_res.details = f"Malformed DKIM public key in DNS: {str(kfe)}"
            perm_error = True
            all_passed = False
        except dkim.MessageFormatError as mfe:
            sig_res.status = "PERMERROR"
            sig_res.details = f"Malformed message headers or DKIM canonicalization error: {str(mfe)}"
            perm_error = True
            all_passed = False
        except (dkim.DnsTimeoutError, dns.exception.DNSException) as de:
            sig_res.status = "TEMPERROR"
            sig_res.details = f"Temporary DNS error during cryptographic check: {str(de)}"
            temp_error = True
            all_passed = False
        except Exception as e:
            sig_res.status = "FAIL"
            sig_res.details = f"Cryptographic verification error: {str(e)}"
            all_passed = False

        result.signatures.append(sig_res)

    # Determine overall status
    if any_passed:
        result.status = "PASS"
        result.summary = f"DKIM Cryptographic Verification Passed for domain '{result.primary_domain}'."
    elif temp_error:
        result.status = "TEMPERROR"
        result.summary = "DKIM verification encountered a temporary DNS error."
    elif perm_error:
        result.status = "PERMERROR"
        result.summary = "DKIM verification encountered a permanent error (missing DNS key or invalid format)."
    else:
        result.status = "FAIL"
        result.summary = "DKIM Cryptographic Verification Failed (invalid signature or altered content)."

    result.cns_security_notes.append(
        "CNS Verification Model: DKIM applies asymmetric cryptography (RSA / Ed25519) with SHA-256 hashing. "
        "The body hash ensures payload integrity, and the header signature proves authenticity of the signing domain."
    )
    return result
