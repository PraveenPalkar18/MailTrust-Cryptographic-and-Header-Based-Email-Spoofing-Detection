"""
MailTrust Cryptographic Hygiene Analyzer
Audits cryptographic configurations, key strengths, algorithms, and RFC compliance
for DKIM and S/MIME digital signatures.

Conforms to NIST SP 800-57, RFC 6376, RFC 8301, and RFC 8463 security requirements.
"""

import base64
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519


class HygieneFinding:
    """Individual cryptographic hygiene observation or vulnerability."""

    def __init__(
        self,
        title: str,
        severity: str,  # "CRITICAL", "HIGH", "WARNING", "INFORMATIONAL", "PASS"
        evidence: str,
        explanation: str,
        recommendation: str
    ):
        self.title = title
        self.severity = severity
        self.evidence = evidence
        self.explanation = explanation
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
        }


class CryptoHygieneResult:
    """Consolidated cryptographic hygiene assessment."""

    def __init__(self):
        self.status: str = "NOT_EVALUABLE"  # "PASS", "WARNING", "FAIL", "NOT_EVALUABLE", "INFORMATIONAL"
        self.score_penalty: int = 0
        self.findings: List[HygieneFinding] = []
        self.key_size: Optional[int] = None
        self.key_type: Optional[str] = None
        self.algorithm: Optional[str] = None
        self.summary: str = "No cryptographic signatures evaluated."

    def add_finding(self, finding: HygieneFinding):
        self.findings.append(finding)

    def compute_status(self):
        """Derive overall hygiene status from finding severities."""
        if not self.findings:
            self.status = "NOT_EVALUABLE"
            self.summary = "No cryptographic elements were available for hygiene analysis."
            return

        has_critical = any(f.severity in ("CRITICAL", "FAIL", "HIGH") for f in self.findings)
        has_warning = any(f.severity == "WARNING" for f in self.findings)

        if has_critical:
            self.status = "FAIL"
            self.summary = "Cryptographic hygiene failed: One or more severe cryptographic weaknesses detected."
            self.score_penalty = 25
        elif has_warning:
            self.status = "WARNING"
            self.summary = "Cryptographic hygiene warning: Sub-optimal configuration or legacy parameters identified."
            self.score_penalty = 10
        else:
            self.status = "PASS"
            self.summary = "Cryptographic hygiene passed: Key lengths, algorithms, and parameters conform to current standards."
            self.score_penalty = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "score_penalty": self.score_penalty,
            "key_size": self.key_size,
            "key_type": self.key_type,
            "algorithm": self.algorithm,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "findings_count": len(self.findings),
        }


def _extract_rsa_key_length(base64_pub_key: str) -> Optional[int]:
    """Parse DER-encoded SubjectPublicKeyInfo or PKCS#1 public key to extract bit length."""
    if not base64_pub_key:
        return None
    try:
        der_bytes = base64.b64decode(base64_pub_key.strip().replace(" ", "").replace("\n", ""))
        try:
            pub_key = load_der_public_key(der_bytes)
            if isinstance(pub_key, rsa.RSAPublicKey):
                return pub_key.key_size
        except Exception:
            # Attempt PKCS#1 parse if SPKI envelope is omitted
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from asn1crypto import keys
            info = keys.RSAPublicKey.load(der_bytes)
            return info.bit_size
    except Exception:
        pass
    return None


def _parse_tag_value_string(header_val: str) -> Dict[str, str]:
    """Parse tag=value strings according to RFC 6376 Section 3.2."""
    tags = {}
    for part in re.split(r";\s*", header_val):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def analyze_dkim_crypto_hygiene(
    dkim_verification_result: Any,
    raw_headers: Optional[List[str]] = None
) -> CryptoHygieneResult:
    """
    Analyze cryptographic hygiene of all DKIM signatures present.
    Evaluates key length, algorithm safety, expiration windows, body-length limits,
    and signed header coverage.
    """
    result = CryptoHygieneResult()

    if not dkim_verification_result or not getattr(dkim_verification_result, "has_signatures", False):
        result.status = "NOT_EVALUABLE"
        result.summary = "No DKIM signatures present to evaluate for cryptographic hygiene."
        return result

    for sig in dkim_verification_result.signatures:
        tags = _parse_tag_value_string(sig.raw_header)
        dns_tags = _parse_tag_value_string(sig.dns_txt_record)

        # 1. Algorithm Analysis (RFC 8301)
        algo = sig.algorithm.lower() if sig.algorithm else tags.get("a", "").lower()
        result.algorithm = algo
        if "rsa-sha1" in algo:
            result.add_finding(HygieneFinding(
                title="Deprecated Signature Algorithm (rsa-sha1)",
                severity="HIGH",
                evidence=f"a={algo}",
                explanation="SHA-1 has verified collision attacks and is deprecated by RFC 8301. Attackers could forge signature bodies.",
                recommendation="Upgrade the DKIM signer configuration to rsa-sha256 or ed25519-sha256."
            ))
        elif "sha256" in algo:
            result.add_finding(HygieneFinding(
                title=f"Robust Signature Algorithm ({algo})",
                severity="PASS",
                evidence=f"a={algo}",
                explanation="SHA-256 provides 128-bit collision and preimage resistance, conforming to CNS standards.",
                recommendation="No action needed."
            ))

        # 2. Key Length & Cryptographic Strength
        pub_p = sig.public_key_p or dns_tags.get("p", "")
        key_type = (sig.public_key_k or dns_tags.get("k", "rsa")).lower()
        result.key_type = key_type

        if key_type == "ed25519":
            result.add_finding(HygieneFinding(
                title="Modern Ed25519 Curve Key (RFC 8463)",
                severity="PASS",
                evidence="k=ed25519",
                explanation="Ed25519 offers optimal security and performance with 128-bit equivalent security.",
                recommendation="No action needed."
            ))
        elif pub_p:
            bit_length = _extract_rsa_key_length(pub_p)
            result.key_size = bit_length
            if bit_length:
                if bit_length < 1024:
                    result.add_finding(HygieneFinding(
                        title=f"Critically Weak RSA Key ({bit_length} bits)",
                        severity="CRITICAL",
                        evidence=f"RSA modulus length: {bit_length} bits",
                        explanation="Keys under 1024 bits can be factorized using GNFS on modern computing infrastructure, allowing digital signature forgery.",
                        recommendation="Immediately rotate DKIM keys to 2048-bit RSA or Ed25519."
                    ))
                elif bit_length < 2048:
                    result.add_finding(HygieneFinding(
                        title=f"Sub-optimal RSA Key Length ({bit_length} bits)",
                        severity="WARNING",
                        evidence=f"RSA modulus length: {bit_length} bits",
                        explanation="1024-bit RSA is deprecated by NIST SP 800-57 for modern signatures. While not trivially broken, 2048 bits is the standard.",
                        recommendation="Plan rotation to a 2048-bit RSA key."
                    ))
                else:
                    result.add_finding(HygieneFinding(
                        title=f"Adequate RSA Key Length ({bit_length} bits)",
                        severity="PASS",
                        evidence=f"RSA modulus length: {bit_length} bits",
                        explanation="Meets current cryptographic security recommendations (2048+ bits).",
                        recommendation="No action needed."
                    ))

        # 3. Test Mode Tag (t=y)
        if dns_tags.get("t") == "y":
            result.add_finding(HygieneFinding(
                title="DKIM Domain in Test Mode (t=y)",
                severity="WARNING",
                evidence="t=y in DNS TXT record",
                explanation="The domain owner has flagged this selector as a test configuration. Receiving MTAs may not enforce strict rejection policies.",
                recommendation="Remove t=y from production DNS records once testing concludes."
            ))

        # 4. Partial Body Signing Tag (l=)
        if "l" in tags:
            length_val = tags["l"]
            result.add_finding(HygieneFinding(
                title="Partial Body Signing (l= tag present)",
                severity="WARNING",
                evidence=f"l={length_val}",
                explanation="RFC 6376 Section 8.2 warns that partial-body signing allows adversaries to append arbitrary malicious payloads without invalidating the DKIM signature.",
                recommendation="Omit the l= tag in DKIM signers so the entire email body is protected."
            ))
        else:
            result.add_finding(HygieneFinding(
                title="Full Body Integrity Protected (l= tag omitted)",
                severity="PASS",
                evidence="l= tag omitted",
                explanation="The entire email body is cryptographically bound to the signature hash.",
                recommendation="No action needed."
            ))

        # 5. Expiration Tag (x=)
        if "x" in tags:
            try:
                exp_ts = int(tags["x"])
                now_ts = int(datetime.now(timezone.utc).timestamp())
                if now_ts > exp_ts:
                    result.add_finding(HygieneFinding(
                        title="Expired DKIM Signature",
                        severity="HIGH",
                        evidence=f"x={exp_ts} (expired {now_ts - exp_ts}s ago)",
                        explanation="The message signature has expired according to the signer's explicit x= parameter.",
                        recommendation="Investigate delivery latency or sender clock skew."
                    ))
                else:
                    result.add_finding(HygieneFinding(
                        title="Valid Signature Expiration Window",
                        severity="PASS",
                        evidence=f"x={exp_ts}",
                        explanation="The signature is within its designated valid lifetime window.",
                        recommendation="No action needed."
                    ))
            except ValueError:
                pass
        else:
            result.add_finding(HygieneFinding(
                title="Indefinite Signature Lifetime (x= omitted)",
                severity="INFORMATIONAL",
                evidence="x= tag omitted",
                explanation="Omitting x= is compliant with RFC 6376, but means the signature does not expire and can theoretically be replayed.",
                recommendation="Consider adding an expiration window if message replay attacks are a concern."
            ))

        # 6. Signed Headers List (h=)
        signed_headers = [h.strip().lower() for h in sig.signed_headers]
        if not signed_headers and "h" in tags:
            signed_headers = [h.strip().lower() for h in tags["h"].split(":")]

        if "from" not in signed_headers:
            result.add_finding(HygieneFinding(
                title="Critical Header 'From' Not Signed",
                severity="CRITICAL",
                evidence=f"h={':'.join(signed_headers)}",
                explanation="RFC 6376 Section 5.4.1 explicitly requires that the From header MUST be signed. An unsigned From header allows sender spoofing with valid DKIM.",
                recommendation="Ensure the mail server signs the From header."
            ))
        else:
            result.add_finding(HygieneFinding(
                title="Sender Header 'From' Cryptographically Bound",
                severity="PASS",
                evidence="From included in h=",
                explanation="The From header is cryptographically bound to the digital signature, preventing sender display spoofing.",
                recommendation="No action needed."
            ))

        # Check for Subject and Date
        missing_rec = [hdr for hdr in ["subject", "date"] if hdr not in signed_headers]
        if missing_rec:
            result.add_finding(HygieneFinding(
                title=f"Non-Critical Headers Omitted from Signature ({', '.join(missing_rec)})",
                severity="INFORMATIONAL",
                evidence=f"Omitted: {', '.join(missing_rec)}",
                explanation="While RFC 6376 permits omitting Subject or Date, signing them prevents subject alteration and timestamp manipulation in transit.",
                recommendation="Include Subject and Date in the signed header list for complete envelope protection."
            ))

    result.compute_status()
    return result
