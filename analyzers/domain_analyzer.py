"""
Domain and Lookalike Analyzer for MailTrust
Performs deterministic CNS checks for display-name spoofing, homoglyphs,
typosquatting, misleading subdomains, header domain inconsistencies,
and deceptive link destinations.
"""

import re
import unicodedata
from typing import Dict, List, Any, Optional, Set
import tldextract

from config import Config
from .dmarc_analyzer import get_organizational_domain


class DomainFinding:
    """Individual security finding produced by domain analysis."""

    def __init__(
        self,
        category: str,
        title: str,
        description: str,
        severity: str,  # INFO, LOW, MEDIUM, HIGH, CRITICAL
        evidence: str,
        confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    ):
        self.category = category
        self.title = title
        self.description = description
        self.severity = severity
        self.evidence = evidence
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


class DomainAnalysisResult:
    """Consolidated result of domain heuristics and consistency checks."""

    def __init__(self):
        self.findings: List[DomainFinding] = []
        self.from_domain: str = ""
        self.from_org_domain: str = ""
        self.reply_to_org_domain: str = ""
        self.return_path_org_domain: str = ""
        self.dkim_org_domain: str = ""
        
        self.has_display_name_spoof: bool = False
        self.has_brand_mismatch: bool = False
        self.has_lookalike_domain: bool = False
        self.has_misleading_subdomain: bool = False
        self.has_header_mismatch: bool = False
        self.has_url_mismatch: bool = False
        self.has_public_form_link: bool = False
        self.summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "from_domain": self.from_domain,
            "from_org_domain": self.from_org_domain,
            "reply_to_org_domain": self.reply_to_org_domain,
            "return_path_org_domain": self.return_path_org_domain,
            "dkim_org_domain": self.dkim_org_domain,
            "has_display_name_spoof": self.has_display_name_spoof,
            "has_brand_mismatch": self.has_brand_mismatch,
            "has_lookalike_domain": self.has_lookalike_domain,
            "has_misleading_subdomain": self.has_misleading_subdomain,
            "has_header_mismatch": self.has_header_mismatch,
            "has_url_mismatch": self.has_url_mismatch,
            "has_public_form_link": self.has_public_form_link,
            "summary": self.summary,
        }


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _normalize_confusables(text: str) -> str:
    """Normalize common visual confusables/substitutions to standard latin letters."""
    mapping = {
        '0': 'o', '1': 'l', '!': 'i', '|': 'l', '3': 'e', '4': 'a',
        '@': 'a', '$': 's', '5': 's', '8': 'b', 'vv': 'w',
    }
    # Also normalize unicode NFKC
    nfkc = unicodedata.normalize('NFKC', text.lower())
    for k, v in mapping.items():
        nfkc = nfkc.replace(k, v)
    return nfkc


def _check_punycode_and_homoglyphs(domain: str) -> Optional[DomainFinding]:
    """Detect Punycode (xn--) and mixed-script unicode homoglyphs."""
    if not domain:
        return None

    # Check for Punycode encoding
    if "xn--" in domain.lower():
        try:
            decoded = domain.encode("ascii").decode("idna")
            return DomainFinding(
                category="Homoglyph / Punycode",
                title="Punycode Encoded Domain Detected",
                description=(
                    f"Domain '{domain}' uses Internationalized Domain Name (IDN) Punycode encoding. "
                    f"Decodes to '{decoded}', which may simulate familiar ASCII Latin characters."
                ),
                severity="HIGH",
                evidence=f"Raw: {domain} -> IDNA Decoded: {decoded}",
                confidence="HIGH"
            )
        except Exception:
            return DomainFinding(
                category="Homoglyph / Punycode",
                title="Malformed Punycode Domain",
                description=f"Domain '{domain}' contains 'xn--' prefix but failed IDNA decoding.",
                severity="HIGH",
                evidence=domain,
                confidence="HIGH"
            )

    # Check for mixed Cyrillic / Greek characters embedded in ASCII domain
    scripts = set()
    for char in domain:
        if char in ".-":
            continue
        try:
            name = unicodedata.name(char, "")
            if "CYRILLIC" in name:
                scripts.add("Cyrillic")
            elif "GREEK" in name:
                scripts.add("Greek")
            elif "LATIN" in name:
                scripts.add("Latin")
        except ValueError:
            pass

    if len(scripts) > 1 and ("Cyrillic" in scripts or "Greek" in scripts):
        return DomainFinding(
            category="Homoglyph / Punycode",
            title="Mixed-Script Unicode Homoglyph Attack",
            description=(
                f"Domain '{domain}' blends characters from multiple scripts ({', '.join(scripts)}). "
                "This is a classic CNS homograph spoofing technique where visually identical non-Latin "
                "glyphs (e.g. Cyrillic 'а', 'о', 'е') imitate Latin characters."
            ),
            severity="CRITICAL",
            evidence=f"Scripts detected: {', '.join(scripts)} in domain '{domain}'",
            confidence="HIGH"
        )

    return None


def _check_typosquatting(org_domain: str) -> Optional[DomainFinding]:
    """Check for typosquatting / edit-distance impersonation of high-value brands."""
    if not org_domain:
        return None

    extracted = tldextract.extract(org_domain)
    label = extracted.domain.lower()

    # Normalize confusables
    normalized_label = _normalize_confusables(label)

    for brand_key, brand_fqdn in Config.TARGET_BRANDS.items():
        brand_extracted = tldextract.extract(brand_fqdn)
        target_label = brand_extracted.domain.lower()

        # If identical label with exact same brand FQDN, it is legitimate
        if org_domain == brand_fqdn:
            continue

        # 1. Exact match after confusable normalization (e.g. 'paypa1' -> 'paypal')
        if normalized_label == target_label and label != target_label:
            return DomainFinding(
                category="Typosquatting",
                title=f"Character-Substitution Lookalike Domain ('{brand_key}')",
                description=(
                    f"Domain '{org_domain}' substitutes characters to visually mimic known brand '{brand_key}' "
                    f"(target: {brand_fqdn}). Normalized: '{normalized_label}'."
                ),
                severity="CRITICAL",
                evidence=f"Sender domain: '{org_domain}' mimics '{brand_fqdn}'",
                confidence="HIGH"
            )

        # 2. Levenshtein edit distance check (distance of 1 or 2 on brands > 4 chars)
        if len(target_label) >= 4:
            dist = _levenshtein_distance(label, target_label)
            if dist == 1:
                return DomainFinding(
                    category="Typosquatting",
                    title=f"Typosquatting Lookalike Domain ('{brand_key}')",
                    description=(
                        f"Domain '{org_domain}' has an edit distance of only 1 from brand '{brand_key}' "
                        f"({brand_fqdn}). This is strong evidence of intentional deceptive typosquatting."
                    ),
                    severity="HIGH",
                    evidence=f"Distance: 1 between '{label}' and '{target_label}'",
                    confidence="HIGH"
                )

    return None


def _check_display_name_spoofing(from_name: str, from_domain: str, org_domain: str) -> Optional[DomainFinding]:
    """Check if display name claims a known brand or email address while domain is unrelated."""
    if not from_name:
        return None

    fn_lower = from_name.lower().strip()

    # 1. Display name contains an email address (e.g. "service@paypal.com" <attacker@evil.com>)
    email_in_name = re.search(r"[\w.-]+@([\w.-]+\.[a-zA-Z]{2,})", fn_lower)
    if email_in_name:
        embedded_domain = email_in_name.group(1).lower()
        embedded_org = get_organizational_domain(embedded_domain)
        if embedded_org != org_domain:
            return DomainFinding(
                category="Display-Name Spoofing",
                title="Deceptive Embedded Email in Display Name",
                description=(
                    f"The display name includes an explicit email address '{email_in_name.group(0)}' "
                    f"with domain '{embedded_domain}', but the actual envelope sending address is on '{from_domain}'."
                ),
                severity="HIGH",
                evidence=f"Display name: '{from_name}' | Sending domain: '{from_domain}'",
                confidence="HIGH"
            )

    # 2. Display name mentions a known brand while sending domain does not belong to that brand
    for brand_key, brand_fqdn in Config.TARGET_BRANDS.items():
        # Check whole word match for brand
        if re.search(r"\b" + re.escape(brand_key) + r"\b", fn_lower):
            brand_org = get_organizational_domain(brand_fqdn)
            if org_domain != brand_org:
                return DomainFinding(
                    category="Display-Name Spoofing",
                    title=f"Brand Impersonation in Display Name ('{brand_key.capitalize()}')",
                    description=(
                        f"The display name '{from_name}' purports to represent '{brand_key.capitalize()}', "
                        f"but the sending domain '{from_domain}' has no legitimate organizational relationship "
                        f"to '{brand_fqdn}'."
                    ),
                    severity="MEDIUM",
                    evidence=f"Display Name: '{from_name}' vs Sender Domain: '{from_domain}'",
                    confidence="MEDIUM"
                )

    return None


def _check_organization_brand_mismatch(parsed_email: Any, from_dom: str, org_domain: str) -> Optional[DomainFinding]:
    """
    Detect potentially misleading organization branding where the subject or sign-off
    claims affiliation with a major brand while sending from an unrelated third-party domain.
    Does NOT flag legitimate news digests, clippings, newsletters, or casual body text mentions.
    """
    subject = (getattr(parsed_email, "subject", "") or "").strip()
    text_body = (getattr(parsed_email, "text_body", "") or "").strip()
    
    # Exclude general news clippings, digests, or media reviews that legitimately report on companies
    subj_lower = subject.lower()
    if any(k in subj_lower for k in ("clipping", "newspaper", "news paper", "digest", "bulletin", "media roundup")):
        return None

    # Check for formal closing / signature block in trailing text
    trailing_chunk = text_body[-500:] if len(text_body) > 500 else text_body

    for brand_key, brand_fqdn in Config.TARGET_BRANDS.items():
        brand_org = get_organizational_domain(brand_fqdn)
        if not org_domain or not brand_org or org_domain == brand_org:
            continue

        brand_pattern = r"\b" + re.escape(brand_key) + r"\b"
        
        # 1. Subject line explicitly features the brand name
        matched_in_subj = bool(re.search(brand_pattern, subject, re.IGNORECASE))
        
        # 2. Formal signoff closing explicitly features the brand name
        # e.g., "Regards, TCS Team" or "Sincerely, Microsoft Support"
        signoff_pattern = r"(?:regards|sincerely|thanks|team|support|recruitment|desk)\s*[,:\n-]+\s*(?:the\s+)?(?:[a-z0-9_-]+\s+)*" + brand_pattern
        matched_in_signoff = bool(re.search(signoff_pattern, trailing_chunk, re.IGNORECASE))

        if matched_in_subj or matched_in_signoff:
            context = "Subject line" if matched_in_subj else "Message sign-off signature"
            
            return DomainFinding(
                category="Organization Brand Divergence",
                title=f"Organization Brand Claim Mismatch ('{brand_key.upper()}')",
                description=(
                    f"The email {context.lower()} prominently references '{brand_key.upper()}', "
                    f"yet the message was sent from domain '{from_dom}' (organizational domain: '{org_domain}'). "
                    "Security Note: Domain divergence does not inherently prove fraud; third-party training "
                    "providers, campus placement partners, or contractors often legitimately deliver programs. "
                    "However, recipients should independently verify authorization before submitting personal data "
                    "or paying program fees."
                ),
                severity="MEDIUM",
                evidence=f"Claimed Brand: '{brand_key.upper()}' in {context} | Sender Domain: '{from_dom}' (expected '{brand_fqdn}')",
                confidence="HIGH"
            )
    return None


def _check_misleading_subdomains(full_domain: str, org_domain: str) -> Optional[DomainFinding]:
    """Check if a known brand is placed into a subdomain of an unrelated third-party domain."""
    if not full_domain or full_domain == org_domain:
        return None

    # Get subdomain portion
    extracted = tldextract.extract(full_domain)
    subdomain_str = extracted.subdomain.lower()

    for brand_key, brand_fqdn in Config.TARGET_BRANDS.items():
        brand_org = get_organizational_domain(brand_fqdn)
        if org_domain == brand_org:
            continue  # Legitimate subdomain of the brand

        if brand_key in subdomain_str.split("."):
            return DomainFinding(
                category="Misleading Subdomain",
                title=f"Brand Subdomain Camouflage ('{brand_key}')",
                description=(
                    f"The domain '{full_domain}' uses '{brand_key}' in its subdomain prefix, "
                    f"camouflaging the true destination under the unrelated organizational domain '{org_domain}'."
                ),
                severity="HIGH",
                evidence=f"Subdomain: '{subdomain_str}' on Host: '{org_domain}'",
                confidence="HIGH"
            )

    return None


def analyze_domains(
    parsed_email: Any,
    dkim_signing_domain: Optional[str] = None
) -> DomainAnalysisResult:
    """
    Run comprehensive CNS domain security heuristics on parsed email headers and links.
    """
    result = DomainAnalysisResult()
    
    from_dom = getattr(parsed_email, "from_domain", "")
    from_name = getattr(parsed_email, "from_name", "")
    reply_to_dom = getattr(parsed_email, "reply_to_domain", "")
    return_path_dom = getattr(parsed_email, "return_path_domain", "")
    urls = getattr(parsed_email, "urls", [])

    result.from_domain = from_dom
    result.from_org_domain = get_organizational_domain(from_dom)
    result.reply_to_org_domain = get_organizational_domain(reply_to_dom)
    result.return_path_org_domain = get_organizational_domain(return_path_dom)
    result.dkim_org_domain = get_organizational_domain(dkim_signing_domain or "")

    # 1. Check Display Name Spoofing
    disp_finding = _check_display_name_spoofing(from_name, from_dom, result.from_org_domain)
    if disp_finding:
        result.has_display_name_spoof = True
        result.findings.append(disp_finding)

    # 1b. Check Organization Brand Claim Mismatch in Subject or Sign-off
    brand_finding = _check_organization_brand_mismatch(parsed_email, from_dom, result.from_org_domain)
    if brand_finding:
        result.has_brand_mismatch = True
        result.findings.append(brand_finding)

    # 2. Check Punycode & Homoglyphs on From domain
    homo_finding = _check_punycode_and_homoglyphs(from_dom)
    if homo_finding:
        result.has_lookalike_domain = True
        result.findings.append(homo_finding)

    # 3. Check Typosquatting on From domain
    typo_finding = _check_typosquatting(result.from_org_domain)
    if typo_finding:
        result.has_lookalike_domain = True
        result.findings.append(typo_finding)

    # 4. Check Misleading Subdomains
    sub_finding = _check_misleading_subdomains(from_dom, result.from_org_domain)
    if sub_finding:
        result.has_misleading_subdomain = True
        result.findings.append(sub_finding)

    # 5. Header Inconsistency Checks
    # Reply-To Mismatch
    if reply_to_dom and result.reply_to_org_domain != result.from_org_domain:
        result.has_header_mismatch = True
        result.findings.append(DomainFinding(
            category="Header Inconsistency",
            title="Reply-To Domain Mismatch",
            description=(
                f"The Reply-To domain ('{reply_to_dom}') belongs to a different organizational domain "
                f"than the From header ('{from_dom}'). User replies will be routed to a separate external recipient."
            ),
            severity="MEDIUM",
            evidence=f"From: {from_dom} -> Reply-To: {reply_to_dom}",
            confidence="HIGH"
        ))

    # Return-Path Mismatch (Informational / Low)
    if return_path_dom and result.return_path_org_domain != result.from_org_domain:
        result.findings.append(DomainFinding(
            category="Header Inconsistency",
            title="Return-Path Domain Divergence",
            description=(
                f"The Return-Path domain ('{return_path_dom}') differs from the visible From domain ('{from_dom}'). "
                "While common in legitimate bulk/ESP mail delivery, it signifies envelope divergence."
            ),
            severity="LOW",
            evidence=f"From: {from_dom} | Return-Path: {return_path_dom}",
            confidence="MEDIUM"
        ))

    # DKIM Third-Party Signing (if DKIM exists and doesn't match From org)
    if dkim_signing_domain and result.dkim_org_domain and result.dkim_org_domain != result.from_org_domain:
        result.findings.append(DomainFinding(
            category="Header Inconsistency",
            title="DKIM Third-Party Signing (Unaligned)",
            description=(
                f"Message was signed by domain '{dkim_signing_domain}', which does not match "
                f"From domain '{from_dom}'. While cryptographically valid for the signing domain, "
                "it does NOT authenticate the visible sender without DMARC alignment."
            ),
            severity="LOW",
            evidence=f"From Org: {result.from_org_domain} | DKIM Org: {result.dkim_org_domain}",
            confidence="HIGH"
        ))

    # 6. URL Destination Mismatch, IP Hostnames & Public Form Detection
    for url_info in urls:
        if url_info.get("is_mismatch"):
            result.has_url_mismatch = True
            result.findings.append(DomainFinding(
                category="Deceptive Link Destination",
                title="Hyperlink Text vs Destination Mismatch",
                description=(
                    f"Link text visually presents one target, but the actual hyperlink routes to a different destination: "
                    f"{url_info.get('mismatch_reason')}"
                ),
                severity="HIGH",
                evidence=f"Text: '{url_info.get('link_text')}' -> URL: '{url_info.get('url')}'",
                confidence="HIGH"
            ))

        # Public cloud form service detection
        if url_info.get("is_public_form"):
            result.has_public_form_link = True
            result.findings.append(DomainFinding(
                category="External Registration Form",
                title="Public Cloud Form Used for Application / Registration",
                description=(
                    f"The email directs recipients to complete registration or submit information via a public "
                    f"form service ('{url_info.get('hostname')}': {url_info.get('url')}). "
                    "Legitimate enterprise organizations and certified programs typically process applications "
                    "through official corporate web domains rather than unauthenticated public form builders."
                ),
                severity="MEDIUM",
                evidence=f"Destination URL: {url_info.get('url')}",
                confidence="HIGH"
            ))

        host = url_info.get("hostname", "")
        # Check IP address as URL host
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            result.findings.append(DomainFinding(
                category="Suspicious URL",
                title="Dotted-Decimal IP Address Used as Hostname in URL",
                description=(
                    f"URL '{url_info.get('url')}' directs traffic to a bare IP address ({host}) "
                    "rather than a registered domain name. This is a common evasion technique to bypass domain filters."
                ),
                severity="HIGH",
                evidence=f"Host: {host} in {url_info.get('url')}",
                confidence="HIGH"
            ))

    # Summary
    if not result.findings:
        result.summary = "No domain inconsistencies or lookalike heuristics triggered."
    else:
        severities = [f.severity for f in result.findings]
        if "CRITICAL" in severities or "HIGH" in severities:
            result.summary = f"Detected {len(result.findings)} domain indicator(s) including high-risk spoofing patterns."
        else:
            result.summary = f"Detected {len(result.findings)} mild domain inconsistency indicator(s)."

    return result
