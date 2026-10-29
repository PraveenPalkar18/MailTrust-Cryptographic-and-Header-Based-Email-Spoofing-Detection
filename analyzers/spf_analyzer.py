"""
SPF (Sender Policy Framework) RFC 7208 Analyzer for MailTrust
Evaluates sender IP authorization against DNS SPF TXT records.
Correctly handles the crucial limitation that static .eml files do not reliably
contain authenticated SMTP envelope parameters unless explicitly supplied.
"""

import ipaddress
import re
from typing import Dict, List, Any, Optional, Tuple, Callable
import dns.resolver
import dns.exception

from config import Config


class SPFResult:
    """Structured result of RFC 7208 SPF evaluation."""

    def __init__(self):
        # PASS, FAIL, SOFTFAIL, NEUTRAL, NONE, TEMPERROR, PERMERROR, NOT_EVALUABLE
        self.status: str = "NOT_EVALUABLE"
        self.qualifier: str = ""
        self.client_ip: str = ""
        self.sender_identity: str = ""  # Envelope sender (MAIL FROM)
        self.domain: str = ""
        self.spf_record: str = ""
        self.all_txt_records: List[str] = []
        self.dns_lookups_count: int = 0
        self.void_lookups_count: int = 0
        self.mechanisms_evaluated: List[Dict[str, Any]] = []
        self.context_source: str = "NONE"  # USER_SUPPLIED, RECEIVED_HEADER_UNVERIFIED, MISSING
        self.summary: str = ""
        self.explanation: str = ""
        self.cns_security_notes: List[str] = []
        self.limitations_disclaimer: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "qualifier": self.qualifier,
            "client_ip": self.client_ip,
            "sender_identity": self.sender_identity,
            "domain": self.domain,
            "spf_record": self.spf_record,
            "all_txt_records": self.all_txt_records,
            "dns_lookups_count": self.dns_lookups_count,
            "mechanisms_evaluated": self.mechanisms_evaluated,
            "context_source": self.context_source,
            "summary": self.summary,
            "explanation": self.explanation,
            "cns_security_notes": self.cns_security_notes,
            "limitations_disclaimer": self.limitations_disclaimer,
        }


def _create_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = Config.DNS_TIMEOUT
    resolver.lifetime = Config.DNS_LIFETIME
    if Config.DEFAULT_NAMESERVERS:
        try:
            resolver.nameservers = Config.DEFAULT_NAMESERVERS
        except Exception:
            pass
    return resolver


def default_dns_query(domain: str, qtype: str = "TXT") -> List[str]:
    """Default DNS query helper returning list of record strings."""
    res = _create_resolver()
    answers = res.resolve(domain, qtype)
    results = []
    for rdata in answers:
        if qtype == "TXT":
            results.append("".join([s.decode("utf-8", errors="replace") if isinstance(s, bytes) else str(s) for s in rdata.strings]))
        elif qtype in ("A", "AAAA"):
            results.append(str(rdata.address))
        elif qtype == "MX":
            results.append(str(rdata.exchange).rstrip("."))
        else:
            results.append(str(rdata))
    return results


class SPFEvaluator:
    """RFC 7208 SPF mechanism parser and evaluator."""

    def __init__(self, dns_query_func: Optional[Callable[[str, str], List[str]]] = None):
        self.dns_query = dns_query_func if dns_query_func is not None else default_dns_query
        self.dns_lookups = 0
        self.void_lookups = 0
        self.mechanisms_log: List[Dict[str, Any]] = []

    def _get_spf_record(self, domain: str) -> Tuple[Optional[str], str]:
        """Fetch SPF TXT record for domain. Checks for multiple SPF records per RFC 7208 Section 3.2."""
        try:
            txt_records = self.dns_query(domain, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None, "NONE"
        except dns.exception.Timeout:
            return None, "TEMPERROR"
        except Exception:
            return None, "TEMPERROR"

        spf_records = [r for r in txt_records if r.lower().startswith("v=spf1 ") or r.lower() == "v=spf1"]
        if not spf_records:
            return None, "NONE"
        if len(spf_records) > 1:
            # RFC 7208 3.2: multiple v=spf1 records constitutes a PermError
            return None, "PERMERROR"
        return spf_records[0], "OK"

    def evaluate(
        self,
        client_ip: str,
        sender_identity: str,
        domain: str,
        recursion_depth: int = 0
    ) -> Tuple[str, str, Optional[str]]:
        """
        Recursively evaluate SPF.
        Returns (result, qualifier, spf_record).
        """
        if recursion_depth > Config.SPF_MAX_RECURSION_DEPTH:
            return "PERMERROR", "", None

        try:
            ip_obj = ipaddress.ip_address(client_ip)
        except ValueError:
            return "PERMERROR", "", None

        record, fetch_status = self._get_spf_record(domain)
        if fetch_status == "NONE":
            return "NONE", "", None
        if fetch_status == "PERMERROR":
            return "PERMERROR", "", None
        if fetch_status == "TEMPERROR":
            return "TEMPERROR", "", None

        terms = record.split()[1:]  # skip v=spf1
        redirect_target = None

        for term in terms:
            term = term.strip()
            if not term:
                continue

            # Check for modifiers (redirect=, exp=)
            if "=" in term:
                mod_name, mod_val = term.split("=", 1)
                mod_name = mod_name.lower()
                if mod_name == "redirect":
                    redirect_target = mod_val
                continue

            # Parse qualifier
            qualifier = "+"
            mech = term
            if term[0] in "+-~?":
                qualifier = term[0]
                mech = term[1:]

            mech_lower = mech.lower()
            matched = False

            # Mechanism: all
            if mech_lower == "all":
                matched = True
                self.mechanisms_log.append({
                    "mechanism": term,
                    "type": "all",
                    "matched": True,
                    "qualifier": qualifier,
                })

            # Mechanism: ip4
            elif mech_lower.startswith("ip4:"):
                cidr = mech[4:]
                try:
                    if "/" not in cidr:
                        cidr = f"{cidr}/32"
                    net = ipaddress.IPv4Network(cidr, strict=False)
                    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in net:
                        matched = True
                except ValueError:
                    return "PERMERROR", "", record

                self.mechanisms_log.append({
                    "mechanism": term,
                    "type": "ip4",
                    "matched": matched,
                    "qualifier": qualifier,
                })

            # Mechanism: ip6
            elif mech_lower.startswith("ip6:"):
                cidr = mech[4:]
                try:
                    if "/" not in cidr:
                        cidr = f"{cidr}/128"
                    net = ipaddress.IPv6Network(cidr, strict=False)
                    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in net:
                        matched = True
                except ValueError:
                    return "PERMERROR", "", record

                self.mechanisms_log.append({
                    "mechanism": term,
                    "type": "ip6",
                    "matched": matched,
                    "qualifier": qualifier,
                })

            # Mechanism: a
            elif mech_lower == "a" or mech_lower.startswith("a:") or mech_lower.startswith("a/"):
                self.dns_lookups += 1
                if self.dns_lookups > Config.SPF_MAX_DNS_LOOKUPS:
                    return "PERMERROR", "", record
                
                target_domain = domain
                prefix_len = None
                if mech_lower.startswith("a:"):
                    target_part = mech[2:]
                    if "/" in target_part:
                        target_domain, pfx = target_part.split("/", 1)
                        prefix_len = int(pfx)
                    else:
                        target_domain = target_part
                elif "/" in mech:
                    prefix_len = int(mech.split("/", 1)[1])

                try:
                    qtype = "AAAA" if isinstance(ip_obj, ipaddress.IPv6Address) else "A"
                    ips = self.dns_query(target_domain, qtype)
                    for ip_str in ips:
                        try:
                            if prefix_len:
                                net = ipaddress.ip_network(f"{ip_str}/{prefix_len}", strict=False)
                                if ip_obj in net:
                                    matched = True
                                    break
                            elif ipaddress.ip_address(ip_str) == ip_obj:
                                matched = True
                                break
                        except ValueError:
                            pass
                except Exception:
                    pass

                self.mechanisms_log.append({
                    "mechanism": term,
                    "type": "a",
                    "matched": matched,
                    "qualifier": qualifier,
                })

            # Mechanism: mx
            elif mech_lower == "mx" or mech_lower.startswith("mx:") or mech_lower.startswith("mx/"):
                self.dns_lookups += 1
                if self.dns_lookups > Config.SPF_MAX_DNS_LOOKUPS:
                    return "PERMERROR", "", record
                
                target_domain = domain
                if mech_lower.startswith("mx:"):
                    target_domain = mech[3:].split("/")[0]

                try:
                    mx_hosts = self.dns_query(target_domain, "MX")
                    qtype = "AAAA" if isinstance(ip_obj, ipaddress.IPv6Address) else "A"
                    for mx_host in mx_hosts:
                        host_ips = self.dns_query(mx_host, qtype)
                        for host_ip in host_ips:
                            if ipaddress.ip_address(host_ip) == ip_obj:
                                matched = True
                                break
                        if matched:
                            break
                except Exception:
                    pass

                self.mechanisms_log.append({
                    "mechanism": term,
                    "type": "mx",
                    "matched": matched,
                    "qualifier": qualifier,
                })

            # Mechanism: include
            elif mech_lower.startswith("include:"):
                self.dns_lookups += 1
                if self.dns_lookups > Config.SPF_MAX_DNS_LOOKUPS:
                    return "PERMERROR", "", record

                inc_domain = mech[8:].strip()
                sub_res, _, _ = self.evaluate(client_ip, sender_identity, inc_domain, recursion_depth + 1)
                
                if sub_res == "PASS":
                    matched = True
                elif sub_res in ("PERMERROR", "TEMPERROR"):
                    return sub_res, "", record

                self.mechanisms_log.append({
                    "mechanism": term,
                    "type": "include",
                    "matched": matched,
                    "qualifier": qualifier,
                    "sub_result": sub_res,
                })

            # Mechanism: exists
            elif mech_lower.startswith("exists:"):
                self.dns_lookups += 1
                if self.dns_lookups > Config.SPF_MAX_DNS_LOOKUPS:
                    return "PERMERROR", "", record

                ex_domain = mech[7:].strip()
                try:
                    ex_ips = self.dns_query(ex_domain, "A")
                    if ex_ips:
                        matched = True
                except Exception:
                    pass

                self.mechanisms_log.append({
                    "mechanism": term,
                    "type": "exists",
                    "matched": matched,
                    "qualifier": qualifier,
                })

            else:
                # Unknown mechanism
                self.mechanisms_log.append({
                    "mechanism": term,
                    "type": "unknown",
                    "matched": False,
                    "qualifier": qualifier,
                })

            if matched:
                outcome_map = {
                    "+": "PASS",
                    "-": "FAIL",
                    "~": "SOFTFAIL",
                    "?": "NEUTRAL",
                }
                return outcome_map.get(qualifier, "PASS"), qualifier, record

        # If no mechanism matched and redirect is present
        if redirect_target:
            self.dns_lookups += 1
            if self.dns_lookups > Config.SPF_MAX_DNS_LOOKUPS:
                return "PERMERROR", "", record
            return self.evaluate(client_ip, sender_identity, redirect_target, recursion_depth + 1)

        # Default outcome if no mechanism matched
        return "NEUTRAL", "?", record


def evaluate_spf(
    parsed_email_or_dict: Any,
    client_ip: Optional[str] = None,
    sender_identity: Optional[str] = None,
    dns_query_func: Optional[Callable[[str, str], List[str]]] = None
) -> SPFResult:
    """
    Evaluate SPF per RFC 7208.
    
    CRITICAL CNS DESIGN PRINCIPLE:
    Uploaded static .eml files do NOT contain a cryptographically verifiable
    connecting IP or SMTP envelope sender (MAIL FROM). Received headers can be forged
    or altered by intermediate mail relays.
    
    If client_ip or sender_identity are not provided by the user, SPF is honestly
    marked as NOT_EVALUABLE with clear explanation of what is missing.
    """
    result = SPFResult()
    result.limitations_disclaimer = (
        "CRITICAL SMTP LIMITATION: In standard SMTP protocol, the connecting client IP "
        "and envelope sender (MAIL FROM) are transient channel parameters negotiated at connection time. "
        "Static .eml files only contain 'Received:' and 'Return-Path:' headers, which cannot be "
        "authentically guaranteed without independent transport verification. Evaluating SPF without "
        "known envelope context would yield an inaccurate or fabricated assessment."
    )

    # Determine domain and sender identity
    from_domain = ""
    if hasattr(parsed_email_or_dict, "from_domain"):
        from_domain = parsed_email_or_dict.from_domain
        return_path = parsed_email_or_dict.return_path_address
    elif isinstance(parsed_email_or_dict, dict):
        from_domain = parsed_email_or_dict.get("from_domain", "")
        return_path = parsed_email_or_dict.get("return_path_address", "")
    else:
        from_domain = ""
        return_path = ""

    # Resolve context
    eff_ip = (client_ip or "").strip()
    context_source = "USER_SUPPLIED" if eff_ip else ""

    # Extract Received-SPF headers if available
    spf_headers = []
    if hasattr(parsed_email_or_dict, "received_spf_parsed"):
        spf_headers = parsed_email_or_dict.received_spf_parsed or []
    elif isinstance(parsed_email_or_dict, dict):
        spf_headers = parsed_email_or_dict.get("received_spf_parsed") or []

    # If no client IP supplied by user, look for IP in transmission headers
    if not eff_ip:
        for item in spf_headers:
            if isinstance(item, dict) and item.get("client_ip"):
                cand_ip = item["client_ip"].strip()
                try:
                    ipaddress.ip_address(cand_ip)
                    eff_ip = cand_ip
                    context_source = "RECEIVED_SPF_HEADER"
                    break
                except ValueError:
                    pass

    if not eff_ip:
        # Check top Received header hops
        hops = []
        if hasattr(parsed_email_or_dict, "received_headers"):
            hops = parsed_email_or_dict.received_headers or []
        elif isinstance(parsed_email_or_dict, dict):
            hops = parsed_email_or_dict.get("received_headers") or []

        for hop in hops:
            if isinstance(hop, dict) and hop.get("ip"):
                cand_ip = hop["ip"].strip()
                try:
                    ipaddress.ip_address(cand_ip)
                    eff_ip = cand_ip
                    context_source = "RECEIVED_HEADER"
                    break
                except ValueError:
                    pass

    # Resolve sender identity (MAIL FROM / Envelope Sender)
    eff_sender = (sender_identity or "").strip()
    if not eff_sender:
        eff_sender = (return_path or "").strip()
    if not eff_sender:
        for item in spf_headers:
            if isinstance(item, dict) and item.get("envelope_from"):
                eff_sender = item["envelope_from"].strip()
                break
    if not eff_sender:
        from_addr = getattr(parsed_email_or_dict, "from_address", "") if hasattr(parsed_email_or_dict, "from_address") else parsed_email_or_dict.get("from_address", "") if isinstance(parsed_email_or_dict, dict) else ""
        eff_sender = (from_addr or "").strip()

    # Resolve domain
    eff_domain = ""
    if eff_sender and "@" in eff_sender:
        eff_domain = eff_sender.split("@")[-1].strip().lower()
    elif eff_sender:
        eff_domain = eff_sender.lower()
    else:
        eff_domain = from_domain.lower()

    result.client_ip = eff_ip
    result.sender_identity = eff_sender
    result.domain = eff_domain
    result.context_source = context_source or "MISSING"

    if not eff_ip or not eff_domain:
        result.status = "NOT_EVALUABLE"
        result.context_source = "MISSING"
        missing_parts = []
        if not eff_ip:
            missing_parts.append("SMTP Connecting IP address (client_ip)")
        if not eff_domain:
            missing_parts.append("Envelope sender domain (MAIL FROM identity)")
        
        result.summary = f"SPF is NOT EVALUABLE: Missing required SMTP parameters ({', '.join(missing_parts)})."
        result.explanation = (
            "RFC 7208 requires both the connecting client's IP address and the envelope sender domain. "
            "Neither parameter was supplied or identified in transmission headers. MailTrust refrains "
            "from fabricating a simulated SPF result. You may provide a connecting IP and envelope sender "
            "to execute an offline contextual SPF evaluation."
        )
        result.cns_security_notes.append(
            "Security Distinction: SPF authenticates the MTA path (hop-by-hop envelope), not the end-user "
            "display header (RFC 5322 From). Forged Received headers are a common evasion technique."
        )
        return result

    # When context is supplied or extracted, evaluate against DNS
    evaluator = SPFEvaluator(dns_query_func=dns_query_func)
    status, qual, spf_rec = evaluator.evaluate(eff_ip, eff_sender, eff_domain)

    result.status = status
    result.qualifier = qual
    result.spf_record = spf_rec or "None published"
    result.dns_lookups_count = evaluator.dns_lookups
    result.mechanisms_evaluated = evaluator.mechanisms_log

    if status == "PASS":
        result.summary = f"SPF Evaluated: PASS (IP {eff_ip} authorized for domain '{eff_domain}')."
        result.explanation = (
            f"The connecting IP address {eff_ip} matched an authorizing mechanism in '{eff_domain}' "
            f"SPF record with qualifier '{qual}'. Lookups performed: {evaluator.dns_lookups}/{Config.SPF_MAX_DNS_LOOKUPS}."
        )
    elif status == "FAIL":
        result.summary = f"SPF Evaluated: FAIL (IP {eff_ip} explicitly rejected by domain '{eff_domain}')."
        result.explanation = (
            f"The connecting IP address {eff_ip} was not authorized and matched an explicit rejection mechanism ('-all')."
        )
    elif status == "SOFTFAIL":
        result.summary = f"SPF Evaluated: SOFTFAIL (IP {eff_ip} not authorized; marked weak fail '~all')."
        result.explanation = (
            f"Domain '{eff_domain}' publishes a transitionary policy (~all); recipient MTA should accept with caution."
        )
    elif status == "NEUTRAL":
        result.summary = f"SPF Evaluated: NEUTRAL (Domain '{eff_domain}' states no assertion for IP {eff_ip})."
        result.explanation = "The SPF record terminated in '?all' or contained no matching mechanism."
    elif status == "NONE":
        result.summary = f"SPF Evaluated: NONE (No SPF DNS TXT record published by '{eff_domain}')."
        result.explanation = f"Domain '{eff_domain}' has not published an SPF record (v=spf1)."
    elif status == "PERMERROR":
        result.summary = f"SPF Evaluated: PERMERROR (Permanent configuration error in SPF for '{eff_domain}')."
        result.explanation = (
            "Possible causes: Syntax error, multiple v=spf1 records in DNS, invalid CIDR prefix, "
            f"or exceeded RFC 7208 limit of 10 DNS lookups (used: {evaluator.dns_lookups})."
        )
    elif status == "TEMPERROR":
        result.summary = f"SPF Evaluated: TEMPERROR (DNS timeout or temporary nameserver failure)."
        result.explanation = f"Nameservers for '{eff_domain}' failed to respond within timeout limits."

    result.cns_security_notes.append(
        "RFC 7208 Compliance: SPF evaluates authorization of the connecting sender MTA. "
        "It does NOT protect against From address display-spoofing; DMARC is required to link SPF to From."
    )
    if context_source in ("RECEIVED_SPF_HEADER", "RECEIVED_HEADER"):
        result.cns_security_notes.append(
            f"Extraction Origin: Connecting IP ({eff_ip}) was extracted from message transmission headers ({context_source}). "
            f"Evaluated against live published DNS TXT record for '{eff_domain}'."
        )
    return result
