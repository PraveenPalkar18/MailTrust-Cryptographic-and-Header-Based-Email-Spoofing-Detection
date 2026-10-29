"""
Email Parser Module for MailTrust
Handles MIME structure parsing, RFC 5322 header extraction, URL parsing,
and untrusted content sanitization.
"""

import email
import email.policy
from email.utils import parseaddr, getaddresses
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from config import Config


class ParsedEmail:
    """Structured container for parsed RFC 5322 and MIME email content."""

    def __init__(self):
        self.raw_bytes: bytes = b""
        self.raw_headers: List[tuple] = []
        
        # Identity Headers
        self.from_header: str = ""
        self.from_name: str = ""
        self.from_address: str = ""
        self.from_domain: str = ""
        
        self.reply_to_header: str = ""
        self.reply_to_name: str = ""
        self.reply_to_address: str = ""
        self.reply_to_domain: str = ""
        
        self.return_path_header: str = ""
        self.return_path_address: str = ""
        self.return_path_domain: str = ""
        
        # Message Metadata
        self.subject: str = ""
        self.date_raw: str = ""
        self.message_id: str = ""
        self.to_addresses: List[str] = []
        self.cc_addresses: List[str] = []
        
        # Authentication & Routing Headers
        self.received_headers: List[Dict[str, Any]] = []
        self.authentication_results_headers: List[Dict[str, Any]] = []
        self.received_spf_headers: List[str] = []
        self.received_spf_parsed: List[Dict[str, Any]] = []
        self.dkim_signature_headers: List[str] = []
        
        # Body and Content
        self.text_body: str = ""
        self.html_body: str = ""
        self.urls: List[Dict[str, Any]] = []
        self.attachments: List[Dict[str, Any]] = []
        
        # Parsing Flags & Errors
        self.parse_warnings: List[str] = []
        self.is_multipart: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_header": self.from_header,
            "from_name": self.from_name,
            "from_address": self.from_address,
            "from_domain": self.from_domain,
            "reply_to_header": self.reply_to_header,
            "reply_to_name": self.reply_to_name,
            "reply_to_address": self.reply_to_address,
            "reply_to_domain": self.reply_to_domain,
            "return_path_header": self.return_path_header,
            "return_path_address": self.return_path_address,
            "return_path_domain": self.return_path_domain,
            "subject": self.subject,
            "date_raw": self.date_raw,
            "message_id": self.message_id,
            "to_addresses": self.to_addresses,
            "cc_addresses": self.cc_addresses,
            "received_headers_count": len(self.received_headers),
            "received_headers": self.received_headers,
            "authentication_results": self.authentication_results_headers,
            "received_spf_headers": self.received_spf_headers,
            "received_spf_parsed": self.received_spf_parsed,
            "dkim_signatures_count": len(self.dkim_signature_headers),
            "dkim_signatures": self.dkim_signature_headers,
            "text_body_preview": self.text_body[:500] if self.text_body else "",
            "urls_count": len(self.urls),
            "urls": self.urls,
            "attachments_count": len(self.attachments),
            "attachments": self.attachments,
            "parse_warnings": self.parse_warnings,
            "is_multipart": self.is_multipart,
        }


def _extract_domain(email_address: str) -> str:
    """Extract domain from an email address in lowercase, stripped of brackets."""
    if not email_address:
        return ""
    addr = email_address.strip("<> \t\r\n")
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return ""


def _parse_received_header(header_val: str) -> Dict[str, Any]:
    """Parse a single Received header to extract hops, relay domains, and IPs."""
    data = {
        "raw": header_val,
        "from_host": "",
        "by_host": "",
        "with_proto": "",
        "timestamp": "",
        "ip": "",
    }
    # Match IP address if present in brackets or parens
    ip_match = re.search(r"\[([0-9a-fA-F:.]+)\]|\b(?:\d{1,3}\.){3}\d{1,3}\b", header_val)
    if ip_match:
        data["ip"] = ip_match.group(1) or ip_match.group(0)

    # Simple regex extractions for RFC 5321 Received syntax
    from_match = re.search(r"\bfrom\s+([^\s;]+)", header_val, re.IGNORECASE)
    if from_match:
        data["from_host"] = from_match.group(1)

    by_match = re.search(r"\bby\s+([^\s;]+)", header_val, re.IGNORECASE)
    if by_match:
        data["by_host"] = by_match.group(1)

    with_match = re.search(r"\bwith\s+([^\s;]+)", header_val, re.IGNORECASE)
    if with_match:
        data["with_proto"] = with_match.group(1)

    if ";" in header_val:
        data["timestamp"] = header_val.split(";")[-1].strip()

    return data


def _parse_received_spf_header(header_val: str) -> Dict[str, Any]:
    """
    Parse a Received-SPF header (RFC 7208 section 9.1).
    Explicitly labeled as receiver-reported delivery evidence.
    """
    data = {
        "raw": header_val,
        "result": "UNKNOWN",
        "comment": "",
        "client_ip": "",
        "envelope_from": "",
        "identity": "",
        "note": "Receiver-reported delivery evidence. Recorded by the receiving MTA during SMTP transmission.",
    }
    cleaned = re.sub(r"\r?\n[ \t]+", " ", header_val.strip())
    # Typically: <result> (<comment>) client-ip=<ip>; envelope-from=<from>; ...
    match = re.match(r"^([a-zA-Z0-9_-]+)\s*(?:\(([^)]*)\))?", cleaned)
    if match:
        data["result"] = match.group(1).upper()
        if match.group(2):
            data["comment"] = match.group(2).strip()

    ip_match = re.search(r"\bclient[-_]ip=[\"']?([0-9a-fA-F:.]+)[\"']?", cleaned, re.IGNORECASE)
    if ip_match:
        data["client_ip"] = ip_match.group(1).strip()
    elif data.get("comment"):
        ip_comment = re.search(r"\bdesignates\s+([0-9a-fA-F:.]+)\s+as", data["comment"], re.IGNORECASE)
        if ip_comment:
            data["client_ip"] = ip_comment.group(1).strip()

    env_match = re.search(r"\b(?:envelope-from|smtp\.mailfrom)=[\"']?([^\s;'\"]+)", cleaned, re.IGNORECASE)
    if env_match:
        data["envelope_from"] = env_match.group(1).strip()
    elif data.get("comment"):
        env_comment = re.search(r"\bdomain of\s+([^\s;:]+)\s+designates", data["comment"], re.IGNORECASE)
        if env_comment:
            data["envelope_from"] = env_comment.group(1).strip()

    return data


def _parse_auth_results_header(header_val: str) -> Dict[str, Any]:
    """
    Parse an Authentication-Results header (RFC 8601 / RFC 7601).
    Explicitly tags this as receiver-reported delivery evidence.
    """
    data = {
        "raw": header_val,
        "authserv_id": "",
        "claims": [],
        "reported_spf": {},
        "reported_dkim": {},
        "reported_dmarc": {},
        "reported_arc": {},
        "note": "Receiver-reported delivery evidence. Recorded by the receiving MTA, distinct from independent offline cryptographic verification.",
    }
    cleaned = re.sub(r"\r?\n[ \t]+", " ", header_val.strip())
    parts = cleaned.split(";", 1)
    if parts:
        data["authserv_id"] = parts[0].strip()

    if len(parts) > 1:
        clauses = parts[1].split(";")
        for clause in clauses:
            clause = clause.strip()
            if not clause:
                continue
            # Look for mechanism=result (comment)
            match = re.match(r"([a-zA-Z0-9_-]+)\s*=\s*([a-zA-Z0-9_-]+)(?:\s*\(([^)]*)\))?", clause, re.IGNORECASE)
            if match:
                mech = match.group(1).upper()
                res = match.group(2).upper()
                comment = match.group(3).strip() if match.group(3) else ""
                claim_item = {
                    "mechanism": mech,
                    "claimed_result": res,
                    "comment": comment,
                    "details": clause,
                }
                data["claims"].append(claim_item)
                if mech == "SPF":
                    data["reported_spf"] = claim_item
                elif mech == "DKIM":
                    data["reported_dkim"] = claim_item
                elif mech == "DMARC":
                    data["reported_dmarc"] = claim_item
                elif mech == "ARC":
                    data["reported_arc"] = claim_item
    return data


def _clean_url(raw_url: str) -> str:
    """Safely sanitize and normalize URL string."""
    url = raw_url.strip("<>\"' \t\r\n")
    while url and url[-1] in ".,;:!?)>'\"]":
        url = url[:-1]
    return url.strip()


def _is_public_form_service(hostname: str, path: str) -> bool:
    """Deterministic check if hostname or path points to a public cloud form service."""
    host = hostname.lower()
    for domain in Config.PUBLIC_FORM_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return True
    if "google.com" in host and "/forms/" in path.lower():
        return True
    return False


def _extract_urls(text_content: str, html_content: str) -> List[Dict[str, Any]]:
    """
    Extract, sanitize, and deduplicate URLs from both text/plain and text/html MIME parts.
    Detects visible-link versus destination mismatches.
    CRITICAL CNS PRINCIPLE: Does NOT automatically visit or fetch extracted URLs.
    """
    extracted_map: Dict[str, Dict[str, Any]] = {}
    url_regex = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]+", re.IGNORECASE)

    # 1. Extract from HTML anchors if present
    if html_content:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            for a in soup.find_all("a", href=True):
                raw_href = a["href"]
                href = _clean_url(raw_href)
                if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    continue

                parsed = urlparse(href)
                hostname = parsed.hostname.lower() if parsed.hostname else ""
                if not hostname:
                    continue

                link_text = a.get_text(strip=True)
                is_mismatched = False
                mismatch_reason = ""

                # Check if visible link text explicitly displays a domain or URL
                # A visible URL/domain never contains whitespace and matches an FQDN or URL pattern
                lt_clean = link_text.strip()
                if lt_clean and not re.search(r"\s", lt_clean):
                    is_url_pattern = bool(re.match(
                        r"^(?:https?://)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?$",
                        lt_clean,
                        re.IGNORECASE
                    ))
                    if is_url_pattern:
                        cleaned_lt = _clean_url(lt_clean)
                        lt_target = cleaned_lt if cleaned_lt.startswith(("http://", "https://")) else f"http://{cleaned_lt}"
                        try:
                            text_parsed = urlparse(lt_target)
                            text_host = text_parsed.hostname.lower() if text_parsed.hostname else ""
                            if text_host and hostname:
                                from analyzers.dmarc_analyzer import get_organizational_domain
                                text_org = get_organizational_domain(text_host)
                                host_org = get_organizational_domain(hostname)
                                if text_org and host_org and text_org != host_org:
                                    is_mismatched = True
                                    mismatch_reason = f"Visible link text displays domain '{text_host}' but points to destination '{hostname}'"
                        except Exception:
                            pass

                is_form = _is_public_form_service(hostname, parsed.path or "")
                url_key = href.rstrip("/")

                extracted_map[url_key] = {
                    "url": href,
                    "hostname": hostname,
                    "scheme": parsed.scheme or "https",
                    "path": parsed.path or "/",
                    "link_text": link_text or href,
                    "is_mismatch": is_mismatched,
                    "mismatch_reason": mismatch_reason,
                    "is_public_form": is_form,
                    "source": "html_anchor",
                }

            # 2. Extract plain text URLs embedded inside HTML markup (excluding <a> tags already processed)
            for a in soup.find_all("a"):
                a.decompose()
            html_text = soup.get_text(separator=" ")
            for match in url_regex.finditer(html_text):
                url = _clean_url(match.group(0))
                url_key = url.rstrip("/")
                if url_key not in extracted_map:
                    parsed = urlparse(url)
                    hostname = parsed.hostname.lower() if parsed.hostname else ""
                    if hostname:
                        extracted_map[url_key] = {
                            "url": url,
                            "hostname": hostname,
                            "scheme": parsed.scheme or "https",
                            "path": parsed.path or "/",
                            "link_text": url,
                            "is_mismatch": False,
                            "mismatch_reason": "",
                            "is_public_form": _is_public_form_service(hostname, parsed.path or ""),
                            "source": "html_text",
                        }
        except Exception:
            pass

    # 3. Extract plain text URLs from text/plain body
    if text_content:
        for match in url_regex.finditer(text_content):
            url = _clean_url(match.group(0))
            url_key = url.rstrip("/")
            if url_key not in extracted_map:
                parsed = urlparse(url)
                hostname = parsed.hostname.lower() if parsed.hostname else ""
                if hostname:
                    extracted_map[url_key] = {
                        "url": url,
                        "hostname": hostname,
                        "scheme": parsed.scheme or "https",
                        "path": parsed.path or "/",
                        "link_text": url,
                        "is_mismatch": False,
                        "mismatch_reason": "",
                        "is_public_form": _is_public_form_service(hostname, parsed.path or ""),
                        "source": "plain_text",
                    }

    return list(extracted_map.values())


def parse_raw_email(raw_input: Any) -> ParsedEmail:
    """
    Safely parse raw bytes or raw string into a structured ParsedEmail object.
    Enforces maximum size limit and handles malformed MIME gracefully.
    """
    result = ParsedEmail()

    if isinstance(raw_input, str):
        raw_bytes = raw_input.encode("utf-8", errors="replace")
    elif isinstance(raw_input, bytes):
        raw_bytes = raw_input
    else:
        result.parse_warnings.append("Invalid input type provided to parser.")
        return result

    if len(raw_bytes) > Config.MAX_CONTENT_LENGTH:
        result.parse_warnings.append(
            f"Input size ({len(raw_bytes)} bytes) exceeds maximum limit ({Config.MAX_CONTENT_LENGTH} bytes)."
        )
        return result

    result.raw_bytes = raw_bytes

    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
    except Exception as e:
        result.parse_warnings.append(f"MIME parsing failed: {str(e)}")
        # Fallback to compat policy
        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
        except Exception as e2:
            result.parse_warnings.append(f"Compat32 fallback failed: {str(e2)}")
            return result

    # Store raw headers
    result.raw_headers = list(msg.items())

    # 1. From Header
    from_hdr = msg.get("From", "")
    result.from_header = str(from_hdr)
    parsed_from_name, parsed_from_addr = parseaddr(result.from_header)
    result.from_name = parsed_from_name
    result.from_address = parsed_from_addr.lower()
    result.from_domain = _extract_domain(result.from_address)

    # 2. Reply-To Header
    reply_to_hdr = msg.get("Reply-To", "")
    result.reply_to_header = str(reply_to_hdr)
    if result.reply_to_header:
        rt_name, rt_addr = parseaddr(result.reply_to_header)
        result.reply_to_name = rt_name
        result.reply_to_address = rt_addr.lower()
        result.reply_to_domain = _extract_domain(result.reply_to_address)

    # 3. Return-Path Header
    ret_path_hdr = msg.get("Return-Path", "")
    result.return_path_header = str(ret_path_hdr)
    if result.return_path_header:
        _, rp_addr = parseaddr(result.return_path_header)
        result.return_path_address = rp_addr.lower()
        result.return_path_domain = _extract_domain(result.return_path_address)

    # 4. Message Metadata
    result.subject = str(msg.get("Subject", "(No Subject)"))
    result.date_raw = str(msg.get("Date", ""))
    result.message_id = str(msg.get("Message-ID", "")).strip("<> ")

    # Recipients
    result.to_addresses = [addr.lower() for _, addr in getaddresses(msg.get_all("To", [])) if addr]
    result.cc_addresses = [addr.lower() for _, addr in getaddresses(msg.get_all("Cc", [])) if addr]

    # 5. Received Headers (in original order)
    received_list = msg.get_all("Received", [])
    for rec in received_list:
        result.received_headers.append(_parse_received_header(str(rec)))

    # 6. Authentication-Results Headers
    auth_results_list = msg.get_all("Authentication-Results", [])
    for ar in auth_results_list:
        result.authentication_results_headers.append(_parse_auth_results_header(str(ar)))

    # 7. Received-SPF Headers
    spf_list = msg.get_all("Received-SPF", [])
    for spf_hdr in spf_list:
        result.received_spf_headers.append(str(spf_hdr))
        result.received_spf_parsed.append(_parse_received_spf_header(str(spf_hdr)))

    # 8. DKIM-Signature Headers
    dkim_list = msg.get_all("DKIM-Signature", [])
    for dkim_hdr in dkim_list:
        result.dkim_signature_headers.append(str(dkim_hdr).strip())

    # 8. MIME Body & Attachments
    result.is_multipart = msg.is_multipart()
    if result.is_multipart:
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            content_type = part.get_content_type()

            # Attachment handling
            filename = part.get_filename()
            if filename or "attachment" in content_disposition.lower():
                fn = filename or "unnamed_attachment"
                payload = part.get_payload(decode=True) or b""
                size = len(payload)
                # Check for executable or dangerous extension
                ext = ("." + fn.split(".")[-1].lower()) if "." in fn else ""
                is_suspicious = ext in Config.DANGEROUS_EXTENSIONS

                result.attachments.append({
                    "filename": fn,
                    "extension": ext,
                    "content_type": content_type,
                    "size_bytes": size,
                    "is_dangerous_extension": is_suspicious,
                })
                continue

            # Body text extraction
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                if payload:
                    text_decoded = payload.decode(charset, errors="replace")
                    if content_type == "text/plain":
                        result.text_body += text_decoded + "\n"
                    elif content_type == "text/html":
                        result.html_body += text_decoded + "\n"
            except Exception as e:
                result.parse_warnings.append(f"Failed decoding body part ({content_type}): {str(e)}")
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            if payload:
                text_decoded = payload.decode(charset, errors="replace")
                if content_type == "text/plain":
                    result.text_body = text_decoded
                elif content_type == "text/html":
                    result.html_body = text_decoded
        except Exception as e:
            result.parse_warnings.append(f"Failed decoding singlepart body: {str(e)}")

    # 9. Extract URLs
    result.urls = _extract_urls(result.text_body, result.html_body)

    return result
