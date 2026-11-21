"""
MailTrust Static Attachment Inspector Module
Performs pure static forensic analysis of email attachments:
- Cryptographic SHA-256 fingerprinting
- Magic byte signature vs file extension validation
- Double-extension obfuscation detection
- Embedded OOXML VBA macro detection (vbaProject.bin)
"""

import hashlib
import io
import os
import re
import zipfile
from typing import Dict, List, Any, Optional

from config import Config

# Magic Byte Signatures for Common Formats
MAGIC_SIGNATURES = [
    (b"MZ", "Executable (PE / Windows Executable)", {".exe", ".dll", ".scr", ".sys", ".cpl", ".ocx"}),
    (b"%PDF", "Adobe Portable Document Format (PDF)", {".pdf"}),
    (b"PK\x03\x04", "ZIP / OOXML Archive", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}),
    (b"Rar!\x1a\x07", "RAR Archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", {".7z"}),
    (b"\x89PNG\r\n\x1a\n", "PNG Image", {".png"}),
    (b"\xff\xd8\xff", "JPEG Image", {".jpg", ".jpeg"}),
    (b"GIF87a", "GIF Image", {".gif"}),
    (b"GIF89a", "GIF Image", {".gif"}),
]

DANGEROUS_EXTENSIONS = Config.DANGEROUS_EXTENSIONS


class InspectedAttachment:
    """Forensic static analysis record for a single attachment."""

    def __init__(self, filename: str, size: int, content_bytes: bytes):
        self.filename: str = filename or "unnamed_attachment"
        self.size: int = size
        self.sha256: str = hashlib.sha256(content_bytes).hexdigest()
        self.magic_detected_type: str = "Unknown / Binary"
        self.extension: str = os.path.splitext(self.filename)[1].lower()
        self.is_dangerous: bool = False
        self.has_double_extension: bool = False
        self.has_magic_mismatch: bool = False
        self.has_embedded_macro: bool = False
        self.findings: List[Dict[str, str]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "size": self.size,
            "sha256": self.sha256,
            "extension": self.extension,
            "magic_detected_type": self.magic_detected_type,
            "is_dangerous": self.is_dangerous,
            "has_double_extension": self.has_double_extension,
            "has_magic_mismatch": self.has_magic_mismatch,
            "has_embedded_macro": self.has_embedded_macro,
            "findings": self.findings,
        }


def _check_double_extension(filename: str) -> bool:
    """Detect camouflage extensions such as invoice.pdf.exe or statement.xlsx.vbs."""
    clean = filename.strip().lower()
    # Check if there is an extension like .pdf, .docx, .xlsx followed by a dangerous extension
    pattern = r"\.(pdf|docx|xlsx|pptx|txt|jpg|png|csv)\.(exe|vbs|bat|cmd|ps1|scr|js|msi|hta|cpl)$"
    return bool(re.search(pattern, clean))


def _check_embedded_macros(content_bytes: bytes) -> bool:
    """Check if a ZIP/OOXML archive contains a VBA macro binary (vbaProject.bin)."""
    if not content_bytes.startswith(b"PK\x03\x04"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(content_bytes), "r") as zf:
            for name in zf.namelist():
                name_low = name.lower()
                if "vbaproject.bin" in name_low or "vba" in name_low:
                    return True
    except Exception:
        pass
    return False


def inspect_attachment(filename: str, content_bytes: bytes) -> InspectedAttachment:
    """Forensically inspect an individual attachment."""
    size = len(content_bytes)
    att = InspectedAttachment(filename, size, content_bytes)

    # 1. Dangerous extension check
    if att.extension in DANGEROUS_EXTENSIONS:
        att.is_dangerous = True
        att.findings.append({
            "severity": "CRITICAL",
            "title": "Dangerous Executable / Script Extension",
            "details": f"Attachment has high-risk extension '{att.extension}'. Executable payloads in email present high risk of malware execution."
        })

    # 2. Double extension detection
    if _check_double_extension(att.filename):
        att.has_double_extension = True
        att.is_dangerous = True
        att.findings.append({
            "severity": "CRITICAL",
            "title": "Deceptive Double Extension Detected",
            "details": f"Filename '{att.filename}' mimics a benign document while hiding an executable script extension."
        })

    # 3. Magic Byte Analysis
    detected_type = None
    expected_exts = set()
    for sig, desc, exts in MAGIC_SIGNATURES:
        if content_bytes.startswith(sig):
            detected_type = desc
            expected_exts = exts
            break

    if detected_type:
        att.magic_detected_type = detected_type
        # If magic byte indicates PE executable, but extension is something else (like .pdf or .doc)
        if detected_type.startswith("Executable") and att.extension not in expected_exts:
            att.has_magic_mismatch = True
            att.is_dangerous = True
            att.findings.append({
                "severity": "CRITICAL",
                "title": "Executable Disguised as Non-Executable File",
                "details": f"File extension is '{att.extension}', but magic bytes reveal a Windows Executable (PE MZ header)!"
            })
    else:
        att.magic_detected_type = "Generic / Text / Unknown"

    # 4. Embedded Macro Detection in Office Documents
    if att.extension in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".zip"}:
        if _check_embedded_macros(content_bytes):
            att.has_embedded_macro = True
            att.is_dangerous = True
            att.findings.append({
                "severity": "HIGH",
                "title": "Embedded VBA Macro Project Detected",
                "details": "Office document contains 'vbaProject.bin'. Weaponized macros are heavily utilized in phishing campaigns for initial access."
            })

    return att


def inspect_all_attachments(attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Inspect all parsed attachments and return enriched forensic representations."""
    results = []
    for a in attachments:
        filename = a.get("filename", "")
        # Get raw bytes or base64 or empty
        raw = a.get("content", b"")
        if isinstance(raw, str):
            try:
                raw = base64.b64decode(raw)
            except Exception:
                raw = raw.encode("utf-8")
        elif not isinstance(raw, bytes):
            raw = b""

        inspected = inspect_attachment(filename, raw)
        # Merge with existing parsed attachment attributes for full backward compatibility
        res = dict(a)
        res.update(inspected.to_dict())
        results.append(res)
    return results
