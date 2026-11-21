"""
Unit Tests for Static Attachment Inspection and Header Provenance Analysis.
"""

import io
import zipfile
import pytest
from analyzers.attachment_inspector import inspect_attachment, inspect_all_attachments
from analyzers.header_provenance import analyze_header_provenance


def test_attachment_dangerous_extension():
    """Verify that dangerous executable extensions are flagged."""
    att = inspect_attachment("payload.exe", b"fake executable payload")
    assert att.is_dangerous is True
    assert any("Dangerous Executable" in f["title"] for f in att.findings)


def test_attachment_double_extension():
    """Verify that disguised double extensions (e.g. invoice.pdf.vbs) are flagged."""
    att = inspect_attachment("invoice.pdf.vbs", b"' VBS script content")
    assert att.has_double_extension is True
    assert att.is_dangerous is True
    assert any("Double Extension" in f["title"] for f in att.findings)


def test_attachment_magic_byte_mismatch():
    """Verify detection when a Windows PE executable (MZ header) is disguised with a benign extension."""
    # File named invoice.pdf with Windows MZ header
    pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
    att = inspect_attachment("invoice.pdf", pe_bytes)
    assert att.has_magic_mismatch is True
    assert att.is_dangerous is True
    assert any("Disguised" in f["title"] for f in att.findings)


def test_attachment_embedded_vba_macro_detection():
    """Verify detection of embedded vbaProject.bin in OOXML Office document."""
    # Construct synthetic ZIP containing word/vbaProject.bin
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types></Types>")
        zf.writestr("word/vbaProject.bin", b"VBA MACRO BYTECODE")
    docx_bytes = buf.getvalue()

    att = inspect_attachment("resume.docx", docx_bytes)
    assert att.has_embedded_macro is True
    assert att.is_dangerous is True
    assert any("Embedded VBA Macro" in f["title"] for f in att.findings)


def test_header_provenance_reply_to_mismatch():
    """Verify detection of Reply-To divergence from visible From domain."""
    headers = [
        ("From", "CEO <ceo@legit-company.com>"),
        ("Reply-To", "attacker@evil-domain.com"),
        ("Subject", "Urgent Wire Transfer"),
    ]
    provenance = analyze_header_provenance(headers)
    assert provenance.has_anomalies is True
    assert any("Reply-To Domain Mismatch" in f["title"] for f in provenance.findings)


def test_header_provenance_multi_hop_auth_results():
    """Verify extraction and order preservation of multi-hop Authentication-Results."""
    headers = [
        ("Authentication-Results", "mx.google.com; dkim=pass header.i=@example.com; spf=pass"),
        ("Authentication-Results", "internal-mta.corp.com; dkim=pass"),
        ("From", "alice@example.com"),
    ]
    provenance = analyze_header_provenance(headers)
    assert provenance.auth_results_count == 2
    assert provenance.authserv_ids == ["mx.google.com", "internal-mta.corp.com"]
    assert provenance.auth_results_chain[0]["is_topmost"] is True
