"""
Unit Tests for MailTrust Email Parser Module
"""

import pytest
from analyzers.email_parser import parse_raw_email, ParsedEmail
from config import Config


def test_parse_valid_email():
    raw_email = (
        "From: Alice Smith <alice@example.com>\r\n"
        "To: Bob Jones <bob@recipient.org>\r\n"
        "Subject: CNS Security Meeting\r\n"
        "Date: Mon, 26 Oct 2026 10:00:00 +0000\r\n"
        "Message-ID: <msg-12345@example.com>\r\n"
        "Reply-To: alice-replies@example.com\r\n"
        "Return-Path: <bounces@example.com>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Please visit https://example.com/meeting for the agenda.\r\n"
    )
    parsed = parse_raw_email(raw_email)
    assert parsed.from_address == "alice@example.com"
    assert parsed.from_name == "Alice Smith"
    assert parsed.from_domain == "example.com"
    assert parsed.reply_to_address == "alice-replies@example.com"
    assert parsed.reply_to_domain == "example.com"
    assert parsed.return_path_address == "bounces@example.com"
    assert parsed.subject == "CNS Security Meeting"
    assert parsed.message_id == "msg-12345@example.com"
    assert len(parsed.urls) == 1
    assert parsed.urls[0]["hostname"] == "example.com"


def test_parse_missing_and_malformed_headers():
    # Email with no Subject, no Message-ID, malformed From
    raw_email = "From: broken-format-without-at\r\n\r\nHello"
    parsed = parse_raw_email(raw_email)
    assert parsed.from_address == "broken-format-without-at"
    assert parsed.from_domain == ""
    assert parsed.subject == "(No Subject)"
    assert parsed.message_id == ""


def test_parse_html_link_mismatch():
    raw_email = (
        "From: alerts@bank.com\r\n"
        "Subject: Account Notice\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "\r\n"
        "<html><body>"
        "<a href=\"http://evil-server.net/login\">https://bank.com/signin</a>"
        "</body></html>"
    )
    parsed = parse_raw_email(raw_email)
    assert len(parsed.urls) == 1
    url_info = parsed.urls[0]
    assert url_info["is_mismatch"] is True
    assert "evil-server.net" in url_info["mismatch_reason"]
    assert "bank.com" in url_info["mismatch_reason"]


def test_parse_dangerous_attachment():
    raw_email = (
        "From: boss@corp.com\r\n"
        "Subject: Urgent Attachment\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n"
        "\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "See attached report.\r\n"
        "--BOUNDARY\r\n"
        "Content-Type: application/octet-stream; name=\"Invoice.pdf.exe\"\r\n"
        "Content-Disposition: attachment; filename=\"Invoice.pdf.exe\"\r\n"
        "\r\n"
        "MZ-fake-binary\r\n"
        "--BOUNDARY--\r\n"
    )
    parsed = parse_raw_email(raw_email)
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att["filename"] == "Invoice.pdf.exe"
    assert att["is_dangerous_extension"] is True


def test_parse_oversized_input_rejection():
    # Exceeding MAX_CONTENT_LENGTH
    oversized_data = b"From: a@b.com\r\n\r\n" + b"X" * (Config.MAX_CONTENT_LENGTH + 50)
    parsed = parse_raw_email(oversized_data)
    assert any("exceeds maximum limit" in w for w in parsed.parse_warnings)
