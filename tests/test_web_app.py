"""
End-to-End & Web Application Integration Tests for MailTrust
"""

import io
import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret"
    with app.test_client() as client:
        yield client


def test_dashboard_loads(client):
    """Verify application starts and dashboard loads successfully with modern SaaS UI."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"MailTrust" in response.data
    assert b"Know which emails you can trust." in response.data
    assert b"Educational CNS Scenarios" in response.data


def test_methodology_page_loads(client):
    """Verify CNS methodology reference page loads."""
    response = client.get("/methodology")
    assert response.status_code == 200
    assert b"CNS Security Methodology" in response.data
    assert b"RFC 6376" in response.data


def test_analyze_pasted_raw_email(client):
    """Submit raw email via POST /analyze."""
    raw_email = (
        "From: Alice <alice@example.com>\r\n"
        "To: Bob <bob@example.com>\r\n"
        "Subject: Meeting Update\r\n"
        "\r\n"
        "See you at noon.\r\n"
    )
    response = client.post("/analyze", data={"raw_email_text": raw_email}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Meeting Update" in response.data
    assert b"alice@example.com" in response.data
    assert b"Core Email Authentication Protocols" in response.data


def test_analyze_uploaded_eml_file(client):
    """Submit .eml file upload via POST /analyze."""
    eml_content = b"From: support@service.org\r\nSubject: Invoice #102\r\n\r\nAttached"
    data = {
        "email_file": (io.BytesIO(eml_content), "invoice.eml")
    }
    response = client.post("/analyze", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert response.status_code == 200
    assert b"Invoice #102" in response.data
    assert b"support@service.org" in response.data


def test_load_sample_endpoint(client):
    """Test loading and analyzing a pre-built CNS sample."""
    response = client.get("/sample/valid_dkim_aligned.eml", follow_redirects=True)
    assert response.status_code == 200
    assert b"Monthly Security Audit Notification" in response.data
    assert b"No major issues detected" in response.data or b"AUTHENTICATION VERIFIED" in response.data


def test_api_analyze_json(client):
    """Test JSON REST API /api/analyze endpoint."""
    raw_email = "From: api-test@domain.com\r\nSubject: API Call\r\n\r\nHello API"
    response = client.post(
        "/api/analyze",
        json={"raw_email": raw_email, "client_ip": "1.2.3.4", "envelope_sender": "bounce@domain.com"}
    )
    assert response.status_code == 200
    json_data = response.get_json()
    assert json_data["status"] == "success"
    assert json_data["parsed_email"]["subject"] == "API Call"
    assert "risk_assessment" in json_data
    assert "verdict" in json_data["risk_assessment"]


def test_html_injection_escaping(client):
    """Test that malicious HTML/XSS inside email headers is safely escaped."""
    xss_payload = "<script>alert('XSS-ATTACK')</script>"
    raw_email = f"From: {xss_payload} <attacker@evil.com>\r\nSubject: <img src=x onerror=alert(1)>\r\n\r\nPayload"
    response = client.post("/analyze", data={"raw_email_text": raw_email}, follow_redirects=True)
    assert response.status_code == 200
    # Must NOT contain unescaped executable script tags or img tags
    assert b"<script>alert('XSS-ATTACK')</script>" not in response.data
    assert b"<img src=x onerror=alert(1)>" not in response.data
    assert b"&lt;img src=x onerror=alert(1)&gt;" in response.data


def test_authentication_lab_pages_and_api(client):
    """Test Authentication Lab UI page and cryptographic sign/verify APIs."""
    # 1. Page load
    resp = client.get("/lab")
    assert resp.status_code == 200
    assert b"Interactive DKIM Authentication Lab" in resp.data

    # 2. Keygen API
    resp_key = client.post("/api/lab/generate-key")
    assert resp_key.status_code == 200
    data_key = resp_key.get_json()
    assert data_key["status"] == "success"
    dns_txt = data_key["dns_record"]
    assert "v=DKIM1" in dns_txt

    # 3. Sign API
    sample_text = "From: lab@example.com\r\nSubject: Lab Test\r\n\r\nIntegrity payload."
    resp_sign = client.post("/api/lab/sign", json={
        "raw_message": sample_text,
        "selector": "labkey",
        "domain": "example.com"
    })
    assert resp_sign.status_code == 200
    data_sign = resp_sign.get_json()
    assert "DKIM-Signature:" in data_sign["signed_email"]
    signed_email = data_sign["signed_email"]

    # 4. Verify API (Authentic state)
    resp_verify = client.post("/api/lab/verify", json={
        "message_str": signed_email,
        "selector": "labkey",
        "domain": "example.com",
        "dns_record": dns_txt
    })
    assert resp_verify.status_code == 200
    data_verify = resp_verify.get_json()
    assert data_verify["verification"]["status"] == "PASS"

    # 5. Verify API (Tampered state)
    tampered_email = signed_email.replace("Integrity payload", "TAMPERED PAYLOAD")
    resp_verify_tampered = client.post("/api/lab/verify", json={
        "message_str": tampered_email,
        "selector": "labkey",
        "domain": "example.com",
        "dns_record": dns_txt
    })
    assert resp_verify_tampered.status_code == 200
    data_verify_tampered = resp_verify_tampered.get_json()
    assert data_verify_tampered["verification"]["status"] == "FAIL"


def test_scan_history_page(client):
    """Test Scan History page and clear action."""
    # Initial load (empty)
    resp = client.get("/history")
    assert resp.status_code == 200
    assert b"Session Scan History" in resp.data

    # Analyze an email to populate history
    client.post("/analyze", data={"raw_email_text": "From: a@b.com\r\nSubject: Test\r\n\r\nHello"})
    resp_after = client.get("/history")
    assert b"Test" in resp_after.data

    # Clear history
    resp_clear = client.post("/history/clear", follow_redirects=True)
    assert resp_clear.status_code == 200
    assert b"Scan history cleared" in resp_clear.data
