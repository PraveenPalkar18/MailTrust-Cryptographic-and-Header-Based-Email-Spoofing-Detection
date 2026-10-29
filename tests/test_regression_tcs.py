"""
Regression tests for MailTrust Analyzer using real-world TCS NQT email fixture.
Verifies all 5 defects identified:
1. Verdict & score logic: Never claims 'Cryptographically aligned' without proof;
   distinguishes authentication from phishing; represents PERMERROR, NOT_EVALUABLE, NONE accurately;
   does not treat absence of DMARC as FAIL; does not assign score 0 for unverified emails.
2. Hyperlink extraction: Parses URLs from text and HTML MIME parts, deduplicates,
   identifies hostnames and public form destinations safely, does not auto-visit.
3. Authentication evidence: Displays receiver-provided Authentication-Results as reported context,
   distinguishes from independent reconstruction, independently checks DKIM.
4. Findings engine: Detects brand mismatch (TCS claimed vs inspireleap.in) with balanced explanation;
   detects public form registration lures.
5. Regression test suite on samples/tcs_nqt.eml.
"""

import os
import pytest
from app import app, run_full_security_analysis
from analyzers.email_parser import parse_raw_email
from analyzers.dkim_analyzer import DKIMVerificationResult
from analyzers.spf_analyzer import SPFResult
from analyzers.dmarc_analyzer import DMARCResult
from analyzers.domain_analyzer import analyze_domains
from analyzers.phishing_rules import inspect_phishing_indicators
from analyzers.risk_engine import compute_risk_verdict, RiskAssessmentResult

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
TCS_EML_PATH = os.path.join(SAMPLES_DIR, "tcs_nqt.eml")


@pytest.fixture
def tcs_raw_bytes():
    assert os.path.exists(TCS_EML_PATH), f"Fixture not found at {TCS_EML_PATH}"
    with open(TCS_EML_PATH, "rb") as f:
        return f.read()


def test_tcs_nqt_hyperlink_extraction(tcs_raw_bytes):
    """
    Defect 2: Confirm Google Forms URL is extracted from email body,
    hostname is identified, flagged as public form, and deduplicated.
    """
    parsed = parse_raw_email(tcs_raw_bytes)
    assert len(parsed.urls) >= 1
    
    extracted_urls = [u["url"] for u in parsed.urls]
    assert "https://forms.gle/gHcG8qiGDfLw7PYt7" in extracted_urls

    form_url_info = next(u for u in parsed.urls if "forms.gle" in u["url"])
    assert form_url_info["hostname"] == "forms.gle"
    assert form_url_info["is_public_form"] is True

    # Confirm URLs are deduplicated
    unique_urls = set(extracted_urls)
    assert len(extracted_urls) == len(unique_urls)


def test_tcs_nqt_authentication_states_accuracy(tcs_raw_bytes):
    """
    Defect 1 & 3: DKIM must be PERMERROR (no key in DNS for google._domainkey.inspireleap.in),
    SPF must be PASS (evaluated using connecting client IP 209.85.220.65 extracted from transmission headers),
    and DMARC must be NONE (no policy record published).
    Absence of DMARC must NOT be treated as FAIL.
    """
    analysis = run_full_security_analysis(tcs_raw_bytes)
    dkim = analysis["dkim_result"]
    spf = analysis["spf_result"]
    dmarc = analysis["dmarc_result"]
    risk = analysis["risk_result"]

    # DKIM: Permanent DNS key error
    assert dkim.status == "PERMERROR"
    assert len(dkim.signatures) >= 1
    assert dkim.signatures[0].status == "PERMERROR"

    # SPF: Evaluated using connecting IP from transmission headers
    assert spf.status == "PASS"
    assert spf.client_ip == "209.85.220.65"
    assert spf.domain == "inspireleap.in"
    assert spf.context_source == "RECEIVED_SPF_HEADER"

    # DMARC: Domain publishes no DMARC record -> NONE (not FAIL)
    assert dmarc.status == "NONE"
    assert dmarc.status != "FAIL"

    # Risk result must reflect authentication failure/permerror
    assert risk.is_cryptographically_aligned is False
    assert risk.authentication_status == "PERMERROR"


def test_tcs_nqt_never_says_cryptographically_aligned(tcs_raw_bytes):
    """
    Defect 1: Never label an email 'Cryptographically aligned' unless alignment
    has actually been established. Do not assign risk score of zero.
    """
    analysis = run_full_security_analysis(tcs_raw_bytes)
    risk = analysis["risk_result"]

    assert risk.is_cryptographically_aligned is False
    assert risk.calculated_risk_score > 0
    assert risk.verdict != "AUTHENTICATION VERIFIED"

    # Render results template using Flask test client
    with app.test_client() as client:
        response = client.post("/analyze", data={"raw_email_text": tcs_raw_bytes.decode("utf-8")})
        assert response.status_code == 200
        html = response.data.decode("utf-8")
        
        # Verify "Cryptographically aligned" is NEVER present in the output
        assert "Cryptographically aligned" not in html
        assert "0 risk points" not in html
        assert "0/100" not in html


def test_tcs_nqt_receiver_evidence_separation(tcs_raw_bytes):
    """
    Defect 3: Receiver-provided Authentication-Results must be captured as reported evidence
    from mx.google.com, distinct from offline reconstruction.
    """
    parsed = parse_raw_email(tcs_raw_bytes)
    
    # Must capture Authentication-Results
    assert len(parsed.authentication_results_headers) >= 1
    ar = parsed.authentication_results_headers[0]
    assert "google.com" in ar["authserv_id"].lower()
    
    # Verify reported claims from mx.google.com
    claimed_mechanisms = {c["mechanism"]: c["claimed_result"] for c in ar["claims"]}
    assert "SPF" in claimed_mechanisms
    assert claimed_mechanisms["SPF"] == "PASS"
    assert "DKIM" in claimed_mechanisms
    assert claimed_mechanisms["DKIM"] == "PERMERROR"

    # Must capture Received-SPF header
    assert len(parsed.received_spf_parsed) >= 1
    rec_spf = parsed.received_spf_parsed[0]
    assert rec_spf["result"] == "PASS"
    assert rec_spf["client_ip"] == "209.85.220.65"


def test_tcs_nqt_findings_and_verdict_consistency(tcs_raw_bytes):
    """
    Defect 1 & 4: Detect organization brand mismatch (TCS claimed vs inspireleap.in sender).
    Verdict must be SUSPICIOUS, not INCONCLUSIVE or SAFE.
    """
    analysis = run_full_security_analysis(tcs_raw_bytes)
    domain_res = analysis["domain_result"]
    risk = analysis["risk_result"]

    # Brand claim mismatch must be detected
    assert domain_res.has_brand_mismatch is True
    brand_finding = next((f for f in domain_res.findings if f.category == "Organization Brand Divergence"), None)
    assert brand_finding is not None
    assert "TCS" in brand_finding.title or "TCS" in brand_finding.evidence
    assert brand_finding.severity == "MEDIUM"

    # Public form link must be detected
    assert domain_res.has_public_form_link is True

    # Final verdict must be SUSPICIOUS
    assert risk.verdict == "SUSPICIOUS"
    assert risk.verdict_badge_class == "warning"
    assert risk.calculated_risk_score >= 50

    # Ensure key findings explain specific evidence
    reasons_text = " ".join(risk.verdict_reasons)
    assert "DKIM" in reasons_text
    assert "Brand" in reasons_text or "corporate brand" in reasons_text


def test_unavailable_checks_not_assigned_zero_score():
    """
    Defect 1: When material authentication checks are unavailable (DKIM NONE, SPF NOT_EVALUABLE,
    DMARC NONE), do not assign score zero or declare the email safe.
    """
    raw_unauth = (
        "From: info@example-unknown-domain.org\r\n"
        "To: recipient@local.net\r\n"
        "Subject: Routine meeting agenda notes\r\n"
        "Date: Mon, 26 Oct 2026 10:00:00 +0000\r\n"
        "Message-ID: <unauth-test-123@example-unknown-domain.org>\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Hello team, please review the agenda for our regular weekly meeting.\r\n"
    )
    analysis = run_full_security_analysis(raw_unauth.encode("utf-8"))
    risk = analysis["risk_result"]

    # Verdict must be INCONCLUSIVE
    assert risk.verdict == "INCONCLUSIVE"
    assert risk.is_cryptographically_aligned is False
    # Score must NOT be 0 when checks are unavailable
    assert risk.calculated_risk_score > 0
    assert risk.calculated_risk_score == 15
    assert any("Unauthenticated Message Exposure" in b["factor"] for b in risk.score_breakdown)
