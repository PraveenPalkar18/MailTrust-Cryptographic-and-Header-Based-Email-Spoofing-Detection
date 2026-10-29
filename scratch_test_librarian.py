from analyzers.email_parser import parse_raw_email
from analyzers.dkim_analyzer import DKIMVerificationResult, DKIMSignatureResult
from analyzers.spf_analyzer import SPFResult
from analyzers.dmarc_analyzer import DMARCResult
from analyzers.domain_analyzer import analyze_domains
from analyzers.phishing_rules import inspect_phishing_indicators
from analyzers.risk_engine import compute_risk_verdict

raw_email = (
    "From: Librarian MSS <librarian.mss@kletech.ac.in>\r\n"
    "To: student@kletech.ac.in\r\n"
    "Subject: News paper Clippings for the Date: 29-10-2026\r\n"
    "Date: Thu, 29 Oct 2026 10:47:48 -0500\r\n"
    "Message-ID: <lib-123@kletech.ac.in>\r\n"
    "Content-Type: text/html; charset=utf-8\r\n\r\n"
    "<html><body><p>Dear students, please find today's newspaper clippings:</p>"
    "<a href=\"https://drive.google.com/file/d/123/view\">Times of India (29.10.2026)</a>"
    "<p>News on Tata and Google updates in education.</p>"
    "<p>Regards,<br>MSS Library Team</p></body></html>"
).encode("utf-8")

parsed = parse_raw_email(raw_email)
print("Parsed urls:", parsed.urls)

dkim_res = DKIMVerificationResult()
dkim_res.status = "PASS"
dkim_res.primary_domain = "kletech.ac.in"
sig = DKIMSignatureResult()
sig.status = "PASS"
sig.signing_domain = "kletech.ac.in"
dkim_res.signatures.append(sig)

spf_res = SPFResult()
spf_res.status = "PASS"
spf_res.domain = "kletech.ac.in"
spf_res.client_ip = "209.85.220.69"

dmarc_res = DMARCResult()
dmarc_res.status = "PASS"
dmarc_res.header_from_domain = "kletech.ac.in"
dmarc_res.dkim_aligned = True
dmarc_res.spf_aligned = True

domain_res = analyze_domains(parsed, dkim_signing_domain="kletech.ac.in")
print("Domain findings:", [f.title for f in domain_res.findings])
print("has_url_mismatch:", domain_res.has_url_mismatch)
print("has_brand_mismatch:", domain_res.has_brand_mismatch)

phish_res = inspect_phishing_indicators(parsed)

verdict = compute_risk_verdict(parsed, dkim_res, spf_res, dmarc_res, domain_res, phish_res)
print("VERDICT:", verdict.verdict)
print("SCORE:", verdict.calculated_risk_score)
print("BADGE:", verdict.verdict_badge_class)
print("REASONS:", verdict.verdict_reasons)

