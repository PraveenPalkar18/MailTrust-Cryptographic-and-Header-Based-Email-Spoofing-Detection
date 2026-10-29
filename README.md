# MailTrust: Cryptographic and Header-Based Email Spoofing Detection

**Domain:** Cryptography and Network Security (CNS)  
**Core Technologies:** Python 3.12, Flask, RFC 6376 (DKIM), RFC 7208 (SPF), RFC 7489 (DMARC), Cryptography (RSA/SHA-256), DNS, Bootstrap 5  
**Design Constraint:** Pure Deterministic CNS Rules — **Zero AI, Zero Machine Learning, Zero LLMs, Zero Fabricated Results**

---

## 1. Executive Summary & CNS Problem Statement

Email remains the primary vector for cyberattacks, responsible for over 90% of organizational breaches via business email compromise (BEC), phishing, and display spoofing. The original Simple Mail Transfer Protocol (SMTP, RFC 821/5321) was designed in 1982 without built-in security, authentication, or origin integrity. Anyone connecting to an open mail relay could inject arbitrary `From:` headers claiming to be anyone else.

To counter these vulnerabilities, the cryptography and network security community developed three complementary protocol standards:
1. **DKIM (RFC 6376):** Asymmetric public-key digital signatures (RSA/Ed25519 + SHA-256) verifying payload and header integrity.
2. **SPF (RFC 7208):** DNS-based authorization establishing which mail server IP addresses are permitted to transmit envelope mail (`MAIL FROM`).
3. **DMARC (RFC 7489):** Policy alignment binding technical envelope authentication (SPF/DKIM) directly to the end-user visible `From:` header.

**MailTrust** is a cybersecurity tool that performs true cryptographic verification, DNS-based policy evaluation, domain homoglyph detection, and transparent heuristic auditing. It provides an explainable security analysis without relying on probabilistic or black-box AI models.

---

## 2. Core CNS Conceptual Distinction

A foundational principle of MailTrust is explaining the vital distinction between three layers of email security:

```
+-----------------------------------------------------------------------------------+
| 1. Cryptographic Verification (DKIM)                                              |
|    - Mathematical integrity (SHA-256 body hash) & non-repudiation (RSA signature) |
|    - PROVES: The holder of the private key for domain 'd=' signed the message.    |
|    - DOES NOT PROVE: The sender is benevolent, nor that From equals signing domain.|
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 2. Sender Authentication & Domain Alignment (SPF & DMARC)                         |
|    - Network-level IP authorization (SPF) + Strict/Relaxed Domain Alignment (DMARC)|
|    - PROVES: The visible RFC 5322 From header is authorized by the domain holder. |
|    - DOES NOT PROVE: The message content is safe or free of social engineering.   |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 3. Heuristic Phishing & Lookalike Detection (Domain & Content Heuristics)         |
|    - Deterministic checks for homoglyphs, Punycode, display-name spoofing, URLs.  |
|    - PROVES: Identifies adversarial techniques that exploit human visual trust.   |
+-----------------------------------------------------------------------------------+
```

---

## 3. CNS Concepts Mapping Table

| Academic CNS Topic | Internet Standard / Primitive | Implementation in MailTrust | Module |
| :--- | :--- | :--- | :--- |
| **Asymmetric Digital Signatures** | RSA-SHA256, Ed25519 | Cryptographic verification of DKIM signature headers via `dkimpy` | `analyzers/dkim_analyzer.py` |
| **Cryptographic Hashing** | SHA-256, Canonicalization (`relaxed`/`simple`) | Verification of `bh=` body hash digest against computed payload hash | `analyzers/dkim_analyzer.py` |
| **Public-Key Distribution** | DNS TXT Resource Records | Dynamic DNS queries resolving public keys at `selector._domainkey.domain` | `analyzers/dkim_analyzer.py` |
| **Network IP Authorization** | RFC 7208 (SPF) | Evaluation of IPv4/IPv6 CIDR subnets, `a`, `mx`, `include`, and `all` | `analyzers/spf_analyzer.py` |
| **DNS Lookup & Recursion Limits** | RFC 7208 Section 4.6.4 | Enforces maximum 10 DNS queries; detects circular include recursion loops | `analyzers/spf_analyzer.py` |
| **Domain Identity Alignment** | RFC 7489 (DMARC) | Strict (`s`) and relaxed (`r`) organizational domain matching | `analyzers/dmarc_analyzer.py` |
| **Public Suffix List (PSL)** | Mozilla PSL / ICANN Root | Organizational domain extraction (e.g. `sub.corp.co.uk` &rarr; `corp.co.uk`) | `analyzers/dmarc_analyzer.py` |
| **Visual Homoglyph Spoofing** | IDN Punycode (RFC 3492), Unicode NFKC | Detection of `xn--` encoding and mixed Cyrillic/Greek/Latin scripts | `analyzers/domain_analyzer.py` |
| **Typosquatting & Confusables** | Levenshtein Distance & Confusable Normalization | Edit-distance checks (distance=1) against high-value target brand database | `analyzers/domain_analyzer.py` |
| **Display-Name Impersonation** | RFC 5322 Parsing | Cross-referencing display name claims against actual sending domain | `analyzers/domain_analyzer.py` |
| **Hyperlink Anchor Divergence** | HTML5 / URI Parsing | Detecting mismatches between visual anchor text and true destination URI | `analyzers/email_parser.py` |

---

## 4. Threat Model & Defensive Boundaries

### In-Scope Adversary Threats
1. **Direct Header Forgery:** Adversary injects `From: ceo@company.com` using an unauthenticated mail relay.
   - *Mitigation:* DMARC alignment failure and lack of valid DKIM signature.
2. **In-Transit Payload Tampering:** Adversary intercepts an email and alters bank details or destination URLs.
   - *Mitigation:* DKIM SHA-256 body hash (`bh=`) mismatch causes cryptographic verification `FAIL`.
3. **Third-Party Signature Evasion:** Adversary signs with their own valid key on `attacker.com` while forging `victim.com` in `From:`.
   - *Mitigation:* DMARC flags unaligned signing domain (`d != From`).
4. **Relay IP Unauthorized Delivery:** Adversary attempts to send through unauthorized network hops.
   - *Mitigation:* SPF evaluation returns `FAIL` or `SOFTFAIL`.
5. **Homoglyph & Punycode Phishing:** Adversary registers `pаypal.com` (with Cyrillic 'а') or `paypa1.com`.
   - *Mitigation:* Mixed-script detector and confusable normalization trigger `HIGH RISK`.
6. **Display-Name Camouflage:** Adversary sends from `attacker@random.com` with display name `"Microsoft Security Team"`.
   - *Mitigation:* Display name cross-check alerts recipient to brand impersonation.
7. **Malware Delivery:** Executable attachments disguised as documents (e.g. `Invoice.pdf.exe`).
   - *Mitigation:* Static MIME parser flags dangerous executable extensions.

### Known Limitations & Out-of-Scope Scenarios
- **Legitimate Mailing List Breakage:** Discussion lists and mailing relays frequently modify message bodies (adding footers) or alter subjects (`[Mailing-List]`), which cryptographically breaks DKIM body hashes.
- **Compromised Valid Accounts:** If an adversary compromises genuine credentials and sends mail through the legitimate server, SPF, DKIM, and DMARC will all pass legitimately. MailTrust alerts users that authentication does not guarantee safety.
- **Offline Static `.eml` Context:** A static `.eml` file does not carry guaranteed authentic SMTP connection parameters. MailTrust honestly reports SPF as `NOT EVALUABLE` unless the user provides verified SMTP context.

---

## 5. System Architecture

```
MailTrust/
├── app.py                      # Flask Application Controller & Routing
├── config.py                   # CNS Security Constants, DNS Settings & Brand Database
├── requirements.txt            # Pinned Dependency Declarations
├── README.md                   # Complete Documentation & Demonstration Guide
├── analyzers/                  # Modular Security Analyzers
│   ├── __init__.py             # Public Package Exports
│   ├── email_parser.py         # MIME Structure, RFC 5322 Parsing & URL Extractor
│   ├── dkim_analyzer.py        # Asymmetric Cryptographic DKIM Verification (RFC 6376)
│   ├── spf_analyzer.py         # Sender Policy Framework Evaluation (RFC 7208)
│   ├── dmarc_analyzer.py       # Domain Alignment & Policy Disposition (RFC 7489)
│   ├── domain_analyzer.py      # Homoglyphs, Punycode, Typosquatting & Display Spoofing
│   ├── phishing_rules.py       # Deterministic Keyword & Indicator Rules (No AI/ML)
│   └── risk_engine.py          # Transparent Explainable Risk Assessment Engine
├── templates/                  # Frontend HTML5 Templates (Bootstrap 5 Dark Mode)
│   ├── base.html               # Base Cyber Layout, Navbar & Security Disclaimer
│   ├── index.html              # Dashboard with Drag-and-Drop & Sample Loader
│   ├── results.html            # Forensic Audit Report & Evidence Tabs
│   └── methodology.html        # Comprehensive Academic Reference & Threat Model
├── static/
│   ├── css/style.css           # Cybersecurity Dark Theme Stylesheet
│   └── js/app.js               # File Ingestion & Drag-and-Drop Script
├── tests/                      # Automated Test Suite (43 Unit & Integration Tests)
│   ├── test_email_parser.py    # MIME Parser & Sanitization Tests
│   ├── test_dkim.py            # Cryptographic RSA Key Verification & Tampering Tests
│   ├── test_spf.py             # SPF Mechanism, Lookup Limits & Qualifier Tests
│   ├── test_dmarc.py           # DMARC Strict/Relaxed Alignment & Policy Tests
│   ├── test_domains.py         # Homoglyph, Punycode & Lookalike Tests
│   ├── test_risk_engine.py     # All 4 Verdicts Verification Tests
│   └── test_web_app.py         # End-to-End Web App & XSS Injection Tests
└── samples/                    # Educational CNS Test Emails
    ├── generate_samples.py     # Reproducible RSA Key & Signature Sample Generator
    ├── valid_dkim_aligned.eml  # Authentic 2048-bit RSA Signed Message
    ├── tampered_dkim.eml       # Modified Payload Demonstrating Hash Mismatch
    ├── display_name_spoof.eml  # Brand Impersonation & Link Mismatch
    ├── unaligned_dkim_dmarc_fail.eml # Third-Party Key Alignment Failure
    ├── phishing_malware_lure.eml     # Typosquatted Domain with .exe Attachment
    ├── no_auth_inconclusive.eml      # Unauthenticated Legacy Message
    └── README.md               # Catalog of Test Samples
```

---

## 6. Installation & Launch Instructions (Windows 11)

### Prerequisites
- Python 3.11 or 3.12 installed on Windows.
- Windows PowerShell.

### Step 1: Open PowerShell and Navigate to MailTrust Directory
```powershell
cd "e:\VII'\CNS\MailTrust"
```

### Step 2: Create and Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Run Automated Tests
```powershell
pytest -v
```
*Expected result: 43 passed in ~3.2 seconds.*

### Step 5: Start the MailTrust Web Application
```powershell
python app.py
```

### Step 6: Access the Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 7. Automated Test Report

Execution run verified with `pytest`:
```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.7.0
rootdir: E:\VII'\CNS\MailTrust
collected 43 items

tests/test_dkim.py::test_dkim_valid_signature_passes PASSED              [  2%]
tests/test_dkim.py::test_dkim_tampered_body_fails PASSED                 [  4%]
tests/test_dkim.py::test_dkim_incorrect_public_key_fails PASSED          [  6%]
tests/test_dkim.py::test_dkim_missing_dns_key_reported PASSED            [  9%]
tests/test_dkim.py::test_dkim_temporary_dns_error PASSED                 [ 11%]
tests/test_dkim.py::test_dkim_no_signature PASSED                        [ 13%]
tests/test_dmarc.py::test_organizational_domain_extraction PASSED        [ 16%]
tests/test_dmarc.py::test_dmarc_pass_via_aligned_dkim PASSED             [ 18%]
tests/test_dmarc.py::test_dmarc_strict_dkim_alignment_failure PASSED     [ 20%]
tests/test_dmarc.py::test_dmarc_unaligned_third_party_dkim_fails PASSED  [ 23%]
tests/test_dmarc.py::test_dmarc_subdomain_inherits_org_policy PASSED     [ 25%]
tests/test_dmarc.py::test_dmarc_no_policy_returns_none PASSED            [ 27%]
tests/test_domains.py::test_display_name_spoofing PASSED                 [ 30%]
tests/test_domains.py::test_character_substitution_typosquatting PASSED  [ 32%]
tests/test_domains.py::test_levenshtein_distance_typosquatting PASSED    [ 34%]
tests/test_domains.py::test_punycode_idn_detection PASSED                [ 37%]
tests/test_domains.py::test_misleading_subdomain PASSED                  [ 39%]
tests/test_domains.py::test_phishing_rules_credential_and_crypto PASSED  [ 41%]
tests/test_email_parser.py::test_parse_valid_email PASSED                [ 44%]
tests/test_email_parser.py::test_parse_missing_and_malformed_headers PASSED [ 46%]
tests/test_email_parser.py::test_parse_html_link_mismatch PASSED         [ 48%]
tests/test_email_parser.py::test_parse_dangerous_attachment PASSED       [ 51%]
tests/test_email_parser.py::test_parse_oversized_input_rejection PASSED  [ 53%]
tests/test_risk_engine.py::test_verdict_authentication_verified PASSED   [ 55%]
tests/test_risk_engine.py::test_verdict_high_risk_on_crypto_fail PASSED  [ 58%]
tests/test_risk_engine.py::test_verdict_high_risk_on_dmarc_rejection PASSED [ 60%]
tests/test_risk_engine.py::test_verdict_suspicious_on_display_spoof PASSED [ 62%]
tests/test_risk_engine.py::test_verdict_inconclusive_on_missing_auth PASSED [ 65%]
tests/test_spf.py::test_spf_not_evaluable_when_context_missing PASSED    [ 67%]
tests/test_spf.py::test_spf_ip4_pass PASSED                              [ 69%]
tests/test_spf.py::test_spf_explicit_fail PASSED                         [ 72%]
tests/test_spf.py::test_spf_softfail PASSED                              [ 74%]
tests/test_spf.py::test_spf_include_mechanism PASSED                     [ 76%]
tests/test_spf.py::test_spf_dns_lookup_limit_exceeded PASSED             [ 75%]
tests/test_spf.py::test_spf_multiple_records_permerror PASSED            [ 77%]
tests/test_spf.py::test_spf_no_record_none PASSED                        [ 80%]
tests/test_web_app.py::test_dashboard_loads PASSED                       [ 82%]
tests/test_web_app.py::test_methodology_page_loads PASSED                [ 84%]
tests/test_web_app.py::test_analyze_pasted_raw_email PASSED              [ 86%]
tests/test_web_app.py::test_analyze_uploaded_eml_file PASSED             [ 88%]
tests/test_web_app.py::test_load_sample_endpoint PASSED                  [ 91%]
tests/test_web_app.py::test_api_analyze_json PASSED                      [ 93%]
tests/test_web_app.py::test_html_injection_escaping PASSED               [ 95%]
tests/test_web_app.py::test_authentication_lab_pages_and_api PASSED      [ 97%]
tests/test_web_app.py::test_scan_history_page PASSED                     [100%]

============================= 45 passed in 3.24s ==============================
```

---

## 8. Academic Demonstration Walkthrough

When presenting this project for an evaluation:

1. **Demonstration of Plain-English Security SaaS UI:**
   - Open `http://127.0.0.1:5000`. Show the clean, accessible SaaS layout, zero clutter, and clear hero "Know which emails you can trust."
   - Click "Where do I find email source?" to show export instructions for Gmail, Outlook, and Apple Mail.

2. **Demonstration of Cryptographic Authenticity:**
   - From the Dashboard, click **Sample 1 ("Authentic RSA Signed Email")**.
   - Show the evaluator:
     - Clear overall verdict: **No major issues detected** with risk score `0/100`.
     - Plain-English cards: DKIM Passed, DMARC Passed.
     - "View technical details" button toggles public key DNS record, algorithm, and selectors without cluttering the screen.

3. **Interactive Authentication Lab (`/lab`):**
   - Click **Authentication Lab** in the navigation bar.
   - Step 1: Show the test email payload and the active 2048-bit RSA key DNS record.
   - Step 2: Click **Sign with Private Key** &rarr; Generates real DKIM signature header with calculated SHA-256 body hash (`bh=`).
   - Step 3: Click **Verify Authentic Signature** &rarr; Shows real `PASS — Cryptographic Integrity Confirmed`.
   - Step 4: Click **Tamper Payload ($10k -> $90k)** &rarr; alters message body text without re-signing.
   - Step 5: Click **Verify Tampered Message** &rarr; Shows real `FAIL — Cryptographic Verification Failed` (body hash mismatch).

4. **Demonstration of Scan History:**
   - Click **Scan History** (`/history`) to inspect past evaluations with search and verdict filtering.

5. **Demonstration of Cryptographic Tampering Detection:**
   - Click **Sample 2 ("Tampered DKIM Signature")** &rarr; Observe `High risk email` verdict.

6. **Demonstration of DMARC Alignment Failure (Third-Party Signing):**
   - Click **Sample 4 ("Third-Party DKIM (DMARC Mismatch)")** &rarr; Shows DKIM passing for attacker domain while failing DMARC alignment against the visible `From:` header.

7. **Demonstration of Ethical Reporting (Inconclusive vs. Fake Results):**
   - Click **Sample 6 ("Legacy Unauthenticated Email")** &rarr; Demonstrates that MailTrust reports `Inconclusive` instead of fabricating simulated outcomes.
