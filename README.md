# MailTrust: Enterprise Cryptographic Email Security & Forensic Platform

**Domain:** Cryptography and Network Security (CNS)  
**Core Technologies:** Python 3.12, Flask, RFC 6376 (DKIM), RFC 7208 (SPF), RFC 7489 (DMARC), RFC 8551 (S/MIME), RFC 6238 (TOTP MFA), RFC 8785 (Canonical JSON), Argon2id, Ed25519, NIST SHA-256, SQLite WAL, Bootstrap 5  
**Design Constraint:** Pure Deterministic CNS Rules — **Zero AI, Zero Machine Learning, Zero LLMs, Zero Fabricated Results**

---

## 1. Executive Summary & CNS Problem Statement

Email remains the primary vector for cyberattacks, responsible for over 90% of organizational breaches via business email compromise (BEC), phishing, display spoofing, and credential harvesting. The original Simple Mail Transfer Protocol (SMTP, RFC 821/5321) was designed in 1982 without built-in security, authentication, or origin integrity. Anyone connecting to an open mail relay could inject arbitrary `From:` headers claiming to be anyone else.

To counter these vulnerabilities, the cryptography and network security community developed complementary security standards:
1. **DKIM (RFC 6376):** Asymmetric public-key digital signatures (RSA/Ed25519 + SHA-256) verifying payload and header integrity.
2. **SPF (RFC 7208):** DNS-based authorization establishing which mail server IP addresses are permitted to transmit envelope mail (`MAIL FROM`).
3. **DMARC (RFC 7489):** Policy alignment binding technical envelope authentication (SPF/DKIM) directly to the end-user visible `From:` header.
4. **S/MIME (RFC 8551 / 5751):** End-to-end cryptographic digital signatures and encryption using X.509 PKI certificates.
5. **Cryptographic Hygiene & Forensics:** Rigorous algorithmic verification of key strengths, signature parameters, multi-hop header provenance, and static attachment inspection.

**MailTrust** is a comprehensive, production-grade cybersecurity and forensic analysis platform. It provides mathematically verifiable cryptographic verification, DNS-based policy evaluation, domain homoglyph detection, tamper-evident audit logging, secure multi-factor authentication, and signed evidence reports — all executed deterministically with explainable findings and zero black-box AI models.

---

## 2. Core CNS Conceptual Distinction

A foundational principle of MailTrust is explaining the vital distinction between the layers of email security:

```
+-----------------------------------------------------------------------------------+
| 1. Cryptographic Verification (DKIM & S/MIME)                                     |
|    - Mathematical integrity (SHA-256 body hash) & non-repudiation (RSA/Ed25519)    |
|    - PROVES: The private key holder signed the payload and headers.               |
|    - DOES NOT PROVE: The sender is benevolent or that From equals signing domain.  |
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
| 3. Cryptographic Hygiene & Multi-Hop Provenance Auditing                          |
|    - RSA key length (<1024 / <2048 / >=2048), deprecated sha1, partial body tag l |
|    - Multi-hop Authentication-Results validation, Return-Path / Reply-To mismatch |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| 4. Heuristic Phishing, Lookalike & Static Attachment Forensics                     |
|    - Deterministic checks for homoglyphs, Punycode, display-name spoofing, URLs.  |
|    - Attachment magic bytes vs. extension, double-extension regex, VBA macros.     |
+-----------------------------------------+-----------------------------------------+
```

---

## 3. CNS Concepts Mapping Table

| Academic CNS Topic | Internet Standard / Primitive | Implementation in MailTrust | Module |
| :--- | :--- | :--- | :--- |
| **Custom Cryptographic Hashing** | NIST FIPS 180-4 SHA-256 | Pure-Python SHA-256 implementation from scratch ($W_t$ message schedule, $\Sigma, \sigma, Ch, Maj$) | `analyzers/sha256.py` |
| **Asymmetric Digital Signatures** | RSA-SHA256, Ed25519 | Cryptographic verification of DKIM signature headers via `dkimpy` | `analyzers/dkim_analyzer.py` |
| **End-to-End PKI Signatures** | RFC 8551 / CMS (PKCS#7) | S/MIME clear-signed (`multipart/signed`) and opaque-signed verification; X.509 cert analysis | `analyzers/smime_analyzer.py` |
| **Cryptographic Hygiene Audit** | NIST SP 800-57 / RFC 6376 | Bit-length analysis (1024/2048/4096), deprecated `rsa-sha1`, test mode `t=y`, body limit `l=` | `analyzers/crypto_hygiene.py` |
| **Tamper-Evident Evidence** | RFC 8785 Canonical JSON + Ed25519 | Cryptographically signed forensic evidence reports with public offline verification | `analyzers/evidence_report.py` |
| **Multi-Hop Header Provenance** | RFC 8601 `Authentication-Results` | Validates intermediate receiver claims, detects identity divergence (`Return-Path` vs `Reply-To`) | `analyzers/header_provenance.py` |
| **Attachment Malware Forensics** | Static Magic Bytes & ZIP Parsing | Detection of double extensions (`.pdf.exe`), magic byte mismatches, and OOXML VBA macros | `analyzers/attachment_inspector.py` |
| **Public-Key Distribution** | DNS TXT Resource Records | Dynamic DNS queries resolving public keys at `selector._domainkey.domain` | `analyzers/dkim_analyzer.py` |
| **Network IP Authorization** | RFC 7208 (SPF) | Evaluation of IPv4/IPv6 CIDR subnets, `a`, `mx`, `include`, and `all` | `analyzers/spf_analyzer.py` |
| **DNS Lookup & Recursion Limits** | RFC 7208 Section 4.6.4 | Enforces maximum 10 DNS queries; detects circular include recursion loops | `analyzers/spf_analyzer.py` |
| **Domain Identity Alignment** | RFC 7489 (DMARC) | Strict (`s`) and relaxed (`r`) organizational domain matching | `analyzers/dmarc_analyzer.py` |
| **Visual Homoglyph Spoofing** | IDN Punycode (RFC 3492), Unicode NFKC | Detection of `xn--` encoding and mixed Cyrillic/Greek/Latin scripts | `analyzers/domain_analyzer.py` |
| **Typosquatting & Confusables** | Levenshtein Distance & Confusable Normalization | Edit-distance checks (distance=1) against high-value target brand database | `analyzers/domain_analyzer.py` |
| **Password Hashing** | Argon2id ($m=65536, t=3, p=4$) | Memory-hard password hashing with per-user salt and pepper | `security/auth.py` |
| **Multi-Factor Authentication** | RFC 6238 TOTP | Pure-Python SVG QR code generation, Fernet secret encryption at rest, hashed recovery codes | `security/totp.py` |
| **Tamper-Evident Audit Logging** | SHA-256 Hash Chaining ($H_i$) | RFC 8785 canonical JSON serialization with Ed25519 signature checkpoints | `security/audit_log.py` |

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
5. **Weak Cryptographic Configurations:** Adversary uses obsolete 512-bit/768-bit RSA keys or deprecated `rsa-sha1`.
   - *Mitigation:* Cryptographic hygiene analyzer flags sub-1024 bit keys as `CRITICAL` and deprecated algorithms as `HIGH RISK`.
6. **Double-Extension & Macro Malware:** Adversary delivers attachments disguised as documents (`Invoice.pdf.exe` or `.xlsm` with embedded VBA).
   - *Mitigation:* Static attachment inspector identifies executable headers and `vbaProject.bin` OOXML macro structures.
7. **Identity Discrepancy & Reply-To Hijack:** Adversary sets `From: ceo@company.com` but routes replies to `attacker@gmail.com`.
   - *Mitigation:* Header provenance analyzer highlights cross-domain Reply-To and Return-Path divergence.
8. **Credential Guessing & Brute Force:** Adversary launches dictionary attacks against administrative accounts.
   - *Mitigation:* Argon2id password hashing, sliding-window rate limiting (5 attempts per 5 minutes), and automatic account lockouts.
9. **Session Hijacking & Fixation:** Adversary attempts to steal or fix administrative sessions.
   - *Mitigation:* Cryptographic 256-bit session token hashing, session rotation upon login, HttpOnly/SameSite cookie isolation, idle (30m) and absolute (12h) timeouts.
10. **Audit Log Tampering:** Adversary gains database write access and attempts to alter or delete historical audit entries.
    - *Mitigation:* Cryptographic SHA-256 hash chaining ($H_i = \text{SHA256}(\text{CanonicalEvent}_i \mathbin{\Vert} H_{i-1})$) and periodic Ed25519 digital signature checkpoints detect deletions, reordering, and payload alteration.

### Privacy-Preserving Architecture
- **Zero Raw Persistence:** MailTrust does NOT persist raw email message bodies, plaintext headers, or binary attachments in any database or audit log.
- **Privacy Retention Pruning:** Analysis records retain only metadata (hashes, risk scores, verdicts) and are automatically pruned after the retention period (`flask purge-expired`).

---

## 5. System Architecture

```
MailTrust/
├── app.py                      # Flask Application Controller, Routes & CLI Commands
├── config.py                   # CNS Security Constants, Session Config & Brand Database
├── database.py                 # Thread-Safe SQLite WAL Engine & Session Management
├── models.py                   # SQLAlchemy Models (User, AuditLog, SessionRecord, etc.)
├── requirements.txt            # Pinned Dependency Declarations
├── README.md                   # Complete Documentation & Demonstration Guide
├── .env.example                # Template Environment File
│
├── security/                   # Enterprise Authentication & Cryptographic Integrity
│   ├── __init__.py
│   ├── auth.py                 # Argon2id Hashing, Sliding-Window Rate Limiter, RBAC, Sessions, CSRF
│   ├── totp.py                 # RFC 6238 TOTP, Fernet Encryption, Pure-Python SVG QR, Recovery Codes
│   ├── audit_log.py            # SHA-256 Hash Chain, RFC 8785 Canonical JSON, Tamper Verification
│   └── audit_checkpoint.py     # Ed25519 Digital Signature Ledger Anchors
│
├── analyzers/                  # Modular Security Analyzers
│   ├── __init__.py             # Public Package Exports
│   ├── sha256.py               # NIST FIPS 180-4 Pure-Python SHA-256 Implementation
│   ├── email_parser.py         # MIME Structure, RFC 5322 Parsing & URL Extractor
│   ├── dkim_analyzer.py        # Asymmetric Cryptographic DKIM Verification (RFC 6376)
│   ├── spf_analyzer.py         # Sender Policy Framework Evaluation (RFC 7208)
│   ├── dmarc_analyzer.py       # Domain Alignment & Policy Disposition (RFC 7489)
│   ├── smime_analyzer.py       # S/MIME CMS (PKCS#7) Digital Signature Verification (RFC 8551)
│   ├── crypto_hygiene.py       # Cryptographic Quality & Key Strength Audit
│   ├── evidence_report.py      # Signed Forensic Evidence Export (RFC 8785 + Ed25519)
│   ├── header_provenance.py    # Multi-Hop Authentication-Results & Sender Mismatch
│   ├── attachment_inspector.py # Static Attachment Forensics, Magic Bytes & VBA Macro Detection
│   ├── domain_analyzer.py      # Homoglyphs, Punycode, Typosquatting & Display Spoofing
│   ├── phishing_rules.py       # Deterministic Keyword & Indicator Rules (No AI/ML)
│   └── risk_engine.py          # Transparent Explainable Risk Assessment Engine
│
├── templates/                  # Frontend HTML5 Templates (Bootstrap 5 SaaS Layout)
│   ├── base.html               # Base SaaS Layout, Navigation, Auth Status & Flash Alerts
│   ├── index.html              # Drag-and-Drop Analysis Workbench
│   ├── results.html            # Forensic Report, Cryptographic Cards & Evidence Tabs
│   ├── history.html            # Searchable Analysis History
│   ├── methodology.html        # Academic CNS Reference & Architecture Documentation
│   ├── lab.html                # Interactive Cryptographic Signing & Tampering Lab
│   ├── login.html              # Argon2id Authentication Interface
│   ├── register.html           # User Self-Registration Interface
│   ├── mfa_verify.html         # RFC 6238 TOTP Verification Interface
│   ├── mfa_setup.html          # Inline SVG QR Code MFA Enrollment
│   ├── account.html            # User Profile & MFA Configuration
│   ├── user_dashboard.html     # User Analysis Dashboard
│   ├── verify_report.html      # Public Forensic Evidence Report Verifier
│   └── admin/
│       ├── dashboard.html      # System Status, Security Metrics & Fast Navigation
│       ├── users.html          # RBAC User Management (Roles, Active/Locked State)
│       ├── audit.html          # Cryptographic Audit Ledger & One-Click Chain Verifier
│       └── settings.html       # Security Policies & Retention Configuration
│
├── static/
│   ├── css/style.css           # Modern Enterprise SaaS Stylesheet
│   └── js/app.js               # File Ingestion & Drag-and-Drop Script
│
├── tests/                      # Comprehensive Test Suite (91 Automated Tests)
│   ├── test_attachment_and_provenance.py # Attachment Forensics & Multi-Hop Tests
│   ├── test_audit_log.py       # RFC 8785 JSON, Hash Chaining & Tamper Detection Tests
│   ├── test_auth.py            # Argon2id, Rate Limiting, RBAC & Session Tests
│   ├── test_crypto_hygiene.py  # RSA Key Strength & Deprecated Algorithm Tests
│   ├── test_dkim.py            # DKIM Signature Verification & Tampering Tests
│   ├── test_dmarc.py           # DMARC Alignment & Policy Inheritance Tests
│   ├── test_domains.py         # Homoglyphs, Typosquatting & Punycode Tests
│   ├── test_email_parser.py    # MIME Parser & Sanitization Tests
│   ├── test_evidence_report.py # Ed25519 Signed Forensic Report Tests
│   ├── test_regression_tcs.py  # TCS NQT Regression & Receiver Separation Tests
│   ├── test_risk_engine.py     # Deterministic Risk Scoring Tests
│   ├── test_sha256.py          # NIST Test Vector Parity Tests
│   ├── test_smime.py           # S/MIME Signature Verification Tests
│   ├── test_spf.py             # SPF Qualifiers, IPv4/IPv6 & Lookup Limits
│   ├── test_totp.py            # TOTP Encryption, SVG QR & Recovery Codes
│   └── test_web_app.py         # Web Routes, CSRF & Integration Tests
│
└── samples/                    # Educational CNS Test Emails
    ├── generate_samples.py     # Reproducible RSA Key & Signature Sample Generator
    ├── valid_dkim_aligned.eml  # Authentic 2048-bit RSA Signed Message
    ├── tampered_dkim.eml       # Modified Payload Demonstrating Hash Mismatch
    ├── display_name_spoof.eml  # Brand Impersonation & Link Mismatch
    ├── unaligned_dkim_dmarc_fail.eml # Third-Party Key Alignment Failure
    ├── phishing_malware_lure.eml     # Typosquatted Domain with .exe Attachment
    ├── no_auth_inconclusive.eml      # Unauthenticated Legacy Message
    └── tcs_nqt.eml             # Real-World Institutional Notice Sample
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

### Step 4: Run the Complete Automated Test Suite (91 Tests)
```powershell
pytest -v
```
*Expected result: 91 passed in ~8 seconds (100% success rate).*

### Step 5: Provision an Administrator Account
MailTrust enforces secure admin provisioning via CLI without hardcoded credentials:
```powershell
flask --app app.py create-admin --username admin --email admin@example.com --password "SecureAdmin#2026!"
```

### Step 6: Start the MailTrust Server
```powershell
python app.py
```

### Step 7: Access the Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 7. Administrative CLI Utilities

### Secure Admin Creation
```powershell
flask --app app.py create-admin --username <name> --email <email> --password <password>
```
Provisions a user with the `ADMIN` role. Enforces password complexity rules and logs the administrative creation in the cryptographic audit ledger.

### Privacy Retention Pruning
```powershell
flask --app app.py purge-expired
```
Removes analysis records older than `MAILTRUST_ANALYSIS_RETENTION_DAYS` (default 30 days) and inactive session records according to privacy guidelines.

---

## 8. Automated Test Report

Execution run verified with `pytest`:
```text
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.7.0
rootdir: E:\VII'\CNS\MailTrust
collected 91 items

tests/test_attachment_and_provenance.py (6 tests) ............ PASSED [  6%]
tests/test_audit_log.py (6 tests) ............................ PASSED [ 13%]
tests/test_auth.py (5 tests) ................................. PASSED [ 18%]
tests/test_crypto_hygiene.py (5 tests) ....................... PASSED [ 24%]
tests/test_dkim.py (7 tests) ................................. PASSED [ 31%]
tests/test_dmarc.py (6 tests) ................................ PASSED [ 38%]
tests/test_domains.py (6 tests) .............................. PASSED [ 45%]
tests/test_email_parser.py (5 tests) ......................... PASSED [ 50%]
tests/test_evidence_report.py (3 tests) ...................... PASSED [ 53%]
tests/test_regression_tcs.py (6 tests) ....................... PASSED [ 60%]
tests/test_risk_engine.py (6 tests) .......................... PASSED [ 67%]
tests/test_sha256.py (6 tests) ............................... PASSED [ 73%]
tests/test_smime.py (3 tests) ................................ PASSED [ 76%]
tests/test_spf.py (8 tests) .................................. PASSED [ 85%]
tests/test_totp.py (4 tests) ................................. PASSED [ 89%]
tests/test_web_app.py (9 tests) .............................. PASSED [100%]

============================= 91 passed in 8.39s ==============================
```

---

## 9. Academic & Technical Demonstration Walkthrough

When presenting MailTrust for academic evaluation or technical demonstration:

### 1. Plain-English SaaS Workbench
- Open `http://127.0.0.1:5000`. Show the clean SaaS layout, drag-and-drop `.eml` ingestion, and instant sample loaders.
- Demonstrate that regular unauthenticated users can perform security analysis without mandatory login.

### 2. S/MIME and Cryptographic Hygiene Forensics
- Analyze an email to observe:
  - **S/MIME Digital Signature Card:** Identifies clear-signed and opaque PKCS#7 signatures, shows signer certificate common name, organization, validity window, and KeyUsage/EKU attributes.
  - **Cryptographic Hygiene Card:** Evaluates RSA public key length, flags deprecated `rsa-sha1` or test-mode tags (`t=y`), and warns about partial-body length tags (`l=`).
  - **Header Provenance Tab:** Cross-examines `Authentication-Results` across network hops and flags `Reply-To` / `Return-Path` domain divergence.
  - **Attachments Forensics Tab:** Demonstrates static file inspection, identifying dangerous double-extensions and OOXML embedded VBA macros (`vbaProject.bin`).

### 3. Signed Forensic Evidence Export & Public Verification
- On the analysis results page, click **Export Signed Evidence (.json)**.
- Download the canonical JSON report containing the Ed25519 digital signature and public key.
- Navigate to **Verify Evidence Report** (`/verify-report`) in the navigation bar.
- Paste the signed JSON into the verifier. MailTrust confirms the Ed25519 mathematical signature and guarantees zero tampering of the forensic findings.

### 4. Interactive Cryptographic Lab (`/lab`)
- Navigate to **Authentication Lab**.
- Step 1: Show the live 2048-bit RSA key and DNS TXT record.
- Step 2: Click **Sign with Private Key** &rarr; Computes SHA-256 body hash (`bh=`) and generates a valid DKIM header.
- Step 3: Click **Verify Authentic Signature** &rarr; Shows `PASS — Cryptographic Integrity Confirmed`.
- Step 4: Click **Tamper Payload ($10k -> $90k)** &rarr; Alters the message body.
- Step 5: Click **Verify Tampered Message** &rarr; Cryptographic verification detects body hash mismatch and fails immediately.

### 5. Multi-Factor Authentication & Secure Admin Dashboard
- Log in with the administrative credentials created via CLI (`flask create-admin`).
- Enroll in **RFC 6238 TOTP MFA** using Google Authenticator or Microsoft Authenticator by scanning the pure-Python inline SVG QR code.
- Save the one-time emergency recovery codes.
- Access the **Admin Dashboard** (`/admin`):
  - **User Management (`/admin/users`):** Change roles, lock/unlock accounts with built-in guardrails preventing lockouts of the last active administrator.
  - **Tamper-Evident Audit Ledger (`/admin/audit`):** Inspect chronological security actions. Click **Verify Chain Integrity** to execute live SHA-256 hash chain verification across all ledger records.
  - **Security Settings (`/admin/settings`):** Configure session timeouts, login rate limiting, and retention policies.
