# MailTrust — CNS Educational Sample Test Suite

This directory contains authentic RFC 5322 email samples designed for testing and demonstrating the Cryptography and Network Security (CNS) capabilities of **MailTrust**.

---

## Sample Email Catalog

### 1. `valid_dkim_aligned.eml`
- **CNS Scenario:** Cryptographically Authenticated & DMARC Aligned.
- **DKIM:** Cryptographically signed using a real 2048-bit RSA private key with selector `cns2026` for domain `example.com`.
- **DMARC:** The signing domain matches the RFC 5322 `From: security-alerts@example.com` domain (strict/relaxed aligned).
- **Expected Verdict:** `AUTHENTICATION VERIFIED`.
- **Pedagogical Note:** Demonstrates that asymmetric public-key cryptography (RSA-SHA256) guarantees message header and body integrity.

### 2. `display_name_spoof.eml`
- **CNS Scenario:** Display-Name Impersonation with Deceptive Link Destination.
- **Display Name:** `"PayPal Security Alert" <security@attacker-phish.net>`.
- **Payload:** Urgency lure ("suspended within 24 hours"), credential solicitation, and mismatched HTML link anchor displaying `https://www.paypal.com/signin` but routing to `http://192.168.1.50/paypal-login`.
- **Expected Verdict:** `HIGH RISK` / `SUSPICIOUS`.
- **Pedagogical Note:** Illustrates why MUA display names cannot be trusted without cryptographic verification.

### 3. `tampered_dkim.eml`
- **CNS Scenario:** In-Transit Message Tampering (Integrity Violation).
- **DKIM:** Contains the authentic signature header from Sample 1, but one sentence in the message body was altered after signing (`passed` -> `FAILED`).
- **DKIM Verification:** `FAIL` (Body hash `bh=` mismatch).
- **Expected Verdict:** `HIGH RISK`.
- **Pedagogical Note:** Demonstrates how the SHA-256 body hash prevents message tampering during mail relay transit.

### 4. `unaligned_dkim_dmarc_fail.eml`
- **CNS Scenario:** Third-Party DKIM Signature (DMARC Alignment Failure).
- **From Domain:** `ceo@trusted-bank.com`.
- **DKIM Signing Domain:** `d=attacker-mail.com`.
- **DMARC Evaluation:** Even though the attacker's DKIM signature is cryptographically valid for `attacker-mail.com`, it fails DMARC alignment against `trusted-bank.com`.
- **Expected Verdict:** `HIGH RISK` / `SUSPICIOUS` (DMARC policy violation).
- **Pedagogical Note:** Explains why DKIM alone is insufficient without DMARC alignment.

### 5. `phishing_malware_lure.eml`
- **CNS Scenario:** Typosquatted Brand Domain, Extortion, and Dangerous Executable Attachment.
- **From Domain:** `paypa1.com` (character substitution `1` -> `l`).
- **Indicators:** Advance-fee/legal threat, payment extortion via Amazon gift cards and Bitcoin, and attached `Invoice_Scan.pdf.exe`.
- **Expected Verdict:** `HIGH RISK`.
- **Pedagogical Note:** Demonstrates multi-vector deterministic heuristic detection without AI/ML.

### 6. `no_auth_inconclusive.eml`
- **CNS Scenario:** Legacy Email Without Authentication Headers.
- **Authentication:** No DKIM signature, no SPF context provided, no DMARC record.
- **Expected Verdict:** `INCONCLUSIVE`.
- **Pedagogical Note:** Demonstrates the CNS principle that lack of authentication data does not equate to proof of malice; MailTrust refuses to fabricate an outcome.
