"""
Sample Email Generator for MailTrust
Generates authentic CNS test samples with real RSA cryptographic keys,
tampered signatures, display spoofing, lookalike domains, and unaligned DMARC.
"""

import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import dkim


def generate_cns_samples(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    
    # 1. Generate RSA Key Pair for 'example.com' (selector: 'cns2026')
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    pub_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.b64encode(pub_der).decode("ascii")
    
    # Save the public key DNS record for testing and reference
    dns_txt_record = f"v=DKIM1; k=rsa; p={pub_b64}"
    with open(os.path.join(output_dir, "test_dkim_dns_record.txt"), "w", encoding="utf-8") as f:
        f.write(f"Domain: cns2026._domainkey.example.com\nTXT: {dns_txt_record}\n")

    # Sample 1: Cryptographically signed email with valid DKIM and aligned DMARC
    email_body_1 = (
        b"From: security-alerts@example.com\r\n"
        b"To: user@recipient.org\r\n"
        b"Subject: Monthly Security Audit Notification\r\n"
        b"Date: Mon, 26 Oct 2026 10:00:00 +0000\r\n"
        b"Message-ID: <audit-2026-1026@example.com>\r\n"
        b"Return-Path: <security-alerts@example.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Hello Admin,\r\n\r\n"
        b"This is a routine monthly security notification from Example Corp.\r\n"
        b"Your system integrity checks have passed with no vulnerabilities detected.\r\n\r\n"
        b"Regards,\r\nSecurity Operations Center\r\n"
    )
    
    sig_1 = dkim.sign(
        message=email_body_1,
        selector=b"cns2026",
        domain=b"example.com",
        privkey=priv_pem
    )
    valid_signed_email = sig_1 + email_body_1
    with open(os.path.join(output_dir, "valid_dkim_aligned.eml"), "wb") as f:
        f.write(valid_signed_email)

    # Sample 2: Display Name Spoofing
    sample_2 = (
        "From: \"PayPal Security Alert\" <security@attacker-phish.net>\n"
        "Reply-To: support@attacker-phish.net\n"
        "To: victim@example.org\n"
        "Subject: Urgent: Verify your PayPal account credentials immediately\n"
        "Date: Mon, 26 Oct 2026 11:15:00 +0000\n"
        "Message-ID: <spoof-001@attacker-phish.net>\n"
        "Return-Path: <bounces@attacker-phish.net>\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n"
        "<html><body>\n"
        "<p>Dear Customer,</p>\n"
        "<p>We detected an unauthorized login to your PayPal account. Immediate action required!</p>\n"
        "<p>Your account will be suspended within 24 hours if you fail to verify your password and 2FA code.</p>\n"
        "<p><a href=\"http://192.168.1.50/paypal-login\">https://www.paypal.com/signin</a></p>\n"
        "<p>Thank you,<br>PayPal Support</p>\n"
        "</body></html>\n"
    )
    with open(os.path.join(output_dir, "display_name_spoof.eml"), "w", encoding="utf-8") as f:
        f.write(sample_2)

    # Sample 3: Tampered DKIM (Valid signature originally, but body altered in transit)
    tampered_email = sig_1 + email_body_1.replace(b"passed with no vulnerabilities", b"FAILED with critical exploits")
    with open(os.path.join(output_dir, "tampered_dkim.eml"), "wb") as f:
        f.write(tampered_email)

    # Sample 4: Unaligned DKIM (Signed by third-party domain 'attacker-mail.com', From is 'bank.com')
    # Generate second key for 'attacker-mail.com'
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_pem = attacker_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    email_body_4 = (
        b"From: ceo@trusted-bank.com\r\n"
        b"To: finance@victim.org\r\n"
        b"Subject: Confidential Wire Transfer Request\r\n"
        b"Date: Mon, 26 Oct 2026 12:30:00 +0000\r\n"
        b"Message-ID: <bank-transfer-99@trusted-bank.com>\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"Please process a confidential wire transfer of $45,000 to the overseas account today.\r\n"
    )
    sig_4 = dkim.sign(
        message=email_body_4,
        selector=b"relay",
        domain=b"attacker-mail.com",
        privkey=attacker_pem
    )
    unaligned_email = sig_4 + email_body_4
    with open(os.path.join(output_dir, "unaligned_dkim_dmarc_fail.eml"), "wb") as f:
        f.write(unaligned_email)

    # Sample 5: High-Risk Phishing with Lookalike Domain, Extorted Gift Card, and Executable Attachment
    sample_5 = (
        "From: \"Account Services\" <support@paypa1.com>\n"
        "Reply-To: refund-desk@evil-mail.ru\n"
        "To: target@victim.org\n"
        "Subject: OVERDUE INVOICE: Immediate wire transfer or gift card payment required\n"
        "Date: Mon, 26 Oct 2026 14:00:00 +0000\n"
        "Message-ID: <invoice-overdue-8812@paypa1.com>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: multipart/mixed; boundary=\"====BOUNDARY_1234====\"\n"
        "\n"
        "--====BOUNDARY_1234====\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "Notice of Legal Action:\n"
        "Your payment is overdue. Failure to respond will result in immediate court summons.\n"
        "Remit the balance of $500 via Amazon gift card or Bitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
        "See attached invoice details.\n"
        "\n"
        "--====BOUNDARY_1234====\n"
        "Content-Type: application/octet-stream; name=\"Invoice_Scan.pdf.exe\"\n"
        "Content-Disposition: attachment; filename=\"Invoice_Scan.pdf.exe\"\n"
        "Content-Transfer-Encoding: base64\n"
        "\n"
        "TVoAAAAFAAAAAEAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "--====BOUNDARY_1234====--\n"
    )
    with open(os.path.join(output_dir, "phishing_malware_lure.eml"), "w", encoding="utf-8") as f:
        f.write(sample_5)

    # Sample 6: Plain email without authentication headers (INCONCLUSIVE)
    sample_6 = (
        "From: colleague@personal-site.org\n"
        "To: friend@example.org\n"
        "Subject: Lunch meeting tomorrow\n"
        "Date: Mon, 26 Oct 2026 15:00:00 +0000\n"
        "Message-ID: <lunch-chat-2026@personal-site.org>\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "Hey, are we still meeting for lunch at 1pm tomorrow?\n"
        "Let me know if that time works for you.\n"
    )
    with open(os.path.join(output_dir, "no_auth_inconclusive.eml"), "w", encoding="utf-8") as f:
        f.write(sample_6)

    print("Successfully generated 6 CNS test samples and public key record in", output_dir)


if __name__ == "__main__":
    generate_cns_samples(os.path.join(os.path.dirname(__file__)))
