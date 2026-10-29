"""
MailTrust Web Application
Flask Application Controller for Cryptographic and Header-Based Email Spoofing Detection
"""

import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.utils import secure_filename

from config import Config
from analyzers import (
    parse_raw_email,
    verify_dkim_signatures,
    evaluate_spf,
    evaluate_dmarc,
    analyze_domains,
    inspect_phishing_indicators,
    compute_risk_verdict,
)
from analyzers.lab_engine import generate_lab_keypair, sign_lab_email, verify_lab_email

app = Flask(__name__)
app.config.from_object(Config)

# Sample directory path
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def run_full_security_analysis(raw_email_data: bytes, client_ip: str = "", envelope_sender: str = ""):
    """Execute complete modular CNS analysis pipeline."""
    # 1. Parse Email MIME & RFC 5322 Headers
    parsed_email = parse_raw_email(raw_email_data)

    # 2. Cryptographic DKIM Verification
    test_dns_record_path = os.path.join(SAMPLES_DIR, "test_dkim_dns_record.txt")
    test_key_txt = None
    if os.path.exists(test_dns_record_path):
        try:
            with open(test_dns_record_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("TXT:"):
                        test_key_txt = line.split("TXT:", 1)[1].strip().encode("utf-8")
        except Exception:
            pass

    def contextual_dnsfunc(name: bytes, timeout: int = 5):
        name_str = name.decode("utf-8", errors="replace").lower().rstrip(".")
        if "cns2026._domainkey.example.com" in name_str and test_key_txt:
            return test_key_txt
        # Live DNS fallback
        from analyzers.dkim_analyzer import default_live_dnsfunc
        return default_live_dnsfunc(name, timeout)

    dkim_result = verify_dkim_signatures(raw_email_data, custom_dnsfunc=contextual_dnsfunc)

    # 3. SPF RFC 7208 Evaluation
    spf_result = evaluate_spf(
        parsed_email,
        client_ip=client_ip,
        sender_identity=envelope_sender
    )

    # 4. DMARC RFC 7489 Alignment
    dmarc_result = evaluate_dmarc(
        from_domain=parsed_email.from_domain,
        dkim_result=dkim_result,
        spf_result=spf_result
    )

    # 5. Domain & Lookalike Heuristics
    domain_result = analyze_domains(
        parsed_email,
        dkim_signing_domain=dkim_result.primary_domain
    )

    # 6. Content Phishing Indicators
    phishing_result = inspect_phishing_indicators(parsed_email)

    # 7. Explainable Risk Engine
    risk_result = compute_risk_verdict(
        parsed_email=parsed_email,
        dkim_res=dkim_result,
        spf_res=spf_result,
        dmarc_res=dmarc_result,
        domain_res=domain_result,
        phish_res=phishing_result
    )

    return {
        "parsed_email": parsed_email,
        "dkim_result": dkim_result,
        "spf_result": spf_result,
        "dmarc_result": dmarc_result,
        "domain_result": domain_result,
        "phishing_result": phishing_result,
        "risk_result": risk_result,
    }


def add_to_session_history(subject: str, from_addr: str, verdict: str, badge_class: str, risk_score: int = 0):
    """Keep track of recent analyses in user session."""
    history = session.get("recent_analyses", [])
    entry = {
        "id": len(history) + 1,
        "subject": (subject[:45] + "...") if len(subject) > 45 else (subject or "(No Subject)"),
        "from": from_addr or "(Unknown)",
        "verdict": verdict,
        "badge_class": badge_class,
        "risk_score": risk_score,
        "timestamp": datetime.now().strftime("%b %d, %H:%M"),
    }
    # Prepend and limit to 10
    history = [entry] + [h for h in history if h.get("subject") != entry["subject"]][:9]
    session["recent_analyses"] = history


@app.route("/")
def index():
    """Main dashboard with clean SaaS UI, input forms, and sample loaders."""
    recent_analyses = session.get("recent_analyses", [])
    
    # List available sample files
    available_samples = []
    if os.path.exists(SAMPLES_DIR):
        sample_meta = {
            "valid_dkim_aligned.eml": {
                "title": "Authentic RSA Signed Email",
                "tag": "Verified Sender",
                "tag_class": "success",
                "desc": "Real 2048-bit RSA signature with valid DMARC domain alignment."
            },
            "tampered_dkim.eml": {
                "title": "Tampered DKIM Signature",
                "tag": "Cryptographic Failure",
                "tag_class": "danger",
                "desc": "Modified body payload invalidates SHA-256 hash digest (bh=)."
            },
            "display_name_spoof.eml": {
                "title": "Display-Name Brand Impersonation",
                "tag": "Suspicious Spoof",
                "tag_class": "warning",
                "desc": "Claims PayPal in display name with attacker sending domain and link mismatch."
            },
            "unaligned_dkim_dmarc_fail.eml": {
                "title": "Third-Party DKIM (DMARC Mismatch)",
                "tag": "DMARC Alignment Fail",
                "tag_class": "danger",
                "desc": "Valid signature on unrelated domain fails DMARC policy check against From."
            },
            "phishing_malware_lure.eml": {
                "title": "Typosquatting & Malware Attachment",
                "tag": "High Risk Phishing",
                "tag_class": "danger",
                "desc": "Domain paypa1.com with urgent gift card extortion and executable file."
            },
            "no_auth_inconclusive.eml": {
                "title": "Legacy Unauthenticated Email",
                "tag": "Inconclusive Data",
                "tag_class": "neutral",
                "desc": "No signatures or records published; reported inconclusive without bias."
            },
            "tcs_nqt.eml": {
                "title": "TCS NQT Career Readiness Lure",
                "tag": "Brand & Form Inconsistency",
                "tag_class": "warning",
                "desc": "Claims TCS NQT assessment from third-party domain inspireleap.in with public Google Form link."
            }
        }
        for fname, meta in sample_meta.items():
            if os.path.exists(os.path.join(SAMPLES_DIR, fname)):
                available_samples.append({
                    "filename": fname,
                    "title": meta["title"],
                    "tag": meta["tag"],
                    "tag_class": meta["tag_class"],
                    "desc": meta["desc"]
                })
                
    return render_template(
        "index.html",
        recent_analyses=recent_analyses,
        samples=available_samples
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    """Handle email submission (file upload or raw paste)."""
    raw_email_bytes = None
    client_ip = request.form.get("client_ip", "").strip()
    envelope_sender = request.form.get("envelope_sender", "").strip()

    # Check for file upload
    if "email_file" in request.files and request.files["email_file"].filename != "":
        file = request.files["email_file"]
        filename = secure_filename(file.filename)
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in Config.ALLOWED_EXTENSIONS:
            flash(f"Unsupported file format '.{ext}'. Supported formats: {', '.join(Config.ALLOWED_EXTENSIONS)}", "danger")
            return redirect(url_for("index"))
        
        raw_email_bytes = file.read()
    else:
        # Check for pasted raw content
        raw_text = request.form.get("raw_email_text", "").strip()
        if raw_text:
            raw_email_bytes = raw_text.encode("utf-8", errors="replace")

    if not raw_email_bytes:
        flash("Please upload an .eml file or paste raw RFC 5322 email text.", "warning")
        return redirect(url_for("index"))

    try:
        analysis_data = run_full_security_analysis(
            raw_email_bytes,
            client_ip=client_ip,
            envelope_sender=envelope_sender
        )
        
        # Save to session history
        parsed = analysis_data["parsed_email"]
        risk = analysis_data["risk_result"]
        add_to_session_history(
            subject=parsed.subject or "(No Subject)",
            from_addr=parsed.from_address or "(Unknown)",
            verdict=risk.verdict,
            badge_class=risk.verdict_badge_class,
            risk_score=risk.calculated_risk_score
        )

        return render_template(
            "results.html",
            parsed_email=parsed,
            dkim=analysis_data["dkim_result"],
            spf=analysis_data["spf_result"],
            dmarc=analysis_data["dmarc_result"],
            domain=analysis_data["domain_result"],
            phishing=analysis_data["phishing_result"],
            risk=analysis_data["risk_result"],
            client_ip=client_ip,
            envelope_sender=envelope_sender
        )
    except Exception as e:
        flash(f"Analysis encountered an error: {str(e)}", "danger")
        return redirect(url_for("index"))


@app.route("/sample/<sample_name>")
def load_sample(sample_name):
    """Load and analyze a pre-built CNS educational sample email."""
    safe_name = secure_filename(sample_name)
    sample_path = os.path.join(SAMPLES_DIR, safe_name)
    
    if not os.path.exists(sample_path) or not safe_name.endswith(".eml"):
        flash("Sample email not found.", "warning")
        return redirect(url_for("index"))

    with open(sample_path, "rb") as f:
        raw_bytes = f.read()

    analysis_data = run_full_security_analysis(raw_bytes)
    
    parsed = analysis_data["parsed_email"]
    risk = analysis_data["risk_result"]
    add_to_session_history(
        subject=parsed.subject or "(No Subject)",
        from_addr=parsed.from_address or "(Unknown)",
        verdict=risk.verdict,
        badge_class=risk.verdict_badge_class,
        risk_score=risk.calculated_risk_score
    )

    return render_template(
        "results.html",
        parsed_email=parsed,
        dkim=analysis_data["dkim_result"],
        spf=analysis_data["spf_result"],
        dmarc=analysis_data["dmarc_result"],
        domain=analysis_data["domain_result"],
        phishing=analysis_data["phishing_result"],
        risk=analysis_data["risk_result"],
        is_sample=True,
        sample_name=safe_name
    )


@app.route("/lab")
def authentication_lab():
    """Interactive CNS Cryptographic Authentication Lab."""
    # Ensure lab key exists in session or generate default
    if "lab_priv_key" not in session or "lab_dns_record" not in session:
        priv_pem, pub_b64, dns_record = generate_lab_keypair(key_size=2048)
        session["lab_priv_key"] = priv_pem.decode("ascii")
        session["lab_dns_record"] = dns_record
        session["lab_selector"] = "labkey"
        session["lab_domain"] = "example.com"

    default_template_email = (
        "From: Alice <alice@example.com>\r\n"
        "To: Bob <bob@example.com>\r\n"
        "Subject: Project Confidential Milestone\r\n"
        "Date: Mon, 26 Oct 2026 12:00:00 +0000\r\n"
        "Message-ID: <lab-msg-001@example.com>\r\n"
        "\r\n"
        "The project milestone is approved. Budget disbursement: $10,000.\r\n"
    )

    return render_template(
        "lab.html",
        dns_record=session.get("lab_dns_record", ""),
        selector=session.get("lab_selector", "labkey"),
        domain=session.get("lab_domain", "example.com"),
        default_email=default_template_email
    )


@app.route("/api/lab/generate-key", methods=["POST"])
def api_lab_generate_key():
    """Generate a fresh RSA keypair for lab simulations."""
    priv_pem, pub_b64, dns_record = generate_lab_keypair(key_size=2048)
    session["lab_priv_key"] = priv_pem.decode("ascii")
    session["lab_dns_record"] = dns_record
    return jsonify({
        "status": "success",
        "dns_record": dns_record,
        "public_key_b64": pub_b64,
        "message": "Fresh 2048-bit RSA keypair generated."
    })


@app.route("/api/lab/sign", methods=["POST"])
def api_lab_sign():
    """Cryptographically sign test email with the lab RSA private key."""
    data = request.get_json() or {}
    raw_message = data.get("raw_message", "")
    selector = data.get("selector", "labkey")
    domain = data.get("domain", "example.com")
    
    priv_pem_str = session.get("lab_priv_key")
    if not priv_pem_str:
        priv_pem, pub_b64, dns_record = generate_lab_keypair(key_size=2048)
        session["lab_priv_key"] = priv_pem.decode("ascii")
        session["lab_dns_record"] = dns_record
        priv_pem_str = session["lab_priv_key"]

    try:
        signed_email = sign_lab_email(
            raw_message_str=raw_message,
            selector=selector,
            domain=domain,
            private_key_pem=priv_pem_str.encode("ascii")
        )
        return jsonify({
            "status": "success",
            "signed_email": signed_email,
            "dns_record": session.get("lab_dns_record", "")
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/api/lab/verify", methods=["POST"])
def api_lab_verify():
    """Cryptographically verify test email against lab public key."""
    data = request.get_json() or {}
    message_str = data.get("message_str", "")
    selector = data.get("selector", "labkey")
    domain = data.get("domain", "example.com")
    dns_record = data.get("dns_record", session.get("lab_dns_record", ""))

    try:
        result = verify_lab_email(
            signed_message_str=message_str,
            selector=selector,
            domain=domain,
            dns_txt_record=dns_record
        )
        return jsonify({
            "status": "success",
            "verification": result
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/history")
def history():
    """Scan history page for session analyses."""
    recent_analyses = session.get("recent_analyses", [])
    return render_template("history.html", history=recent_analyses)


@app.route("/history/clear", methods=["POST"])
def clear_history():
    """Clear session scan history."""
    session["recent_analyses"] = []
    flash("Scan history cleared for this session.", "info")
    return redirect(url_for("history"))


@app.route("/methodology")
def methodology():
    """CNS Educational Reference & Theoretical Methodology page."""
    return render_template("methodology.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """REST API endpoint for programmatic evaluation."""
    raw_bytes = None
    client_ip = request.form.get("client_ip", "")
    envelope_sender = request.form.get("envelope_sender", "")

    if "email_file" in request.files:
        raw_bytes = request.files["email_file"].read()
    elif request.is_json:
        data = request.get_json()
        raw_text = data.get("raw_email", "")
        client_ip = data.get("client_ip", "")
        envelope_sender = data.get("envelope_sender", "")
        raw_bytes = raw_text.encode("utf-8")
    else:
        raw_text = request.form.get("raw_email_text", "")
        if raw_text:
            raw_bytes = raw_text.encode("utf-8")

    if not raw_bytes:
        return jsonify({"error": "No email content provided"}), 400

    try:
        data = run_full_security_analysis(raw_bytes, client_ip=client_ip, envelope_sender=envelope_sender)
        return jsonify({
            "status": "success",
            "parsed_email": data["parsed_email"].to_dict(),
            "dkim": data["dkim_result"].to_dict(),
            "spf": data["spf_result"].to_dict(),
            "dmarc": data["dmarc_result"].to_dict(),
            "domain_heuristics": data["domain_result"].to_dict(),
            "phishing_indicators": data["phishing_result"].to_dict(),
            "risk_assessment": data["risk_result"].to_dict(),
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.errorhandler(413)
def file_too_large(e):
    flash("Uploaded file exceeds the maximum 10MB limit.", "danger")
    return redirect(url_for("index"))


@app.after_request
def set_security_headers(response):
    """Apply defensive web application headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
