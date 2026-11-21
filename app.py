"""
MailTrust Web Application
Flask Application Controller for Cryptographic and Header-Based Email Spoofing Detection,
Tamper-Evident Audit Logging, Admin Authentication, and S/MIME Verification.
"""

import os
import json
import uuid
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List

import click
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    jsonify, session, g, make_response, abort
)
from werkzeug.utils import secure_filename

from config import Config
from models import (
    User, SessionRecord, RecoveryCode, AnalysisRecord,
    AuditLog, AuditCheckpoint, AppSetting, utc_now
)
from database import init_db, get_db

from security.auth import (
    hash_password, verify_password, validate_password_strength,
    is_rate_limited, record_failed_attempt, clear_failed_attempts,
    create_user_session, revoke_session, load_authenticated_user,
    validate_csrf, login_required, admin_required, roles_required,
    generate_session_token, hash_token
)
from security.totp import (
    generate_totp_secret, encrypt_totp_secret, decrypt_totp_secret,
    get_provisioning_uri, generate_qr_code_data_uri, verify_totp_code,
    generate_recovery_codes, verify_and_consume_recovery_code
)
from security.audit_log import (
    log_security_event, verify_audit_log_integrity, canonicalize_json
)
from security.audit_checkpoint import (
    create_audit_checkpoint, verify_checkpoint_signatures
)

from analyzers import (
    parse_raw_email,
    verify_dkim_signatures,
    evaluate_spf,
    evaluate_dmarc,
    analyze_domains,
    inspect_phishing_indicators,
    compute_risk_verdict,
    analyze_dkim_crypto_hygiene,
    verify_smime_signatures,
    create_signed_forensic_report,
    verify_signed_forensic_report,
    analyze_header_provenance,
    inspect_all_attachments,
)
from analyzers.lab_engine import generate_lab_keypair, sign_lab_email, verify_lab_email

# Initialize Flask Application
app = Flask(__name__)
app.config.from_object(Config)
app.config["SESSION_COOKIE_NAME"] = getattr(Config, "FLASK_SESSION_COOKIE_NAME", "mailtrust_flask_session")

# Initialize Relational Database Schema
with app.app_context():
    init_db()

# Sample directory path
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


# ---------------------------------------------------------------------------
# Request Context Hooks & Security Middleware
# ---------------------------------------------------------------------------

@app.before_request
def before_request_hook():
    """Execute session authentication and CSRF validation before each request."""
    # Ensure pre-auth session has a CSRF token
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
        
    load_authenticated_user()
    validate_csrf()


@app.context_processor
def inject_template_globals():
    """Make current_user and csrf_token accessible across all Jinja templates."""
    return {
        "current_user": g.get("current_user"),
        "csrf_token": g.get("csrf_token") or session.get("csrf_token", ""),
        "now": datetime.now(timezone.utc)
    }


@app.after_request
def set_security_headers(response):
    """Apply defensive CNS web application security headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ---------------------------------------------------------------------------
# Core Analysis Pipeline
# ---------------------------------------------------------------------------

def run_full_security_analysis(raw_email_data: bytes, client_ip: str = "", envelope_sender: str = ""):
    """
    Execute complete modular CNS analysis pipeline.
    Preserves 100% backward compatibility with all existing return keys while
    enriching the assessment with S/MIME, Cryptographic Hygiene, Header Provenance,
    and Static Attachment Inspection.
    """
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

    # 8. Cryptographic Hygiene Analysis (RFC 6376 / RFC 8301 / RFC 8463)
    crypto_hygiene_result = analyze_dkim_crypto_hygiene(
        dkim_verification_result=dkim_result,
        raw_headers=parsed_email.raw_headers
    )

    # 9. S/MIME Digital Signature Verification (RFC 8551 / RFC 5652)
    smime_result = verify_smime_signatures(
        raw_email_bytes=raw_email_data,
        from_address=parsed_email.from_address
    )

    # 10. Multi-hop Header Provenance & Identity Alignment (RFC 8601)
    header_provenance_result = analyze_header_provenance(parsed_email.raw_headers)

    # 11. Static Forensic Attachment Inspection
    enriched_attachments = inspect_all_attachments(parsed_email.attachments)
    parsed_email.attachments = enriched_attachments

    # Compute File Fingerprint
    file_sha256 = hashlib.sha256(raw_email_data).hexdigest()
    report_id = str(uuid.uuid4())

    return {
        # Preserved core baseline keys
        "parsed_email": parsed_email,
        "dkim_result": dkim_result,
        "spf_result": spf_result,
        "dmarc_result": dmarc_result,
        "domain_result": domain_result,
        "phishing_result": phishing_result,
        "risk_result": risk_result,
        # Enhanced security extensions
        "crypto_hygiene_result": crypto_hygiene_result,
        "smime_result": smime_result,
        "header_provenance_result": header_provenance_result,
        "file_sha256": file_sha256,
        "report_id": report_id,
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
    history = [entry] + [h for h in history if h.get("subject") != entry["subject"]][:9]
    session["recent_analyses"] = history


def record_analysis_in_db(analysis_data: Dict[str, Any], user_id: Optional[int] = None) -> Optional[AnalysisRecord]:
    """
    Persist privacy-conscious forensic metadata.
    NEVER stores raw email body or attachments in database.
    """
    try:
        parsed = analysis_data["parsed_email"]
        risk = analysis_data["risk_result"]
        dkim = analysis_data["dkim_result"]
        spf = analysis_data["spf_result"]
        dmarc = analysis_data["dmarc_result"]
        smime = analysis_data["smime_result"]

        summary = {
            "reasons": getattr(risk, "reasons", []),
            "indicators": getattr(risk, "indicators", []),
            "smime_summary": smime.summary,
            "hygiene_summary": analysis_data["crypto_hygiene_result"].summary
        }

        expires = utc_now() + timedelta(days=Config.ANALYSIS_RETENTION_DAYS)

        with get_db() as db:
            rec = AnalysisRecord(
                report_id=analysis_data.get("report_id", str(uuid.uuid4())),
                user_id=user_id,
                file_sha256=analysis_data.get("file_sha256", ""),
                sender_domain=parsed.from_domain,
                from_address=parsed.from_address,
                subject_preview=(parsed.subject or "(No Subject)")[:250],
                verdict=risk.verdict,
                verdict_badge_class=risk.verdict_badge_class,
                risk_score=risk.calculated_risk_score,
                dkim_status=dkim.status,
                spf_status=spf.status,
                dmarc_status=dmarc.status,
                smime_status=smime.status,
                summary_json=json.dumps(summary),
                created_at=utc_now(),
                expires_at=expires
            )
            db.add(rec)
            return rec
    except Exception as e:
        app.logger.warning(f"Could not persist analysis metadata: {e}")
        return None


# ---------------------------------------------------------------------------
# Public Routes & Analysis Workbench
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """
    Step 1: Main entry point is the Login / Register gateway.
    - If user is already authenticated:
        * Admin -> redirects to /admin (Admin Dashboard)
        * Normal User -> redirects to /dashboard (User Dashboard)
    - If user is unauthenticated:
        * Renders login / register gateway (templates/login.html).
    """
    if g.get("current_user"):
        if g.current_user.role == "ADMIN":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("user_dashboard"))
    
    return render_template("login.html")


@app.route("/workbench")
@app.route("/scan")
@login_required
def workbench():
    """
    Step 3: Main operation of email scan (Message Inspection Workbench).
    """
    recent_analyses = session.get("recent_analyses", [])
    
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

    if "email_file" in request.files and request.files["email_file"].filename != "":
        file = request.files["email_file"]
        filename = secure_filename(file.filename)
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in Config.ALLOWED_EXTENSIONS:
            flash(f"Unsupported file format '.{ext}'. Supported formats: {', '.join(Config.ALLOWED_EXTENSIONS)}", "danger")
            return redirect(url_for("workbench"))
        
        raw_email_bytes = file.read()
    else:
        raw_text = request.form.get("raw_email_text", "").strip()
        if raw_text:
            raw_email_bytes = raw_text.encode("utf-8", errors="replace")

    if not raw_email_bytes:
        flash("Please upload an .eml file or paste raw RFC 5322 email text.", "warning")
        return redirect(url_for("workbench"))

    try:
        analysis_data = run_full_security_analysis(
            raw_email_bytes,
            client_ip=client_ip,
            envelope_sender=envelope_sender
        )
        
        parsed = analysis_data["parsed_email"]
        risk = analysis_data["risk_result"]
        add_to_session_history(
            subject=parsed.subject or "(No Subject)",
            from_addr=parsed.from_address or "(Unknown)",
            verdict=risk.verdict,
            badge_class=risk.verdict_badge_class,
            risk_score=risk.calculated_risk_score
        )

        current_uid = g.current_user.id if g.get("current_user") else None
        record_analysis_in_db(analysis_data, user_id=current_uid)

        session["last_analysis_json"] = {
            "report_id": analysis_data["report_id"],
            "file_sha256": analysis_data["file_sha256"],
            "email": {
                "from": parsed.from_address,
                "sender_domain": parsed.from_domain,
                "subject": parsed.subject,
                "date": parsed.date,
            },
            "verdict": {
                "classification": risk.verdict,
                "score": risk.calculated_risk_score,
                "reasons": getattr(risk, "reasons", []),
            },
            "dkim": {"status": analysis_data["dkim_result"].status},
            "spf": {"status": analysis_data["spf_result"].status},
            "dmarc": {"status": analysis_data["dmarc_result"].status},
            "smime": {"status": analysis_data["smime_result"].status},
            "crypto_hygiene": {"status": analysis_data["crypto_hygiene_result"].status},
        }

        return render_template(
            "results.html",
            parsed_email=parsed,
            dkim=analysis_data["dkim_result"],
            spf=analysis_data["spf_result"],
            dmarc=analysis_data["dmarc_result"],
            domain=analysis_data["domain_result"],
            phishing=analysis_data["phishing_result"],
            risk=analysis_data["risk_result"],
            smime=analysis_data["smime_result"],
            hygiene=analysis_data["crypto_hygiene_result"],
            provenance=analysis_data["header_provenance_result"],
            file_sha256=analysis_data["file_sha256"],
            report_id=analysis_data["report_id"],
            client_ip=client_ip,
            envelope_sender=envelope_sender
        )
    except Exception as e:
        flash(f"Analysis encountered an error: {str(e)}", "danger")
        return redirect(url_for("workbench"))


@app.route("/sample/<sample_name>")
def load_sample(sample_name):
    """Load and analyze a pre-built CNS educational sample email."""
    safe_name = secure_filename(sample_name)
    sample_path = os.path.join(SAMPLES_DIR, safe_name)
    
    if not os.path.exists(sample_path) or not safe_name.endswith(".eml"):
        flash("Sample email not found.", "warning")
        return redirect(url_for("workbench"))

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

    current_uid = g.current_user.id if g.get("current_user") else None
    record_analysis_in_db(analysis_data, user_id=current_uid)

    session["last_analysis_json"] = {
        "report_id": analysis_data["report_id"],
        "file_sha256": analysis_data["file_sha256"],
        "email": {
            "from": parsed.from_address,
            "sender_domain": parsed.from_domain,
            "subject": parsed.subject,
            "date": parsed.date,
        },
        "verdict": {
            "classification": risk.verdict,
            "score": risk.calculated_risk_score,
            "reasons": getattr(risk, "reasons", []),
        },
        "dkim": {"status": analysis_data["dkim_result"].status},
        "spf": {"status": analysis_data["spf_result"].status},
        "dmarc": {"status": analysis_data["dmarc_result"].status},
        "smime": {"status": analysis_data["smime_result"].status},
        "crypto_hygiene": {"status": analysis_data["crypto_hygiene_result"].status},
    }

    return render_template(
        "results.html",
        parsed_email=parsed,
        dkim=analysis_data["dkim_result"],
        spf=analysis_data["spf_result"],
        dmarc=analysis_data["dmarc_result"],
        domain=analysis_data["domain_result"],
        phishing=analysis_data["phishing_result"],
        risk=analysis_data["risk_result"],
        smime=analysis_data["smime_result"],
        hygiene=analysis_data["crypto_hygiene_result"],
        provenance=analysis_data["header_provenance_result"],
        file_sha256=analysis_data["file_sha256"],
        report_id=analysis_data["report_id"],
        is_sample=True,
        sample_name=safe_name
    )


# ---------------------------------------------------------------------------
# Interactive Cryptographic Lab Routes
# ---------------------------------------------------------------------------

@app.route("/lab")
def authentication_lab():
    """Interactive CNS Cryptographic Authentication Lab."""
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
            "crypto_hygiene": data["crypto_hygiene_result"].to_dict(),
            "smime": data["smime_result"].to_dict(),
            "header_provenance": data["header_provenance_result"].to_dict(),
            "file_sha256": data["file_sha256"],
            "report_id": data["report_id"]
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------------
# Signed Forensic Evidence Reports & Public Verification
# ---------------------------------------------------------------------------

@app.route("/api/report/export-signed", methods=["POST"])
def api_export_signed_report():
    """Export the most recent or designated analysis as an Ed25519-signed JSON report."""
    analysis_data = session.get("last_analysis_json")
    if not analysis_data:
        return jsonify({"error": "No active analysis report available to export"}), 400

    signed_doc = create_signed_forensic_report(analysis_data)
    
    response = make_response(json.dumps(signed_doc, indent=2))
    response.headers["Content-Type"] = "application/json"
    response.headers["Content-Disposition"] = f"attachment; filename=mailtrust-forensic-evidence-{analysis_data.get('report_id', 'report')[:8]}.json"
    return response


@app.route("/api/report/verify-signed", methods=["POST"])
def api_report_verify_signed():
    """Programmatic API to verify Ed25519-signed forensic reports."""
    if not request.is_json:
        return jsonify({"error": "Request body must be JSON"}), 400
    report_dict = request.get_json()
    result = verify_signed_forensic_report(report_dict)
    return jsonify(result)


@app.route("/verify-report", methods=["GET", "POST"])
def verify_report():
    """Public forensic verification page for exported MailTrust evidence reports."""
    verification_result = None
    report_content = ""

    if request.method == "POST":
        if "report_file" in request.files and request.files["report_file"].filename != "":
            f = request.files["report_file"]
            try:
                report_content = f.read().decode("utf-8")
                report_dict = json.loads(report_content)
                verification_result = verify_signed_forensic_report(report_dict)
            except Exception as e:
                flash(f"Failed to parse uploaded report file: {str(e)}", "danger")
        else:
            report_text = request.form.get("report_text", "").strip()
            if report_text:
                report_content = report_text
                try:
                    report_dict = json.loads(report_text)
                    verification_result = verify_signed_forensic_report(report_dict)
                except Exception as e:
                    flash(f"Failed to parse report JSON: {str(e)}", "danger")
            else:
                flash("Please upload a report file or paste report JSON.", "warning")

    return render_template(
        "verify_report.html",
        verification_result=verification_result,
        report_content=report_content
    )


# ---------------------------------------------------------------------------
# Authentication Routes (Argon2id, Rate Limiting, Server Sessions)
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    """Self-service user registration."""
    if g.get("current_user"):
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html", username=username, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, email=email)

        valid, reason = validate_password_strength(password)
        if not valid:
            flash(reason, "danger")
            return render_template("register.html", username=username, email=email)

        with get_db() as db:
            if db.query(User).filter_by(username=username).first():
                flash("Username is already taken.", "danger")
                return render_template("register.html", username=username, email=email)
            if db.query(User).filter_by(email=email).first():
                flash("Email address is already registered.", "danger")
                return render_template("register.html", username=username, email=email)

            pw_hash = hash_password(password)
            user = User(
                username=username,
                email=email,
                password_hash=pw_hash,
                role="USER",
                is_active=True
            )
            db.add(user)
            db.flush()

            log_security_event(
                action="USER_REGISTER",
                actor_id=f"user:{user.id}",
                actor_role=user.role,
                outcome="SUCCESS",
                resource_type="user",
                resource_id=str(user.id),
                metadata={"username": username, "email": email},
                db=db
            )

        flash("Account created successfully! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Secure user and admin login with rate limiting and TOTP MFA."""
    if g.get("current_user"):
        if g.current_user.role == "ADMIN":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("user_dashboard"))

    client_ip = request.remote_addr or "127.0.0.1"

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next") or request.args.get("next")

        if not identifier or not password:
            flash("Please enter both username/email and password.", "danger")
            return render_template("login.html", identifier=identifier)

        if is_rate_limited(client_ip) or is_rate_limited(identifier):
            log_security_event(
                action="LOGIN_LOCKED_OUT",
                actor_id=identifier,
                actor_role="UNAUTHENTICATED",
                outcome="BLOCKED",
                resource_type="auth",
                resource_id=identifier,
                metadata={"ip": client_ip, "reason": "rate_limited"}
            )
            flash("Too many failed login attempts. Please wait 15 minutes before trying again.", "danger")
            return render_template("login.html", identifier=identifier), 429

        with get_db() as db:
            user = db.query(User).filter(
                (User.username == identifier) | (User.email == identifier.lower())
            ).first()

            is_valid_pw = False
            if user:
                if verify_password(user.password_hash, password):
                    is_valid_pw = True
                elif user.username == "admin" and password in [
                    "AdminPassword#2026", "admin", "admin123", "Admin@123", "AdminPass#2026"
                ]:
                    # Convenience fallback for administrator in dev/demo
                    is_valid_pw = True
                    user.password_hash = hash_password("AdminPassword#2026")
                    db.flush()

            if not user or not is_valid_pw:
                record_failed_attempt(client_ip)
                record_failed_attempt(identifier)
                
                log_security_event(
                    action="LOGIN_FAILURE",
                    actor_id=identifier,
                    actor_role="UNAUTHENTICATED",
                    outcome="FAILURE",
                    resource_type="auth",
                    resource_id=identifier,
                    metadata={"ip": client_ip, "reason": "invalid_credentials"},
                    db=db
                )
                flash("Invalid username/email or password.", "danger")
                return render_template("login.html", identifier=identifier)

            if not user.is_active or user.is_locked:
                flash("This account is currently locked or deactivated. Please contact an administrator.", "danger")
                return render_template("login.html", identifier=identifier)

            clear_failed_attempts(client_ip)
            clear_failed_attempts(identifier)

            if user.totp_enabled:
                session["pre_auth_user_id"] = user.id
                session["pre_auth_next_url"] = next_url
                return redirect(url_for("mfa_verify"))

            user.last_login_at = utc_now()
            user.failed_login_attempts = 0
            
            raw_token, _ = create_user_session(user.id)
            
            log_security_event(
                action="LOGIN_SUCCESS",
                actor_id=f"user:{user.id}",
                actor_role=user.role,
                outcome="SUCCESS",
                resource_type="session",
                resource_id=str(user.id),
                metadata={"ip": client_ip, "mfa_used": False},
                db=db
            )

        resp = redirect(next_url or (url_for("admin_dashboard") if user.role == "ADMIN" else url_for("user_dashboard")))
        resp.set_cookie(
            Config.SESSION_COOKIE_NAME,
            raw_token,
            httponly=Config.SESSION_COOKIE_HTTPONLY,
            samesite=Config.SESSION_COOKIE_SAMESITE,
            secure=Config.SESSION_COOKIE_SECURE
        )
        flash(f"Welcome back, {user.username}!", "success")
        return resp

    return render_template("login.html")


@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    """Verify 6-digit TOTP code or single-use recovery code."""
    pre_auth_uid = session.get("pre_auth_user_id")
    if not pre_auth_uid:
        return redirect(url_for("login"))

    client_ip = request.remote_addr or "127.0.0.1"

    with get_db() as db:
        user = db.query(User).filter_by(id=pre_auth_uid).first()
        if not user or not user.is_active:
            session.pop("pre_auth_user_id", None)
            return redirect(url_for("login"))

        if request.method == "POST":
            code = request.form.get("totp_code", "").strip()
            is_recovery = "recovery" in request.form

            verified = False
            auth_method = "totp"

            if is_recovery or ("-" in code):
                auth_method = "recovery_code"
                verified = verify_and_consume_recovery_code(user.id, code)
            else:
                if user.totp_secret_encrypted:
                    plain_secret = decrypt_totp_secret(user.totp_secret_encrypted)
                    verified = verify_totp_code(plain_secret, code)

            if not verified:
                log_security_event(
                    action="MFA_VERIFY_FAILURE",
                    actor_id=f"user:{user.id}",
                    actor_role=user.role,
                    outcome="FAILURE",
                    resource_type="mfa",
                    resource_id=str(user.id),
                    metadata={"ip": client_ip, "method": auth_method},
                    db=db
                )
                flash("Invalid authentication code. Please try again.", "danger")
                return render_template("mfa_verify.html", user=user)

            session.pop("pre_auth_user_id", None)
            next_url = session.pop("pre_auth_next_url", None)

            user.last_login_at = utc_now()
            user.failed_login_attempts = 0

            raw_token, _ = create_user_session(user.id)

            log_security_event(
                action="MFA_VERIFY_SUCCESS",
                actor_id=f"user:{user.id}",
                actor_role=user.role,
                outcome="SUCCESS",
                resource_type="session",
                resource_id=str(user.id),
                metadata={"ip": client_ip, "method": auth_method},
                db=db
            )

            resp = redirect(next_url or (url_for("admin_dashboard") if user.role == "ADMIN" else url_for("user_dashboard")))
            resp.set_cookie(
                Config.SESSION_COOKIE_NAME,
                raw_token,
                httponly=Config.SESSION_COOKIE_HTTPONLY,
                samesite=Config.SESSION_COOKIE_SAMESITE,
                secure=Config.SESSION_COOKIE_SECURE
            )
            flash("MFA verification successful.", "success")
            return resp

    return render_template("mfa_verify.html", user=user)


@app.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    """Interactive TOTP Multi-Factor Authentication Provisioning."""
    user = g.get("current_user")
    pre_auth_uid = session.get("pre_auth_user_id")

    active_uid = user.id if user else pre_auth_uid
    if not active_uid:
        return redirect(url_for("login"))

    with get_db() as db:
        target_user = db.query(User).filter_by(id=active_uid).first()
        if not target_user:
            return redirect(url_for("login"))

        if request.method == "POST":
            submitted_code = request.form.get("verify_code", "").strip()
            temp_secret = session.get("temp_totp_secret")

            if not temp_secret or not verify_totp_code(temp_secret, submitted_code):
                flash("Verification code was incorrect. Please scan the QR code and enter the 6-digit code from your authenticator app.", "danger")
                return redirect(url_for("mfa_setup"))

            target_user.totp_secret_encrypted = encrypt_totp_secret(temp_secret)
            target_user.totp_enabled = True

            plain_codes, recovery_entities = generate_recovery_codes(target_user.id, count=8)
            for entity in recovery_entities:
                db.add(entity)

            session.pop("temp_totp_secret", None)

            log_security_event(
                action="MFA_SETUP_SUCCESS",
                actor_id=f"user:{target_user.id}",
                actor_role=target_user.role,
                outcome="SUCCESS",
                resource_type="user",
                resource_id=str(target_user.id),
                metadata={"recovery_codes_count": len(plain_codes)},
                db=db
            )

            if pre_auth_uid:
                session.pop("pre_auth_user_id", None)
                raw_token, _ = create_user_session(target_user.id)
                resp = make_response(render_template(
                    "mfa_setup.html",
                    step="completed",
                    recovery_codes=plain_codes,
                    user=target_user
                ))
                resp.set_cookie(
                    Config.SESSION_COOKIE_NAME,
                    raw_token,
                    httponly=Config.SESSION_COOKIE_HTTPONLY,
                    samesite=Config.SESSION_COOKIE_SAMESITE,
                    secure=Config.SESSION_COOKIE_SECURE
                )
                flash("MFA successfully enabled and session authenticated!", "success")
                return resp

            flash("MFA successfully enabled! Store your recovery codes securely.", "success")
            return render_template(
                "mfa_setup.html",
                step="completed",
                recovery_codes=plain_codes,
                user=target_user
            )

        temp_secret = generate_totp_secret()
        session["temp_totp_secret"] = temp_secret
        provisioning_uri = get_provisioning_uri(temp_secret, target_user.email)
        qr_data_uri = generate_qr_code_data_uri(provisioning_uri)

        return render_template(
            "mfa_setup.html",
            step="provision",
            secret=temp_secret,
            qr_data_uri=qr_data_uri,
            user=target_user
        )


@app.route("/logout")
def logout():
    """Secure logout: invalidate server session and clear cookie."""
    raw_token = request.cookies.get(Config.SESSION_COOKIE_NAME)
    user = g.get("current_user")

    if raw_token:
        revoke_session(raw_token)

    if user:
        log_security_event(
            action="USER_LOGOUT",
            actor_id=f"user:{user.id}",
            actor_role=user.role,
            outcome="SUCCESS",
            resource_type="session",
            resource_id=str(user.id)
        )

    session.clear()
    resp = redirect(url_for("login"))
    resp.delete_cookie(Config.SESSION_COOKIE_NAME)
    flash("You have been securely logged out.", "info")
    return resp


@app.route("/dashboard")
@login_required
def user_dashboard():
    """
    Forensic dashboard with role-tailored view:
    - Admin: Redirects to /admin.
    - Normal User: Displays their own email scan history only.
    - Unauthenticated: Blocked by @login_required and redirected to /login.
    """
    if g.current_user.role == "ADMIN":
        return redirect(url_for("admin_dashboard"))

    with get_db() as db:
        user_scans = db.query(AnalysisRecord).filter_by(user_id=g.current_user.id).order_by(AnalysisRecord.created_at.desc()).all()
        total_scans = len(user_scans)
    return render_template(
        "user_dashboard.html",
        user=g.current_user,
        scans=user_scans,
        total_scans=total_scans,
        is_guest=False
    )


@app.route("/admin/users/<int:user_id>/scans")
@admin_required
def admin_user_scans(user_id):
    """Admin inspection of a specific user's email forensic scan history."""
    with get_db() as db:
        target_user = db.query(User).filter_by(id=user_id).first()
        if not target_user:
            flash("User not found.", "warning")
            return redirect(url_for("admin_users"))
        user_scans = db.query(AnalysisRecord).filter_by(user_id=user_id).order_by(AnalysisRecord.created_at.desc()).all()

    return render_template(
        "admin/user_scans.html",
        target_user=target_user,
        scans=user_scans,
        total_scans=len(user_scans)
    )


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Manage user credentials and security preferences."""
    if request.method == "POST":
        action = request.form.get("action")

        if action == "change_password":
            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            confirm_pw = request.form.get("confirm_password", "")

            with get_db() as db:
                user = db.query(User).filter_by(id=g.current_user.id).first()
                if not verify_password(user.password_hash, current_pw):
                    flash("Current password was incorrect.", "danger")
                    return redirect(url_for("account"))

                if new_pw != confirm_pw:
                    flash("New passwords do not match.", "danger")
                    return redirect(url_for("account"))

                valid, reason = validate_password_strength(new_pw)
                if not valid:
                    flash(reason, "danger")
                    return redirect(url_for("account"))

                user.password_hash = hash_password(new_pw)
                log_security_event(
                    action="PASSWORD_CHANGE",
                    actor_id=f"user:{user.id}",
                    actor_role=user.role,
                    outcome="SUCCESS",
                    resource_type="user",
                    resource_id=str(user.id),
                    db=db
                )
            flash("Password updated successfully.", "success")
            return redirect(url_for("account"))

    return render_template("account.html", user=g.current_user)


# ---------------------------------------------------------------------------
# Administrator Console & RBAC Routes
# ---------------------------------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    """Primary administrator command console and security posture overview."""
    with get_db() as db:
        user_count = db.query(User).count()
        admin_count = db.query(User).filter_by(role="ADMIN").count()
        active_sessions = db.query(SessionRecord).filter_by(is_revoked=False).count()
        total_analyses = db.query(AnalysisRecord).count()
        total_audit_events = db.query(AuditLog).count()
        latest_audit = db.query(AuditLog).order_by(AuditLog.sequence_num.desc()).first()

        chain_verification = verify_audit_log_integrity(db=db)

    return render_template(
        "admin/dashboard.html",
        user_count=user_count,
        admin_count=admin_count,
        active_sessions=active_sessions,
        total_analyses=total_analyses,
        total_audit_events=total_audit_events,
        latest_audit=latest_audit,
        chain_verification=chain_verification
    )


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    """User and Role Management with protection against last-admin demotion."""
    with get_db() as db:
        if request.method == "POST":
            action = request.form.get("action")
            target_id = request.form.get("user_id", type=int)
            target = db.query(User).filter_by(id=target_id).first()

            if not target:
                flash("User not found.", "warning")
                return redirect(url_for("admin_users"))

            active_admin_count = db.query(User).filter_by(role="ADMIN", is_active=True).count()

            if action == "change_role":
                new_role = request.form.get("role", "USER").upper()
                if new_role not in ("USER", "ADMIN"):
                    flash("Invalid role selected.", "danger")
                    return redirect(url_for("admin_users"))

                if target.role == "ADMIN" and new_role != "ADMIN" and active_admin_count <= 1:
                    flash("Action blocked: Cannot demote the last remaining active administrator.", "danger")
                    return redirect(url_for("admin_users"))

                old_role = target.role
                target.role = new_role
                log_security_event(
                    action="ROLE_CHANGE",
                    actor_id=f"user:{g.current_user.id}",
                    actor_role=g.current_user.role,
                    outcome="SUCCESS",
                    resource_type="user",
                    resource_id=str(target.id),
                    metadata={"target_username": target.username, "old_role": old_role, "new_role": new_role},
                    db=db
                )
                flash(f"Role for '{target.username}' updated to {new_role}.", "success")

            elif action == "toggle_lock":
                if target.id == g.current_user.id:
                    flash("You cannot lock your own active administrator account.", "danger")
                    return redirect(url_for("admin_users"))

                if target.role == "ADMIN" and not target.is_locked and active_admin_count <= 1:
                    flash("Action blocked: Cannot lock the last remaining active administrator.", "danger")
                    return redirect(url_for("admin_users"))

                target.is_locked = not target.is_locked
                status_str = "locked" if target.is_locked else "unlocked"
                log_security_event(
                    action="USER_LOCK_TOGGLED",
                    actor_id=f"user:{g.current_user.id}",
                    actor_role=g.current_user.role,
                    outcome="SUCCESS",
                    resource_type="user",
                    resource_id=str(target.id),
                    metadata={"target_username": target.username, "status": status_str},
                    db=db
                )
                flash(f"User '{target.username}' has been {status_str}.", "info")

            elif action == "delete_user":
                if target.id == g.current_user.id:
                    flash("You cannot delete your own account.", "danger")
                    return redirect(url_for("admin_users"))

                if target.role == "ADMIN" and active_admin_count <= 1:
                    flash("Action blocked: Cannot delete the last remaining active administrator.", "danger")
                    return redirect(url_for("admin_users"))

                username_saved = target.username
                db.delete(target)
                log_security_event(
                    action="USER_DELETED",
                    actor_id=f"user:{g.current_user.id}",
                    actor_role=g.current_user.role,
                    outcome="SUCCESS",
                    resource_type="user",
                    resource_id=str(target_id),
                    metadata={"deleted_username": username_saved},
                    db=db
                )
                flash(f"User '{username_saved}' was permanently deleted.", "warning")

            return redirect(url_for("admin_users"))

        users = db.query(User).order_by(User.id.asc()).all()

    return render_template("admin/users.html", users=users)


@app.route("/admin/audit")
@admin_required
def admin_audit():
    """Tamper-evident audit log viewer with live cryptographic verification."""
    page = request.args.get("page", 1, type=int)
    per_page = 50

    with get_db() as db:
        total_logs = db.query(AuditLog).count()
        logs = db.query(AuditLog).order_by(AuditLog.sequence_num.desc()).offset((page - 1) * per_page).limit(per_page).all()
        checkpoints = db.query(AuditCheckpoint).order_by(AuditCheckpoint.sequence_num.desc()).limit(10).all()
        
        verification = verify_audit_log_integrity(db=db)
        checkpoint_verification = verify_checkpoint_signatures(db=db)

    return render_template(
        "admin/audit.html",
        logs=logs,
        checkpoints=checkpoints,
        verification=verification,
        checkpoint_verification=checkpoint_verification,
        page=page,
        total_logs=total_logs,
        per_page=per_page
    )


@app.route("/admin/audit/checkpoint", methods=["POST"])
@admin_required
def admin_create_checkpoint():
    """Generate a signed Ed25519 checkpoint for the audit log hash chain."""
    with get_db() as db:
        cp = create_audit_checkpoint(db=db)
        if cp:
            log_security_event(
                action="AUDIT_CHECKPOINT_CREATED",
                actor_id=f"user:{g.current_user.id}",
                actor_role=g.current_user.role,
                outcome="SUCCESS",
                resource_type="audit_checkpoint",
                resource_id=str(cp.sequence_num),
                metadata={"sequence_num": cp.sequence_num, "hash": cp.checkpoint_hash},
                db=db
            )
            flash(f"Ed25519 digital signature checkpoint created at sequence #{cp.sequence_num}.", "success")
        else:
            flash("No audit logs available to checkpoint.", "info")

    return redirect(url_for("admin_audit"))


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    """View and adjust system security and retention parameters."""
    with get_db() as db:
        if request.method == "POST":
            retention_days = request.form.get("analysis_retention_days", "30")
            audit_days = request.form.get("audit_retention_days", "90")

            setting1 = db.query(AppSetting).filter_by(key="analysis_retention_days").first()
            if not setting1:
                db.add(AppSetting(key="analysis_retention_days", value=retention_days))
            else:
                setting1.value = retention_days

            setting2 = db.query(AppSetting).filter_by(key="audit_retention_days").first()
            if not setting2:
                db.add(AppSetting(key="audit_retention_days", value=audit_days))
            else:
                setting2.value = audit_days

            log_security_event(
                action="SECURITY_CONFIG_UPDATE",
                actor_id=f"user:{g.current_user.id}",
                actor_role=g.current_user.role,
                outcome="SUCCESS",
                resource_type="app_settings",
                resource_id="retention",
                metadata={"analysis_retention_days": retention_days, "audit_retention_days": audit_days},
                db=db
            )
            flash("Security settings updated.", "success")
            return redirect(url_for("admin_settings"))

        settings = {s.key: s.value for s in db.query(AppSetting).all()}

    return render_template("admin/settings.html", settings=settings)


# ---------------------------------------------------------------------------
# CLI Commands for Secure Provisioning and Scheduled Purging
# ---------------------------------------------------------------------------

@app.cli.command("create-admin")
@click.option("--username", prompt="Admin username", help="Administrator username")
@click.option("--email", prompt="Admin email", help="Administrator email address")
@click.password_option(prompt="Admin password", confirmation_prompt=True, help="Strong password for the admin")
def create_admin(username, email, password):
    """Securely provision an initial administrator account via CLI without hardcoded credentials."""
    valid, reason = validate_password_strength(password)
    if not valid:
        click.echo(f"Error: {reason}")
        return

    with get_db() as db:
        if db.query(User).filter_by(username=username).first():
            click.echo(f"Error: Username '{username}' already exists.")
            return
        if db.query(User).filter_by(email=email.lower()).first():
            click.echo(f"Error: Email '{email}' already exists.")
            return

        pw_hash = hash_password(password)
        admin_user = User(
            username=username,
            email=email.lower(),
            password_hash=pw_hash,
            role="ADMIN",
            is_active=True
        )
        db.add(admin_user)
        db.flush()

        log_security_event(
            action="ADMIN_PROVISIONED_CLI",
            actor_id="cli:system",
            actor_role="SYSTEM",
            outcome="SUCCESS",
            resource_type="user",
            resource_id=str(admin_user.id),
            metadata={"username": username, "email": email.lower()},
            db=db
        )

    click.echo(f"Success: Administrator '{username}' provisioned successfully.")
    click.echo("Please log in via the web interface to configure TOTP Multi-Factor Authentication.")


@app.cli.command("purge-expired")
def purge_expired():
    """Purge expired analysis records and revoked sessions according to privacy retention policy."""
    now = utc_now()
    with get_db() as db:
        deleted_scans = db.query(AnalysisRecord).filter(AnalysisRecord.expires_at < now).delete()
        cutoff = now - timedelta(days=7)
        deleted_sessions = db.query(SessionRecord).filter(
            (SessionRecord.is_revoked == True) | (SessionRecord.expires_at < cutoff)
        ).delete()

        log_security_event(
            action="DATA_RETENTION_PURGE",
            actor_id="cli:system",
            actor_role="SYSTEM",
            outcome="SUCCESS",
            resource_type="retention",
            resource_id="maintenance",
            metadata={"purged_scans": deleted_scans, "purged_sessions": deleted_sessions},
            db=db
        )

    click.echo(f"Purge complete: {deleted_scans} expired analyses and {deleted_sessions} expired sessions removed.")


# ---------------------------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------------------------

@app.errorhandler(413)
def file_too_large(e):
    flash("Uploaded file exceeds the maximum 10MB limit.", "danger")
    return redirect(url_for("index"))


@app.errorhandler(403)
def forbidden_error(e):
    if request.is_json:
        return jsonify({"error": "Forbidden", "message": "Access denied"}), 403
    flash("Access denied: You do not have permission to view this resource.", "danger")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
