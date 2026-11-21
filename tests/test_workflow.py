"""
Test MailTrust 3-Step Workflow & Role-Based Navigation
Step 1: Application starts with Login / Register page
Step 2: According to role, user accesses role-specific Dashboard (Admin, Normal User, Guest Stateless)
Step 3: User launches Main Operation of Email Scan (Workbench at /workbench)
"""

import re
import pytest
from app import app
from database import get_db
from models import User
from security.auth import hash_password


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_step_1_start_page_is_login_register(client):
    """Step 1: Unauthenticated request to '/' displays the Login / Register gateway."""
    client.get("/logout")
    res = client.get("/")
    assert res.status_code == 200
    html = res.data.decode()
    assert "Sign In" in html
    assert "MailTrust" in html
    assert "Know which emails you can trust." in html
    assert "Educational CNS Scenarios" in html
    assert "Continue as Guest" in html
    assert "Default Administrator Account" in html


def test_step_2_guest_accesses_stateless_dashboard(client):
    """Step 2 (Guest): Accesses dashboard without credentials in stateless mode with 0 scan history."""
    client.get("/logout")
    res = client.get("/dashboard")
    assert res.status_code == 200
    html = res.data.decode()
    assert "Guest (Stateless)" in html or "Stateless" in html
    assert "Stateless Email Inspector" in html
    assert "Personal Forensic Scan History" not in html


def test_step_2_normal_user_accesses_user_dashboard(client):
    """Step 2 (User): Normal user logs in, accesses their personal scan dashboard, and '/' redirects to dashboard."""
    username = "workflow_user"
    email = "workflow_user@example.com"
    password = "WorkflowPass#2026"

    with get_db() as db:
        existing = db.query(User).filter((User.username == username) | (User.email == email)).first()
        if existing:
            db.delete(existing)
            db.flush()
        u = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role="USER",
            is_active=True
        )
        db.add(u)

    client.get("/logout")
    res_login_page = client.get("/login")
    m = re.search(r'name="csrf_token" value="([^"]+)"', res_login_page.data.decode())
    csrf = m.group(1) if m else ""

    res_login = client.post("/login", data={
        "csrf_token": csrf,
        "identifier": username,
        "password": password
    }, follow_redirects=True)
    assert res_login.status_code == 200
    assert "workflow_user" in res_login.data.decode()
    assert "Personal Forensic Scan History" in res_login.data.decode()

    # Authenticated user visiting '/' is auto-redirected to /dashboard
    res_root = client.get("/", follow_redirects=False)
    assert res_root.status_code == 302
    assert "/dashboard" in res_root.headers.get("Location", "")


def test_step_2_admin_accesses_admin_dashboard(client):
    """Step 2 (Admin): Admin logs in, accesses Admin Console (/admin), and '/' redirects to /admin."""
    client.get("/logout")
    res_login_page = client.get("/login")
    m = re.search(r'name="csrf_token" value="([^"]+)"', res_login_page.data.decode())
    csrf = m.group(1) if m else ""

    res_login = client.post("/login", data={
        "csrf_token": csrf,
        "identifier": "admin",
        "password": "AdminPassword#2026"
    }, follow_redirects=True)
    assert res_login.status_code == 200
    assert "Administrative Security Console" in res_login.data.decode()

    # Authenticated admin visiting '/' is auto-redirected to /admin
    res_root = client.get("/", follow_redirects=False)
    assert res_root.status_code == 302
    assert "/admin" in res_root.headers.get("Location", "")


def test_step_3_email_scan_workbench(client):
    """Step 3: Main operation of email scan (Message Inspection Workbench at /workbench)."""
    res = client.get("/workbench")
    assert res.status_code == 200
    html = res.data.decode()
    assert "Message Inspection Workbench" in html
    assert "Upload Message File (.EML)" in html
    assert "Educational CNS Scenarios" in html
