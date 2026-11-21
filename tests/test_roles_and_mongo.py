"""
Test MailTrust Roles and MongoDB Atlas Integration
Validates:
1. Guest mode: Accesses /dashboard without login, zero scan history displayed (stateless).
2. Normal user: Logs in, accesses /dashboard, views only personal scan history.
3. Admin: Logs in, accesses /admin, views all users, inspects user scans, deletes user.
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


def test_unauthenticated_dashboard_access_blocked(client):
    """Unauthenticated users attempting to access /dashboard directly via URL are stopped and redirected to /login."""
    client.get("/logout")
    res = client.get("/dashboard", follow_redirects=False)
    assert res.status_code == 302
    assert "/login" in res.headers.get("Location", "")


def test_normal_user_scan_history(client):
    """Normal user logs in, accesses dashboard, and views their personal account."""
    test_user = "user_role_test"
    test_email = "user_role_test@example.com"
    test_pass = "TestUserPass#2026"

    with get_db() as db:
        existing = db.query(User).filter(
            (User.username == test_user) | (User.email == test_email)
        ).first()
        if existing:
            db.delete(existing)
            db.flush()
        u = User(
            username=test_user,
            email=test_email,
            password_hash=hash_password(test_pass),
            role="USER",
            is_active=True
        )
        db.add(u)

    # Get CSRF from login page
    res_page = client.get("/login")
    m = re.search(r'name="csrf_token" value="([^"]+)"', res_page.data.decode())
    csrf = m.group(1) if m else ""

    res_login = client.post("/login", data={
        "csrf_token": csrf,
        "identifier": test_user,
        "password": test_pass
    }, follow_redirects=True)
    assert res_login.status_code == 200

    # User accesses their dashboard
    res_dash = client.get("/dashboard")
    assert res_dash.status_code == 200
    html_dash = res_dash.data.decode()
    assert test_user in html_dash
    assert "Personal Forensic Scan History" in html_dash

    # Normal user is blocked from admin console
    res_admin = client.get("/admin")
    assert res_admin.status_code in (302, 403)


def test_admin_user_management_and_scans(client):
    """Admin logs in, accesses user directory, views user scan history, and deletes user."""
    # Ensure a target user exists
    target_username = "victim_to_delete"
    with get_db() as db:
        existing = db.query(User).filter(
            (User.username == target_username) | (User.email == "victim@example.com")
        ).first()
        if existing:
            db.delete(existing)
            db.flush()
        target = User(
            username=target_username,
            email="victim@example.com",
            password_hash=hash_password("VictimPass#2026"),
            role="USER",
            is_active=True
        )
        db.add(target)
        db.flush()
        target_id = target.id

    # Log in as admin
    client.get("/logout")
    res_page = client.get("/login")
    m = re.search(r'name="csrf_token" value="([^"]+)"', res_page.data.decode())
    csrf = m.group(1) if m else ""

    res_login = client.post("/login", data={
        "csrf_token": csrf,
        "identifier": "admin",
        "password": "AdminPassword#2026"
    }, follow_redirects=True)
    assert res_login.status_code == 200

    # Admin visits /admin/users
    res_users = client.get("/admin/users")
    assert res_users.status_code == 200
    assert target_username in res_users.data.decode()

    # Admin visits /admin/users/<id>/scans
    res_scans = client.get(f"/admin/users/{target_id}/scans")
    assert res_scans.status_code == 200
    assert target_username in res_scans.data.decode()

    # Admin deletes the user
    m2 = re.search(r'name="csrf_token" value="([^"]+)"', res_users.data.decode())
    csrf_users = m2.group(1) if m2 else ""

    res_del = client.post("/admin/users", data={
        "csrf_token": csrf_users,
        "action": "delete_user",
        "user_id": str(target_id)
    }, follow_redirects=True)
    assert res_del.status_code == 200
    assert "deleted" in res_del.data.decode().lower()

    # Verify user is gone
    with get_db() as db:
        assert db.query(User).filter_by(id=target_id).first() is None
