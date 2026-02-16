"""
Tests for audit logging (M13). No tokens or passwords in audit records.
"""
import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("AUTH_DATABASE_URL", "sqlite:///:memory:")

from auth_server.audit import EVENT_LOGIN_FAIL
from auth_server.database import SessionLocal, init_db
from auth_server.main import app
from auth_server.models import AuditLog, Client, User
from auth_server.seed import hash_password


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seeded(client):
    init_db()
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == "audituser").first() is None:
            db.add(User(username="audituser", password_hash=hash_password("auditpass")))
        if db.query(Client).filter(Client.client_id == "test-client").first() is None:
            import json
            db.add(
                Client(
                    client_id="test-client",
                    redirect_uris=json.dumps(["http://127.0.0.1:8000/callback"]),
                )
            )
        db.commit()
        yield db
    finally:
        db.close()


def test_audit_login_fail_recorded(client, seeded):
    """Failed login records login_fail in audit log."""
    client.post(
        "/authorize",
        data={
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "scope": "api.read",
            "state": "s",
            "response_type": "code",
            "username": "audituser",
            "password": "wrong",
            "code_challenge": "x",
            "code_challenge_method": "S256",
        },
    )
    db = SessionLocal()
    try:
        row = db.query(AuditLog).filter(AuditLog.event_type == EVENT_LOGIN_FAIL).order_by(AuditLog.id.desc()).first()
        assert row is not None
        assert row.client_id == "test-client"
        assert row.outcome == "fail"
    finally:
        db.close()


def test_audit_get_audit_returns_recent(client, seeded):
    """GET /audit returns recent audit entries (no token/password fields)."""
    client.post(
        "/authorize",
        data={
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "scope": "api.read",
            "state": "s",
            "response_type": "code",
            "username": "audituser",
            "password": "wrong",
            "code_challenge": "x",
            "code_challenge_method": "S256",
        },
    )
    r = client.get("/audit")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    entry = data[0]
    assert "event_type" in entry
    assert "created_at" in entry
    assert "client_id" in entry
    assert "outcome" in entry
    assert entry["event_type"] == EVENT_LOGIN_FAIL
    assert "token" not in str(entry).lower() and "password" not in str(entry).lower()
