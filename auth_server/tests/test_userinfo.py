"""
Tests for GET /userinfo (OIDC UserInfo) and consent flow (Milestone 5).
"""
import hashlib
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from auth_server.database import SessionLocal, init_db
from auth_server.main import app
from auth_server.models import AuthorizationCode, Client, User
from auth_server.seed import hash_password


def _make_code_verifier_and_challenge():
    import secrets
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seeded(client):
    init_db()
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.username == "userinfouser").first()
        if not u:
            db.add(User(
                username="userinfouser",
                password_hash=hash_password("userinfopass"),
                name="Test User",
                email="test@example.com",
            ))
        else:
            u.name = "Test User"
            u.email = "test@example.com"
            db.commit()
        c = db.query(Client).filter(Client.client_id == "test-client").first()
        if not c:
            import json
            db.add(Client(client_id="test-client", redirect_uris=json.dumps(["http://127.0.0.1:8000/callback"])))
        db.commit()
        yield db
    finally:
        db.close()


def test_userinfo_no_bearer_returns_401(client, seeded):
    r = client.get("/userinfo")
    assert r.status_code == 401


def test_userinfo_invalid_token_returns_401(client, seeded):
    r = client.get("/userinfo", headers={"Authorization": "Bearer invalid.jwt.here"})
    assert r.status_code == 401


def test_userinfo_valid_token_returns_sub(client, seeded):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "userinfouser").first()
        user_id = user.id
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="userinfo-code-1",
            client_id="test-client",
            redirect_uri="http://127.0.0.1:8000/callback",
            user_id=user_id,
            scope="openid",
            code_challenge=challenge,
            code_challenge_method="S256",
            nonce=None,
            expires_at=expires,
        )
        db.add(auth_code)
        db.commit()
    finally:
        db.close()

    token_r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "userinfo-code-1",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert token_r.status_code == 200
    access_token = token_r.json()["access_token"]

    r = client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["sub"] == str(user_id)


def test_userinfo_profile_scope_returns_name_and_preferred_username(client, seeded):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "userinfouser").first()
        user_id = user.id
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="userinfo-code-2",
            client_id="test-client",
            redirect_uri="http://127.0.0.1:8000/callback",
            user_id=user_id,
            scope="openid profile",
            code_challenge=challenge,
            code_challenge_method="S256",
            nonce=None,
            expires_at=expires,
        )
        db.add(auth_code)
        db.commit()
    finally:
        db.close()

    token_r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "userinfo-code-2",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert token_r.status_code == 200
    access_token = token_r.json()["access_token"]

    r = client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["sub"] == str(user_id)
    assert data.get("preferred_username") == "userinfouser"
    assert data.get("name") == "Test User"


def test_userinfo_email_scope_returns_email(client, seeded):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "userinfouser").first()
        user_id = user.id
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="userinfo-code-3",
            client_id="test-client",
            redirect_uri="http://127.0.0.1:8000/callback",
            user_id=user_id,
            scope="openid email",
            code_challenge=challenge,
            code_challenge_method="S256",
            nonce=None,
            expires_at=expires,
        )
        db.add(auth_code)
        db.commit()
    finally:
        db.close()

    token_r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "userinfo-code-3",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert token_r.status_code == 200
    access_token = token_r.json()["access_token"]

    r = client.get("/userinfo", headers={"Authorization": f"Bearer {access_token}"})
    assert r.status_code == 200
    data = r.json()
    assert data["sub"] == str(user_id)
    assert data.get("email") == "test@example.com"
