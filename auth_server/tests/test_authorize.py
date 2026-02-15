"""
Pytest tests for /authorize and login flow (Milestone 2).
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

# Ensure in-memory DB before importing app (conftest sets it; redundant here for clarity)
os.environ.setdefault("AUTH_DATABASE_URL", "sqlite:///:memory:")

from auth_server.database import SessionLocal, init_db
from auth_server.main import app
from auth_server.models import AuthorizationCode, Client, User
from auth_server.seed import hash_password, seed_from_env


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seeded_db(client):
    """Ensure tables exist and seed test user/client (lifespan may not have run yet)."""
    init_db()
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.username == "testuser").first()
        if not u:
            db.add(User(username="testuser", password_hash=hash_password("testpass")))
        c = db.query(Client).filter(Client.client_id == "test-client").first()
        if not c:
            db.add(Client(client_id="test-client", redirect_uris=json.dumps(["http://127.0.0.1:8000/callback"])))
        db.commit()
        yield db
    finally:
        db.close()


# --- GET /authorize validation ---


def test_authorize_get_missing_response_type(client, seeded_db):
    response = client.get(
        "/authorize",
        params={"client_id": "test-client", "redirect_uri": "http://127.0.0.1:8000/callback", "state": "abc"},
    )
    assert response.status_code == 400
    assert "response_type" in response.text.lower()


def test_authorize_get_wrong_response_type(client, seeded_db):
    response = client.get(
        "/authorize",
        params={
            "response_type": "token",
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "state": "xyz",
        },
    )
    assert response.status_code == 400


def test_authorize_get_missing_state(client, seeded_db):
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
        },
    )
    assert response.status_code == 400


def test_authorize_get_unknown_client(client, seeded_db):
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "unknown-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "state": "s1",
        },
    )
    assert response.status_code == 400
    assert "unknown" in response.text.lower() or "invalid" in response.text.lower()


def test_authorize_get_redirect_uri_mismatch(client, seeded_db):
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://evil.com/callback",
            "state": "s1",
        },
    )
    assert response.status_code == 400


def test_authorize_get_success_returns_login_form(client, seeded_db):
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "state": "mystate",
            "scope": "api.read",
        },
    )
    assert response.status_code == 200
    assert "Log in" in response.text
    assert "username" in response.text
    assert "password" in response.text
    assert "client_id" in response.text or "form" in response.text


# --- POST /authorize (login) ---


def test_authorize_post_invalid_credentials(client, seeded_db):
    response = client.post(
        "/authorize",
        data={
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "scope": "api.read",
            "state": "s2",
            "response_type": "code",
            "username": "testuser",
            "password": "wrongpass",
        },
    )
    assert response.status_code == 401
    assert "Invalid" in response.text
    assert "Log in" in response.text


def test_authorize_post_success_shows_consent(client, seeded_db):
    """After login, consent page is shown (M5); no redirect until user Allows/Denies."""
    response = client.post(
        "/authorize",
        data={
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "scope": "api.read",
            "state": "mystate",
            "response_type": "code",
            "username": "testuser",
            "password": "testpass",
            "code_challenge": "x",
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code == 200
    assert "Consent" in response.text
    assert "test-client" in response.text
    assert "Allow" in response.text and "Deny" in response.text
    assert "/authorize/confirm" in response.text


def test_authorize_confirm_allow_redirects_with_code(client, seeded_db):
    """Allow on consent creates code and redirects to client."""
    # First get to consent (login)
    client.post(
        "/authorize",
        data={
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "scope": "api.read",
            "state": "mystate",
            "response_type": "code",
            "username": "testuser",
            "password": "testpass",
            "code_challenge": "x",
            "code_challenge_method": "S256",
        },
    )
    db = SessionLocal()
    user_id = db.query(User).filter(User.username == "testuser").first().id
    db.close()

    response = client.post(
        "/authorize/confirm",
        data={
            "user_id": user_id,
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "scope": "api.read",
            "state": "mystate",
            "allow": "true",
            "code_challenge": "x",
            "code_challenge_method": "S256",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("http://127.0.0.1:8000/callback?")
    assert "code=" in location
    assert "state=mystate" in location
    db = SessionLocal()
    try:
        codes = db.query(AuthorizationCode).filter(AuthorizationCode.client_id == "test-client").all()
        assert len(codes) >= 1
        assert not codes[-1].used
        assert codes[-1].scope == "api.read"
    finally:
        db.close()


def test_authorize_confirm_deny_redirects_with_access_denied(client, seeded_db):
    """Deny on consent redirects to client with error=access_denied."""
    db = SessionLocal()
    user_id = db.query(User).filter(User.username == "testuser").first().id
    db.close()

    response = client.post(
        "/authorize/confirm",
        data={
            "user_id": user_id,
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "scope": "api.read",
            "state": "mystate",
            "allow": "false",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = response.headers["location"]
    assert "http://127.0.0.1:8000/callback?" in location
    assert "error=access_denied" in location
    assert "state=mystate" in location


def test_authorize_post_invalid_scope_redirects_with_error(client, seeded_db):
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "state": "s3",
            "scope": "invalid_scope",
        },
        follow_redirects=False,
    )
    # GET with invalid scope should redirect to redirect_uri with error
    assert response.status_code == 302
    location = response.headers["location"]
    assert "http://127.0.0.1:8000/callback?" in location
    assert "error=" in location


# --- health ---


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json().get("service") == "auth_server"
