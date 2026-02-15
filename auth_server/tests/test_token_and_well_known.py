"""
Tests for POST /token and well-known endpoints (Milestone 4).
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
from auth_server.config import ACCESS_TOKEN_EXPIRES, API_AUDIENCE, ISSUER


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seeded(client):
    init_db()
    db = SessionLocal()
    try:
        u = db.query(User).filter(User.username == "tokenuser").first()
        if not u:
            db.add(User(username="tokenuser", password_hash=hash_password("tokenpass")))
        c = db.query(Client).filter(Client.client_id == "test-client").first()
        if not c:
            import json
            db.add(Client(client_id="test-client", redirect_uris=json.dumps(["http://127.0.0.1:8000/callback"])))
        db.commit()
        yield db
    finally:
        db.close()


def _make_code_verifier_and_challenge():
    import secrets
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def test_jwks_returns_keys(client, seeded):
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1
    key = data["keys"][0]
    assert key.get("kty") == "RSA"
    assert key.get("alg") == "RS256"
    assert "n" in key and "e" in key


def test_openid_configuration(client, seeded):
    r = client.get("/.well-known/openid-configuration")
    assert r.status_code == 200
    data = r.json()
    assert data.get("issuer") == ISSUER
    assert data.get("authorization_endpoint") == f"{ISSUER}/authorize"
    assert data.get("token_endpoint") == f"{ISSUER}/token"
    assert data.get("jwks_uri") == f"{ISSUER}/.well-known/jwks.json"
    assert "code" in data.get("response_types_supported", [])
    assert "S256" in data.get("code_challenge_methods_supported", [])


def test_token_invalid_grant_type(client, seeded):
    r = client.post(
        "/token",
        data={
            "grant_type": "password",
            "code": "x",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": "x",
        },
    )
    assert r.status_code == 400
    assert (r.json().get("detail") or r.json()).get("error") == "unsupported_grant_type"


def test_token_invalid_code(client, seeded):
    verifier, challenge = _make_code_verifier_and_challenge()
    r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "invalid-code",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 400
    assert (r.json().get("detail") or r.json()).get("error") == "invalid_grant"


def test_token_success_returns_access_token(client, seeded):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "tokenuser").first()
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="test-code-123",
            client_id="test-client",
            redirect_uri="http://127.0.0.1:8000/callback",
            user_id=user.id,
            scope="api.read",
            code_challenge=challenge,
            code_challenge_method="S256",
            nonce=None,
            expires_at=expires,
        )
        db.add(auth_code)
        db.commit()
    finally:
        db.close()

    r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "test-code-123",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert data.get("token_type") == "Bearer"
    assert data.get("expires_in") == ACCESS_TOKEN_EXPIRES
    assert data.get("scope") == "api.read"
    # No openid scope so no id_token
    assert "id_token" not in data or data.get("id_token") is None


def test_token_success_with_openid_returns_id_token(client, seeded):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "tokenuser").first()
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="test-code-openid",
            client_id="test-client",
            redirect_uri="http://127.0.0.1:8000/callback",
            user_id=user.id,
            scope="openid api.read",
            code_challenge=challenge,
            code_challenge_method="S256",
            nonce="test-nonce-123",
            expires_at=expires,
        )
        db.add(auth_code)
        db.commit()
    finally:
        db.close()

    r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "test-code-openid",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert "id_token" in data
    assert data["id_token"]
    # ID token should contain nonce when decoded (optional check)
    import jwt
    from auth_server.keys import get_jwks
    jwks = get_jwks()
    # Decode without verify for quick claim check
    payload = jwt.decode(data["id_token"], options={"verify_signature": False})
    assert payload.get("nonce") == "test-nonce-123"
    assert payload.get("aud") == "test-client"
    assert payload.get("iss") == ISSUER
