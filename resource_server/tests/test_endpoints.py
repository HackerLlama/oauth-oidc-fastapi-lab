"""
Pytest tests for resource server endpoints (Milestone 1).
Tests /public, /me, /admin success and failure paths.
"""
import json
import time
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.backends import default_backend
from fastapi.testclient import TestClient

from resource_server import auth as auth_module
from resource_server.config import API_AUDIENCE, ISSUER
from resource_server.main import app


def _int_to_b64url(value: int) -> str:
    """Encode a positive int as base64url (JWK n/e)."""
    length = (value.bit_length() + 7) // 8
    byt = value.to_bytes(length, "big")
    s = jwt.utils.base64url_encode(byt)
    return s.decode("utf-8") if isinstance(s, bytes) else s


def _make_key_and_jwks():
    """Generate RSA key and JWKS dict for testing."""
    key = generate_private_key(65537, 2048, default_backend())
    pub = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "kid": "test-key",
        "alg": "RS256",
        "n": _int_to_b64url(pub.n),
        "e": _int_to_b64url(pub.e),
    }
    jwks = {"keys": [jwk]}
    return key, jwks


def _make_token(key, sub: str, scope: str, *, aud=API_AUDIENCE, iss=ISSUER):
    """Build a valid access token for tests."""
    now = int(time.time())
    payload = {
        "sub": sub,
        "scope": scope,
        "iss": iss,
        "aud": aud,
        "exp": now + 3600,
        "iat": now,
    }
    return jwt.encode(
        payload,
        key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def key_and_jwks():
    return _make_key_and_jwks()


def _mock_urlopen(jwks: dict):
    """Return a patch that makes urlopen return the given JWKS JSON."""

    class MockResponse:
        def read(self):
            return json.dumps(jwks).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def fake_urlopen(req, timeout=None, context=None):
        return MockResponse()

    return patch("urllib.request.urlopen", fake_urlopen)


def _reset_jwks_client():
    """Force next request to refetch JWKS (for mock to apply)."""
    auth_module._jwks_client = None


# --- /public (no auth) ---


def test_public_returns_200(client):
    response = client.get("/public")
    assert response.status_code == 200
    data = response.json()
    assert data.get("message") == "Public data"
    assert data.get("access") == "anonymous"


# --- /me (requires api.read) ---


def test_me_without_auth_returns_401(client):
    response = client.get("/me")
    assert response.status_code == 401
    body = response.json()
    error = body.get("detail", {}).get("error") or body.get("error")
    assert error in ("invalid_request", "invalid_token")


def test_me_with_invalid_token_returns_401(client):
    response = client.get("/me", headers={"Authorization": "Bearer invalid-token"})
    assert response.status_code == 401
    body = response.json()
    error = body.get("detail", {}).get("error") or body.get("error")
    assert error == "invalid_token"


def test_me_with_valid_token_without_scope_returns_403(client, key_and_jwks):
    key, jwks = key_and_jwks
    token = _make_token(key, "user1", "openid profile")  # no api.read
    _reset_jwks_client()
    with _mock_urlopen(jwks):
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    body = response.json()
    assert (body.get("detail") or body).get("error") == "insufficient_scope"


def test_me_with_valid_token_with_scope_returns_200(client, key_and_jwks):
    key, jwks = key_and_jwks
    token = _make_token(key, "user1", "api.read")
    _reset_jwks_client()
    with _mock_urlopen(jwks):
        response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data.get("message") == "Authenticated"
    assert data.get("sub") == "user1"


# --- /admin (requires api.admin) ---


def test_admin_without_auth_returns_401(client):
    response = client.get("/admin")
    assert response.status_code == 401


def test_admin_with_valid_token_without_scope_returns_403(client, key_and_jwks):
    key, jwks = key_and_jwks
    token = _make_token(key, "user1", "api.read")  # has api.read but not api.admin
    _reset_jwks_client()
    with _mock_urlopen(jwks):
        response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403
    body = response.json()
    assert (body.get("detail") or body).get("error") == "insufficient_scope"


def test_admin_with_valid_token_with_scope_returns_200(client, key_and_jwks):
    key, jwks = key_and_jwks
    token = _make_token(key, "admin1", "api.read api.admin")
    _reset_jwks_client()
    with _mock_urlopen(jwks):
        response = client.get("/admin", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data.get("message") == "Admin access"
    assert data.get("sub") == "admin1"


# --- health ---


def test_health_returns_200(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json().get("service") == "resource_server"
