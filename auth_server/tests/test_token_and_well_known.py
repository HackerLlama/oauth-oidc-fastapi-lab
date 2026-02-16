"""
Tests for POST /token and well-known endpoints (Milestone 4, 6, 8, 9).
"""
import hashlib
import json
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from auth_server.config import ACCESS_TOKEN_EXPIRES, API_AUDIENCE, ISSUER
from auth_server.database import SessionLocal, init_db
from auth_server.main import app
from auth_server.models import AuthorizationCode, Client, RefreshToken, User
from auth_server.seed import hash_password


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
        logout_uris = [
            "http://127.0.0.1:8000/callback",
            "http://127.0.0.1:8000/logged-out",
            "http://127.0.0.1:8000/",
        ]
        c = db.query(Client).filter(Client.client_id == "test-client").first()
        if not c:
            db.add(Client(client_id="test-client", redirect_uris=json.dumps(logout_uris)))
        else:
            uris = c.get_redirect_uris_list()
            for u in logout_uris:
                if u not in uris:
                    uris.append(u)
                    c.redirect_uris = json.dumps(uris)
                    break
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
    """JWKS returns at least the current key with kid; may include previous key for rotation (M11)."""
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1
    kids = [k.get("kid") for k in data["keys"] if k.get("kid")]
    assert "auth-server-key" in kids
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
    assert data.get("userinfo_endpoint") == f"{ISSUER}/userinfo"
    assert data.get("revocation_endpoint") == f"{ISSUER}/revoke"
    assert data.get("introspection_endpoint") == f"{ISSUER}/introspect"
    assert data.get("end_session_endpoint") == f"{ISSUER}/logout"
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
    assert "refresh_token" in data
    assert data.get("refresh_expires_in")
    # No openid scope so no id_token
    assert "id_token" not in data or data.get("id_token") is None


def test_token_granted_scope_only_in_token(client, seeded):
    """M12: Token and refresh token carry granted scope (subset), not requested scope."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "tokenuser").first()
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        # Code has only granted scope "api.read" (user could have requested openid api.read profile)
        auth_code = AuthorizationCode(
            code="granted-scope-code",
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
            "code": "granted-scope-code",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data.get("scope") == "api.read"
    # Introspect access token: scope claim should be granted only
    r2 = client.post("/introspect", data={"token": data["access_token"], "client_id": "test-client"})
    assert r2.status_code == 200
    assert r2.json().get("scope") == "api.read"


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
    assert "refresh_token" in data


def test_token_refresh_grant_success(client, seeded):
    """Exchange refresh_token for new access_token; old refresh token is revoked (rotation)."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "tokenuser").first()
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="test-code-refresh",
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

    r1 = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "test-code-refresh",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert r1.status_code == 200
    refresh = r1.json()["refresh_token"]
    access1 = r1.json()["access_token"]

    r2 = client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh, "client_id": "test-client"},
    )
    assert r2.status_code == 200
    data2 = r2.json()
    assert "access_token" in data2
    assert "refresh_token" in data2
    assert data2["refresh_token"] != refresh  # rotation: new refresh token issued

    # Old refresh token is revoked (rotation)
    r3 = client.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh, "client_id": "test-client"},
    )
    assert r3.status_code == 400
    assert (r3.json().get("detail") or r3.json()).get("error") == "invalid_grant"


def test_token_refresh_grant_missing_token(client, seeded):
    r = client.post(
        "/token",
        data={"grant_type": "refresh_token", "client_id": "test-client"},
    )
    assert r.status_code == 400
    assert (r.json().get("detail") or r.json()).get("error") == "invalid_request"


def test_revoke_refresh_token_returns_200(client, seeded):
    """POST /revoke with a refresh token revokes it; RFC 7009 says 200 even if token unknown."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "tokenuser").first()
        exp = datetime.now(timezone.utc) + timedelta(seconds=3600)
        rt = RefreshToken(
            token="revoke-me-token",
            user_id=user.id,
            client_id="test-client",
            scope="api.read",
            expires_at=exp,
        )
        db.add(rt)
        db.commit()
    finally:
        db.close()

    r = client.post("/revoke", data={"token": "revoke-me-token", "token_type_hint": "refresh_token"})
    assert r.status_code == 200

    db2 = SessionLocal()
    try:
        rt2 = db2.query(RefreshToken).filter(RefreshToken.token == "revoke-me-token").first()
        assert rt2 is not None
        assert rt2.revoked is True
    finally:
        db2.close()


def test_revoke_unknown_token_returns_200(client, seeded):
    """RFC 7009: return 200 even when token is unknown to avoid leaking info."""
    r = client.post("/revoke", data={"token": "unknown-token-value"})
    assert r.status_code == 200


def test_revoke_missing_token_returns_422(client, seeded):
    """Missing required token form field yields 422 (FastAPI validation)."""
    r = client.post("/revoke", data={})
    assert r.status_code == 422


def test_revoke_confidential_client_without_auth_401(client, seeded):
    """Revoking a refresh token of a confidential client without client_secret returns 401."""
    from auth_server.seed import hash_password

    db = SessionLocal()
    try:
        if db.query(Client).filter(Client.client_id == "conf-revoke").first() is None:
            db.add(
                Client(
                    client_id="conf-revoke",
                    redirect_uris=json.dumps(["http://127.0.0.1:8000/callback"]),
                    client_secret_hash=hash_password("revoke-secret"),
                )
            )
            db.commit()
        user = db.query(User).filter(User.username == "tokenuser").first()
        exp = datetime.now(timezone.utc) + timedelta(seconds=3600)
        rt = RefreshToken(
            token="conf-revoke-rt",
            user_id=user.id,
            client_id="conf-revoke",
            scope="api.read",
            expires_at=exp,
        )
        db.add(rt)
        db.commit()
    finally:
        db.close()

    r = client.post(
        "/revoke",
        data={"token": "conf-revoke-rt", "token_type_hint": "refresh_token", "client_id": "conf-revoke"},
    )
    assert r.status_code == 401
    assert (r.json().get("detail") or r.json()).get("error") == "invalid_client"


def test_revoke_confidential_client_with_auth_200(client, seeded):
    """Revoking a refresh token of a confidential client with correct client_secret returns 200."""
    from auth_server.seed import hash_password

    db = SessionLocal()
    try:
        if db.query(Client).filter(Client.client_id == "conf-revoke").first() is None:
            db.add(
                Client(
                    client_id="conf-revoke",
                    redirect_uris=json.dumps(["http://127.0.0.1:8000/callback"]),
                    client_secret_hash=hash_password("revoke-secret"),
                )
            )
            db.commit()
        user = db.query(User).filter(User.username == "tokenuser").first()
        exp = datetime.now(timezone.utc) + timedelta(seconds=3600)
        rt = RefreshToken(
            token="conf-revoke-rt-2",
            user_id=user.id,
            client_id="conf-revoke",
            scope="api.read",
            expires_at=exp,
        )
        db.add(rt)
        db.commit()
    finally:
        db.close()

    r = client.post(
        "/revoke",
        data={
            "token": "conf-revoke-rt-2",
            "token_type_hint": "refresh_token",
            "client_id": "conf-revoke",
            "client_secret": "revoke-secret",
        },
    )
    assert r.status_code == 200

    db2 = SessionLocal()
    try:
        rt2 = db2.query(RefreshToken).filter(RefreshToken.token == "conf-revoke-rt-2").first()
        assert rt2 is not None
        assert rt2.revoked is True
    finally:
        db2.close()


# --- M8: Token introspection ---


def test_introspect_unknown_client_401(client, seeded):
    r = client.post("/introspect", data={"token": "any", "client_id": "unknown-client"})
    assert r.status_code == 401
    assert (r.json().get("detail") or r.json()).get("error") == "invalid_client"


def test_introspect_missing_client_id_401(client, seeded):
    r = client.post("/introspect", data={"token": "any"})
    assert r.status_code == 422  # Form validation: client_id required


def test_introspect_invalid_token_active_false(client, seeded):
    r = client.post("/introspect", data={"token": "invalid-token", "client_id": "test-client"})
    assert r.status_code == 200
    assert r.json().get("active") is False


def test_introspect_access_token_returns_active_and_claims(client, seeded):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "tokenuser").first()
        user_id = user.id
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="introspect-code",
            client_id="test-client",
            redirect_uri="http://127.0.0.1:8000/callback",
            user_id=user_id,
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

    token_r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "introspect-code",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert token_r.status_code == 200
    access_token = token_r.json()["access_token"]

    r = client.post("/introspect", data={"token": access_token, "client_id": "test-client"})
    assert r.status_code == 200
    data = r.json()
    assert data["active"] is True
    assert data.get("scope") == "api.read"
    assert data.get("sub") == str(user_id)
    assert data.get("iss") == ISSUER
    assert data.get("aud") == API_AUDIENCE
    assert "exp" in data


def test_introspect_refresh_token_returns_active_and_claims(client, seeded):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "tokenuser").first()
        user_id = user.id
        exp = datetime.now(timezone.utc) + timedelta(seconds=3600)
        rt = RefreshToken(
            token="introspect-rt",
            user_id=user_id,
            client_id="test-client",
            scope="openid api.read",
            expires_at=exp,
        )
        db.add(rt)
        db.commit()
    finally:
        db.close()

    r = client.post(
        "/introspect",
        data={"token": "introspect-rt", "token_type_hint": "refresh_token", "client_id": "test-client"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["active"] is True
    assert data.get("scope") == "openid api.read"
    assert data.get("sub") == str(user_id)
    assert data.get("client_id") == "test-client"
    assert "exp" in data


def test_token_confidential_client_without_secret_401(client, seeded):
    """Confidential client must send client_secret (or Basic); otherwise 401."""
    import base64
    from auth_server.seed import hash_password

    db = SessionLocal()
    try:
        # Create confidential client
        c = db.query(Client).filter(Client.client_id == "confidential-client").first()
        if not c:
            db.add(
                Client(
                    client_id="confidential-client",
                    redirect_uris=json.dumps(["http://127.0.0.1:8000/callback"]),
                    client_secret_hash=hash_password("secret123"),
                )
            )
            db.commit()
        user = db.query(User).filter(User.username == "tokenuser").first()
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="conf-code",
            client_id="confidential-client",
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

    # No client_secret -> 401
    r = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "conf-code",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "confidential-client",
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 401
    assert (r.json().get("detail") or r.json()).get("error") == "invalid_client"


def test_token_confidential_client_with_secret_success(client, seeded):
    """Confidential client with correct client_secret in form gets tokens."""
    from auth_server.seed import hash_password

    db = SessionLocal()
    try:
        if db.query(Client).filter(Client.client_id == "confidential-client").first() is None:
            db.add(
                Client(
                    client_id="confidential-client",
                    redirect_uris=json.dumps(["http://127.0.0.1:8000/callback"]),
                    client_secret_hash=hash_password("secret123"),
                )
            )
            db.commit()
        user = db.query(User).filter(User.username == "tokenuser").first()
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="conf-code-2",
            client_id="confidential-client",
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
            "code": "conf-code-2",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "confidential-client",
            "client_secret": "secret123",
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_introspect_revoked_refresh_active_false(client, seeded):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "tokenuser").first()
        exp = datetime.now(timezone.utc) + timedelta(seconds=3600)
        rt = RefreshToken(
            token="revoked-introspect-rt",
            user_id=user.id,
            client_id="test-client",
            scope="api.read",
            expires_at=exp,
            revoked=True,
        )
        db.add(rt)
        db.commit()
    finally:
        db.close()

    r = client.post(
        "/introspect",
        data={"token": "revoked-introspect-rt", "client_id": "test-client"},
    )
    assert r.status_code == 200
    assert r.json().get("active") is False


def test_introspect_confidential_client_without_secret_401(client, seeded):
    """Introspect with confidential client_id but no client_secret returns 401."""
    from auth_server.seed import hash_password

    db = SessionLocal()
    try:
        if db.query(Client).filter(Client.client_id == "conf-introspect").first() is None:
            db.add(
                Client(
                    client_id="conf-introspect",
                    redirect_uris=json.dumps(["http://127.0.0.1:8000/callback"]),
                    client_secret_hash=hash_password("intro-secret"),
                )
            )
            db.commit()
    finally:
        db.close()

    r = client.post(
        "/introspect",
        data={"token": "any-token", "client_id": "conf-introspect"},
    )
    assert r.status_code == 401
    assert (r.json().get("detail") or r.json()).get("error") == "invalid_client"


def test_introspect_confidential_client_with_secret_200(client, seeded):
    """Introspect with confidential client_id and correct client_secret returns 200 (active true/false per token)."""
    from auth_server.seed import hash_password

    db = SessionLocal()
    try:
        if db.query(Client).filter(Client.client_id == "conf-introspect").first() is None:
            db.add(
                Client(
                    client_id="conf-introspect",
                    redirect_uris=json.dumps(["http://127.0.0.1:8000/callback"]),
                    client_secret_hash=hash_password("intro-secret"),
                )
            )
            db.commit()
    finally:
        db.close()

    r = client.post(
        "/introspect",
        data={"token": "invalid-token", "client_id": "conf-introspect", "client_secret": "intro-secret"},
    )
    assert r.status_code == 200
    assert r.json().get("active") is False


# --- M10: RP-Initiated Logout ---


def test_logout_no_params_returns_logged_out_html(client, seeded):
    """GET /logout with no id_token_hint shows simple logged-out page (no redirect to arbitrary URI)."""
    r = client.get("/logout")
    assert r.status_code == 200
    assert "Logged out" in r.text or "logged out" in r.text.lower()


def test_logout_with_valid_hint_and_redirect_uri_redirects(client, seeded):
    """GET /logout with valid id_token_hint and allowed post_logout_redirect_uri returns 302 to that URI."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "tokenuser").first()
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="logout-code",
            client_id="test-client",
            redirect_uri="http://127.0.0.1:8000/callback",
            user_id=user.id,
            scope="openid api.read",
            code_challenge=challenge,
            code_challenge_method="S256",
            nonce="logout-nonce",
            expires_at=expires,
        )
        db.add(auth_code)
        db.commit()
    finally:
        db.close()

    # Exchange code for tokens to get id_token
    r_token = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "logout-code",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert r_token.status_code == 200
    id_token = r_token.json().get("id_token")
    assert id_token

    # Seed ensures test-client has http://127.0.0.1:8000/logged-out in redirect_uris
    post_logout = "http://127.0.0.1:8000/logged-out"
    state = "logout-state-123"
    r = client.get(
        "/logout",
        params={
            "id_token_hint": id_token,
            "post_logout_redirect_uri": post_logout,
            "state": state,
        },
        follow_redirects=False,
    )
    assert r.status_code == 302, f"Expected 302, got {r.status_code}: {r.text[:500]}"
    loc = r.headers.get("location", "")
    assert post_logout in loc
    assert state in loc


def test_logout_disallowed_redirect_uri_returns_400(client, seeded):
    """GET /logout with post_logout_redirect_uri not in client's list returns 400."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "tokenuser").first()
        verifier, challenge = _make_code_verifier_and_challenge()
        expires = datetime.now(timezone.utc) + timedelta(seconds=60)
        auth_code = AuthorizationCode(
            code="logout-code-2",
            client_id="test-client",
            redirect_uri="http://127.0.0.1:8000/callback",
            user_id=user.id,
            scope="openid api.read",
            code_challenge=challenge,
            code_challenge_method="S256",
            nonce="n2",
            expires_at=expires,
        )
        db.add(auth_code)
        db.commit()
    finally:
        db.close()

    r_token = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "logout-code-2",
            "redirect_uri": "http://127.0.0.1:8000/callback",
            "client_id": "test-client",
            "code_verifier": verifier,
        },
    )
    assert r_token.status_code == 200
    id_token = r_token.json().get("id_token")
    assert id_token

    r = client.get(
        "/logout",
        params={
            "id_token_hint": id_token,
            "post_logout_redirect_uri": "https://evil.example.com/",
        },
    )
    assert r.status_code == 400
