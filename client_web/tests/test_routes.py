"""Tests for client_web routes (Milestone 3, 4, 7)."""
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from client_web.flow_store import store_flow
from client_web.main import app
from client_web.token_store import clear_tokens, get_tokens, store_tokens

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json().get("service") == "client_web"


def test_home_returns_html_with_start_login_link():
    r = client.get("/")
    assert r.status_code == 200
    assert "start-login" in r.text or "Log in" in r.text


def test_start_login_redirects_to_as():
    r = client.get("/start-login", follow_redirects=False)
    assert r.status_code == 302
    location = r.headers["location"]
    assert "/authorize?" in location
    assert "response_type=code" in location
    assert "code_challenge=" in location
    assert "code_challenge_method=S256" in location
    assert "state=" in location
    assert "nonce=" in location


def test_callback_missing_state():
    r = client.get("/callback")
    assert r.status_code == 400
    assert "state" in r.text.lower() or "Missing" in r.text


def test_callback_unknown_state():
    r = client.get("/callback", params={"state": "unknown-state", "code": "somecode"})
    assert r.status_code == 400
    assert "Invalid" in r.text or "expired" in r.text.lower()


def test_callback_valid_state_and_code():
    store_flow("valid-state-123", nonce="n", code_verifier="v")

    class MockResponse:
        status_code = 200
        headers = {}

        def json(self):
            return {
                "access_token": "at",
                "token_type": "Bearer",
                "expires_in": 600,
                "scope": "api.read",
                "refresh_token": "rt",
                "refresh_expires_in": 86400,
            }

    with patch("client_web.main.httpx.post", return_value=MockResponse()):
        r = client.get("/callback", params={"state": "valid-state-123", "code": "auth-code-xyz"})
    assert r.status_code == 200
    assert "success" in r.text.lower()
    assert "access token" in r.text.lower() or "token" in r.text.lower()
    assert get_tokens() is not None
    assert get_tokens().access_token == "at"
    assert get_tokens().refresh_token == "rt"
    clear_tokens()


def test_callback_error_from_as():
    store_flow("state-for-error", nonce="n", code_verifier="v")
    r = client.get(
        "/callback",
        params={"state": "state-for-error", "error": "access_denied", "error_description": "User denied"},
    )
    assert r.status_code == 400
    assert "error" in r.text.lower() or "denied" in r.text


# --- M7: Call /me and refresh ---


def test_call_me_no_tokens():
    clear_tokens()
    r = client.get("/call-me")
    assert r.status_code == 200
    assert "No tokens" in r.text or "Log in" in r.text


def test_call_me_success():
    store_tokens(access_token="fake-at", refresh_token="fake-rt", expires_in=600, scope="api.read")

    class MockGet:
        status_code = 200
        headers = {"content-type": "application/json"}

        def json(self):
            return {"message": "Authenticated", "sub": "42"}

    with patch("client_web.main.httpx.get", return_value=MockGet()):
        r = client.get("/call-me")
    assert r.status_code == 200
    assert "200" in r.text
    assert "Authenticated" in r.text or "sub" in r.text
    clear_tokens()


def test_call_me_401_refresh_then_retry():
    store_tokens(access_token="expired-at", refresh_token="valid-rt", expires_in=600, scope="api.read")

    class MockGet401:
        status_code = 401
        headers = {}
        text = "Unauthorized"

    class MockGet200:
        status_code = 200
        headers = {"content-type": "application/json"}

        def json(self):
            return {"message": "Authenticated", "sub": "1"}

    class MockPostRefresh:
        status_code = 200
        headers = {}

        def json(self):
            return {
                "access_token": "new-at",
                "token_type": "Bearer",
                "expires_in": 600,
                "scope": "api.read",
                "refresh_token": "new-rt",
                "refresh_expires_in": 86400,
            }

    with patch("client_web.main.httpx.get", side_effect=[MockGet401(), MockGet200()]), patch(
        "client_web.main.httpx.post", return_value=MockPostRefresh()
    ):
        r = client.get("/call-me")
    assert r.status_code == 200
    assert "200" in r.text
    assert "Authenticated" in r.text or "sub" in r.text
    assert get_tokens() is not None
    assert get_tokens().access_token == "new-at"
    clear_tokens()


def test_home_has_call_me_link():
    r = client.get("/")
    assert r.status_code == 200
    assert "call-me" in r.text
