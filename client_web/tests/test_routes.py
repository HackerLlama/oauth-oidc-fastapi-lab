"""Tests for client_web routes (Milestone 3)."""
import pytest
from fastapi.testclient import TestClient

from client_web.flow_store import store_flow
from client_web.main import app

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
    r = client.get("/callback", params={"state": "valid-state-123", "code": "auth-code-xyz"})
    assert r.status_code == 200
    assert "success" in r.text.lower()
    assert "auth-code-xyz" in r.text


def test_callback_error_from_as():
    store_flow("state-for-error", nonce="n", code_verifier="v")
    r = client.get(
        "/callback",
        params={"state": "state-for-error", "error": "access_denied", "error_description": "User denied"},
    )
    assert r.status_code == 400
    assert "error" in r.text.lower() or "denied" in r.text
