"""Tests for PKCE and auth URL building."""
import re

import pytest

from client_web.pkce import build_authorize_url, generate_nonce, generate_pkce, generate_state


def test_generate_state_length():
    s = generate_state()
    assert len(s) >= 32
    assert re.match(r"^[A-Za-z0-9_-]+$", s)


def test_generate_nonce_length():
    n = generate_nonce()
    assert len(n) >= 32
    assert re.match(r"^[A-Za-z0-9_-]+$", n)


def test_generate_pkce_returns_verifier_and_challenge():
    verifier, challenge = generate_pkce()
    assert len(verifier) >= 43
    assert len(verifier) <= 128
    assert re.match(r"^[A-Za-z0-9_-]+$", verifier)
    assert re.match(r"^[A-Za-z0-9_-]+$", challenge)
    assert len(challenge) == 43  # base64url(SHA256 digest) no padding


def test_build_authorize_url_includes_required_params():
    url = build_authorize_url(
        issuer="https://as.example",
        client_id="client1",
        redirect_uri="https://client.example/cb",
        scope="openid api.read",
        state="mystate",
        code_challenge="challenge123",
        nonce="mynonce",
    )
    assert url.startswith("https://as.example/authorize?")
    assert "response_type=code" in url
    assert "client_id=client1" in url
    assert "redirect_uri=" in url
    assert "scope=" in url
    assert "state=mystate" in url
    assert "code_challenge=challenge123" in url
    assert "code_challenge_method=S256" in url
    assert "nonce=mynonce" in url


def test_build_authorize_url_without_nonce():
    url = build_authorize_url(
        issuer="https://as.example",
        client_id="c",
        redirect_uri="https://c/cb",
        scope="api.read",
        state="s",
        code_challenge="ch",
        nonce=None,
    )
    assert "nonce=" not in url
