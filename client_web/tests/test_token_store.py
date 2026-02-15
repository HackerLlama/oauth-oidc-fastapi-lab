"""Tests for token_store (M7): expired_or_soon logic."""
import time

import pytest

from client_web.token_store import StoredTokens


def test_fresh_token_not_expired_or_soon():
    """Token just issued with 600s lifetime: should not trigger refresh."""
    t = StoredTokens(
        access_token="at",
        refresh_token="rt",
        expires_in=600,
        scope="api.read",
        issued_at=time.time(),
    )
    assert t.access_token_expired_or_soon(buffer_seconds=60) is False


def test_short_lifetime_not_expired():
    """Token with 30s lifetime, 10s elapsed: should not trigger refresh (bug fix: was always True before)."""
    t = StoredTokens(
        access_token="at",
        refresh_token="rt",
        expires_in=30,
        scope="api.read",
        issued_at=time.time() - 10,
    )
    assert t.access_token_expired_or_soon(buffer_seconds=60) is False


def test_short_lifetime_expired():
    """Token with 30s lifetime, 31s elapsed: should trigger refresh."""
    t = StoredTokens(
        access_token="at",
        refresh_token="rt",
        expires_in=30,
        scope="api.read",
        issued_at=time.time() - 31,
    )
    assert t.access_token_expired_or_soon(buffer_seconds=60) is True


def test_long_lifetime_near_expiry():
    """Token with 600s lifetime, 550s elapsed (50s left): within 60s buffer, should trigger refresh."""
    t = StoredTokens(
        access_token="at",
        refresh_token="rt",
        expires_in=600,
        scope="api.read",
        issued_at=time.time() - 550,
    )
    assert t.access_token_expired_or_soon(buffer_seconds=60) is True


def test_long_lifetime_mid_life():
    """Token with 600s lifetime, 300s elapsed: not near expiry, should not trigger refresh."""
    t = StoredTokens(
        access_token="at",
        refresh_token="rt",
        expires_in=600,
        scope="api.read",
        issued_at=time.time() - 300,
    )
    assert t.access_token_expired_or_soon(buffer_seconds=60) is False
