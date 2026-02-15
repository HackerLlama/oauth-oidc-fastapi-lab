"""
In-memory store for tokens after successful login (M7).
Stores access_token, refresh_token, expires_in, scope, issued_at for calling the resource server and refreshing on 401.
Lab use only; single stored set (no per-user/session).
"""
import time
from dataclasses import dataclass


@dataclass
class StoredTokens:
    access_token: str
    refresh_token: str
    expires_in: int
    scope: str
    issued_at: float

    def access_token_expired_or_soon(self, buffer_seconds: int = 60) -> bool:
        """True if access token is expired or within buffer_seconds of expiry (for proactive refresh)."""
        return (time.time() - self.issued_at) >= (self.expires_in - buffer_seconds)


_tokens: StoredTokens | None = None


def store_tokens(
    access_token: str,
    refresh_token: str,
    expires_in: int,
    scope: str = "",
) -> None:
    global _tokens
    _tokens = StoredTokens(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        scope=scope,
        issued_at=time.time(),
    )


def get_tokens() -> StoredTokens | None:
    return _tokens


def clear_tokens() -> None:
    global _tokens
    _tokens = None
