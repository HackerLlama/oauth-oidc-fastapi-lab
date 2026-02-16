"""
In-memory store for tokens after successful login (M7).
Stores access_token, refresh_token, id_token (optional, M10), expires_in, scope, issued_at.
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
    id_token: str | None = None

    def access_token_expired_or_soon(self, buffer_seconds: int = 60) -> bool:
        """
        True if access token is expired or within buffer_seconds of expiry (for proactive refresh).
        When token lifetime is shorter than buffer_seconds, only return True when actually expired.
        """
        elapsed = time.time() - self.issued_at
        if elapsed >= self.expires_in:
            return True
        # "Expiring soon" only when lifetime is longer than buffer (else we'd refresh on every request)
        if self.expires_in > buffer_seconds and elapsed >= (self.expires_in - buffer_seconds):
            return True
        return False


_tokens: StoredTokens | None = None


def store_tokens(
    access_token: str,
    refresh_token: str,
    expires_in: int,
    scope: str = "",
    id_token: str | None = None,
) -> None:
    global _tokens
    _tokens = StoredTokens(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        scope=scope,
        issued_at=time.time(),
        id_token=id_token,
    )


def get_tokens() -> StoredTokens | None:
    return _tokens


def clear_tokens() -> None:
    global _tokens
    _tokens = None
