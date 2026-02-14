"""
PKCE (RFC 7636) and auth request helpers for client login initiation (Milestone 3).
S256 only; state and nonce generation.
"""
import hashlib
import secrets
from base64 import urlsafe_b64encode
from urllib.parse import urlencode


def generate_state() -> str:
    """Opaque value for CSRF protection; returned in callback."""
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    """Random value for ID token binding; required when openid scope is requested."""
    return secrets.token_urlsafe(32)


def generate_pkce() -> tuple[str, str]:
    """
    Generate code_verifier and code_challenge (S256).
    Returns (code_verifier, code_challenge). Verifier is 43 chars (256 bits entropy).
    """
    # 32 bytes -> 43 chars base64url (RFC 7636 recommendation)
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def build_authorize_url(
    *,
    issuer: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    nonce: str | None = None,
) -> str:
    """Build AS /authorize URL with required and optional params."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if nonce:
        params["nonce"] = nonce
    return f"{issuer}/authorize?{urlencode(params)}"
