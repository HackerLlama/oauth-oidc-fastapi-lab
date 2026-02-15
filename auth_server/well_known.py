"""
Well-known endpoints: JWKS and OpenID Connect discovery.
"""
from fastapi import APIRouter

from auth_server.config import ISSUER
from auth_server.keys import get_jwks

router = APIRouter()


@router.get("/.well-known/jwks.json")
def jwks_json():
    """JSON Web Key Set for token signature verification."""
    return get_jwks()


@router.get("/.well-known/openid-configuration")
def openid_configuration():
    """OpenID Connect discovery document."""
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "revocation_endpoint": f"{ISSUER}/revoke",
        "jwks_uri": f"{ISSUER}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "scopes_supported": ["openid", "profile", "email", "api.read", "api.admin"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
    }
