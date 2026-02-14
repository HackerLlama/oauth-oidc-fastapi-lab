"""
JWT validation via JWKS for the resource server (Milestone 1).
Validates access tokens from the Authorization Server; no OAuth logic here.
"""
import logging
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient

from resource_server.config import API_AUDIENCE, ISSUER, SCOPE_ADMIN, SCOPE_READ

logger = logging.getLogger(__name__)

# JWKS endpoint per PROJECT_CONTEXT (AS exposes /.well-known/jwks.json in M4; same URL for M1 readiness)
JWKS_URI = f"{ISSUER}/.well-known/jwks.json"

# Single shared client; PyJWKClient caches the JWK set and keys
_jwks_client: PyJWKClient | None = None


def get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(
            uri=JWKS_URI,
            cache_jwk_set=True,
            lifespan=300,
        )
    return _jwks_client


security = HTTPBearer(auto_error=False)


def get_bearer_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> str:
    """Extract Bearer token from Authorization header. Raises 401 if missing or not Bearer."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_request", "error_description": "Authorization header missing"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    if credentials.scheme != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_request", "error_description": "Bearer scheme required"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials


def verify_access_token(token: str) -> dict:
    """
    Verify JWT signature via JWKS and validate iss, aud, exp.
    Returns decoded claims. Raises HTTPException on invalid token.
    """
    try:
        client = get_jwks_client()
        signing_key = client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=API_AUDIENCE,
            issuer=ISSUER,
            options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "Token expired"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "Invalid audience"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "Invalid issuer"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.debug("JWT verification failed: %s", e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "error_description": "Token verification failed"},
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_claims(
    token: Annotated[str, Depends(get_bearer_token)],
) -> dict:
    """Dependency: valid Bearer token -> decoded claims."""
    return verify_access_token(token)


def _parse_scope(scope_value: str | list | None) -> set[str]:
    """Normalize scope claim to a set of scope strings."""
    if scope_value is None:
        return set()
    if isinstance(scope_value, list):
        return set(str(s) for s in scope_value)
    return set(scope_value.split())


def require_scope(required: str):
    """Dependency factory: require the given scope in the access token."""

    def _check(claims: Annotated[dict, Depends(get_claims)]) -> dict:
        scopes = _parse_scope(claims.get("scope"))
        if required not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "insufficient_scope",
                    "error_description": f"Scope '{required}' required",
                },
            )
        return claims

    return Depends(_check)


# Convenience dependencies for /me and /admin
RequireRead = require_scope(SCOPE_READ)
RequireAdmin = require_scope(SCOPE_ADMIN)
