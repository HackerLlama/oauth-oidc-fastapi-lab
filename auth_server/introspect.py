"""
Token introspection endpoint (POST /introspect). RFC 7662.
Protected: caller must provide client_id and be a registered client (M9 will add client_secret).
"""
import logging
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy.orm import Session

from auth_server.client_auth import require_client_auth

from auth_server.config import API_AUDIENCE, ISSUER
from auth_server.database import get_db
from auth_server.keys import get_signing_key
from auth_server.models import RefreshToken

logger = logging.getLogger(__name__)
router = APIRouter()


def _introspect_access_token(token: str) -> dict | None:
    """Verify JWT access token; return payload dict if valid and not expired, else None."""
    private_key, _ = get_signing_key()
    public_key = private_key.public_key()
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=API_AUDIENCE,
        )
        return payload
    except jwt.InvalidTokenError:
        return None


@router.post("/introspect")
def introspect(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    client_id: str = Form(...),
    client_secret: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """
    RFC 7662: return whether the token is active and its claims.
    Caller must provide client_id; confidential clients must also authenticate (M9).
    """
    if not token or not token.strip():
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "error_description": "token is required"},
        )

    client = require_client_auth(db, request, client_id, client_secret)

    hint = (token_type_hint or "").strip().lower()
    token_value = token.strip()

    # Try as access token (JWT) if hint is access_token or no hint
    if hint in ("", "access_token"):
        payload = _introspect_access_token(token_value)
        if payload:
            return {
                "active": True,
                "scope": payload.get("scope", ""),
                "sub": payload.get("sub"),
                "exp": payload.get("exp"),
                "iat": payload.get("iat"),
                "iss": payload.get("iss"),
                "aud": payload.get("aud"),
            }

    # Try as refresh token
    if hint in ("", "refresh_token"):
        rt = db.query(RefreshToken).filter(RefreshToken.token == token_value).first()
        if rt and not rt.revoked:
            if rt.expires_at.replace(tzinfo=timezone.utc) >= datetime.now(timezone.utc):
                return {
                    "active": True,
                    "scope": rt.scope or "",
                    "sub": str(rt.user_id),
                    "exp": int(rt.expires_at.timestamp()),
                    "client_id": rt.client_id,
                }

    return {"active": False}
