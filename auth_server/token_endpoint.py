"""
Token endpoint (POST /token). Validate code and PKCE; issue access_token and id_token (JWTs).
"""
import hashlib
import logging
from base64 import urlsafe_b64encode
from datetime import datetime, timezone, timedelta

import jwt
from fastapi import APIRouter, Depends, Form, HTTPException
from sqlalchemy.orm import Session

from auth_server.config import ACCESS_TOKEN_EXPIRES, API_AUDIENCE, ISSUER
from auth_server.database import get_db
from auth_server.keys import get_signing_key
from auth_server.models import AuthorizationCode, User

logger = logging.getLogger(__name__)
router = APIRouter()


def _pkce_verify(code_verifier: str, code_challenge: str, method: str | None) -> bool:
    """Verify PKCE: S256 only; SHA256(verifier) base64url == challenge."""
    if method != "S256":
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed == code_challenge


@router.post("/token")
def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str = Form(...),
    code_verifier: str = Form(...),
    db: Session = Depends(get_db),
):
    """
    Exchange authorization code for tokens. Returns access_token (JWT) and id_token (JWT when openid scope).
    """
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail={"error": "unsupported_grant_type", "error_description": "Only authorization_code is supported"})

    auth_code = db.query(AuthorizationCode).filter(AuthorizationCode.code == code).first()
    if not auth_code:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Invalid or expired authorization code"})
    if auth_code.used:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Authorization code already used"})
    if auth_code.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Authorization code expired"})
    if auth_code.client_id != client_id:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Client mismatch"})
    if auth_code.redirect_uri != redirect_uri:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "redirect_uri mismatch"})

    if not _pkce_verify(code_verifier, auth_code.code_challenge or "", auth_code.code_challenge_method):
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "PKCE verification failed"})

    auth_code.used = True
    db.commit()

    user = db.query(User).filter(User.id == auth_code.user_id).first()
    if not user:
        raise HTTPException(status_code=500, detail={"error": "server_error"})
    sub = str(user.id)
    scope = auth_code.scope or ""
    nonce = auth_code.nonce
    private_key, kid = get_signing_key()
    now = datetime.now(timezone.utc)
    access_exp = now + timedelta(seconds=ACCESS_TOKEN_EXPIRES)

    access_payload = {
        "iss": ISSUER,
        "sub": sub,
        "aud": API_AUDIENCE,
        "exp": int(access_exp.timestamp()),
        "iat": int(now.timestamp()),
        "scope": scope,
    }
    access_token = jwt.encode(
        access_payload,
        private_key,
        algorithm="RS256",
        headers={"kid": kid, "typ": "JWT"},
    )
    if isinstance(access_token, bytes):
        access_token = access_token.decode("utf-8")

    id_token = None
    if "openid" in scope.split():
        id_payload = {
            "iss": ISSUER,
            "sub": sub,
            "aud": client_id,
            "exp": int(access_exp.timestamp()),
            "iat": int(now.timestamp()),
            "nonce": nonce,
        }
        if not nonce:
            id_payload.pop("nonce", None)
        id_token = jwt.encode(
            id_payload,
            private_key,
            algorithm="RS256",
            headers={"kid": kid, "typ": "JWT"},
        )
        if isinstance(id_token, bytes):
            id_token = id_token.decode("utf-8")

    response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRES,
        "scope": scope,
    }
    if id_token:
        response["id_token"] = id_token
    return response
