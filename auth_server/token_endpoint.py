"""
Token endpoint (POST /token). Authorization code exchange and refresh_token grant (M6).
"""
import hashlib
import logging
import secrets
from base64 import urlsafe_b64encode
from datetime import datetime, timezone, timedelta

import jwt
from fastapi import APIRouter, Depends, Form, HTTPException
from sqlalchemy.orm import Session

from auth_server.config import (
    ACCESS_TOKEN_EXPIRES,
    API_AUDIENCE,
    ISSUER,
    REFRESH_TOKEN_EXPIRES,
)
from auth_server.database import get_db
from auth_server.keys import get_signing_key
from auth_server.models import AuthorizationCode, RefreshToken, User

logger = logging.getLogger(__name__)
router = APIRouter()


def _pkce_verify(code_verifier: str, code_challenge: str, method: str | None) -> bool:
    """Verify PKCE: S256 only; SHA256(verifier) base64url == challenge."""
    if method != "S256":
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed == code_challenge


def _issue_tokens(user: User, client_id: str, scope: str, nonce: str | None) -> tuple[str, str | None, str]:
    """Build access_token and id_token JWTs; return (access_token, id_token, scope)."""
    private_key, kid = get_signing_key()
    now = datetime.now(timezone.utc)
    access_exp = now + timedelta(seconds=ACCESS_TOKEN_EXPIRES)
    sub = str(user.id)

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
    return access_token, id_token, scope


@router.post("/token")
def token(
    grant_type: str = Form(...),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    client_id: str = Form(...),
    code_verifier: str | None = Form(None),
    refresh_token: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """
    authorization_code: exchange code for access_token, id_token, refresh_token.
    refresh_token: exchange refresh_token for new access_token (and id_token if openid in scope); rotates refresh token.
    """
    if grant_type == "authorization_code":
        return _token_authorization_code(
            code=code, redirect_uri=redirect_uri, client_id=client_id, code_verifier=code_verifier, db=db
        )
    if grant_type == "refresh_token":
        return _token_refresh_token(refresh_token=refresh_token, client_id=client_id, db=db)
    raise HTTPException(
        status_code=400,
        detail={"error": "unsupported_grant_type", "error_description": "Only authorization_code and refresh_token are supported"},
    )


def _token_authorization_code(
    code: str | None,
    redirect_uri: str | None,
    client_id: str,
    code_verifier: str | None,
    db: Session,
):
    if not code or not redirect_uri or not code_verifier:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "error_description": "code, redirect_uri, and code_verifier are required for authorization_code grant"},
        )

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
    scope = auth_code.scope or ""
    access_token, id_token, _ = _issue_tokens(user, client_id, scope, auth_code.nonce)

    # Issue refresh token (M6)
    now = datetime.now(timezone.utc)
    refresh_exp = now + timedelta(seconds=REFRESH_TOKEN_EXPIRES)
    rt_value = secrets.token_urlsafe(48)
    db.add(
        RefreshToken(
            token=rt_value,
            user_id=user.id,
            client_id=client_id,
            scope=scope,
            expires_at=refresh_exp,
        )
    )
    db.commit()

    response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRES,
        "scope": scope,
        "refresh_token": rt_value,
        "refresh_expires_in": REFRESH_TOKEN_EXPIRES,
    }
    if id_token:
        response["id_token"] = id_token
    return response


def _token_refresh_token(refresh_token: str | None, client_id: str, db: Session):
    if not refresh_token:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_request", "error_description": "refresh_token is required"},
        )
    rt = db.query(RefreshToken).filter(RefreshToken.token == refresh_token).first()
    if not rt:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Invalid or revoked refresh token"})
    if rt.revoked:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Refresh token has been revoked"})
    if rt.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Refresh token expired"})
    if rt.client_id != client_id:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "Client mismatch"})

    user = db.query(User).filter(User.id == rt.user_id).first()
    if not user:
        raise HTTPException(status_code=500, detail={"error": "server_error"})

    # Rotate: revoke old, issue new refresh token
    rt.revoked = True
    now = datetime.now(timezone.utc)
    refresh_exp = now + timedelta(seconds=REFRESH_TOKEN_EXPIRES)
    new_rt_value = secrets.token_urlsafe(48)
    db.add(
        RefreshToken(
            token=new_rt_value,
            user_id=user.id,
            client_id=client_id,
            scope=rt.scope,
            expires_at=refresh_exp,
        )
    )
    db.commit()

    # No nonce for refresh-issued ID token (OIDC: optional to omit or use new nonce)
    access_token, id_token, scope = _issue_tokens(user, client_id, rt.scope, None)

    logger.info(
        "refresh_token grant: new tokens issued for client_id=%s sub=%s (refresh token rotated)",
        client_id,
        user.id,
    )

    response = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRES,
        "scope": scope,
        "refresh_token": new_rt_value,
        "refresh_expires_in": REFRESH_TOKEN_EXPIRES,
    }
    if id_token:
        response["id_token"] = id_token
    return response
