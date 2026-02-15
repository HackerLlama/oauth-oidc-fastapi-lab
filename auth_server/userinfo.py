"""
OIDC UserInfo endpoint (GET /userinfo). Bearer token required; returns claims by scope.
"""
import logging

import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from auth_server.config import ISSUER
from auth_server.database import get_db
from auth_server.keys import get_signing_key
from auth_server.models import User

logger = logging.getLogger(__name__)
router = APIRouter()
security = HTTPBearer(auto_error=True)


def _decode_access_token(credentials: HTTPAuthorizationCredentials) -> dict:
    """Decode and validate access token issued by this server. Returns payload or raises."""
    token = credentials.credentials
    private_key, _ = get_signing_key()
    public_key = private_key.public_key()
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False},
        )
        return payload
    except jwt.InvalidTokenError as e:
        logger.debug("UserInfo token invalid: %s", e)
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@router.get("/userinfo")
def userinfo(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    Return claims for the authenticated user. Requires Bearer access_token.
    Claims returned depend on token scope: sub always; profile -> name, preferred_username; email -> email.
    """
    payload = _decode_access_token(credentials)
    sub = payload.get("sub")
    scope = (payload.get("scope") or "").split()

    try:
        user_id = int(sub)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token subject")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    claims = {"sub": sub}

    if "profile" in scope or "openid" in scope:
        claims["preferred_username"] = user.username
        if user.name is not None:
            claims["name"] = user.name

    if "email" in scope and user.email is not None:
        claims["email"] = user.email

    return claims
