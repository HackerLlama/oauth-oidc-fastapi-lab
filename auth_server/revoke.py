"""
Token revocation endpoint (POST /revoke). RFC 7009.
Invalidates refresh tokens; access tokens are stateless JWTs so we return 200 without server-side revoke.
"""
import logging

from fastapi import APIRouter, Depends, Form, HTTPException
from sqlalchemy.orm import Session

from auth_server.database import get_db
from auth_server.models import RefreshToken

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/revoke")
def revoke(
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """
    Revoke a refresh or access token. RFC 7009: always return 200 for valid requests
    (even if token unknown) to avoid leaking information.
    """
    if not token or not token.strip():
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "token is required"})

    hint = (token_type_hint or "").strip().lower()

    # If hint is refresh_token, or no hint, try to revoke as refresh token
    if hint in ("", "refresh_token"):
        rt = db.query(RefreshToken).filter(RefreshToken.token == token.strip()).first()
        if rt:
            rt.revoked = True
            db.commit()
            logger.debug("Revoked refresh token id=%s", rt.id)

    # If hint is access_token: we don't store access tokens (JWTs); nothing to revoke. Still 200.
    return {}
