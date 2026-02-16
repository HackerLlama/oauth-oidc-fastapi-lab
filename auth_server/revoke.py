"""
Token revocation endpoint (POST /revoke). RFC 7009.
Invalidates refresh tokens; access tokens are stateless JWTs so we return 200 without server-side revoke.
Confidential clients must authenticate when revoking a refresh token (M9).
"""
import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy.orm import Session

from auth_server.client_auth import get_client_credentials_from_request, verify_client_credentials
from auth_server.database import get_db
from auth_server.models import Client, RefreshToken

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/revoke")
def revoke(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """
    Revoke a refresh or access token. RFC 7009: always return 200 for valid requests
    (even if token unknown) to avoid leaking information.
    When revoking a refresh token belonging to a confidential client, client must authenticate (M9).
    """
    if not token or not token.strip():
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "token is required"})

    hint = (token_type_hint or "").strip().lower()

    # If hint is refresh_token, or no hint, try to revoke as refresh token
    if hint in ("", "refresh_token"):
        rt = db.query(RefreshToken).filter(RefreshToken.token == token.strip()).first()
        if rt:
            client = db.query(Client).filter(Client.client_id == rt.client_id).first()
            if client and client.is_confidential:
                cid, csecret = get_client_credentials_from_request(request, client_id, client_secret)
                if not verify_client_credentials(db, rt.client_id, csecret):
                    raise HTTPException(
                        status_code=401,
                        detail={"error": "invalid_client", "error_description": "Invalid client credentials"},
                    )
            rt.revoked = True
            db.commit()
            logger.debug("Revoked refresh token id=%s", rt.id)

    # If hint is access_token: we don't store access tokens (JWTs); nothing to revoke. Still 200.
    return {}
