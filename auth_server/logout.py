"""
OIDC RP-Initiated Logout (Milestone 10).
GET /logout: accept id_token_hint, post_logout_redirect_uri, state; validate redirect URI; redirect back to client.
Stateless AS: no server-side session to clear; we clear no cookie. Main effect is redirect with consistent flow.
"""
import logging
from urllib.parse import urlencode

import jwt
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from auth_server.config import ISSUER
from auth_server.database import get_db
from auth_server.keys import get_public_key_for_kid
from auth_server.models import Client

logger = logging.getLogger(__name__)
router = APIRouter()


def _decode_id_token_hint(id_token: str) -> dict | None:
    """Decode and verify id_token_hint JWT (resolve key by kid for rotation); return payload if valid, else None."""
    if not id_token or not id_token.strip():
        return None
    try:
        unverified = jwt.get_unverified_header(id_token.strip())
        kid = unverified.get("kid")
        if not kid:
            return None
        public_key = get_public_key_for_kid(kid)
        if not public_key:
            return None
        payload = jwt.decode(
            id_token.strip(),
            public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False},  # aud is client_id; we use it after decode
        )
        return payload
    except jwt.InvalidTokenError:
        return None


@router.get("/logout")
def logout(
    request: Request,
    id_token_hint: str | None = None,
    post_logout_redirect_uri: str | None = None,
    state: str | None = None,
    db: Session = Depends(get_db),
):
    """
    OIDC RP-Initiated Logout. Redirects to post_logout_redirect_uri with state if provided.
    Validates post_logout_redirect_uri against the client's allowed redirect_uris.
    Client is identified by id_token_hint (aud claim).
    """
    client_id = None
    if id_token_hint:
        payload = _decode_id_token_hint(id_token_hint)
        if payload:
            client_id = payload.get("aud")
            if isinstance(client_id, list):
                client_id = client_id[0] if client_id else None

    if not client_id:
        # No valid id_token_hint: show simple "logged out" page (no redirect to arbitrary URI)
        return HTMLResponse(
            """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Logged out</title></head>
<body>
  <h1>Logged out</h1>
  <p>You are logged out. Close this window or return to the application.</p>
</body>
</html>"""
        )

    client = db.query(Client).filter(Client.client_id == client_id).first()
    if not client:
        return HTMLResponse("<h1>Invalid request</h1><p>Unknown client.</p>", status_code=400)

    if post_logout_redirect_uri and post_logout_redirect_uri.strip():
        if not client.redirect_uri_allowed(post_logout_redirect_uri.strip()):
            return HTMLResponse(
                "<h1>Invalid request</h1><p>post_logout_redirect_uri not allowed for this client.</p>",
                status_code=400,
            )
        params = {}
        if state and state.strip():
            params["state"] = state.strip()
        redirect_url = post_logout_redirect_uri.strip()
        if params:
            redirect_url = f"{redirect_url}{'&' if '?' in redirect_url else '?'}{urlencode(params)}"
        return RedirectResponse(url=redirect_url, status_code=302)

    # Valid client but no post_logout_redirect_uri: show logged out page
    return HTMLResponse(
        """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Logged out</title></head>
<body>
  <h1>Logged out</h1>
  <p>You are logged out.</p>
</body>
</html>"""
    )
