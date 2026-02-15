"""
Authorization endpoint and login flow (Milestone 2).
GET /authorize: validate params, show login. POST /authorize: process login, issue code, redirect.
"""
import html
import logging
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from auth_server.config import ALLOWED_SCOPES, CODE_TTL_SECONDS
from auth_server.database import get_db
from auth_server.models import AuthorizationCode, Client, User
from auth_server.seed import verify_password

logger = logging.getLogger(__name__)
router = APIRouter()


def _redirect_error(redirect_uri: str, error: str, error_description: str, state: str | None) -> RedirectResponse:
    params = {"error": error, "error_description": error_description}
    if state:
        params["state"] = state
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


def _validate_scope(scope: str | None) -> tuple[bool, str]:
    """Return (ok, normalized_scope_or_error)."""
    if not scope or not scope.strip():
        return True, ""
    requested = set(s.strip() for s in scope.split() if s.strip())
    invalid = requested - ALLOWED_SCOPES
    if invalid:
        return False, f"Invalid scope(s): {', '.join(sorted(invalid))}"
    return True, " ".join(sorted(requested))


@router.get("/authorize", response_class=HTMLResponse)
def authorize_get(
    request: Request,
    response_type: str | None = None,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    scope: str | None = None,
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    db: Session = Depends(get_db),
):
    """
    OAuth2 authorization endpoint (GET).
    Validates client_id, redirect_uri (exact match), response_type=code, state required.
    Renders login form on success.
    """
    # Require response_type=code
    if response_type != "code":
        return HTMLResponse(
            "<h1>Invalid request</h1><p>response_type must be 'code'.</p>",
            status_code=400,
        )

    if not client_id or not redirect_uri or not state:
        return HTMLResponse(
            "<h1>Invalid request</h1><p>client_id, redirect_uri, and state are required.</p>",
            status_code=400,
        )

    client = db.query(Client).filter(Client.client_id == client_id).first()
    if not client:
        return HTMLResponse("<h1>Invalid request</h1><p>Unknown client_id.</p>", status_code=400)

    if not client.redirect_uri_allowed(redirect_uri):
        return HTMLResponse("<h1>Invalid request</h1><p>redirect_uri not allowed.</p>", status_code=400)

    ok, scope_result = _validate_scope(scope)
    if not ok:
        return _redirect_error(redirect_uri, "invalid_scope", scope_result, state)

    # PKCE: accept and store for M4; only S256 allowed later, for M2 we just store if present
    if code_challenge_method and code_challenge_method != "S256":
        return _redirect_error(
            redirect_uri,
            "invalid_request",
            "code_challenge_method must be S256",
            state,
        )

    # Render login form with auth request params as hidden fields (values escaped for XSS)
    def e(s: str) -> str:
        return html.escape(s or "")

    nonce_val = request.query_params.get("nonce", "")
    body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Log in</title></head>
<body>
  <h1>Log in</h1>
  <form method="post" action="/authorize">
    <input type="hidden" name="client_id" value="{e(client_id)}"/>
    <input type="hidden" name="redirect_uri" value="{e(redirect_uri)}"/>
    <input type="hidden" name="scope" value="{e(scope)}"/>
    <input type="hidden" name="state" value="{e(state)}"/>
    <input type="hidden" name="response_type" value="code"/>
    <input type="hidden" name="code_challenge" value="{e(code_challenge)}"/>
    <input type="hidden" name="code_challenge_method" value="{e(code_challenge_method)}"/>
    <input type="hidden" name="nonce" value="{e(nonce_val)}"/>
    <label>Username: <input type="text" name="username" required/></label><br/>
    <label>Password: <input type="password" name="password" required/></label><br/>
    <button type="submit">Log in</button>
  </form>
</body>
</html>"""
    return HTMLResponse(body)


@router.post("/authorize")
def authorize_post(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(""),
    state: str = Form(...),
    response_type: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    code_challenge: str | None = Form(None),
    code_challenge_method: str | None = Form(None),
    nonce: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """
    Process login. On success: create authorization code, redirect to redirect_uri?code=...&state=...
    On failure: re-show login form with error.
    """
    if response_type != "code":
        return HTMLResponse("<h1>Invalid request</h1>", status_code=400)

    client = db.query(Client).filter(Client.client_id == client_id).first()
    if not client or not client.redirect_uri_allowed(redirect_uri):
        return HTMLResponse("<h1>Invalid request</h1>", status_code=400)

    ok, normalized_scope = _validate_scope(scope or None)
    if not ok:
        return _redirect_error(redirect_uri, "invalid_scope", normalized_scope, state)

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        # Re-show login form with error (escape for XSS)
        def e(s: str) -> str:
            return html.escape(s or "")

        body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Log in</title></head>
<body>
  <h1>Log in</h1>
  <p style="color:red;">Invalid username or password.</p>
  <form method="post" action="/authorize">
    <input type="hidden" name="client_id" value="{e(client_id)}"/>
    <input type="hidden" name="redirect_uri" value="{e(redirect_uri)}"/>
    <input type="hidden" name="scope" value="{e(scope)}"/>
    <input type="hidden" name="state" value="{e(state)}"/>
    <input type="hidden" name="response_type" value="code"/>
    <input type="hidden" name="code_challenge" value="{e(code_challenge)}"/>
    <input type="hidden" name="code_challenge_method" value="{e(code_challenge_method)}"/>
    <input type="hidden" name="nonce" value="{e(nonce)}"/>
    <label>Username: <input type="text" name="username" value="{e(username)}"/></label><br/>
    <label>Password: <input type="password" name="password" required/></label><br/>
    <button type="submit">Log in</button>
  </form>
</body>
</html>"""
        return HTMLResponse(body, status_code=401)

    # Consent step (M5): show Allow/Deny before issuing code
    def e(s: str) -> str:
        return html.escape(s or "")

    scope_display = normalized_scope or "(none)"
    body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Consent</title></head>
<body>
  <h1>Consent</h1>
  <p><strong>{e(client_id)}</strong> requests the following scopes: {e(scope_display)}</p>
  <form method="post" action="/authorize/confirm" style="display:inline;">
    <input type="hidden" name="user_id" value="{user.id}"/>
    <input type="hidden" name="client_id" value="{e(client_id)}"/>
    <input type="hidden" name="redirect_uri" value="{e(redirect_uri)}"/>
    <input type="hidden" name="scope" value="{e(normalized_scope)}"/>
    <input type="hidden" name="state" value="{e(state)}"/>
    <input type="hidden" name="code_challenge" value="{e(code_challenge)}"/>
    <input type="hidden" name="code_challenge_method" value="{e(code_challenge_method)}"/>
    <input type="hidden" name="nonce" value="{e(nonce)}"/>
    <input type="hidden" name="allow" value="true"/>
    <button type="submit">Allow</button>
  </form>
  <form method="post" action="/authorize/confirm" style="display:inline;">
    <input type="hidden" name="user_id" value="{user.id}"/>
    <input type="hidden" name="client_id" value="{e(client_id)}"/>
    <input type="hidden" name="redirect_uri" value="{e(redirect_uri)}"/>
    <input type="hidden" name="scope" value="{e(normalized_scope)}"/>
    <input type="hidden" name="state" value="{e(state)}"/>
    <input type="hidden" name="code_challenge" value="{e(code_challenge)}"/>
    <input type="hidden" name="code_challenge_method" value="{e(code_challenge_method)}"/>
    <input type="hidden" name="nonce" value="{e(nonce)}"/>
    <input type="hidden" name="allow" value="false"/>
    <button type="submit">Deny</button>
  </form>
</body>
</html>"""
    return HTMLResponse(body)


@router.post("/authorize/confirm")
def authorize_confirm(
    user_id: int = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(""),
    state: str = Form(...),
    allow: str = Form(...),
    code_challenge: str | None = Form(None),
    code_challenge_method: str | None = Form(None),
    nonce: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """
    Process consent. If allow: create authorization code and redirect to client. If deny: redirect with access_denied.
    """
    client = db.query(Client).filter(Client.client_id == client_id).first()
    if not client or not client.redirect_uri_allowed(redirect_uri):
        return HTMLResponse("<h1>Invalid request</h1>", status_code=400)

    if allow.lower() in ("true", "1", "yes", "allow"):
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return HTMLResponse("<h1>Invalid request</h1>", status_code=400)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=CODE_TTL_SECONDS)
        code = secrets.token_urlsafe(32)
        db.add(
            AuthorizationCode(
                code=code,
                client_id=client_id,
                redirect_uri=redirect_uri,
                user_id=user_id,
                scope=scope if scope else None,
                code_challenge=code_challenge if code_challenge else None,
                code_challenge_method=code_challenge_method if code_challenge_method else None,
                nonce=nonce if nonce else None,
                expires_at=expires_at,
            )
        )
        db.commit()
        params = {"code": code, "state": state}
        return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)
    # Deny
    return _redirect_error(redirect_uri, "access_denied", "User denied authorization", state)
