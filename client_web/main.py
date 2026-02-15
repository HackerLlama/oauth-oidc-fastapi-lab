"""
Client Web App — Milestone 4.
Generate state, nonce, PKCE; redirect to AS; callback exchanges code for tokens.
GET /, /start-login, /callback. Port 8000 per PROJECT_CONTEXT.md.
"""
import html
from urllib.parse import parse_qs

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from client_web.config import CLIENT_ID, DEFAULT_SCOPE, ISSUER, REDIRECT_URI, RESOURCE_SERVER_URL
from client_web.flow_store import get_flow, store_flow
from client_web.pkce import build_authorize_url, generate_nonce, generate_pkce, generate_state
from client_web.token_store import clear_tokens, get_tokens, store_tokens

app = FastAPI(title="Client Web", version="0.3.0")


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "client_web"}


@app.get("/", response_class=HTMLResponse)
def home():
    """Home page with link to start login and Call /me (M7)."""
    return HTMLResponse(
        """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>OAuth Client</title></head>
<body>
  <h1>OAuth2 + OIDC Client</h1>
  <p><a href="/start-login">Log in</a></p>
  <p><a href="/call-me">Call /me</a> (resource server; requires login)</p>
</body>
</html>"""
    )


@app.get("/start-login")
def start_login():
    """
    Generate state, nonce, PKCE verifier + challenge; store for callback; redirect to AS /authorize.
    """
    state = generate_state()
    nonce = generate_nonce()
    code_verifier, code_challenge = generate_pkce()
    store_flow(state, nonce=nonce, code_verifier=code_verifier)

    url = build_authorize_url(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT_URI,
        scope=DEFAULT_SCOPE,
        state=state,
        code_challenge=code_challenge,
        nonce=nonce,  # required when openid scope requested
    )
    return RedirectResponse(url=url, status_code=302)


@app.get("/callback", response_class=HTMLResponse)
def callback(request: Request):
    """
    Handle redirect from AS. Validates state; shows code (or error). Token exchange in M4.
    """
    # Prefer query params (AS redirects with ?code=...&state=... or ?error=...&state=...)
    query = request.url.query
    if query:
        params = parse_qs(query, keep_blank_values=False)
        code_list = params.get("code")
        state_list = params.get("state")
        error_list = params.get("error")
        error_desc_list = params.get("error_description")
        code = code_list[0] if code_list else None
        state = state_list[0] if state_list else None
        error = error_list[0] if error_list else None
        error_description = error_desc_list[0] if error_desc_list else None
    else:
        code = state = error = error_description = None

    if error:
        flow = get_flow(state) if state else None
        msg = html.escape(error_description or error)
        return HTMLResponse(
            f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Login error</title></head>
<body>
  <h1>Login error</h1>
  <p>{msg}</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
            status_code=400,
        )

    if not state:
        return HTMLResponse(
            """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Error</title></head>
<body>
  <h1>Error</h1>
  <p>Missing state parameter.</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
            status_code=400,
        )

    flow = get_flow(state)
    if not flow:
        return HTMLResponse(
            """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Error</title></head>
<body>
  <h1>Error</h1>
  <p>Invalid or expired state. Please try logging in again.</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
            status_code=400,
        )

    if not code:
        return HTMLResponse(
            """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Error</title></head>
<body>
  <h1>Error</h1>
  <p>Missing code parameter.</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
            status_code=400,
        )

    # Exchange code for tokens (Milestone 4)
    try:
        r = httpx.post(
            f"{ISSUER}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": flow.code_verifier,
            },
            headers={"Accept": "application/json"},
            timeout=10.0,
        )
    except Exception as e:
        return HTMLResponse(
            f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Token error</title></head>
<body>
  <h1>Token exchange failed</h1>
  <p>{html.escape(str(e))}</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
            status_code=502,
        )

    if r.status_code != 200:
        err = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        err_desc = err.get("error_description", err.get("error", r.text)) or "Token exchange failed"
        return HTMLResponse(
            f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Token error</title></head>
<body>
  <h1>Token exchange failed</h1>
  <p>{html.escape(str(err_desc))}</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
            status_code=400,
        )

    data = r.json()
    access_token = data.get("access_token", "")
    refresh_token = data.get("refresh_token", "")
    expires_in = data.get("expires_in", 0)
    scope = data.get("scope", "")
    if access_token and refresh_token:
        store_tokens(access_token=access_token, refresh_token=refresh_token, expires_in=expires_in, scope=scope)
    id_token = data.get("id_token", "")
    has_id = "Yes" if id_token else "No"
    return HTMLResponse(
        f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Login success</title></head>
<body>
  <h1>Login success</h1>
  <p>Access token and ID token received.</p>
  <p>Scope: <code>{html.escape(scope)}</code></p>
  <p>ID token received: {has_id}</p>
  <p><a href="/call-me">Call /me</a> (resource server)</p>
  <p><a href="/">Home</a></p>
</body>
</html>"""
    )


def _refresh_tokens(refresh_token_value: str) -> dict | None:
    """Exchange refresh_token for new tokens. Returns token response dict or None on failure."""
    try:
        r = httpx.post(
            f"{ISSUER}/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token_value,
                "client_id": CLIENT_ID,
            },
            headers={"Accept": "application/json"},
            timeout=10.0,
        )
    except Exception:
        return None
    if r.status_code != 200:
        return None
    return r.json()


@app.get("/call-me", response_class=HTMLResponse)
def call_me():
    """
    Call resource server GET /me with stored access token. On 401, refresh and retry once (M7).
    """
    tokens = get_tokens()
    if not tokens:
        return HTMLResponse(
            """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Call /me</title></head>
<body>
  <h1>Call /me</h1>
  <p>No tokens. <a href="/start-login">Log in</a> first.</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
            status_code=200,
        )

    # Proactive refresh: if access token is expired or soon to expire, refresh first
    if tokens.access_token_expired_or_soon(buffer_seconds=60):
        data = _refresh_tokens(tokens.refresh_token)
        if data:
            store_tokens(
                access_token=data["access_token"],
                refresh_token=data["refresh_token"],
                expires_in=data.get("expires_in", tokens.expires_in),
                scope=data.get("scope", tokens.scope),
            )
            tokens = get_tokens()
        else:
            clear_tokens()
            return HTMLResponse(
                """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Call /me</title></head>
<body>
  <h1>Call /me</h1>
  <p>Token expired and refresh failed. <a href="/start-login">Log in</a> again.</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
                status_code=200,
            )

    # Call resource server
    try:
        r = httpx.get(
            f"{RESOURCE_SERVER_URL}/me",
            headers={"Authorization": f"Bearer {tokens.access_token}"},
            timeout=10.0,
        )
    except Exception as e:
        return HTMLResponse(
            f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Call /me</title></head>
<body>
  <h1>Call /me</h1>
  <p>Request failed: {html.escape(str(e))}</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
            status_code=502,
        )

    # On 401: refresh and retry once
    if r.status_code == 401:
        data = _refresh_tokens(tokens.refresh_token)
        if not data:
            clear_tokens()
            return HTMLResponse(
                """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Call /me</title></head>
<body>
  <h1>Call /me</h1>
  <p>401 Unauthorized; refresh failed. <a href="/start-login">Log in</a> again.</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
                status_code=200,
            )
        store_tokens(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_in=data.get("expires_in", tokens.expires_in),
            scope=data.get("scope", tokens.scope),
        )
        tokens = get_tokens()
        try:
            r = httpx.get(
                f"{RESOURCE_SERVER_URL}/me",
                headers={"Authorization": f"Bearer {tokens.access_token}"},
                timeout=10.0,
            )
        except Exception as e:
            return HTMLResponse(
                f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Call /me</title></head>
<body>
  <h1>Call /me</h1>
  <p>Retry failed: {html.escape(str(e))}</p>
  <p><a href="/">Home</a></p>
</body>
</html>""",
                status_code=502,
            )

    # Display result
    try:
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text
        if isinstance(body, dict):
            import json
            body_str = json.dumps(body, indent=2)
        else:
            body_str = html.escape(str(body))
    except Exception:
        body_str = html.escape(r.text[:500] if r.text else "(no body)")
    status = r.status_code
    return HTMLResponse(
        f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Call /me</title></head>
<body>
  <h1>Call /me</h1>
  <p>Status: {status}</p>
  <pre>{body_str}</pre>
  <p><a href="/call-me">Call /me again</a> | <a href="/">Home</a></p>
</body>
</html>"""
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "client_web.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
