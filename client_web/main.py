"""
Client Web App — Milestone 3.
Generate state, nonce, PKCE verifier + challenge; redirect to AS. GET /, /start-login, /callback.
Port 8000 per PROJECT_CONTEXT.md.
"""
import html
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from client_web.config import CLIENT_ID, DEFAULT_SCOPE, ISSUER, REDIRECT_URI
from client_web.flow_store import get_flow, store_flow
from client_web.pkce import build_authorize_url, generate_nonce, generate_pkce, generate_state

app = FastAPI(title="Client Web", version="0.3.0")


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "client_web"}


@app.get("/", response_class=HTMLResponse)
def home():
    """Home page with link to start login."""
    return HTMLResponse(
        """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>OAuth Client</title></head>
<body>
  <h1>OAuth2 + OIDC Client</h1>
  <p><a href="/start-login">Log in</a></p>
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

    # State valid; we have code_verifier in flow for M4 token exchange
    code_display = html.escape(code) if code else "(none)"
    return HTMLResponse(
        f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Login success</title></head>
<body>
  <h1>Login success</h1>
  <p>Authorization code received (token exchange in next milestone).</p>
  <p><code>code</code>: <code>{code_display}</code></p>
  <p><a href="/">Home</a></p>
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
