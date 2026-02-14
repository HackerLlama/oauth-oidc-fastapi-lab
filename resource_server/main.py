"""
Resource Server (Protected API) — Milestone 1.
JWT validation via JWKS; /public, /me (api.read), /admin (api.admin).
Port 7000 per PROJECT_CONTEXT.md.
"""
from fastapi import FastAPI

from resource_server.auth import RequireAdmin, RequireRead

app = FastAPI(title="Resource Server", version="0.1.0")


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "resource_server"}


@app.get("/public")
def public():
    """Public endpoint; no authentication required."""
    return {"message": "Public data", "access": "anonymous"}


@app.get("/me")
def me(claims: dict = RequireRead):
    """Requires scope api.read. Returns caller identity from token."""
    sub = claims.get("sub", "unknown")
    return {"message": "Authenticated", "sub": sub}


@app.get("/admin")
def admin(claims: dict = RequireAdmin):
    """Requires scope api.admin."""
    sub = claims.get("sub", "unknown")
    return {"message": "Admin access", "sub": sub}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "resource_server.main:app",
        host="127.0.0.1",
        port=7000,
        reload=True,
    )
