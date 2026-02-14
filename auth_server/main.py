"""
Authorization Server (OIDC Provider) — Milestone 0 scaffolding.
No OAuth logic yet. Port 9000 per PROJECT_CONTEXT.md.
"""
from fastapi import FastAPI

app = FastAPI(title="Auth Server", version="0.1.0")


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "auth_server"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "auth_server.main:app",
        host="127.0.0.1",
        port=9000,
        reload=True,
    )
