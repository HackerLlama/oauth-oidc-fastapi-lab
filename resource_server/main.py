"""
Resource Server (Protected API) — Milestone 0 scaffolding.
No OAuth logic yet. Port 7000 per PROJECT_CONTEXT.md.
"""
from fastapi import FastAPI

app = FastAPI(title="Resource Server", version="0.1.0")


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "resource_server"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "resource_server.main:app",
        host="127.0.0.1",
        port=7000,
        reload=True,
    )
