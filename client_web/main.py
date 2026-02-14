"""
Client Web App — Milestone 0 scaffolding.
No OAuth logic yet. Port 8000 per PROJECT_CONTEXT.md.
"""
from fastapi import FastAPI

app = FastAPI(title="Client Web", version="0.1.0")


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "client_web"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "client_web.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
