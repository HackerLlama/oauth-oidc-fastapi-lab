"""
Authorization Server (OIDC Provider) — Milestone 2.
User login, client registry, GET/POST /authorize, authorization code storage.
Port 9000 per PROJECT_CONTEXT.md.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI

from auth_server.authorize import router as authorize_router
from auth_server.database import init_db, get_db, SessionLocal
from auth_server.seed import seed_from_env


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables and seed user/client from env on startup."""
    init_db()
    db = SessionLocal()
    try:
        seed_from_env(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Auth Server", version="0.2.0", lifespan=lifespan)
app.include_router(authorize_router, tags=["authorize"])


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
