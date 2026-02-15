"""
Authorization Server (OIDC Provider) — Milestone 2.
User login, client registry, GET/POST /authorize, authorization code storage.
Port 9000 per PROJECT_CONTEXT.md.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI

from auth_server.authorize import router as authorize_router
from auth_server.database import init_db, SessionLocal
from auth_server.keys import get_signing_key
from auth_server.seed import seed_from_env
from auth_server.token_endpoint import router as token_router
from auth_server.userinfo import router as userinfo_router
from auth_server.well_known import router as well_known_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables, load signing key, seed user/client from env on startup."""
    init_db()
    get_signing_key()
    db = SessionLocal()
    try:
        seed_from_env(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Auth Server", version="0.4.0", lifespan=lifespan)
app.include_router(authorize_router, tags=["authorize"])
app.include_router(token_router, tags=["token"])
app.include_router(userinfo_router, tags=["userinfo"])
app.include_router(well_known_router, tags=["well-known"])


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
