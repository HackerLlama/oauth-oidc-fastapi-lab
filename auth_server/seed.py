"""
Seed users and OAuth clients from environment. No hardcoded credentials.
Optional: set OAUTH_SEED_USER + OAUTH_SEED_PASSWORD, OAUTH_CLIENT_ID + OAUTH_REDIRECT_URI(s).
"""
import json
import logging
import os

import bcrypt
from sqlalchemy.orm import Session

from auth_server.models import User, Client

logger = logging.getLogger(__name__)


def hash_password(password: str) -> str:
    # Bcrypt has a 72-byte limit
    raw = password.encode("utf-8")
    if len(raw) > 72:
        raw = raw[:72]
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def seed_from_env(db: Session) -> None:
    """Create one user and/or one client from env if set."""
    # Optional seed user (no default credentials)
    seed_user = os.environ.get("OAUTH_SEED_USER")
    seed_password = os.environ.get("OAUTH_SEED_PASSWORD")
    if seed_user and seed_password:
        if db.query(User).filter(User.username == seed_user).first() is None:
            db.add(User(username=seed_user, password_hash=hash_password(seed_password)))
            db.commit()
            logger.info("Seeded user: %s", seed_user)
        else:
            logger.debug("User already exists: %s", seed_user)

    # Optional seed client: client_id and redirect_uri(s) comma-separated; optional client_secret (confidential)
    client_id = os.environ.get("OAUTH_CLIENT_ID")
    redirect_uris_str = os.environ.get("OAUTH_REDIRECT_URI") or os.environ.get("OAUTH_REDIRECT_URIS")
    client_secret = os.environ.get("OAUTH_SEED_CLIENT_SECRET")
    if client_id and redirect_uris_str:
        uris = [u.strip() for u in redirect_uris_str.split(",") if u.strip()]
        if uris and db.query(Client).filter(Client.client_id == client_id).first() is None:
            secret_hash = hash_password(client_secret) if client_secret else None
            db.add(Client(client_id=client_id, redirect_uris=json.dumps(uris), client_secret_hash=secret_hash))
            db.commit()
            logger.info("Seeded client: %s (confidential=%s)", client_id, bool(secret_hash))
        elif uris:
            logger.debug("Client already exists: %s", client_id)

    # Development fallback: ensure default dev client exists for client_web (PROJECT_CONTEXT topology)
    # Create test-client if missing so quick start works even when DB already has other clients
    default_client_id = "test-client"
    default_redirect_uri = "http://127.0.0.1:8000/callback"
    if db.query(Client).filter(Client.client_id == default_client_id).first() is None:
        db.add(Client(client_id=default_client_id, redirect_uris=json.dumps([default_redirect_uri])))
        db.commit()
        logger.info("Seeded default dev client: %s", default_client_id)
