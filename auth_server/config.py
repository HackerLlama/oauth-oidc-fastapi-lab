"""
Authorization Server configuration. Values from PROJECT_CONTEXT.md.
No secrets in this file; credentials come from env or DB.
"""
import os

# Issuer URL (public identifier)
ISSUER = os.environ.get("OAUTH_ISSUER", "http://127.0.0.1:9000").rstrip("/")

# Authorization code lifetime (seconds). PROJECT_CONTEXT: short-lived (1 minute)
CODE_TTL_SECONDS = 60

# Allowed scopes (PROJECT_CONTEXT supported scopes)
ALLOWED_SCOPES = {"openid", "profile", "email", "api.read", "api.admin"}

# SQLite DB for development (PROJECT_CONTEXT: SQLite acceptable)
DATABASE_URL = os.environ.get("AUTH_DATABASE_URL", "sqlite:///./auth_server.db")
