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

# API audience for access tokens (PROJECT_CONTEXT)
API_AUDIENCE = os.environ.get("OAUTH_API_AUDIENCE", "http://127.0.0.1:7000")

# Access token lifetime (seconds). PROJECT_CONTEXT: short-lived (10 minutes)
ACCESS_TOKEN_EXPIRES = 600

# Path to RSA private key PEM file for signing tokens. If unset or file missing, a key is generated and saved to .auth_signing_key.pem (no secret in code).
SIGNING_KEY_PATH = os.environ.get("OAUTH_SIGNING_KEY_PATH", ".auth_signing_key.pem")
