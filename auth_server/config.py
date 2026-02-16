"""
Authorization Server configuration. Values from PROJECT_CONTEXT.md.
No secrets in this file; credentials come from env or DB.
"""
import os

# Issuer URL (public identifier)
ISSUER = os.environ.get("OAUTH_ISSUER", "http://127.0.0.1:9000").rstrip("/")

# Authorization code lifetime (seconds). PROJECT_CONTEXT: short-lived (30 seconds)
CODE_TTL_SECONDS = 30

# Allowed scopes (PROJECT_CONTEXT supported scopes)
ALLOWED_SCOPES = {"openid", "profile", "email", "api.read", "api.admin"}

# SQLite DB for development (PROJECT_CONTEXT: SQLite acceptable)
DATABASE_URL = os.environ.get("AUTH_DATABASE_URL", "sqlite:///./auth_server.db")

# API audience for access tokens (PROJECT_CONTEXT)
API_AUDIENCE = os.environ.get("OAUTH_API_AUDIENCE", "http://127.0.0.1:7000")

# Access token lifetime (seconds). PROJECT_CONTEXT: short-lived (1 minute)
ACCESS_TOKEN_EXPIRES = 60

# Refresh token lifetime (seconds). Long-lived for obtaining new access tokens without re-auth.
REFRESH_TOKEN_EXPIRES = int(os.environ.get("OAUTH_REFRESH_TOKEN_EXPIRES", "180"))  # default 3 minutes

# Path to RSA private key PEM file for signing tokens. If unset or file missing, a key is generated and saved to .auth_signing_key.pem (no secret in code).
SIGNING_KEY_PATH = os.environ.get("OAUTH_SIGNING_KEY_PATH", ".auth_signing_key.pem")
# Optional previous key for rotation (M11): included in JWKS so existing tokens still verify; not used for new tokens.
SIGNING_KEY_PREVIOUS_PATH = os.environ.get("OAUTH_SIGNING_KEY_PREVIOUS_PATH", "").strip() or None

# Rate limiting (M14): per-IP, per minute. No credentials in code.
RATE_LIMIT_LOGIN_PER_MINUTE = int(os.environ.get("OAUTH_RATE_LIMIT_LOGIN_PER_MINUTE", "20"))
RATE_LIMIT_TOKEN_PER_MINUTE = int(os.environ.get("OAUTH_RATE_LIMIT_TOKEN_PER_MINUTE", "60"))
