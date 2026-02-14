"""
Resource server configuration. Values from PROJECT_CONTEXT.md.
Issuer and API audience are public identifiers, not secrets.
"""
import os

# Authorization Server (OIDC Provider) — where we fetch JWKS and validate iss
ISSUER = os.environ.get("OAUTH_ISSUER", "http://127.0.0.1:9000").rstrip("/")

# This API's audience — access tokens must include this in aud
API_AUDIENCE = os.environ.get("OAUTH_API_AUDIENCE", "http://127.0.0.1:7000")

# Scopes required by protected routes (from PROJECT_CONTEXT supported scopes)
SCOPE_READ = "api.read"
SCOPE_ADMIN = "api.admin"
