"""
Client Web configuration. Values from PROJECT_CONTEXT.md.
"""
import os

# Authorization Server (issuer) — where we redirect for login
ISSUER = os.environ.get("OAUTH_ISSUER", "http://127.0.0.1:9000").rstrip("/")

# Our client_id (must be registered at AS)
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "test-client")

# Callback URL where AS redirects after authorization (PROJECT_CONTEXT: client at 8000)
REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "http://127.0.0.1:8000/callback")

# Where AS redirects after logout (M10); must be in client's redirect_uris at AS
POST_LOGOUT_REDIRECT_URI = os.environ.get("OAUTH_POST_LOGOUT_REDIRECT_URI", "http://127.0.0.1:8000/logged-out")

# Default scopes: openid (so nonce is required) + api.read for resource server
DEFAULT_SCOPE = os.environ.get("OAUTH_SCOPE", "openid api.read")

# Resource Server base URL (for M7: call /me, /admin, etc.)
RESOURCE_SERVER_URL = os.environ.get("OAUTH_RESOURCE_SERVER_URL", "http://127.0.0.1:7000").rstrip("/")
