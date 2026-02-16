# Environment variables (all three servers)

No credentials are hardcoded. Use these env vars to configure each service. Defaults match PROJECT_CONTEXT (ports 9000, 8000, 7000).

For API endpoint details, see the [OpenAPI specs](README.md) in this folder.

---

## Authorization Server (auth_server, port 9000)

| Variable | Purpose | Default |
|----------|---------|---------|
| `OAUTH_ISSUER` | Issuer URL (public) | `http://127.0.0.1:9000` |
| `AUTH_DATABASE_URL` | SQLAlchemy DB URL | `sqlite:///./auth_server.db` |
| `OAUTH_SIGNING_KEY_PATH` | Path to RSA PEM for signing tokens | `.auth_signing_key.pem` |
| `OAUTH_SIGNING_KEY_PREVIOUS_PATH` | Optional previous key for rotation (M11); included in JWKS for verification only | — |
| `OAUTH_RATE_LIMIT_LOGIN_PER_MINUTE` | Max POST /authorize (login) attempts per IP per minute (M14); 429 when exceeded | `20` |
| `OAUTH_RATE_LIMIT_TOKEN_PER_MINUTE` | Max POST /token requests per IP per minute (M14); 429 when exceeded | `60` |
| `OAUTH_REFRESH_TOKEN_EXPIRES` | Refresh token lifetime (seconds) | `86400` (24h) |
| **Optional seed (no default credentials)** | | |
| `OAUTH_SEED_USER` | Create a login user with this username | — |
| `OAUTH_SEED_PASSWORD` | Password for that user (hashed with bcrypt) | — |
| `OAUTH_CLIENT_ID` | Register a client with this `client_id` | — |
| `OAUTH_REDIRECT_URI` | Allowed redirect URI(s), comma-separated | — |
| `OAUTH_REDIRECT_URIS` | Alternative to `OAUTH_REDIRECT_URI` | — |
| `OAUTH_SEED_CLIENT_SECRET` | If set, the seeded client is confidential; secret is hashed and stored | — |

If no clients exist at startup, a default dev client is created: `client_id=test-client`, `redirect_uri=http://127.0.0.1:8000/callback`. You still need at least one user (via `OAUTH_SEED_USER` + `OAUTH_SEED_PASSWORD`) to log in.

**Audit UI (M15, lab only):** `GET {OAUTH_ISSUER}/audit/ui` — read-only HTML view of recent audit events, with optional filters (event type, outcome, client_id, limit). Unauthenticated; do not expose in production.

---

## Client Web (client_web, port 8000)

| Variable | Purpose | Default |
|----------|---------|---------|
| `OAUTH_ISSUER` | Authorization Server URL | `http://127.0.0.1:9000` |
| `OAUTH_CLIENT_ID` | Client ID (must be registered at AS) | `test-client` |
| `OAUTH_REDIRECT_URI` | Callback URL for this app | `http://127.0.0.1:8000/callback` |
| `OAUTH_SCOPE` | Requested scopes | `openid api.read` |
| `OAUTH_RESOURCE_SERVER_URL` | Resource server base URL (for Call /me) | `http://127.0.0.1:7000` |
| `OAUTH_POST_LOGOUT_REDIRECT_URI` | Where AS redirects after logout (M10); must be in client's redirect_uris at AS | `http://127.0.0.1:8000/logged-out` |

---

## Resource Server (resource_server, port 7000)

| Variable | Purpose | Default |
|----------|---------|---------|
| `OAUTH_ISSUER` | Authorization Server URL (for JWKS) | `http://127.0.0.1:9000` |
| `OAUTH_API_AUDIENCE` | Audience value in access tokens | `http://127.0.0.1:7000` |

---

## Quick start (all defaults)

**Mandatory for a working login flow:** only the auth server needs env vars. You must set `OAUTH_SEED_USER` and `OAUTH_SEED_PASSWORD` before starting the auth server so at least one user exists; otherwise login will always fail. The client and resource server need no env vars when using the default topology (ports 9000, 8000, 7000).

```bash
# 1. Auth server: set seed user (mandatory for login; no default credentials)
export OAUTH_SEED_USER=alice
export OAUTH_SEED_PASSWORD=yourpassword
python -m auth_server.main

# 2. Client (separate terminal; no env needed — defaults match dev client)
python -m client_web.main

# 3. Resource server (separate terminal; no env needed)
python -m resource_server.main
```

If you set `OAUTH_CLIENT_ID` and `OAUTH_REDIRECT_URI` on the auth server, they register an extra client; otherwise the default dev client (`test-client`, `http://127.0.0.1:8000/callback`) is created so the client_web can log in.
