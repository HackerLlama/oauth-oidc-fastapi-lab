# Environment variables (all three servers)

No credentials are hardcoded. Use these env vars to configure each service. Defaults match PROJECT_CONTEXT (ports 9000, 8000, 7000).

---

## Authorization Server (auth_server, port 9000)

| Variable | Purpose | Default |
|----------|---------|---------|
| `OAUTH_ISSUER` | Issuer URL (public) | `http://127.0.0.1:9000` |
| `AUTH_DATABASE_URL` | SQLAlchemy DB URL | `sqlite:///./auth_server.db` |
| **Optional seed (no default credentials)** | | |
| `OAUTH_SEED_USER` | Create a login user with this username | — |
| `OAUTH_SEED_PASSWORD` | Password for that user (hashed with bcrypt) | — |
| `OAUTH_CLIENT_ID` | Register a client with this `client_id` | — |
| `OAUTH_REDIRECT_URI` | Allowed redirect URI(s), comma-separated | — |
| `OAUTH_REDIRECT_URIS` | Alternative to `OAUTH_REDIRECT_URI` | — |

If no clients exist at startup, a default dev client is created: `client_id=test-client`, `redirect_uri=http://127.0.0.1:8000/callback`. You still need at least one user (via `OAUTH_SEED_USER` + `OAUTH_SEED_PASSWORD`) to log in.

---

## Client Web (client_web, port 8000)

| Variable | Purpose | Default |
|----------|---------|---------|
| `OAUTH_ISSUER` | Authorization Server URL | `http://127.0.0.1:9000` |
| `OAUTH_CLIENT_ID` | Client ID (must be registered at AS) | `test-client` |
| `OAUTH_REDIRECT_URI` | Callback URL for this app | `http://127.0.0.1:8000/callback` |
| `OAUTH_SCOPE` | Requested scopes | `openid api.read` |

---

## Resource Server (resource_server, port 7000)

| Variable | Purpose | Default |
|----------|---------|---------|
| `OAUTH_ISSUER` | Authorization Server URL (for JWKS) | `http://127.0.0.1:9000` |
| `OAUTH_API_AUDIENCE` | Audience value in access tokens | `http://127.0.0.1:7000` |

---

## Quick start (all defaults)

```bash
# 1. Auth server: create one user (required to log in)
export OAUTH_SEED_USER=alice
export OAUTH_SEED_PASSWORD=yourpassword
python -m auth_server.main

# 2. Client (separate terminal; defaults match dev client)
python -m client_web.main

# 3. Resource server (separate terminal)
python -m resource_server.main
```

If you set `OAUTH_CLIENT_ID` and `OAUTH_REDIRECT_URI` on the auth server, they register an extra client; otherwise the default dev client is used so the client_web can log in.
