# OAuth2 + OIDC FastAPI Lab — Project Context

## Objective

Build a complete OAuth2 + OpenID Connect ecosystem using FastAPI for all three roles:

1. Authorization Server (OIDC Provider)
2. Resource Server (Protected API)
3. Client (Web client)

The purpose is educational: implement protocol-correct OAuth2 + OIDC with PKCE, JWTs, discovery, and proper validation.

This project prioritizes correctness, security clarity, and incremental milestones over production hardening.

---

# Local Development Topology

All services run on the same host using different ports:

- Authorization Server (AS / OIDC Provider):
  http://127.0.0.1:9000

- Client Web App:
  http://127.0.0.1:8000

- Resource Server (API):
  http://127.0.0.1:7000

Issuer:
http://127.0.0.1:9000

API Audience:
http://127.0.0.1:7000

---

# Supported OAuth2 Flow

Authorization Code + PKCE (S256 only)

- state REQUIRED
- nonce REQUIRED when `openid` scope requested
- exact redirect URI matching
- Authorization codes are:
  - short-lived (1 minute)
  - single-use

---

# Supported Scopes

openid
profile
email
api.read
api.admin

---

# Token Format

Access Token:
- JWT
- signed with RSA key
- aud = http://127.0.0.1:7000
- includes `scope`
- short lifetime (10 minutes)

ID Token:
- JWT
- aud = client_id
- includes `nonce`
- includes standard claims:
  - iss
  - sub
  - aud
  - exp
  - iat
  - nonce

---

# Required Endpoints

Authorization Server:

GET  /authorize
POST /token
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /userinfo
POST /revoke

Client:

GET  /
GET  /start-login
GET  /callback

Resource Server:

GET  /public
GET  /me (requires api.read)
GET  /admin (requires api.admin)

**API specs:** OpenAPI 3.0 YAML for each service are in [docs/](docs/README.md): [auth server](docs/openapi-auth-server.yaml), [client web](docs/openapi-client-web.yaml), [resource server](docs/openapi-resource-server.yaml).

---

# Security Rules

- Exact redirect URI matching
- PKCE S256 only
- Validate state
- Validate nonce in ID token
- Validate iss, aud, exp in both RS and Client
- One-time-use authorization codes
- Short-lived access tokens

---

# Persistence

Use SQLAlchemy for:

- Users
- OAuth Clients
- Authorization Codes
- Refresh Tokens

SQLite is acceptable for development.

---

# Project plan

The implementation plan is in [MILESTONES.md](MILESTONES.md): **M0–M6** (core OAuth2/OIDC flow, UserInfo, consent, refresh, revocation) and **M7–M14** (client refresh, introspection, client auth, logout, key rotation, scope refinement, audit logging, rate limiting). Implement incrementally in that order.

---

# Development Philosophy

- Implement incrementally in milestones
- No feature creep
- No adding new OAuth flows
- No implicit flow
- No password grant
- Follow documented behavior exactly
