# OAuth2 + OIDC FastAPI Lab

A small **educational** OAuth2 and OpenID Connect (OIDC) ecosystem built with [FastAPI](https://fastapi.tiangolo.com/). The project implements all three roles—Authorization Server (OIDC provider), Resource Server (protected API), and Client (web app)—so you can see the full flow and security checks in one repo.

**Disclosure:** This repository and its implementation were generated with AI assistance (e.g. ChatGPT, Cursor/Codex) as part of a structured “learn by doing” path. Use it as a reference or lab; review and harden before any production use.

---

## What’s in this repo

- **auth_server** (port 9000) — Authorization Server / OIDC provider (scaffolding; OAuth logic in later milestones).
- **client_web** (port 8000) — Web client that will initiate login and handle the callback (scaffolding).
- **resource_server** (port 7000) — Protected API with JWT validation via JWKS; endpoints: `/public`, `/me` (requires `api.read`), `/admin` (requires `api.admin`).

Flow: **Authorization Code + PKCE (S256)** only; JWTs for access and ID tokens; exact redirect URI matching and scope checks. See [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) for topology, scopes, token format, and security rules.

---

## Quick start

```bash
# Clone and enter the repo
git clone https://github.com/YOUR_USERNAME/oauth-oidc-fastapi-lab.git
cd oauth-oidc-fastapi-lab

# Use a virtual environment and install one app’s deps (example: resource server)
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r resource_server/requirements.txt

# Run one service (from repo root)
python -m resource_server.main   # API at http://127.0.0.1:7000
# Or: python -m auth_server.main   (9000)
# Or: python -m client_web.main     (8000)
```

- **Health:** `GET http://127.0.0.1:7000/health` (or 8000 / 9000).
- **Public API:** `GET http://127.0.0.1:7000/public` (no auth). `/me` and `/admin` require a valid access token from the auth server (once it issues tokens in later milestones).

**Tests (resource server):**

```bash
pip install -r resource_server/requirements.txt
pytest resource_server/tests/ -v
```

---

## Project layout

| Path | Purpose |
|------|--------|
| [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) | Ports, flows, scopes, token format, endpoints, security rules |
| [MILESTONES.md](MILESTONES.md) | Step-by-step implementation plan and prerequisite links |
| `auth_server/` | Authorization Server app |
| `client_web/` | Client web app |
| `resource_server/` | Resource Server app + JWT/JWKS auth |
| `docs/` | Extra docs (e.g. endpoints, threat model) |

---

## Status

- **Milestone 0** — Done: three FastAPI apps, health endpoints, uvicorn entrypoints.
- **Milestone 1** — Done: resource server JWT validation via JWKS; `/public`, `/me`, `/admin`; pytest for success and failure paths.
- **Milestones 2–6** — Planned: authorize endpoint, client login + PKCE, token endpoint + JWTs, UserInfo/consent, refresh and revocation.

Details and “before you start” notes for each milestone are in [MILESTONES.md](MILESTONES.md).

---

## License

MIT License. See [LICENSE](LICENSE).
