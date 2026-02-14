# Milestones

## Milestone 0 — Scaffolding
- Create three FastAPI apps:
  - auth_server
  - client_web
  - resource_server
- Add uvicorn entrypoints
- Add health endpoints

## Milestone 1 — Resource Server
- Implement JWT validation via JWKS
- Implement:
  - /public
  - /me (api.read)
  - /admin (api.admin)

## Milestone 2 — Authorization Endpoint
- User login
- Client registry
- /authorize endpoint
- Store authorization codes

## Milestone 3 — Client Login Initiation
- Generate state
- Generate nonce
- Generate PKCE verifier + challenge
- Redirect to AS

## Milestone 4 — Token Endpoint + JWT Issuance
- Validate code
- Validate PKCE
- Issue access_token
- Issue id_token
- Add JWKS
- Add discovery document

## Milestone 5 — OIDC UserInfo + Consent

## Milestone 6 — Refresh Tokens + Revocation
