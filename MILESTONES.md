# Milestones

Each milestone includes a **Before you start** section: concepts and terms you should understand (or briefly look up) before implementing it.

---

## Milestone 0 — Scaffolding

**Before you start:** FastAPI basics (routing, dependency injection), running an ASGI app with uvicorn. No OAuth knowledge required.

**Tutorial and reference links:**
- [FastAPI – First steps](https://fastapi.tiangolo.com/tutorial/first-steps/)
- [FastAPI – Run with uvicorn](https://fastapi.tiangolo.com/deployment/manual/)

- Create three FastAPI apps:
  - auth_server
  - client_web
  - resource_server
- Add uvicorn entrypoints
- Add health endpoints

---

## Milestone 1 — Resource Server

**Before you start:**
- **JWT structure:** header, payload (claims), signature; meaning of `iss`, `aud`, `exp`, `iat`.
- **JWKS:** JSON Web Key Set — how a server publishes public keys so others can verify JWTs (e.g. `kid`, RSA `n`/`e`).
- **Bearer token:** client sends `Authorization: Bearer <access_token>`; resource server must validate the token before trusting it.
- **Scope:** access token carries `scope`; your API will require `api.read` or `api.admin` for specific routes.

**Tutorial and reference links:**
- [Verifying JWTs with JWKs and PyJWT](https://renzolucioni.com/verifying-jwts-with-jwks-and-pyjwt/)
- [PyJWT – Usage examples](https://pyjwt.readthedocs.io/en/stable/usage.html)
- [RFC 7519 – JWT (structure, claims)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7517 – JWKS](https://datatracker.ietf.org/doc/html/rfc7517)

- Implement JWT validation via JWKS
- Implement:
  - /public
  - /me (api.read)
  - /admin (api.admin)

---

## Milestone 2 — Authorization Endpoint

**Before you start:**
- **Authorization code flow (high level):** user is sent to the AS, AS shows login/consent, AS redirects back to the client with a one-time **authorization code** (not the token).
- **Redirect URI:** where the AS sends the user after approval; must be pre-registered and matched exactly (security).
- **Client registration:** AS stores `client_id`, allowed redirect URIs, and (if used) client secret; we use PKCE so no secret for this lab’s client.
- **Authorization code:** short-lived, single-use; exchanged for tokens at the token endpoint (Milestone 4).

**Tutorial and reference links:**
- [OAuth 2.0 – Authorization Code Grant](https://oauth.net/2/grant-types/authorization-code/)
- [Auth0 – Authorization Code Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow)
- [RFC 6749 §4.1 – Authorization Code](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1)

- User login
- Client registry
- /authorize endpoint
- Store authorization codes

---

## Milestone 3 — Client Login Initiation

**Before you start:**
- **state:** opaque value the client generates, sends to the AS, and receives back on the callback; used to prevent CSRF — you must verify it matches.
- **nonce:** random value sent in the auth request and later reflected in the ID token; binds the ID token to this auth request (replay protection).
- **PKCE (S256):** client generates a random `code_verifier`, derives `code_challenge = BASE64URL(SHA256(code_verifier))`, sends `code_challenge` + `code_challenge_method=S256` to the AS; later sends `code_verifier` at the token endpoint. Protects the authorization code if the redirect is intercepted.
- **Authorization request:** GET (or POST) to AS `/authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`, and (for OIDC) `nonce`.

**Tutorial and reference links:**
- [OAuth 2.0 – PKCE](https://oauth.net/2/pkce/)
- [oauth.com – PKCE authorization request](https://www.oauth.com/oauth2-servers/pkce/authorization-request/)
- [RFC 7636 – Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636)

- Generate state
- Generate nonce
- Generate PKCE verifier + challenge
- Redirect to AS

---

## Milestone 4 — Token Endpoint + JWT Issuance

**Before you start:**
- **Token endpoint:** POST, typically `application/x-www-form-urlencoded`; parameters include `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`.
- **AS validates:** code exists, not expired, not already used; `redirect_uri` matches the one used in the auth request; PKCE `code_verifier` hashes to the stored `code_challenge`.
- **Access token:** JWT you issue for the resource server; sign with your RSA key; include `aud` (RS URL), `scope`, `exp`, `iss`, `sub` (or similar).
- **ID token:** JWT for the client (OIDC); `aud` = client_id, must include `nonce` (and standard claims). Client will validate it (iss, aud, exp, nonce).
- **JWKS and discovery:** AS exposes `/.well-known/jwks.json` (public keys for token verification) and `/.well-known/openid-configuration` (URLs and capabilities).

**Tutorial and reference links:**
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [Auth0 – Locate JSON Web Key Sets](https://auth0.com/docs/secure/tokens/json-web-tokens/locate-json-web-key-sets)
- [oauth.com – Token endpoint (code exchange)](https://www.oauth.com/oauth2-servers/access-tokens/authorization-code-request/)

- Validate code
- Validate PKCE
- Issue access_token
- Issue id_token
- Add JWKS
- Add discovery document

---

## Milestone 5 — OIDC UserInfo + Consent

**Before you start:**
- **UserInfo endpoint:** GET (with Bearer access token); returns claims about the authenticated user (e.g. `sub`, `name`, `email`) per requested scopes.
- **Consent:** optional step at the AS where the user approves which scopes to grant; can be simplified (e.g. approve all requested) for the lab.

**Tutorial and reference links:**
- [OpenID Connect Core – UserInfo](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
- [OpenID Connect Core – Claims](https://openid.net/specs/openid-connect-core-1_0.html#Claims)

---

## Milestone 6 — Refresh Tokens + Revocation

**Before you start:**
- **Refresh token:** long-lived credential used to obtain new access (and optionally ID) tokens without re-prompting the user; stored securely by the client; sent to token endpoint with `grant_type=refresh_token`.
- **Revocation:** endpoint (e.g. POST `/revoke`) where client can invalidate a refresh token or access token so it can no longer be used.

**Tutorial and reference links:**
- [OAuth 2.0 – Token Revocation](https://oauth.net/2/token-revocation/)
- [RFC 7009 – OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
- [RFC 6749 §6 – Refresh Token Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-6)
