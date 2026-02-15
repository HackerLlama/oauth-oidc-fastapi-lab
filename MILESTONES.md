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

---

# Project state after M0–M6

You have a **complete, protocol-correct** OAuth2 + OIDC lab: auth server (login, consent, codes, token endpoint with code + refresh grants, UserInfo, revocation, JWKS, discovery); client (state, nonce, PKCE, callback with token exchange; receives refresh_token but does not use it yet); resource server (JWT/JWKS, /public, /me, /admin); OpenAPI docs and ENV reference. Milestones **M7–M14** below extend the lab in a sensible order: client refresh, then AS capabilities (introspection, client auth, logout, key rotation), then consent refinement, audit, and rate limiting.

---

## Milestone 7 — Client use of refresh token

**Before you start:**
- **Refresh flow in practice:** the client stores the refresh_token and uses it when the access token expires or when the resource server returns 401; it calls the token endpoint with `grant_type=refresh_token` and then retries the API call with the new access_token.
- **Token storage:** in a real app, tokens are stored securely (e.g. httpOnly cookie, secure storage); for the lab, in-memory or a simple server-side store is fine.
- **When to refresh:** proactively (before expiry) vs on demand (when you get 401); both are valid; on demand is simpler to implement first.

**Tutorial and reference links:**
- [OAuth 2.0 – Refresh Token Grant](https://oauth.net/2/grant-types/refresh-token/)
- [RFC 6749 §6 – Refresh Token Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-6)

- Store refresh_token (and access_token, expires_in) in the client after callback (e.g. in-memory or simple session/cookie for lab).
- Add a way to call the resource server (e.g. "Call /me" button or page) using the current access_token.
- On 401 from the resource server, call the token endpoint with `grant_type=refresh_token`, update stored tokens, then retry the request.
- Optionally: refresh proactively when access_token is near expiry.

---

## Milestone 8 — Token introspection (RFC 7662)

**Before you start:**
- **Token introspection:** a protected endpoint where a resource server (or client) sends a token and receives whether it is active plus its claims (scope, sub, exp, client_id, etc.). Used for opaque or reference tokens, or when the RS wants the AS to assert validity.
- **Authentication:** the introspection endpoint must be protected (e.g. client credentials or a dedicated introspection client) so only trusted callers can query tokens.
- **Response:** JSON with `active` (boolean); when active, include standard claims. When inactive, return only `active: false`.

**Tutorial and reference links:**
- [RFC 7662 – OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
- [oauth.com – Token Introspection](https://www.oauth.com/oauth2-servers/token-introspection-endpoint/)

- Add POST /introspect: accept `token` (required), optional `token_type_hint`; authenticate caller (e.g. client_id + client_secret or Basic Auth).
- For JWT access tokens: verify signature and exp; return active + claims (scope, sub, exp, client_id, iss, etc.).
- For refresh tokens: look up in DB; return active if exists, not revoked, not expired; include same-style claims where applicable.
- Return 200 with JSON `{"active": true, ...}` or `{"active": false}`. Add introspection_endpoint to discovery if desired.

---

## Milestone 9 — Client authentication (confidential clients)

**Before you start:**
- **Public vs confidential clients:** public clients cannot keep a secret (e.g. SPAs, native apps); confidential clients can (e.g. server-side apps). Confidential clients authenticate at the token and revoke endpoints.
- **Client authentication methods:** RFC 6749 allows client_secret in the request body or HTTP Basic (client_id:client_secret, base64). Basic is common for token/revoke.
- **Storage:** store client_secret hashed (e.g. bcrypt) like passwords; never log or return it.

**Tutorial and reference links:**
- [RFC 6749 §3.2.1 – Client Authentication](https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1)
- [OAuth 2.0 – Client Types](https://oauth.net/2/client-types/)
- [oauth.com – Client Authentication](https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/)

- Add optional `client_secret` (or hashed secret) to the Client model; support both public and confidential clients.
- At POST /token and POST /revoke: if the client is confidential, require authentication (e.g. Authorization: Basic base64(client_id:client_secret), or client_id + client_secret in form). Reject with 401 if invalid.
- Optionally: policy choice such as issuing refresh_token only to confidential clients, or allowing refresh_token grant only for confidential clients.
- Update seed or docs so a confidential client can be created for testing (e.g. client_secret in env, hashed on seed).

---

## Milestone 10 — Logout / session management (OIDC RP-Initiated Logout)

**Before you start:**
- **RP-Initiated Logout:** the client (relying party) redirects the user to the AS logout endpoint with parameters such as id_token_hint (so the AS knows which session), post_logout_redirect_uri, and optional state.
- **Session vs tokens:** ending the "session" at the AS (e.g. cookie or server-side session) means the user must log in again on next authorize; tokens already issued remain valid until expiry unless you also revoke them.
- **Stateless AS:** if the AS does not maintain sessions, logout can still redirect and clear any AS cookie; the main effect is redirecting the user back to the client with a consistent flow.

**Tutorial and reference links:**
- [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [Auth0 – Logout](https://auth0.com/docs/authenticate/login/logout)

- Client: add "Log out" link that redirects to AS logout URL with id_token_hint (current id_token or sub), post_logout_redirect_uri, and optional state.
- Auth server: add GET (or POST) logout route (e.g. /logout or /session/end); validate post_logout_redirect_uri against allowed list if desired; invalidate user session if you add server-side sessions (or clear AS cookie); redirect to post_logout_redirect_uri with state.
- If you add sessions: store session server-side or in a signed cookie; create session at login; clear it at logout.

---

## Milestone 11 — Key rotation and multiple keys in JWKS

**Before you start:**
- **Key rotation:** production ASes rotate signing keys; existing tokens (with old kid) must still verify until they expire, so JWKS exposes multiple keys during a grace period.
- **kid in JWT header:** the JWT header contains `kid` (key id); the verifier looks up that key in JWKS to verify the signature.
- **Issuing:** new tokens use the current (new) key; old tokens continue to validate via the old key in JWKS until they expire, then the old key can be removed from JWKS.

**Tutorial and reference links:**
- [OIDC Core – Signing Key Rotation](https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys)
- [RFC 7517 – JWKS](https://datatracker.ietf.org/doc/html/rfc7517)

- Support multiple signing keys (e.g. current + previous); each with a distinct kid; store or load from config/files.
- Issue new access and ID tokens with the current key (current kid); include all still-valid keys in JWKS (current + previous).
- In UserInfo (and introspection if implemented): resolve key by kid from JWT header and verify with the matching key from JWKS.
- Document or implement a simple rotation procedure: generate new key, add to JWKS, switch "current" to new key, stop issuing with old key; after token max lifetime, remove old key from JWKS.

---

## Milestone 12 — Scope refinement at consent

**Before you start:**
- **Consent granularity:** users may grant only a subset of requested scopes (e.g. profile but not email). The AS must store and issue tokens only for the granted subset.
- **Authorization code and tokens:** the scope on the code and on access/refresh tokens should be the granted scope, not the originally requested scope.

**Tutorial and reference links:**
- [OAuth 2.0 – Scopes](https://oauth.net/2/scope/)
- [OIDC Core – Claims and Scopes](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)

- Consent page: display each requested scope with a checkbox (or "Allow all" / "Deny all"); form submits the list of granted scopes (e.g. allow list or space-separated string).
- POST /authorize/confirm: accept granted scope (e.g. list or string); store granted scope on the authorization code (not the full requested scope).
- Token endpoint: issue access_token and refresh_token with scope = granted scope from the code (or from the refresh token for refresh grant).
- UserInfo and resource server behavior remain scope-based; they already use the token’s scope.

---

## Milestone 13 — Audit logging

**Before you start:**
- **Audit events:** security-relevant actions to log: login success/failure, consent (allow/deny), authorization code issued, token issued (grant type), refresh, revocation, introspection (if implemented).
- **What not to log:** full tokens, passwords, or other secrets; minimize PII where possible (e.g. user_id or client_id is often enough; avoid logging full request bodies with tokens).

**Tutorial and reference links:**
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [CIS – Audit Logging](https://www.cisecurity.org/white-papers/cis-security-logging-best-practices/)

- Define a small set of event types (e.g. login_ok, login_fail, consent_allow, consent_deny, code_issued, token_issued, token_refreshed, token_revoked, introspect).
- For each event: log timestamp, event type, client_id, user_id or "anonymous", IP if available, outcome (success/fail). Log to a table (SQLite) or file; avoid logging tokens or passwords.
- Optionally: add a simple query or admin view to list recent audit events (for lab use).

---

## Milestone 14 — Rate limiting and abuse protection

**Before you start:**
- **Rate limiting:** cap the number of requests per identifier (e.g. per IP, per client_id) per time window; return 429 Too Many Requests when exceeded.
- **Targets:** login (POST /authorize) and token endpoint are primary targets for abuse (brute force, code guessing, token theft). Optional: limit GET /authorize or revoke.
- **Lockout / CAPTCHA:** optional; after N failed logins, require CAPTCHA or temporary lockout to mitigate credential stuffing.

**Tutorial and reference links:**
- [OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-bcp) (threats and countermeasures)
- [RFC 6585 – 429 Too Many Requests](https://datatracker.ietf.org/doc/html/rfc6585)

- Apply rate limits (e.g. per IP or per client_id): e.g. max N login attempts per minute, max M token requests per minute; return 429 with Retry-After when exceeded.
- Optionally: after K failed logins (per user or per IP), temporarily lock out or require CAPTCHA on the login form.
- Use in-memory store or a small table for lab; document limits in config or ENV.
