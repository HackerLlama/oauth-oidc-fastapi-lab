# Signing key rotation (M11)

The auth server supports **multiple signing keys** so you can rotate the key without invalidating existing tokens. New tokens are signed with the **current** key; tokens signed with a **previous** key remain valid until they expire because JWKS exposes all keys and verifiers resolve the key by `kid` from the JWT header.

## Current behaviour

- **Current key:** `OAUTH_SIGNING_KEY_PATH` (default `.auth_signing_key.pem`), kid `auth-server-key`. Used for signing new access and ID tokens.
- **Previous key (optional):** `OAUTH_SIGNING_KEY_PREVIOUS_PATH`. If set, that key is loaded with kid `auth-server-key-prev`, included in JWKS, and used only for **verification** (UserInfo, introspection, logout, resource server). Not used for signing.

## Rotation procedure

1. **Generate a new key** (e.g. `openssl genrsa 2048 -out .auth_signing_key_new.pem` or use the same method as your key generation).
2. **Set the new key as “previous”** (see steps below):
   - Copy the current key: `cp .auth_signing_key.pem .auth_signing_key_prev.pem`
   - Replace the current key file with the new key: `mv .auth_signing_key_new.pem .auth_signing_key.pem` (or overwrite `.auth_signing_key.pem` with the new key).
   - Set env and restart: `OAUTH_SIGNING_KEY_PATH=.auth_signing_key.pem` (new key), `OAUTH_SIGNING_KEY_PREVIOUS_PATH=.auth_signing_key_prev.pem` (old key).
   - New tokens are signed with the new key; existing tokens (signed with the old key) still verify because the old key is in JWKS.
3. **After the max token lifetime** (access + refresh expiry), no tokens signed with the old key remain. Remove the previous key: unset `OAUTH_SIGNING_KEY_PREVIOUS_PATH` and restart; optionally delete `.auth_signing_key_prev.pem`.

## Summary

- **New tokens:** signed with the key at `OAUTH_SIGNING_KEY_PATH` (kid `auth-server-key`).
- **Verification:** UserInfo, introspection, logout, and resource server (via JWKS) resolve the key by `kid` from the JWT header. Tokens signed with the previous key (kid `auth-server-key-prev`) continue to validate until they expire.
- **Rotate:** put the new key at `OAUTH_SIGNING_KEY_PATH`, old key at `OAUTH_SIGNING_KEY_PREVIOUS_PATH`; after token max lifetime, drop the previous path.
