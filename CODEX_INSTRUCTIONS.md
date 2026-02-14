# Instructions for Codex Agent

You are implementing an educational OAuth2 + OIDC ecosystem.

Strict requirements:

- Follow PROJECT_CONTEXT.md exactly.
- Do NOT introduce additional OAuth flows.
- Do NOT implement implicit flow.
- Do NOT implement password grant.
- Do NOT introduce new scopes.
- Do NOT change ports or issuer.
- Do NOT add dependencies without justification.

When implementing endpoints:

- Validate inputs strictly.
- Return correct OAuth2 error responses.
- Keep code minimal and readable.
- Prefer explicit over clever.

Before implementing a milestone:
- Confirm assumptions match PROJECT_CONTEXT.md.

After implementing:
- Add pytest tests for success and failure paths.
