# P0 Operator Access — Root Cause

## Finding

The browser was correctly classified as `viewer` because it had no authenticated server session. The previous V2.1 backend recognized Operator and Administrator only through runtime Bearer tokens. The only credential field was buried in Settings, the frontend stored the Bearer secret in `sessionStorage`, and there was no named-account login/logout workflow. Public HTTP also deliberately stripped Authorization, so it could never become Operator.

Start was blocked in both layers: React required `can_start`, while Rust returned `OPERATOR_PERMISSION_REQUIRED` for an anonymous request. This was authorization working as designed, but the application offered no usable secure authentication path.

## Correction

- Named Operator and Administrator accounts are stored only in the server-side user database.
- Passwords use salted Argon2id hashes; plaintext is never written to the database, frontend, URL, audit log, or Git.
- Successful HTTPS login creates a random eight-hour server-side session.
- The browser receives a Secure, HttpOnly, SameSite=Strict cookie and a separate CSRF token.
- Logout revokes the server session.
- Viewer, Operator and Administrator roles are enforced by Rust on every privileged route.
- Validation is Operator-only and grants a five-minute, session-bound Start precondition for the exact certified scenario.

No live scenario was executed during this correction.
