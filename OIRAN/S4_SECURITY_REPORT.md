# S4 Security Report

> Current deployment note (2026-10-25): bearer-token authentication was removed by explicit operator request. The deployed API is public and strictly read-only; live capture and mutation routes remain unavailable.

## Implemented controls

- Backend refuses non-loopback bind addresses.
- All `/api/v1` routes require a bearer token; token comparison is constant-time and tokens are never logged.
- Viewer/admin roles are established server-side. Only read permissions and GET routes exist in S4.
- Tokens are runtime environment values; the browser keeps its token in `sessionStorage`, not the bundle or persistent storage.
- User-derived values are rendered by React escaping; no decoded HTML injection exists.
- Source paths are canonicalized at startup and sanitized in responses. No arbitrary path, upload or command endpoint exists.
- Subscriber identity remains the certified pseudonym `UE-A`; authentication material and unrestricted payloads are not exposed.
- Raw payload UI exposes only cryptographic references. Export routes remain authenticated.
- `nosniff`, `no-referrer` and `no-store` response headers are applied.
- Live capture/write controls are disabled and no corresponding API exists.
- `npm audit` reports zero known vulnerabilities.

## Remaining risks

S4 token authentication is appropriate only for localhost/private evaluation. It has no token expiry, central identity provider, TLS termination, CSRF-oriented cookie flow or durable audit sink. Before multi-user/private-network deployment, add short-lived identities, TLS, token rotation, per-user audit records, rate limits and a least-privilege service account outside `/root`.

Prepared deployment files are documentation only and were not installed. The example systemd unit uses root because the approved workspace is under `/root`; production hardening requires relocation to a dedicated service-owned read-only path.
