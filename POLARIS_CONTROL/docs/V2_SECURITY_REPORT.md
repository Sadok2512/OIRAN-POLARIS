# POLARIS Control V2 Security Report

- The prior operator-approved public viewer mode is preserved; no access token is required for read-only views.
- Anonymous callers receive viewer authority only. Start and Stop return HTTP 403.
- Live execution still requires both an operator-capable path and explicit live-test approval; neither is enabled.
- Traffic destinations are validated against the fixed laboratory allowlist.
- Runtime discovery uses fixed container identifiers; the browser cannot supply shell commands or filesystem paths.
- Controller ownership and idempotent lifecycle rules remain covered by Rust tests.
- Disk policy remains fail-closed at monitor failure with 75/80/85/90 thresholds and no automatic deletion.
- The backend binds to loopback; the existing fixed reverse proxy publishes the Web UI/API.

Residual risk: the publicly reachable read-only UI exposes laboratory health metadata. Network-layer restriction should be considered if public read-only access is no longer required.
