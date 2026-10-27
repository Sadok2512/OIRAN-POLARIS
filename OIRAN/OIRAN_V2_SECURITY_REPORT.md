# OIRAN V2 Security Report

## Implemented controls

- Same-origin API and frontend on the existing OIRAN listener.
- Fixed, server-owned artifact paths; no arbitrary path or command execution.
- Sanitized capture provenance (`capture://...`) and restricted raw payload display.
- Output rendered as React text; canonical JSON remains escaped by React.
- Read-only public Viewer identity is explicit at `/api/v1/auth/me`.
- Capture Start fails closed and no operational backend is wired.
- Disk measurement, 75/80/85/90 policy, bounded rotation model and disabled writes remain exposed.

## Residual risks

This deployment intentionally preserves the previously approved public read-only mode. Operator/Admin authentication and authorized capture control are not configured; therefore V2 is not certified for live capture. Public network exposure is handled by the pre-existing Caddy listener and was not changed by this mission.
