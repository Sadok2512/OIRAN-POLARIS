# Controlled Multi-UE Test Plan — Approval Required

This plan is documentation only. It must not run until disk usage is below 85%, subscriber provisioning is approved, and baseline service health passes.

## Common gates

- Preserve Open5GS and the shared gNB; no restart.
- Provision synthetic subscribers through an approved, secret-safe procedure.
- Precompute unique UE context inputs and verify no identity collision.
- Use exact controller ownership for every new UE process.
- Capture N2/N3/N4 with bounded rotation and a write budget that cannot reach 90%.
- Generate five bounded UDP datagrams per UE only to `10.46.0.1:49001`.
- Stop on disk >=85%, resource pressure, registration/PDU failure, capture error or production degradation.

## Stage 1 — One new UE

Validate provisioning, registration, one PDU Session, TUN/IP uniqueness, five UDP writes, capture integrity, graceful stop and zero orphan processes. This stage is distinct from the existing shared-UE traffic test.

## Stage 2 — Two UEs

Start sequentially with a conservative stagger. Verify distinct NGAP IDs, subscriber pseudonyms, UE IPs, PFCP sessions and GTP-U tunnels. Confirm two independent owned jobs or a documented single-process ownership boundary.

## Stage 3 — Five UEs

Run staggered registration before any concurrent attempt. Measure CPU/RAM and capture growth, validate five independent PDU Sessions and Call Flows, then test bounded concurrency only if the staggered run passes.

## Rollback

Gracefully stop only controller-owned UE/traffic processes, finalize only controller-owned captures, preserve shared Open5GS/gNB and all existing PCAPs, release reservations and retain terminal job/audit records. No automatic deletion is permitted.
