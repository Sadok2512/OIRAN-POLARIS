# OIRAN P0 — Secure Isolated Capture Helper

## Outcome

The tcpdump subprocess adapter has been removed from `live-probe`. A new native Rust helper uses Linux AF_PACKET, a Unix-domain IPC contract, `SO_PEERCRED` mutual identity checks, fixed N2/N3/N4 mappings, bounded PCAP rotation, disk safety, atomic manifests, and SHA-256 integrity.

The API retains its versioned HTTP contracts. Its internal adapter now fails closed unless both the deployment gate and authorized helper socket are present. `COMPLETED_EMPTY` is an explicit terminal state and never fabricates a session.

## Offline validation

- Peer UID/GID acceptance and rejection.
- Real Unix socket round trip and `0660` permissions.
- Interface/path/filter/command allowlist enforcement.
- Initialization failure before `CAPTURING`.
- In-memory packet to valid PCAP and atomic checksum manifest.
- Empty capture classification.
- Stop ownership and idempotency.
- Disk quota rejection.
- Explicit Unix termination-signal schema.
- Existing decoder, session, API, and Web contracts remain unchanged.

Results:

- Rust workspace: 119 tests passed, 0 failed.
- Capture helper: 12 tests passed, including real Unix IPC and offline PCAP generation.
- API: 16 tests passed.
- Frontend: 9 tests passed; TypeScript and production build passed.
- Release builds: `oiran-capture-helper` and `oiran-api` passed.
- Capture helper Release SHA-256: `35486254cda1755f9e2af18e049fa5c110e742cfcb029d5ec7673a946f8712bf`.
- Static systemd security assessment: exposure level 4.2 (`OK`). The verifier's only deployment-time warning is the intentionally absent `/opt/oiran/bin/oiran-capture-helper` path because the review-only binary was not installed.

No helper service was installed or started. No live packet socket was opened. No simulator traffic was generated.
