# Atomic Derived-Dataset Registration

Endpoint: `POST /api/v1/datasets/import-derived`

The endpoint requires Operator authorization and accepts only `dataset_id`; callers cannot supply a filesystem path. The configured import root must remain inside the OIRAN workspace.

Before registration the backend verifies:

1. safe, derived-prefixed dataset identity and import-root containment;
2. source capture and source dataset identity;
3. every original PCAP byte count, packet count and SHA256;
4. normalized-event and correlation artifact SHA256;
5. supported schema and decoder-version allowlists;
6. source packet references, source paths, packet ranges and source hashes;
7. recomputed event/session counts and typed correlation evidence;
8. incomplete E2E status when NG-U evidence is absent.

Registration writes into a private staging directory, generates session callflows, atomically renames the completed directory, and atomically persists the registry. Re-import is idempotent when content matches. A conflicting existing dataset ID is rejected.

Candidate result:

- Dataset: `derived-e2e-002-live-1793054609378-0001`
- Packets: 543
- Events: 92
- Sessions: 1
- Correlation edges: 3
- Complete E2E certified: false
