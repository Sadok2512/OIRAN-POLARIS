# Release Consolidation Fix V1.1 — OIRAN

Date: 2026-10-27 UTC

## Root cause

The continuous importer removed runtime-derived session IDs when live credit expired or the job was finalized. Its next publication also rebuilt the dataset from only the bounded current PCAP ring. As files rotated, previously indexed events and their five evidence-backed call flows could disappear even though the durable checkpoint was valid.

## Correction

- Active UE/IP credit still expires, but durable session IDs are no longer removed.
- A continuous publication validates the existing manifest and artifacts before processing new segments.
- Existing and new events are merged by the stable semantic observation ID, then written atomically.
- Existing call flows are retained only when every referenced event remains in the merged event set.
- A malformed checkpoint fails closed and leaves the last published event file unchanged.

## Checkpoint evidence

The immutable pre-maintenance snapshot at `/var/backups/oiran-polaris-release-20261027T091651Z/oiran/checkpoint-prestop-1-GBU5xg` was inspected read-only.

- Snapshot tree SHA256: `a83db1d49ab4778408d6e00e7da400102b0f07fabf71c952fcc9c7f30129b91c`
- Packets indexed: 1,483
- Events: 123 lines, 123 unique event IDs
- Sessions: 5
- Unique call-flow event references: 62
- Missing call-flow event references: 0
- Decode errors: 0

The earlier 1,471 packet / 117 event figures are therefore correctly treated as reference minima, not ceilings.

## Validation

- Rust workspace: 197 passed, 0 failed.
- OIRAN API tests: 21 passed, 0 failed.
- Frontend: 20 passed, 0 failed; TypeScript and production build passed.
- Browser E2E: 47 passed, 0 failed against an isolated candidate with a copied capture registry.
- The new deterministic test proves five sessions survive manager restart, acquire a new event without loss, and remain idempotent on replay.
- A first full Rust run observed one pre-existing queue-scheduling assertion failure; the isolated test passed five consecutive runs and the complete suite then passed. No code in that module changed.

## Candidate artifacts

- `oiran-api`: `c810649758f675c2cc0d9847ae6bbdff32d1b19e36764f1cf639734ad9f21fc5`
- `oiran-capture-helper`: `6a9d1a952de8ba4bd92db7a5745b6f22e6dcd4f3c585910afc60b161f760fa0a`
- Frontend JavaScript: `e25f5fd91b36ae6a6ad8994260bfdcb70e89575d659eab9c1db1d26d5a6443ca`

No production service, external capture, UE, Open5GS component, or ETV/OTV process was modified.
