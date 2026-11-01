# ANR1 final release certification

Date: 2026-11-01 UTC  
Mode: offline release review; production unchanged

## Integrated source

- Integration branch: `release/oiran-polaris-final-p0`
- Integration commit before this report: `f58c8b2`
- POLARIS: `0.28.0`, `ac8748c1713cb039686ad42f6549ca0a55dff5ba`
- OIRAN API: `2.7.2`, live-probe `0.4.1`, Analyzer `2.7.0`,
  `9ea4d1758cd7869f26bb598b43d5d29a4d581206`

Both component commits are real ancestors of the integration merge. The POLARIS
production source `4669de8b...` and the OIRAN 2.5.4 source line are ancestors of
their candidates. No `merge -s ours` was used.

## Contract and security decision

POLARIS exposes `POST /api/v1/lte/runs/:run_id/evidence-envelope`. The HTTP body
contains only `bundle_id`; Operator RBAC and CSRF are mandatory. A completed,
clean LTE run is required. The server opens only a private, canonicalized bundle,
rejects traversal/symlinks/non-regular files, streams SHA-256 over the sanitized
capture and event files, and validates the three unique planes `S1_MME`, `S11`,
`S1_U` before publishing references. The route does not set
`LTE_E2E_CERTIFIED=true`.

OIRAN accepts the direct `oiran.lte-evidence-ingestion.v1` request emitted by
POLARIS and, defensively, the strict outer
`polaris-oiran.lte-import-envelope.v1`. It checks outer/inner provenance,
deduplication, file/event hashes, frame bounds, packet provenance, decoder/schema
versions, cleanup evidence and identity absence before atomic publication.

No real `capture_ref` was fabricated or published during this offline review.
There is no approved real LTE capture manifest in the reviewed tree, therefore a
real Session Explorer/Call Flow result cannot be certified yet.

## Tests and artifacts

- POLARIS API library: 248 passed, 0 failed, 3 explicitly ignored manual tests.
- POLARIS bridge/security/hash tests: 4 passed.
- POLARIS frontend: typecheck passed; 235/235 Vitest passed.
- OIRAN exact outer-envelope test: 1 passed.
- OIRAN final API route Operator/CSRF test, replayed by ANR1: 1 passed, 0 failed.
- Prior OIRAN candidate evidence: 136 Rust/API passed, 4 ignored; 82 decoder
  tests passed; 75/75 frontend tests passed. The entire suite was not replayed on
  the final 2.7.2 tree.
- POLARIS frontend 0.20.0 production build passed. Manifest SHA-256:
  `de4df146689613372b0b72e360e32f7bc6b28fb7c4c686e695edc257f17442fd`.
- OIRAN Analyzer 2.7.0 production build and leak scan passed. Manifest SHA-256:
  `44648d68680cacfc4657f21f1dc731a6992589b3fde60b0772089825d88e8867`.
- Both API release builds were stopped by the mandatory RAM gate during
  compilation/linking. No API artifact or SHA-256 is claimed.
- Playwright was not executed against an integrated API staging deployment.

## Runtime and rollback preparation

At `2026-11-01T09:30:57Z`, measured values were:

- memory used: `16,333,783,040` bytes;
- memory available: `4,636,798,976` bytes;
- root disk: `58%`, `174,761,689,088` bytes available;
- external dumpcap processes: 12;
- `polaris-control.service` and `oiran-api.service`: active.

The API release link steps crossed below 4 GiB and were stopped. The running
production artifacts remain:

- POLARIS API 0.26.0 SHA-256
  `5d042aa4620f4d92c05f5d73ef316dfc1df18940d78a58a7eb4ab5ee43f27fc8`;
- OIRAN API 2.5.4 SHA-256
  `7a9c5711ed1827dc9ed8fef1c34ff63816a86deccc70fadf4219643153cfd657`.

The deployment recipe is prepared: fresh immutable backup of API/UI/config,
registries and unit files; hash verification; atomic component replacement;
component-only restart; API/auth/privacy/browser checks; restore previous hashes
on any failure. Fresh backups were not taken because deployment is not authorized
and would become stale before the actual window.

The 12 capture processes were never signalled. Their current PIDs renewed around
09:15 UTC under the known hourly rotation mechanism. A lossless handoff was not
proved; dumpcap continuity remains `UNKNOWN`, not PASS.

## Verdict

`BLOCKED`

The source integration and core contracts are materially closed, but promotion is
blocked by missing API release artifacts/hashes, incomplete final-tree OIRAN suite,
missing integrated Playwright, and absent real LTE capture/session evidence.
Production deployment and LTE live certification remain separate gates.

— ANR1
