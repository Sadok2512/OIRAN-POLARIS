# OIRAN / POLARIS final release report

POLARIS_VERSION = 0.28.0 candidate; production remains 0.26.0 / UI 0.19.0

POLARIS_SHA = ac8748c1713cb039686ad42f6549ca0a55dff5ba

OIRAN_VERSION = API 2.7.2, live-probe 0.4.1, Analyzer 2.7.0 candidate; production remains API 2.5.4

OIRAN_SHA = 9ea4d1758cd7869f26bb598b43d5d29a4d581206

GIT_LINEAGE = PASS; both candidates are real ancestors of integration merge f58c8b2 and descend from their production lines

CAPTURE_REFS = CODE PASS / REAL EVIDENCE NOT EXECUTED; only server-staged, re-hashed, SANITIZED_APPROVED S1_MME/S11/S1_U references are admitted

IMPORT_CONTRACT = PASS offline; direct OIRAN request and strict outer-envelope compatibility tested, Operator/CSRF route test 1/1 PASS

SECURITY = PASS offline for RBAC, CSRF, private-root confinement, hash verification, deduplication and fail-closed cleanup; LTE_E2E_CERTIFIED remains false

PRIVACY = PASS targeted; recursive API/export sanitization and filename hardening present, no approved real capture opened

RUST_TESTS = POLARIS 248 PASS / 0 FAIL / 3 ignored; OIRAN final-envelope 1 PASS and final route 1 PASS; full OIRAN final-tree replay NOT EXECUTED

FRONTEND_TESTS = POLARIS typecheck PASS and 235/235 Vitest PASS; OIRAN prior candidate 75/75 PASS; final builds/leak scan PASS

PLAYWRIGHT = NOT EXECUTED against integrated staging

RAM = latest measured 16,333,783,040 bytes used / 4,636,798,976 bytes available; API release links crossed below 4 GiB and were stopped

DISK = 58%, 174,761,689,088 bytes available

DUMPCAP = 12 present and never signalled; lossless hourly rotation continuity UNKNOWN

BACKUP = PLAN READY; fresh backup intentionally deferred until an authorized deployment window

ROLLBACK = PLAN READY; current running API hashes recorded; rollback artifacts not freshly captured

DEPLOYMENT = NOT AUTHORIZED / NOT EXECUTED

LTE_E2E = NOT CERTIFIED; no real LTE run or approved capture manifest used

5G_E2E = EXISTING DATA ONLY / NOT RE-CERTIFIED; no new 5G live action authorized

CALLFLOW = synthetic approved LTE contract PASS; real LTE chronological Call Flow NOT PROVED

FINAL_VERDICT = BLOCKED

BLOCKERS = API release builds and SHA-256 absent due RAM gate; full OIRAN final-tree suite absent; integrated Playwright absent; dumpcap lossless rotation unproved; real LTE evidence absent

NEXT_ACTION = provide a build host/window that preserves at least 4 GiB available during linking, build/hash both APIs, replay the remaining OIRAN and integrated Playwright suites, then request explicit deployment authorization naming the final SHAs

— ANR1
