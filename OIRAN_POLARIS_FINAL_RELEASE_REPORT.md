POLARIS_VERSION = 0.28.1 API / 0.20.0 UI
POLARIS_SHA = 8cb356a7e4264b80fb82e2f1c90b9511f581df41
OIRAN_VERSION = 2.7.2 API / 0.4.1 live-probe / 2.7.0 Analyzer
OIRAN_SHA = 9ea4d1758cd7869f26bb598b43d5d29a4d581206
GIT_LINEAGE = PASS from POLARIS production candidates 2dd98d70 and 4669de8b through 70faacb5; OIRAN 92c1b08 -> 9ea4d17 PASS
CAPTURE_REFS = OFFLINE_PASS: exact staged S1_MME/S11/S1_U refs, rehashed, scoped and replay-bound; no real run refs published
IMPORT_CONTRACT = OFFLINE_PASS: exact oiran.lte-evidence-ingestion.v1 direct body; OIRAN also accepts strict polaris-oiran.lte-import-envelope.v1
SECURITY = OFFLINE_PASS for Grant V2/RBAC/CSRF/ownership/digests/expiry/revocation/anti-replay/cleanup; no live grant created
PRIVACY = OFFLINE_PASS tests; IMSI role separation and prohibited secret fields covered; no approved real capture imported
RUST_TESTS = POLARIS 0.28.1 final binary 249 PASS / 0 FAIL / 3 ignored in 369.87 s; all 3 new targeted tests PASS after one corrected RED fixture; OIRAN final report remains resource-gated
FRONTEND_TESTS = PASS: Node 20.20.0, TypeScript PASS, Vitest 235/235, Vite build PASS
PLAYWRIGHT = PASS offline/read-only: 24/24 at 1280/1440/1920 light/dark for LTE, Topology, UE Manager and Traffic
RAM = PASS; final available 4,554,108,928 bytes; minimum sampled during final compile 4,326,772,736 bytes, above 4 GiB gate
DISK = PASS, 59%
DUMPCAP = 12 active; PID set rotated externally around 09:15 UTC; uninterrupted packet continuity NOT PROVEN
BACKUP = NOT EXECUTED; deployment authorization absent; fresh backup/hash procedure prepared
ROLLBACK = PREPARED, NOT EXECUTED; coordinated API/UI restore and full read-only recipe required
DEPLOYMENT = NOT AUTHORIZED / NOT EXECUTED; production remains POLARIS API 0.26.0, UI 0.19.0, OIRAN API 2.5.4
LTE_E2E = NOT CERTIFIED; no grant, srsENB, srsUE or traffic started in this mission
5G_E2E = NOT RE-RUN; no new 5G live operation authorized; existing production data alone is not a new certification
CALLFLOW = OFFLINE contract/tests only; no newly imported approved real LTE session shown end-to-end
FINAL_VERDICT = BLOCKED
BLOCKERS = final API artifact/hash; OIRAN final resource-gated tests/artifact; collector rotation continuity proof; deployment authorization; approved real LTE capture and complete E2E import/Call Flow
NEXT_ACTION = finish final targeted builds/tests above resource gates, produce signed artifact hashes, then request explicit coordinated deployment authorization for the final POLARIS and OIRAN SHAs; only afterward execute bounded LTE certification with exact Grant V2

— ANR2
