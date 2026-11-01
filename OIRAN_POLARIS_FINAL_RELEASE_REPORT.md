# OIRAN / POLARIS final release report

POLARIS_VERSION = API `0.28.1`, UI `0.20.0`; production remains API `0.26.0`, UI `0.19.0`.

POLARIS_SHA = `8cb356a7e4264b80fb82e2f1c90b9511f581df41` (release code; contained in remote report branch `release/oiran-polaris-final-p0-anr2-report`).

OIRAN_VERSION = API/platform `2.7.2`, live-probe `0.4.1`, Analyzer `2.7.1`; production remains API `2.5.4`.

OIRAN_SHA = release code merge `430a09454f36b92a5ddef40aabc29b305bb3c90d`; the following branch-head commit changes reports only.

GIT_LINEAGE = PASS: POLARIS `70faacb5` is ancestor of `8cb356a7`; OIRAN candidate `92c1b08c` and provenance adapter `9ea4d175` are real ancestors of the final merge. No `merge -s ours`.

CAPTURE_REFS = OFFLINE_PASS: POLARIS accepts only exact server-staged, rehashed, run-scoped S1_MME/S11/S1_U references; no real reference was invented or published.

IMPORT_CONTRACT = OFFLINE_PASS: direct `oiran.lte-evidence-ingestion.v1` is mutually compatible; OIRAN additionally validates `polaris-oiran.lte-import-envelope.v1`, capture IDs, timestamps, RAT, run/scenario and provenance equality.

SECURITY = OFFLINE_PASS: Grant V2 ownership/digest/RBAC/CSRF/expiry/revocation/anti-replay/cleanup regressions passed in POLARIS; no grant was created and `LTE_E2E_CERTIFIED` remains false.

PRIVACY = OFFLINE_PASS: ingress plus datasets/sessions/events/packets/Call Flow JSON/HTML boundaries reject subscriber/equipment identities and secrets; no approved real capture was imported.

RUST_TESTS = POLARIS 249 passed, 0 failed, 3 ignored; OIRAN live-probe 56 passed, 0 failed, 4 ignored; OIRAN API 41 passed, 0 failed, 0 ignored. Initial post-merge fixture/import defects were corrected and full suites rerun green. OIRAN release binary SHA-256 `8c99a76d037d6dc731f6c16349505f1f1b26e1381874c70f12d9baff450a28e1`.

FRONTEND_TESTS = POLARIS TypeScript PASS, Vitest 235/235, Vite build PASS; OIRAN TypeScript PASS, Vitest 77/77, Vite build PASS.

PLAYWRIGHT = POLARIS 24/24 PASS at 1280/1440/1920 light/dark; OIRAN isolated read-only Session Explorer 3/3 PASS. No mutating production browser test.

RAM = PASS at final build start: `4,931,432,448` bytes available, `16,039,149,568` used; all test/build starts respected >=4 GiB available and <=16 GiB used.

DISK = PASS, root `59%` (<80% warning, <85% stop).

DUMPCAP = 12 active and untouched. Supervisor rotated PIDs around 09:15 UTC; final PID/start snapshot `b6f5a7771f9b013b9052f7eaf810693523f62937fe9b61970355ecfddb0cb8b9`. Lossless continuity is NOT PROVEN.

BACKUP = NOT EXECUTED because deployment is not authorized; fresh API/UI/config/state backups and hashes are mandatory inside the authorized window.

ROLLBACK = PREPARED, NOT EXECUTED: atomic component restore, restart only deployed applications, then version/health/privacy/real-data/UI/resource/dumpcap checks; any FAIL requires rollback.

DEPLOYMENT = NOT AUTHORIZED / NOT PERFORMED. Production services and versions are unchanged.

LTE_E2E = BLOCKED: no candidate deployment, no approved real LTE three-plane bundle/import, and no bounded live run was started.

5G_E2E = PARTIAL: 11 historical 5G SA sessions exist; one inspected 54-event N2/N4/N3 Call Flow is strongly/exactly correlated. No new 5G live operation was authorized.

CALLFLOW = OFFLINE_PASS for LTE fixtures and UI; historical 5G Call Flow observed read-only; real LTE Call Flow not certified.

FINAL_VERDICT = BLOCKED.

BLOCKERS = POLARIS final release binary/hash absent; explicit coordinated deployment authorization absent; fresh backups absent; dumpcap rotation continuity unproven; approved real LTE bundle/import and full LTE E2E Call Flow absent.

NEXT_ACTION = Build/hash the POLARIS release binary above resource gates, then request explicit deployment authorization naming POLARIS `0.28.1`/`8cb356a7...` and the final OIRAN `2.7.2` SHA. After fresh backups, deploy coordinately with rollback-on-FAIL; only then execute the exact bounded LTE grant and certify the real import/Call Flow.

— ANR3
