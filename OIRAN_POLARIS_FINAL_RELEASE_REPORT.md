# OIRAN / POLARIS final release report

POLARIS_VERSION = `0.27.1` candidate; production remains `0.26.0`.

POLARIS_SHA = `70faacb5c9c98b8e2968de0944c1d05414704c2a` reviewed base; ANR2 final P0 SHA pending exchange.

OIRAN_VERSION = API/platform `2.7.2`, live-probe `0.4.1`, Analyzer `2.7.1` prepared; production remains API `2.5.4`.

OIRAN_SHA = pending commit on `release/anr3-oiran-final-p0` (base `92c1b08cd63202272986b64702ee97a334f010a3`).

GIT_LINEAGE = PASS for supplied candidates from each deployed source; final modified SHAs must be rechecked before any deployment. POLARIS and OIRAN remain independent divergent component trees.

CAPTURE_REFS = FAIL on supplied POLARIS `70faacb5...`: runs initialize `capture_refs=[]`, `set_capture_refs` has no caller, and no real reference was published. ANR2 final delta pending review.

IMPORT_CONTRACT = PARTIAL: OIRAN's strict, versioned, atomic/idempotent import is implemented; no supplied POLARIS producer/staging path exists and no real approved three-plane bundle was available.

SECURITY = PASS offline on supplied POLARIS review (Grant V2/RBAC/CSRF/digest/expiry/revocation/anti-replay/cleanup); no grant was created in this task. Final ANR2 delta pending review.

PRIVACY = OIRAN delta fixes prohibited-identity admission, LTE session sanitation and JSON/HTML LTE export sanitation; post-delta Rust/API validation pending resource gate.

RUST_TESTS = Base 14 targeted OIRAN tests PASS; post-delta run pending. A resource-gate-aborted compile is not counted.

FRONTEND_TESTS = Targeted Call Flow 10/10 PASS; TypeScript PASS. Full suite/build pending.

PLAYWRIGHT = NOT_RUN yet. Mutating authenticated import spec is prohibited against production; only an isolated/read-only candidate recipe may be counted.

RAM = Initial PASS (`5,062,410,240` available; `15,908,171,776` used). Every later test is independently gated; one compilation was stopped below the 4 GiB available threshold.

DISK = PASS, root `57%` (<80% warning and <85% stop).

DUMPCAP = 12, untouched; initial PID/start-time snapshot `4fe9f419d92e43bd68cdf78cf7e36d15e7fed415245bc36bff072f23084cf9e5`. Lossless continuity through deployment is not certified.

BACKUP = NOT_CREATED: deployment is not authorized. Fresh API/UI/config/state backups with hashes and restore rehearsal are mandatory immediately after authorization and before replacement.

ROLLBACK = PREPARED conceptually: component-local atomic restore, restart only the failed application, read-only health/privacy/API/UI recipe, resource check and exact dumpcap snapshot comparison. Never roll back or rewrite captures/datasets.

DEPLOYMENT = NOT_AUTHORIZED / NOT_PERFORMED. Production versions are unchanged.

LTE_E2E = BLOCKED: no real POLARIS capture refs, no approved real S1-MME/S11/S1-U bundle/import and no deployed candidates. No LTE live operation was started.

5G_E2E = PARTIAL: current production exposes 11 historical 5G SA sessions; one selected Call Flow has 54 observed NGAP/PFCP/GTP-U events on N2/N4/N3 with STRONG/EXACT bridges. This is existing read-only evidence, not a new live certification.

CALLFLOW = PARTIAL: historical 5G Call Flow observed in production; LTE pipeline and UI corrections prepared offline but no real LTE session exists to certify.

FINAL_VERDICT = BLOCKED pending post-delta release tests and, independently, real integration/deployment prerequisites. This must not be interpreted as `FINAL_PASS` or `REAL_PASS`.

BLOCKERS = POLARIS real capture-reference publication and OIRAN envelope producer/staging; approved real LTE bundle; final cross-component SHA exchange; post-delta Rust/full frontend/build/Playwright/artifact hashes; explicit deployment authorization; fresh backups; deployed API/UI recipe; real bounded LTE E2E.

NEXT_ACTION = Finish resource-gated OIRAN tests/build and publish its SHA; review ANR2's final SHA for real capture refs/envelope; if both releases become READY, request explicit deployment authorization naming the exact versions and SHAs. Do not deploy or run LTE before those gates.

— ANR3
