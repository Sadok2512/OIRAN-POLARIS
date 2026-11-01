# OIRAN / POLARIS final offline build certification

Date: 2026-11-01 UTC
Mode: offline only; no deployment, grant, traffic or service restart

POLARIS_SOURCE_SHA = `8cb356a7e4264b80fb82e2f1c90b9511f581df41` (API 0.28.1; exact POLARIS tree `812dfe946d9466d43e2235154a091ee0c1f8afc7`)

POLARIS_BINARY_SHA256 = **MISSING**. Two sequential mono-job attempts were stopped when available RAM fell below 4 GiB. A concurrent attempt was also stopped; a later 512 MiB systemd memory-limit attempt was rejected because it repeated the previously unsafe constrained-build strategy. No partial binary is certified.

OIRAN_SOURCE_SHA = `430a094` (API 2.7.2, live-probe 0.4.1, Analyzer 2.7.1; exact OIRAN tree `bbe48c382f05d52c8c692ae148a12062bca94aeb`); candidate `9ea4d1758cd7869f26bb598b43d5d29a4d581206` is an ancestor.

OIRAN_BINARY_SHA256 = `8c99a76d037d6dc731f6c16349505f1f1b26e1381874c70f12d9baff450a28e1` (`oiran-api`, 13,544,688 bytes). The artifact was built from commit `18291753`, whose `OIRAN/` tree is byte-identical to `430a094`.

UI_ASSETS_SHA256 = POLARIS deterministic `dist` tar `bd749ab68cd57803d21f43b73baaf0693b3c0487686238d595dde870703cb06d`; OIRAN deterministic `dist` tar `09b7a94bf7dd597c07c3503ab51557987854003605f4dadd14b50fb815037b37`. Their source trees exactly match the integration trees.

GIT_LINEAGE = PASS. Integration code/documentation SHA `c79ca579e9616a48ab1c89578b4b0d626cd8c87a`; `4669de8b`, `8cb356a7`, `6464476a`, `9ea4d175` and `430a094` are all ancestors. No `merge -s ours` was used.

RUST_TESTS = POLARIS full final suite previously executed from the exact 0.28.1 tree: 249 passed, 0 failed, 3 explicitly ignored; three evidence publication/HTTP tests rerun from its SHA256-verified test binary and passed. OIRAN exact final tree: live-probe full recorded suite 56 passed / 4 ignored and API 41 passed; this certification directly reran 8 LTE ingestion/dedup/privacy/Call Flow tests plus 3 API route/privacy/pagination tests, all PASS. A first API invocation with incomplete test names selected zero tests and is not counted as PASS; the fully-qualified reruns each executed one test.

FRONTEND_TESTS = exact source trees: POLARIS TypeScript PASS, Vitest 235/235, Vite build PASS; OIRAN TypeScript PASS, Vitest 77/77, Vite build PASS. No source change affected either UI after these builds.

PLAYWRIGHT = exact source trees: POLARIS 24/24 read-only tests at 1280/1440/1920 light/dark; OIRAN 3/3 isolated Session Explorer tests. Not rerun against production.

CAPTURE_REFS = OFFLINE PASS on fixtures: private staged manifest is bound to run/profile/scenario, files are canonical-path confined and rehashed, exact S1_MME/S11/S1_U references are persisted idempotently, and drift returns `LTE_EVIDENCE_PUBLICATION_CONFLICT` / HTTP 409. No real capture reference was created or published.

IMPORT = PARTIAL. OIRAN exact final tests prove atomic import, exact replay deduplication, rollback on conflict, three-plane provenance validation and LTE session/Call Flow materialization. The direct `oiran.lte-evidence-ingestion.v1` type produced by POLARIS is statically compatible. A single integrated test that serializes the actual POLARIS response and imports it successfully through the OIRAN HTTP route is still absent; the API route test exercises the supported strict outer adapter for RBAC/CSRF.

PRIVACY = OFFLINE PASS on the final OIRAN tree: ingress rejects prohibited identity labels/values; API JSON and HTML route tests remove subscriber/equipment identities; export remains pending review. No real approved capture was opened and no subscriber secret was printed.

RAM = final sample: 4,550,475,776 bytes available and 16,420,106,240 bytes used. Concurrent builds drove available RAM to 4,215,840,768 bytes and were stopped. The controlled release build was stopped at 4,150,685,696 bytes. The mandatory reserve was therefore enforced, but the POLARIS artifact could not be completed on this host.

DISK = 59%, below warning/stop limits.

DUMPCAP = 12 active and never signalled by this task. The PID set rotated externally twice during the release work (from `1090415...1090497` to `1261893...1261992`). Packet-level handoff evidence is unavailable; continuity without loss is **not proven**.

RELEASE_READY = **NO**.

BLOCKERS = mandatory POLARIS 0.28.1 release binary/hash missing; no sufficiently resourced isolated build host available; direct POLARIS-response-to-OIRAN-HTTP success fixture absent; dumpcap rotation continuity unproven. Real LTE E2E remains outside this offline mission and is not certified.

## Commands and observed results

```text
git merge --no-ff 8cb356a7...       # merged as fde5712
git merge --no-ff 430a094...        # merged as 4921b85
git merge-base --is-ancestor ...    # all five bases exit 0

CARGO_BUILD_JOBS=1 CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo build --offline --locked --release -p polaris-control-api \
  --bin polaris-control-api
# stopped by resource monitor at MemAvailable=4,150,685,696; no artifact

polaris_control_api-0e958ab... <three exact evidence tests>
# 3 executed, 3 passed, 0 failed

live_probe-c36fdc00ffe3dfbf 'lte_evidence::tests::' --test-threads=1
# 8 passed, 0 failed

oiran_api-e0bcda4e17d8392e tests::<route-test> --exact --nocapture
# 3 tests executed separately, 3 passed, 0 failed

sha256sum OIRAN/target/release/oiran-api
# 8c99a76d037d6dc731f6c16349505f1f1b26e1381874c70f12d9baff450a28e1
```

No backup or rollback execution was appropriate because deployment was not authorized. The existing coordinated backup/rollback plan remains mandatory for any later deployment window.

— ANR2
