# OIRAN / POLARIS final build certification

Date: 2026-11-01 UTC

Scope: offline only. No production deployment, grant, traffic, service restart,
capture action, Open5GS change, or historical dataset mutation was performed.

POLARIS_SOURCE_SHA = `8cb356a7e4264b80fb82e2f1c90b9511f581df41`; its `POLARIS_CONTROL` tree is byte-identical in integration `4921b857959ed7d68c0bc11a981b51c53583637a` and certification HEAD.

POLARIS_BINARY_SHA256 = MISSING. Sequential release builds produced no final executable. The host-gated attempt stopped before artifact publication; the 512 MiB cgroup attempt was killed by the cgroup OOM at a measured 512 MiB peak. A codegen-units=256 constrained retry also produced no final executable and is not accepted as a PASS. Older binaries found on disk predate 0.28.1 and were rejected.

OIRAN_SOURCE_SHA = `430a09454f36b92a5ddef40aabc29b305bb3c90d`; supplied candidate `9ea4d1758cd7869f26bb598b43d5d29a4d581206` is an ancestor. The integrated `OIRAN` tree is byte-identical to `430a094`.

OIRAN_BINARY_SHA256 = `8c99a76d037d6dc731f6c16349505f1f1b26e1381874c70f12d9baff450a28e1` (`oiran-api`, 13,544,688 bytes, built with `CARGO_BUILD_JOBS=1 cargo build --locked --release -p oiran-api`).

UI_ASSETS_SHA256 = POLARIS Control web tree `ce29fc7ba0e77045ebd2e3adc5425ec57177773a7d12132e9b61cef1a86b1781`; POLARIS Simulator Control tree `d9cc7240d036833cca323a5615bd645c85a0118becbabab785aa09c1931de4c1`; OIRAN Analyzer tree `5b01d808510df2d749baacd1d1019b10ec0f6bb333215e82aaab68634c890a67`. These identify local build outputs; `dist/` is not Git-tracked.

GIT_LINEAGE = PASS. `9ea4d175` is an ancestor of the integration. Real merges include POLARIS `8cb356a7` and OIRAN `430a094`; component tree comparisons return zero. No `merge -s ours` was used.

RUST_TESTS = POLARIS exact 0.28.1 source: 249 passed, 0 failed, 3 explicitly ignored. OIRAN integrated source: live-probe 56 passed, 0 failed, 4 explicitly ignored; API 41 passed, 0 failed. The ignored OIRAN cases are documented high-volume memory tests. Release-build failures are resource/artifact failures, not test PASS.

FRONTEND_TESTS = POLARIS TypeScript PASS, Vitest 235/235 and Vite build PASS; additional Control web 5/5 plus typecheck/build PASS. OIRAN TypeScript PASS, Vitest 77/77 and Vite build PASS.

PLAYWRIGHT = POLARIS 24/24 PASS at 1280/1440/1920 in light/dark; OIRAN isolated read-only Session Explorer 3/3 PASS. No mutating test was run against production.

CAPTURE_REFS = OFFLINE_PASS on synthetic server-staged fixtures: exactly one rehashed, run-scoped `SANITIZED_APPROVED` reference for S1_MME/S11/S1_U; exact replay is idempotent and changed evidence returns HTTP 409. No real capture reference was invented or published.

IMPORT = OFFLINE_PASS: POLARIS direct `oiran.lte-evidence-ingestion.v1` and OIRAN strict outer envelope are compatible; provenance drift, duplicate planes/events, hash mismatch, wrong packet source and unapproved material fail closed. LTE fixture Call Flow/correlation passes without fake counters. No real LTE import was performed.

PRIVACY = OFFLINE_PASS: ingress and datasets/sessions/events/packets/Call Flow JSON/HTML boundaries reject subscriber/equipment identities and K/OPc/authentication material. Canonical evidence SHA-256 and opaque pseudonyms remain usable. Existing N2/N3/N4 decoder/correlation trees are unchanged.

RAM = Final sample: `4,600,819,712` bytes available, `16,369,762,304` bytes used. Test/build starts were gated at >=4 GiB available and <=16 GiB used. POLARIS release linking cannot currently be completed while preserving that reserve; no separate build host was configured.

DISK = PASS, root 59% (<80% warning, <85% stop).

DUMPCAP = 12 active and untouched. Final PID/start-time snapshot SHA-256 `be5749279937a7e72c9961fd25137f19a31a385d46adee9f7a574dbe5cd5ef25`. External rotations occurred; lossless continuity is not certified.

RELEASE_READY = NO.

BLOCKERS = Mandatory POLARIS API 0.28.1 release binary and SHA-256 are missing. The current host cannot complete that build under the mandatory RAM reserve, and no approved isolated build machine is available. Consequently no complete artifact manifest can be certified. Deployment remains unauthorized; real LTE E2E/import remains outside this offline certification.

— ANR3
