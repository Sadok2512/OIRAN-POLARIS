# Release Consolidation V1

Date: 2026-10-27 UTC

The OIRAN and POLARIS candidates were consolidated in isolated worktrees. No production artifact, service, dataset, simulator, UE, traffic job, or external capture process was changed.

## Result

- OIRAN source candidate: `f31d2e40b4f3056a2b479a3fbbec913c1a5702d6`.
- POLARIS source candidate: `836196e8bb372bd3cc2bcb39f048ff43af3544b2`.
- OIRAN incorporates S5.1/S5.2/S5.3, four-plane capture and validation, E2E-002 evidence correlation, atomic derived-dataset registration, V2.3 navigation, directional Call Flow, provenance, and the preserved continuous-certification production-source delta.
- POLARIS incorporates V3.2 multi-UE controls, targeted traffic, V3.2.1 resource safety, warning policy, durable decision evidence, authentication, and shared-UE protection.
- Tests: OIRAN Rust 196/196, frontend 20/20, browser E2E 47/47; POLARIS Rust 88/88, frontend 5/5, browser E2E 20/20. API tests are included in the Rust workspace totals (OIRAN 21, POLARIS 54).
- Authenticated browser cases executed with ephemeral least-privilege credentials injected from mode-0600 files. No credential is committed.
- Independent clean-worktree rebuild: `oiran-api`, `oiran-recover`, and all frontend files are byte-identical. `oiran-capture-helper` is functionally reproducible but not byte-identical because Rust panic-location strings embed the absolute worktree path; both builds use identical source, lockfile, compiler and flags.

The release candidates are not deployed and are not live-certified by this work.
