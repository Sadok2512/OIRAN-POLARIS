# POLARIS srsENB Docker Health Fix P0

Date UTC: 2026-11-01

ROOT_CAUSE = `DockerSrsranRuntime::resolve` extracted `.State.Health.Status` through a Docker Go template and flattened the optional object into an untyped string. Containers without a Docker healthcheck can omit `State.Health` or expose it as null; this made discovery/startup dependent on a field that is not part of Docker's guaranteed process-state contract.

FIX = POLARIS API 0.28.2 / srsRAN controller 0.2.2 parses the complete `docker inspect --format '{{json .}}'` payload. Health is classified as absent, starting, healthy, unhealthy or unknown. A running container with absent/null health is accepted only as process-start evidence. Unhealthy/unknown, stopped and crashed states fail closed. After `docker start`, POLARIS re-inspects the exact owned container; timeout or invalid state triggers removal of a newly created container and clears ownership. `S1_READY` uses the separate `s1_setup_is_proven` predicate and still requires process running, EPC running and an independently observed SCTP/S1 association (`s1_state=CONNECTED`). Stop, bounded host timeouts, cancellation and grant-independent cleanup paths are unchanged.

TESTS = PASS

- `CARGO_BUILD_JOBS=1 cargo test --locked -p polaris-control-api srsran_controller::tests:: -- --nocapture` — 19 passed, 0 failed.
- Explicit coverage: newly created container, missing Health, null Health, starting, healthy, unhealthy, unknown, stopped, crashed, inspect timeout and timeout cleanup.
- `running_without_healthcheck_does_not_prove_s1_ready` — PASS.
- `post_start_inspect_timeout_cleans_new_container_and_ownership` — PASS.
- `CARGO_BUILD_JOBS=1 cargo test --locked --workspace` — 300 passed, 0 failed, 3 explicitly ignored manual benchmark/integration tests.
- Grant V2 negative/security tests and all 15 `ueransim-adapter` tests passed in the workspace regression.
- `git diff --check` — PASS.
- `cargo fmt --all -- --check` — baseline formatting drift remains in multiple files already present at source SHA 8cb356a7; no bulk reformat was applied. The modified diff has no whitespace error.

SOURCE_SHA = `d22b24ffc0b4fea792310084dbc7b5020aafbbff`

BINARY_SHA256 = `c7b2687c6f2f374609c4b8455b0583f1a1211b810cab1d3018c7ff039bb2a2f3`

Binary:

```text
/root/ANR2_POLARIS_SRSENB_HEALTH_FIX/POLARIS_CONTROL/target/release/polaris-control-api
size=21,255,432 bytes
ELF=x86-64 PIE GNU/Linux
Build ID=33f2acac495102f6359d1a15f62405288d8db490
```

Build command:

```text
CARGO_BUILD_JOBS=1 RUSTFLAGS='-C link-arg=-Wl,--no-keep-memory' \
  cargo build --release --locked -p polaris-control-api -j 1
Finished release [optimized] in 10m42s
```

Resource evidence after build: 12,778,209,280 bytes RAM available; disk 64%; 12 dumpcap processes present. No service was restarted and no live/grant/traffic action was executed.

RELEASE_READY = YES — offline review/build candidate only; production deployment and LTE E2E remain separately gated.

BLOCKERS = None for code review. The existing repository-wide rustfmt drift is documented and was not expanded into an unrelated formatting change.

— ANR2
