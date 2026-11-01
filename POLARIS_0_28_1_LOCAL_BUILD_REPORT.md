# POLARIS 0.28.1 local release build report

Date: 2026-11-01 UTC

BUILD = `PASS`

BINARY_SHA256 = `3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450`

MEMORY_PEAK = `837,120,000` bytes (`798.34 MiB`), read directly from the dedicated cgroup `memory.peak` while the compiler/linker was active.

RESOURCE_GATES = Dedicated transient build unit only: `MemoryHigh=1,610,612,736`, `MemoryMax=2,147,483,648`, `MemorySwapMax=0`; host safety stop at `MemAvailable < 3,221,225,472`. Lowest sampled host availability was `4,033,777,664` bytes. Cgroup `memory.events` remained `high=0,max=0,oom=0,oom_kill=0`; 12 dumpcap PIDs remained unchanged. Production services were not restarted or stopped.

TESTS = Three critical exact-source tests executed and passed: staged capture rehash/scope validation, persistent idempotence plus publication conflict, and Operator/CSRF HTTP envelope publication. Existing full exact-source result remains 249 passed / 0 failed / 3 explicitly ignored. Release ELF smoke check executed successfully through the non-loopback fail-closed path (`exit 2`, expected).

BLOCKERS = None for artifact construction. Deployment, grant and Live operations remain unauthorized and were not performed.

## Source and artifact provenance

```text
Source SHA: 8cb356a7e4264b80fb82e2f1c90b9511f581df41
POLARIS_CONTROL tree: 812dfe946d9466d43e2235154a091ee0c1f8afc7
Package compiled: polaris-control-api v0.28.1
Cargo.lock SHA256: 54e5ec6dbeda764415b028cf7f990e80dcc2d830340de57adc8073c9d422b07f
API Cargo.toml SHA256: 29ffb3af3984518473866ea181d3db8242fcff1ac8e1d1a35c0e04180b55ed94
Rust: rustc 1.75.0 / LLVM 17.0.6
Target: x86_64-unknown-linux-gnu / glibc 2.39
```

Artifact:

```text
/root/ANR2_POLARIS_FINAL_BUILD/POLARIS_CONTROL/target-no-keep-memory/release/polaris-control-api
size: 21,273,992 bytes
mode: 0755
ELF: 64-bit x86-64 PIE, dynamically linked, GNU/Linux >=3.2
Build ID: 45f776983b4678d536bfbd26c1055a6c1aa4212e
SHA256: 3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450
runtime libraries: libc.so.6, libgcc_s.so.1, libm.so.6
```

The compiler log identifies `polaris-control-api v0.28.1`; the version comes from the exact locked Cargo manifest at the requested SHA. The executable loader/ABI smoke test used an intentionally forbidden non-loopback address, so it exited before loading state or touching any laboratory service:

```text
POLARIS_BIND=0.0.0.0:1 ./polaris-control-api
refusing non-loopback bind: 0.0.0.0:1
exit=2 (expected)
```

## Build command

The old 512/768 MiB limits were not reused. Only the transient compilation unit received the new memory budget; no production service limit was changed.

```bash
systemd-run --wait --pipe --collect --unit=polaris-0281-build2 \
  -p MemoryHigh=1610612736 \
  -p MemoryMax=2147483648 \
  -p MemorySwapMax=0 \
  -p RuntimeMaxSec=2400 \
  -p WorkingDirectory=/root/ANR2_POLARIS_FINAL_BUILD/POLARIS_CONTROL \
  /bin/bash -lc '
    CARGO_BUILD_JOBS=1 \
    CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_RELEASE_DEBUG=0 \
    CARGO_TARGET_DIR=/root/ANR2_POLARIS_FINAL_BUILD/POLARIS_CONTROL/target-no-keep-memory \
    RUSTFLAGS="-C link-arg=-Wl,--no-keep-memory" \
    cargo build --offline --locked --release \
      -p polaris-control-api --bin polaris-control-api
  '
```

Result:

```text
Finished release [optimized] target(s) in 5m 39s
CARGO_EXIT=0
```

An initial transient unit populated the same cache and reached a sampled peak of approximately 500 MiB but ended without producing an artifact or a conclusive Cargo footer. It was not treated as success. The second unit resumed the cache, logged the explicit Cargo return code and produced the certified binary.

## Critical tests

The SHA256-verified test binary was built previously from the identical source tree:

```text
test binary SHA256:
3a04dadc055e72d714203aab93cebc404af7e503843dfbbde1cea727962554f1

staged_bundle_is_rehashed_and_operator_metadata_cannot_bypass_it
capture_publication_is_persistently_idempotent_and_rejects_drift
lte_evidence_envelope_requires_operator_csrf_and_publishes_exact_wrapper

result: 3 executed, 3 passed, 0 failed
```

## Post-build safety verification

- Production remained POLARIS API 0.26.0 and OIRAN API 2.5.4.
- Open5GS LTE/5G containers and the capture container remained healthy.
- All 12 dumpcap PIDs were unchanged throughout the certified build.
- Final `MemAvailable` after build/tests: `4,958,412,800` bytes.
- Root filesystem: 59% used.
- No new kernel OOM record appeared during the certified build window.
- No deployment, grant, srsENB/srsUE start or traffic was executed.

The artifact remains local and has not been transferred or deployed.

— ANR2
