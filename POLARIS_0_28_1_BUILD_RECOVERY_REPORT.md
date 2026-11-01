# POLARIS 0.28.1 build recovery report

Date: 2026-11-01 UTC

BUILD_ENV = `BUILD_ENV_REQUIRED`

SOURCE_SHA = `8cb356a7e4264b80fb82e2f1c90b9511f581df41`

BINARY_SHA256 = `MISSING`

BUILD = `BLOCKED`

RESOURCE_GATES = Laboratory unchanged. Root disk 59%; 12 external dumpcap processes preserved. A concurrent Rust test was interrupted only after `MemAvailable` fell to 4,268,863,488 bytes, below the mandatory 4 GiB threshold; availability recovered to 4,958,015,488 bytes. No release build was retried during this recovery mission.

TESTS = Existing exact-source evidence remains valid: Rust 249 passed / 0 failed / 3 ignored; frontend 235 passed; targeted Playwright passed. No skipped test is reclassified as PASS. No new test or compilation was launched.

BLOCKER = No authorized isolated build host or private runner with sufficient measured headroom is configured. The laboratory cannot safely establish the compiler's uncapped peak while retaining its mandatory 4 GiB system reserve.

NEXT_ACTION = Provide or explicitly authorize an existing x86_64 Linux build host meeting the build envelope below. Build exact SHA offline/locked, record cgroup peak, verify the binary, then transfer it through a separately approved channel with SHA256 verification.

## Initial Git isolation

The dirty shared foundation worktree was inspected and left untouched. This report was prepared in the dedicated worktree `/root/ANR2_POLARIS_BUILD_RECOVERY`, branch `docs/polaris-0.28.1-build-recovery-anr2`, created directly from the requested SHA. The source tree itself was not changed; SemVer remains API 0.28.1 and the existing changelog remains authoritative.

## OOM evidence

Two relevant cgroup OOM kills are proven by the kernel/systemd journal; they are not successful peak measurements.

### 768 MiB scope — lower bound only

At `2026-11-01T02:21:05Z`, scope `hermes-final-anr2-fix1.scope` reported:

```text
MemoryMax / usage = 786432 KiB = 805,306,368 bytes
MemoryPeak = 768.0 MiB
MemorySwapMax / peak = 0
rustc anon-rss = 595,560 KiB
rustc file-rss = 150,164 KiB
rustc total-vm = 1,342,336 KiB
result = oom-kill
```

The exact outer command was a `systemd-run --scope` worker with:

```text
MemoryMax=768M MemorySwapMax=0 RuntimeMaxSec=2400
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
```

That scope included the agent worker plus Cargo/rustc and was executing targeted Rust correction tests, not a clean standalone release build. Its peak being exactly the limit proves only that 768 MiB is insufficient.

### 512 MiB direct release attempt — lower bound only

At `2026-11-01T10:19:34Z`, unit `run-u10061.service` reported:

```text
MemoryMax = 536,870,912 bytes
MemoryPeak = 512.0 MiB
MemorySwapMax / peak = 0
rustc anon-rss = 505,576 KiB
rustc file-rss = 192,028 KiB
rustc total-vm = 1,275,828 KiB
result = oom-kill
```

Exact command:

```text
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/root/ANR2_POLARIS_FINAL_BUILD/POLARIS_CONTROL/target
cargo build --offline --locked --release \
  -p polaris-control-api --bin polaris-control-api
```

The later codegen-units experiment was stopped and produced no binary. Neither 512 nor 768 MiB can be used to infer the uncapped peak. Raising either limit blindly on the laboratory would not satisfy the safety contract.

## Required isolated build envelope

The measured lower bound is strictly greater than 805,306,368 bytes for the complete scoped workload. A successful isolated run is required to measure the true compiler peak. The approved host must provide this conservative, explicit envelope:

```text
Architecture/target: x86_64 / x86_64-unknown-linux-gnu
CPU: at least 2 vCPU; CARGO_BUILD_JOBS=1
RAM: at least 8 GiB total and 6 GiB MemAvailable before build
Build cgroup: MemoryMax at least 4 GiB, or no child cap inside the isolated VM
Swap: not required; if present it must be recorded, not used to mask pressure
Disk: at least 10 GiB free on workspace/target filesystem
Network: not required; use the locked, pre-populated Cargo cache
Secrets: none copied to the build host
```

The 4 GiB compiler allowance is a safety envelope, not a claim that the binary requires 4 GiB. The successful run must record `memory.peak`, `memory.events`, start/end `MemAvailable`, elapsed time and artifact size so the requirement can later be narrowed from evidence.

## Reproducible target and toolchain

Observed canonical environment:

```text
OS/ABI: Linux x86_64, GNU, glibc 2.39
Rust: rustc 1.75.0 (82e1608dfa6e0b5569232559e3d385fea5a93112)
LLVM: 17.0.6
Cargo: 1.75.0
GCC: 13.3.0
Cargo.lock SHA256: 54e5ec6dbeda764415b028cf7f990e80dcc2d830340de57adc8073c9d422b07f
API Cargo.toml SHA256: 29ffb3af3984518473866ea181d3db8242fcff1ac8e1d1a35c0e04180b55ed94
POLARIS_CONTROL tree: 812dfe946d9466d43e2235154a091ee0c1f8afc7
Full repository tree: 492df97e880b28f4988c3d51cdff50ba7d53a3c2
Full source archive SHA256: fd34bc515170028f1ec72f092624ce205aac89f428b8548bf013b7dea83bd117
```

The dependency tree contains no additional `*-sys` package beyond normal libc-backed runtime dependencies. Existing POLARIS release binaries are x86-64 PIE executables using `/lib64/ld-linux-x86-64.so.2`, `libc.so.6`, `libgcc_s.so.1` and `libm.so.6`. Building on a newer glibc than 2.39 is prohibited because it could raise the deployment ABI floor.

Exact build command on the isolated host:

```bash
git verify-commit 8cb356a7e4264b80fb82e2f1c90b9511f581df41  # if signed metadata is available
test "$(git rev-parse HEAD)" = 8cb356a7e4264b80fb82e2f1c90b9511f581df41
sha256sum POLARIS_CONTROL/Cargo.lock POLARIS_CONTROL/apps/api/Cargo.toml
cd POLARIS_CONTROL
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0 \
  cargo build --offline --locked --release \
  -p polaris-control-api --bin polaris-control-api
```

## Environment discovery

Read-only discovery found:

- no configured VM manager;
- no self-hosted runner files;
- no GitHub CLI/authentication for querying private runners;
- no build workflow in the repository (only `.github/workflows/README.md`);
- one SSH alias, `github-oiran-polaris`, which is a Git remote rather than a build host;
- Docker containers only on this laboratory, sharing the same host memory and therefore not isolated.

No paid runner, cloud VM, external service or resource was created. No source or secret was transferred.

## Artifact acceptance and transfer

After a successful build, acceptance requires:

```bash
file target/release/polaris-control-api
ldd target/release/polaris-control-api
sha256sum target/release/polaris-control-api
target/release/polaris-control-api --version
```

The three critical capture publication/idempotence/HTTP tests must execute from the same source SHA. Record the binary size, mode, BuildID, SHA256, toolchain, source/lock hashes and memory peak in a machine-readable manifest.

No artifact-transfer channel is currently authorized. Once one is named, transfer only the binary plus manifest, never environment files or subscriber data. Recompute SHA256 on both ends before accepting the artifact. No deployment follows from artifact acceptance.

— ANR2
