# S2.1 integrity test report

Command: `cargo test --workspace --no-fail-fast`.

Result: **21 unit tests passed, 0 failed**; all binary and documentation test targets also passed. No benchmark was executed by the test suite.

`cargo clippy` was unavailable in the installed Rust toolchain and was not installed because package/toolchain installation is forbidden. `cargo fmt`, debug tests, release build, shell syntax validation, and `git diff --check` passed.

Coverage includes:

- GTP-U parsing at 64/128/512/1500 bytes and malformed/truncated packets;
- immutable preloaded fingerprints and provenance lengths;
- deterministic flow partitioning across four workers and unique template ordinals;
- worker-local preloaded accounting and observable TEID work;
- exact four-worker accounting, queue saturation with explicit drops, and bounded occupancy;
- graceful drain, same-flow ordering, deterministic replay, and length-error reporting;
- cpuset-aware automatic/explicit affinity validation;
- mandatory 900-second fresh receipt and isolated A/B/C mode structure.

The completed full-pipeline invariant is checked in code as `generated = processed + dropped` and `enqueued = processed` after drain. Any malformed frame, fingerprint error, provenance-length error, or mismatch fails the run. Performance values are `NOT_RUN`; packet loss and integrity error counts for S2.1 throughput runs are therefore also `NOT_RUN`, not zero.
