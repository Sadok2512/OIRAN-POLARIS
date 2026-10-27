# POLARIS Source Provenance

The running production process is PID 76637, executable `/root/POLARIS_CONTROL/target/release/polaris-control-api`, SHA256 `141605dfa8a506c233091dc6f226a47677fcf991d3d672743bc3ff57dcd7b1e8`. It was inspected read-only and not restarted.

Candidate `ddbc53f703cc1e4f8dce3cba1fd4310c3233368d` descends from the certified V3.2 feature line: profile visibility, runtime reconciliation, UE-targeted traffic `7845580d`, host/cgroup-aware safety `0314b8a7`, and decision evidence `c0a43690`. Release source commit `836196e8bb372bd3cc2bcb39f048ff43af3544b2` adds worktree-independent authenticated evidence paths and recognizes the backend's existing fail-closed `INSUFFICIENT_RESOURCES` state without weakening policy.

Build inputs:

- rustc/cargo 1.75.0
- bundled Node 22.23.4 for frontend scripts (host Node 18.19.1, npm 9.2.0)
- Cargo.lock SHA256 `4fb38bb19e57399c162b59285578f75c53ab5582f62f1567df0ab832ca371b15`
- package-lock.json SHA256 `54121be4245fba9064dc242a979a308968b84a4d258d6a8e3da8002d2780f397`
- standard Cargo release profile

The production binary hash differs from the candidate build. Version strings were not treated as binary provenance.

An independent detached-worktree build of `836196e8` reproduced the API SHA256 `0a276b…` and every frontend file byte-for-byte. POLARIS source reproducibility is therefore verified for the recorded toolchain, lockfiles, and build commands.
