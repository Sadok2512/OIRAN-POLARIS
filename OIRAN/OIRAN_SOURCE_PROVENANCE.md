# OIRAN Source Provenance

## Production preservation

The running API is PID 604529 at `/opt/oiran/bin/oiran-api`, SHA256 `e3daa282e3d4208863f72595327d6484c27fbcf7a6a696e9354de4d374b32e77`. The running helper is PID 604488 at `/opt/oiran/bin/oiran-capture-helper`, SHA256 `051d2ab9605a262957b676a43996b04fec6c349aa1a822b819c40303ec35c892`.

Production was built from a dirty continuous-certification worktree based on `d7d8ec700b1b1f90222a44ba10f74d24913c5fa4`. Its source delta was preserved immutably on branch `preserve/production-dirty-20261027` at commit `7ef47076b72c6d5a811a9ef3542da496d5da502a`. The original dirty worktree and running files were not overwritten.

## Consolidated ancestry

The reviewed `f4f844fac5a5fd57aed73f2ae3dd33bf0b081689` ancestry contains S5.1 `ca623fe3`, S5.2 `0ec2a6fc`, S5.3 `f343c67c`, S5.5 `ab5e3e34`, S5.5.1 `d7d8ec70`, and E2E-002 correlation `c7ae16aa`. Commit `8f024c49` integrates the preserved continuous-certification delta while retaining the atomic derived-dataset import. Commit `f31d2e40` makes authenticated evidence paths worktree-independent.

## Build inputs

- rustc/cargo 1.75.0
- bundled Node 22.23.4 for frontend scripts (host Node 18.19.1, npm 9.2.0)
- Cargo.lock SHA256 `802cf01d909d09bfe0fb9213eaac671956881fc02456eae99ea4eb2fe99dcc9f`
- package-lock.json SHA256 `9fb7cdb0d82a1d7670c9f15cd0bb1e0fe5e51353e11d3d0db6e4729ed06f1462`
- release profile: thin LTO, one codegen unit, panic abort

## Reproducibility result

An independent detached worktree build of `f31d2e40` reproduced the API (`4c862b…`), recovery tool (`43925e…`), and each frontend file exactly. The helper rebuilt as `25d928f8…` rather than primary hash `40066162…`; `strings` confirms that the only identified source of path dependence is the embedded absolute `capture-helper/src/lib.rs` panic-location path. No semantic source difference exists. Fully byte-reproducible helper output therefore requires a controlled path remap/build root in a future release pipeline.
