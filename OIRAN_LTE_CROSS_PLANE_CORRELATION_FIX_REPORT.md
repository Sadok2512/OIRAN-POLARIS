# OIRAN LTE cross-plane correlation fix — ANR3

Date: 2026-11-01 UTC  
Scope: offline only; synthetic anonymized fixtures; no live, grant, deployment,
traffic, production restart, Open5GS change, or capture-process change.

ROOT_CAUSE = `discover_lte_sessions` keyed the S1 context correctly by its
S1-MME `capture_id`, but then also required S11 and S1-U events to carry that
same ID. `correlate_lte_evidence` repeated the error through
`capture_scope(...) == capture_scope(...)`. Each plane file is independently
hashed, so valid S1-MME, S11 and S1-U PCAPs necessarily had distinct IDs.

CORRELATION_KEYS = S1 context (`enb_ue_s1ap_id`, `mme_ue_s1ap_id`) + exact
opaque pseudonym + normalized S1AP E-RAB/S11 F-TEID relationship. S1-U is
admitted only when the established S1/S11 chain gives its TEID one session
owner. A 300-second window is only an eligibility bound, never an identity
key. Ambiguous/reused TEIDs remain unmatched. Original per-file `capture_id`
values are retained as provenance.

HTTP_E2E = PASS (offline). The exact previously failing POLARIS envelope and
the same three fixture files were replayed against OIRAN 2.7.3 on
`127.0.0.1:49282`: anonymous import `403`, Operator without CSRF `403`, first
import `201`, exact replay `200` with `idempotent=true`, changed bundle for the
same run `409`. Invalid cursor and `limit=257` both returned `422`. Listener
was stopped after the recipe.

EVENTS_MATCHED = `3/3`; `source_events=3`, `session_events=3`,
`unmatched_events=0`, `duplicate_events=0`, `correlation_edge_count=2`.

SESSIONS = one LTE session, `ACTIVE_WITH_USER_PLANE`, containing S1-MME, S11
and S1-U. The session retains the three distinct source hashes:

- `sha256:945d910a58b3e2d1d9153e5df4352ead855ed4cb58c6804a5aec59224ef5fc0c`
- `sha256:ed7874878bdfe25e65e5232dae8e956cdb69a7e6267424e9a734a89d1088353a`
- `sha256:f04bb9ddccb4c3eff858b80b610884524031bd31a23fbf48c251a7c120303aa3`

CALLFLOW = PASS; three chronological events and two evidence edges.
`S1_MME_S11=STRONG`, `S11_S1_U=EXACT`, `E2E=STRONG`. The generic session
route returned the same three-event status. This is not a real LTE claim.

MULTI_UE_ISOLATION = PASS. Dedicated regressions cover distinct multi-PCAP
SHA values, two UE contexts, TEID reuse, partial captures and out-of-order
input. A TEID shared by two established contexts is not assigned to either
S1-U session.

PRIVACY = PASS. Recursive scans of recorded HTTP evidence and the isolated
store found zero forbidden identity/secret labels, zero clear IMSI occurrences
outside `imsi_pseudonym`, and zero DEMO/mock/fake markers presented as LIVE.

TESTS = PASS, with the following real commands/results:

```text
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_INCREMENTAL=false cargo test --locked -p session-engine --lib
18 passed; 0 failed; 0 ignored

CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_INCREMENTAL=false cargo test --locked -p correlation-engine -p callflow-schema --lib
callflow-schema: 3 passed; correlation-engine: 15 passed; 0 failed

CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_INCREMENTAL=false cargo test --locked -p oiran-api --lib
41 passed; 0 failed; 0 ignored

CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_INCREMENTAL=false cargo test --locked -p live-probe --lib
56 passed; 0 failed; 4 ignored (pre-existing large-memory tests; not counted PASS)

Node 22.23.3 + TypeScript tsc -b --pretty false
PASS

Node 22.23.3 + vitest run
11 files; 77 passed; 0 failed

Node 22.23.3 + tsc -b + vite build + scripts/check-dist-leaks.mjs
PASS; 1,636 modules; leak scan clean (3 files, 2 markers)

CARGO_BUILD_JOBS=1 CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_INCREMENTAL=0 cargo build --locked --release -p oiran-api
PASS in 11m18s
```

The first `npm run typecheck` attempt failed because the repository script
expects `node_modules/node/bin/node`, which was absent. After `npm ci
--ignore-scripts`, the host Node 18 remained below the declared engine range;
the actual frontend validation therefore used the installed Node 22.23.3 at
`/opt/telecom-tools/node_modules/node/bin/node`. Rust emitted one pre-existing
`unused_mut` warning and Live Probe three pre-existing redundant-import
warnings.

SOURCE_SHA = `724e6a0c93fdc09c28dfe9fb255ef64d8a5563bd`

BINARY_SHA256 =
`bbb7ca640794d17654540c4b80f23c17cd5afb0cacb401337e96fae4e23c0845`
(`OIRAN/target/release/oiran-api`, version 2.7.3).

BLOCKERS = No blocker for offline review. Real LTE certification remains
blocked until approved real captures and the separately authorized live E2E
procedure exist. Four explicitly ignored high-memory Live Probe tests remain
documented and were not converted to PASS.

## Safety and evidence

- Final RAM sample: `4,949,385,216` bytes available; `16,021,196,800` bytes
  used (within the requested gates).
- Root disk: 60% used.
- External dumpcap: 12 processes before/after; final PID/start/command snapshot
  SHA-256 `b9925f6c0bc1963f951bc684a9005d39fceb974a3d23f26614ae45e2f3ee8a00`.
- HTTP evidence directory:
  `/tmp/anr3-lte-correlation-http.tJER4A/evidence`; manifest SHA-256
  `8e4926fbd5594adacea27dfde03f2160ce9a4a1b750c4ccf5c10f8144ac7951f`.
- SemVer: OIRAN API/platform 2.7.3; session-engine 0.5.1;
  correlation-engine 0.5.1; LTE rule 1.1.0-offline.1. CHANGELOG updated.

VERDICT = **OFFLINE_PASS**. Never interpret this report as `REAL_PASS LTE`.

— ANR3
