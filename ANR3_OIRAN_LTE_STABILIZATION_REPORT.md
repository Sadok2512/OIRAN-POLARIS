# ANR3 — OIRAN LTE stabilization V1

Date: 2026-10-31 UTC  
Base: `b011432b17235d85a08aa21bf4afe1c65fa6eeba`  
Branch: `fix/anr3-oiran-lte-stabilization-v1`  
Scope: offline only; no live capture, traffic, deployment or production change  
Verdict: **READY_FOR_REVIEW** (real LTE certification remains blocked)

## Git isolation and lineage

The shared worktree `/root/OIRAN_POLARIS_FOUNDATION` contained extensive
staged/unstaged changes and index conflicts belonging to other work. It was not
modified. This work used `/root/OIRAN_LTE_STABILIZATION_ANR3`, created directly
from the requested base. `git merge-base --is-ancestor b011432... HEAD`
returned 0.

Lineage before this stabilization commit:

| Component | Last component commit on base |
|---|---|
| OIRAN API | `b011432b17235d85a08aa21bf4afe1c65fa6eeba` |
| Live Probe | `b011432b17235d85a08aa21bf4afe1c65fa6eeba` |
| oiran-decode | `b011432b17235d85a08aa21bf4afe1c65fa6eeba` |
| Analyzer | `2c67fe6b2cbb450fefaa789c76f947678388953c` |
| session-engine | `2c67fe6b2cbb450fefaa789c76f947678388953c` |
| correlation-engine | `2c67fe6b2cbb450fefaa789c76f947678388953c` |
| callflow-schema | `2c67fe6b2cbb450fefaa789c76f947678388953c` |

## Audit of the six Playwright failures

Reproduction server: `127.0.0.1:49335`, isolated worktree, capture execution
disabled by default.

```console
OIRAN_E2E_BASE_URL=http://127.0.0.1:49335 \
  /root/POLARIS_CONTROL/apps/web/node_modules/node/bin/node \
  node_modules/@playwright/test/cli.js test v2_3_session_explorer.spec.ts
```

Initial result: **1 passed / 6 failed**. The failures were:

1. Inventory asserted `meta.total >= 4`; actual isolated value was 1.
2. Scope test waited 60 s for option
   `recovered-dataset-live-1792964646320-0003`, which was absent.
3. Light 1440 visual test timed out on the same absent option.
4. Dark 1440 visual test timed out on the same absent option.
5. Light 1920 visual test hit the same absent option; the browser target then
   crashed while retrying the impossible selection.
6. Dark 1920 visual test timed out on the same absent option.

The historical Call Flow test passed during this failing run. Therefore the
six failures represented two stale fixture assumptions, not six LTE defects.

Failure traces produced by the audit are retained outside this branch under:

```text
/root/OIRAN_LTE_FINAL_ANR3/OIRAN/apps/web/test-results/
  v2_3_session_explorer-V2-3-97d67-d-truthfully-session-scoped/trace.zip
  v2_3_session_explorer-V2-3-792c2-nrelated-historical-session/trace.zip
  v2_3_session_explorer-V2-3-Session-Explorer-light-1440x900/trace.zip
  v2_3_session_explorer-V2-3-Session-Explorer-dark-1440x900/trace.zip
  v2_3_session_explorer-V2-3-Session-Explorer-light-1920x1080/trace.zip
  v2_3_session_explorer-V2-3-Session-Explorer-dark-1920x1080/trace.zip
```

Trace sizes were respectively 6,135; 558,155; 1,104,371; 1,100,023;
831,414; and 865,122 bytes. Error contexts confirm
`locator.selectOption: did not find some options`.

## Dataset registry proof

```console
curl -fsS http://127.0.0.1:49335/api/v1/datasets?page_size=100
```

Result: exactly one registered dataset,
`OIRAN_5G_PDU_SESSION_DATA_V1`, with 78 packets, 54 normalized events and one
session.

Direct API checks returned `404 DATASET_NOT_FOUND` for all three external IDs:

| Dataset ID | HTTP status |
|---|---:|
| `recovered-dataset-live-1792964646320-0003` | 404 |
| `dataset-live-1792966547779-0001` | 404 |
| `derived-e2e-002-live-1793054609378-0001` | 404 |

The first two have no matching directory under the repository or `/root`. The
third has a checked-in, unregistered evidence directory under
`OIRAN/benchmarks/E2E_002`, but importing it requires an authenticated operator
operation. It was not imported, reconstructed or substituted.

## Stabilization change

- The V2.3 test now anchors on the explicitly checked-in
  `OIRAN_5G_PDU_SESSION_DATA_V1` fixture.
- It asserts that the former recovered ID is absent.
- Empty live/recovered behavior is tested through explicit dataset scopes,
  without selecting a nonexistent dataset.
- The S4 regression no longer expects Probe Manager in an Analyzer navigation
  which explicitly excludes that separate application; it validates the real
  route instead.
- S4 assertions no longer require the absent recovered dataset.
- Two tests which genuinely require external runtime captures are explicitly
  skipped with the exact missing capture ID, rather than fabricating evidence.

SemVer changes:

| Component | Before | After |
|---|---:|---:|
| OIRAN API | 2.6.0 | 2.6.1 |
| Analyzer | 2.6.0-pre.1+lte.offline.1 | 2.6.0-pre.2+lte.stabilization.1 |
| Live Probe | 0.3.0 | unchanged |

`OIRAN/CHANGELOG.md`, Cargo lock and web package lock were updated.

## LTE fixture and correlation evidence

```console
jq '.expected' OIRAN/tests/fixtures/lte-offline-certification-synthetic-manifest.json
```

Result: 2 UE sessions, 2 EPS bearers, 2 distinct S1-U TEIDs, 1 UL packet,
1 DL packet and 4 correlation edges.

```console
jq '.expected' OIRAN/tests/fixtures/lte-pipeline-synthetic-v1.json
```

Result: 5 decoded cases, 2 S1-U packets (1 UL, 1 DL) and 2 distinct TEIDs.

Rust tests validate:

- S1AP/NAS-EPS, S11/GTPv2-C and S1-U/GTP-U decoding;
- explicit multi-UE partitioning without time-only identity joins;
- exact unique S11/S1-U TEID edges;
- rejection of ambiguous/reused TEIDs;
- LTE Call Flow generation and Session Explorer API filtering;
- 5G N2/N3/N4 STRONG/EXACT correlations without regression.

No clear subscriber identity was introduced. Fixtures remain classified
synthetic/offline and anonymized.

## Manual test results

### Rust

```console
cargo test -p oiran-decode -p session-engine -p correlation-engine \
  -p callflow-schema -p live-probe -p oiran-api
```

Result: **126 passed, 0 failed, 4 ignored**. The four ignored tests are the
pre-existing very-large import/aggregation stress cases.

### Pagination and memory

```console
cargo test -p live-probe \
  streams_large_callflow_with_bounded_rss_and_cursor_pages -- --nocapture
```

Result: PASS; 8,192 events; cursor pages of 100; peak RSS
`12,668,928` bytes, below the asserted 256 MiB ceiling.

### Frontend

```console
/root/POLARIS_CONTROL/apps/web/node_modules/node/bin/node \
  node_modules/vitest/vitest.mjs run
```

Result: **10 files / 73 tests passed**.

```console
/root/POLARIS_CONTROL/apps/web/node_modules/node/bin/node \
  node_modules/typescript/bin/tsc -b --pretty false
```

Result: PASS.

```console
/root/POLARIS_CONTROL/apps/web/node_modules/node/bin/node \
  node_modules/vite/bin/vite.js build
```

Result: PASS; 1,636 modules; JS 358.59 kB, 106.16 kB gzip.

```console
/root/POLARIS_CONTROL/apps/web/node_modules/node/bin/node \
  scripts/check-dist-leaks.mjs
```

Result: PASS; 3 files scanned, no forbidden identity marker.

### Playwright after stabilization

```console
... playwright test v2_3_session_explorer.spec.ts
```

Result: **7 passed / 0 failed** in 10.6 s.

```console
... playwright test s5_5_four_plane.spec.ts
```

Result: **2 passed / 0 failed** in 22.8 s.

```console
... playwright test s4.spec.ts
```

Result: **35 passed / 0 failed / 2 skipped**. Each skip names the exact absent
external runtime capture required by the test.

The authenticated E2E-002 scenario was not run because
`OIRAN_E2E_OPERATOR_TOKEN=ABSENT`. No token was invented and no authenticated
dataset import was attempted.

## Safety proof

```console
df -P /root/OIRAN_LTE_STABILIZATION_ANR3
```

Result after testing: 77% usage, below 85%.

```console
pgrep -a dumpcap | wc -l
```

Result after testing: 12. No process was signalled, stopped or restarted.

No production endpoint was modified or used for mutation. All HTTP/UI tests
targeted the isolated loopback API. No capture, UE, scenario or traffic was
started.

## Remaining anomalies and blockers

1. The two external capture-dependent S4 tests remain skipped until their
   exact historical runtime fixtures are supplied read-only.
2. The authenticated E2E-002 import test requires a securely injected operator
   token and was not authorized in this mission.
3. Four giant Rust stress tests remain ignored by their upstream test flags;
   bounded pagination itself was executed and passed.
4. Real LTE certification remains blocked until approved anonymized S1-MME,
   S11 and S1-U PCAPs are supplied.

## Verdict

**READY_FOR_REVIEW** for the offline OIRAN LTE stabilization branch. All tests
which are satisfiable from checked-in, explicitly identified fixtures pass.
External-history tests are transparently skipped or blocked, never replaced by
synthetic history. This verdict does not authorize live LTE or deployment and
does not constitute real-PCAP certification.

— ANR3
