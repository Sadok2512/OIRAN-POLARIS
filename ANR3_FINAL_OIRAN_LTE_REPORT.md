# ANR3 — Final OIRAN LTE report

Date: 2026-10-31 UTC  
Scope: OIRAN offline LTE integration only  
Branch: `feat/anr3-oiran-lte-final-integration-v1`  
Base: `2c67fe6b2cbb450fefaa789c76f947678388953c`  
Verdict: **OFFLINE_PARTIAL — REAL certification BLOCKED**

## Outcome

The existing LTE decoders and correlation engines are now connected to the
offline Live Probe finalisation and OIRAN API dataset-loading paths. Synthetic
S1-MME/S11/S1-U evidence produces an LTE Call Flow, a Session Explorer entry,
protocol inventory, pagination and safe per-session pseudonyms. The live
capture interface allowlist was deliberately not expanded.

This is not `REAL_PASS`: no ANR1-approved PCAP, LTE live grant, Grant V2
certification, live traffic, deployment or production recipe was available or
authorised.

## Versions

| Component | Version in this branch |
|---|---:|
| OIRAN API | 2.6.0 |
| Live Probe | 0.3.0 |
| Analyzer | 2.6.0-pre.1+lte.offline.1 |
| oiran-decode | 0.6.0 |
| session-engine | 0.5.0 |
| correlation-engine | 0.5.0 |
| callflow-schema | 1.2.0 |

The API version endpoint now reports installed NGAP, S1AP, NAS-5GMM,
NAS-5GSM, NAS-EPS-MM, NAS-EPS-SM, PFCP, GTPv2-C, GTP-U and SBI-HTTP2 decoder
versions rather than the decoder subset present in the primary Call Flow.

## Offline architecture

```text
approved PCAP copy (future) / synthetic fixture (current)
  -> oiran-decode: S1AP + NAS-EPS / GTPv2-C / GTP-U
  -> normalized immutable events with packet provenance
  -> session-engine: explicit S1AP context + pseudonym + F-TEID partition
  -> correlation-engine: S1-MME <-> S11 and S11 <-> S1-U evidence
  -> callflow-schema: LTE procedures, participants and correlations
  -> Live Probe persisted JSON/HTML (bounded to 128 LTE sessions/dataset)
  -> OIRAN API: Session Explorer, Call Flow and paginated events
  -> Analyzer generic LTE filters and views
```

No timestamp-only UE identity join is accepted. S11/S1-U correlation requires
an explicit unique TEID; ambiguous/reused TEIDs fail closed.

## Protocol matrix

| Plane | Supported | Offline configured | Synthetic decoded | Correlated/sessionized | Live capturing |
|---|---|---|---|---|---|
| S1-MME / S1AP + NAS-EPS | PASS | PASS | PASS | PASS | BLOCKED by gates 2–4 |
| S11 / GTPv2-C | PASS | PASS | PASS | PASS | BLOCKED by gates 2–4 |
| S1-U / GTP-U | PASS | PASS | PASS | PASS | BLOCKED by gates 2–4 |
| N2 / NGAP | PASS (regression) | PASS | PASS | PASS | unchanged |
| N3 / GTP-U | PASS (regression) | PASS | PASS | PASS | unchanged |
| N4 / PFCP | PASS (regression) | PASS | PASS | PASS | unchanged |
| SBI / HTTP2 | PASS (regression) | PASS | PASS | PASS | unchanged |

LTE procedures covered by synthetic fixtures/tests: S1 Setup, EPS Attach/NAS,
Initial Context Setup, E-RAB setup, Detach/release grouping, Create Session,
bearer F-TEID extraction and S1-U G-PDU UL/DL accounting.

## Measured synthetic statistics

Commands:

```console
jq '.expected' OIRAN/tests/fixtures/lte-offline-certification-synthetic-manifest.json
```

Result: 2 UE sessions, 2 EPS bearers, 2 distinct S1-U TEIDs, 1 UL packet,
1 DL packet and 4 correlation edges over timestamps
`2026-10-31T12:00:00.000000000Z` through
`2026-10-31T12:00:00.900000000Z`.

```console
jq '.expected' OIRAN/tests/fixtures/lte-pipeline-synthetic-v1.json
```

Result: 5 decoded cases, 2 S1-U packets (1 UL, 1 DL), 2 distinct TEIDs.
The fixture declares `real_capture=false`,
`classification=SYNTHETIC_OFFLINE_NOT_REAL_CERTIFICATION` and
`clear_subscriber_identities_present=false`.

The new API integration test independently injects 3 synthetic events (one per
LTE plane), materialises 1 LTE session and obtains `E2E=STRONG`. The S11/S1-U
edge is exact; the overall S1-MME/S11/S1-U identity claim is intentionally not
upgraded to exact.

## Performance and safety

```console
cargo test -p live-probe streams_large_callflow_with_bounded_rss_and_cursor_pages -- --nocapture
```

PASS: 8,192 events; two cursor pages of 100; peak RSS 12,939,264 bytes;
hard assertion below 256 MiB. API page default is 100 and maximum is 256.
The LTE materialiser rejects datasets above 128 discovered LTE sessions rather
than growing without bound. No current OOM was observed in the offline tests;
historical production OOM status was not re-certified in this no-production
mission.

```console
df -P /root/OIRAN_LTE_FINAL_ANR3
```

Result after tests: `/dev/sda1` at 75%, below the strict 85% ceiling.

```console
pgrep -a dumpcap | wc -l
```

Result after tests: 12. No dumpcap process was signalled, restarted or stopped
by ANR3.

## Manual tests and actual results

```console
cargo check -p live-probe -p oiran-api
```

PASS.

```console
cargo test -p oiran-decode -p session-engine -p correlation-engine \
  -p callflow-schema -p live-probe -p oiran-api
```

Final result: 126 passed, 0 failed, 4 ignored. The ignored cases are explicitly
marked large capture/import stress tests.

```console
cargo test -p oiran-api api_load_materialises_synthetic_lte_session_without_live_capture -- --nocapture
```

PASS: 1 passed, 0 failed. This validates dataset load, LTE Call Flow creation,
Session Explorer API filtering, three-plane visibility and pseudonymized UE ID.

```console
/root/POLARIS_CONTROL/apps/web/node_modules/node/bin/node \
  node_modules/vitest/vitest.mjs run
```

PASS: 10 files, 73 tests.

```console
/root/POLARIS_CONTROL/apps/web/node_modules/node/bin/node \
  node_modules/typescript/bin/tsc -b --pretty false
```

PASS.

```console
/root/POLARIS_CONTROL/apps/web/node_modules/node/bin/node \
  node_modules/vite/bin/vite.js build
```

PASS: 1,636 modules; JS 358.59 kB (106.16 kB gzip).

```console
/root/POLARIS_CONTROL/apps/web/node_modules/node/bin/node scripts/check-dist-leaks.mjs
```

PASS: 3 files scanned, 2 forbidden-identity markers checked, no leak.

Playwright ran against an isolated loopback API on `127.0.0.1:49333` with
capture execution disabled:

```console
OIRAN_E2E_BASE_URL=http://127.0.0.1:49333 .../node \
  node_modules/@playwright/test/cli.js test \
  v2_3_session_explorer.spec.ts s5_5_four_plane.spec.ts
```

Result: 3 PASS / 6 FAIL. Both four-plane tests and the exact historical Call
Flow navigation passed. The failures are fixture-state failures: the test
requires at least 4 registered datasets but the clean isolated API has 1, and
therefore the expected recovered dataset is absent from the selector. No FAIL
is reported as PASS. Generated screenshots/results were restored afterward.

## Matrix

| Requirement | Verdict | Evidence/limitation |
|---|---|---|
| LTE decoder pipeline | PASS offline | Rust decoder and fixture tests |
| Multi-UE partition | PASS offline | 2 sessions / 2 TEIDs fixture |
| UL/DL counters | PASS offline | 1 UL + 1 DL fixture |
| LTE correlation | PASS offline | exact TEID edge; E2E STRONG |
| LTE Call Flow | PASS offline | Live Probe materialisation test |
| LTE Session Explorer API | PASS offline | API load/filter integration test |
| Analyzer LTE contract | PASS offline | 73 frontend tests + build/typecheck |
| Pagination/memory | PASS offline | 8,192 events, 12,939,264-byte peak RSS |
| Complete Playwright historical corpus | PARTIAL | missing recovered datasets in clean worktree |
| Real LTE PCAP certification | BLOCKED | no ANR1-approved anonymized PCAP |
| Live LTE capture/E2E | BLOCKED | no gates 2–4 grant/authorisation |
| Deployment/production recipe | BLOCKED | no gate 8 authorisation |

## Open defects and prioritized next steps

1. **P0 — certification input:** obtain ANR1-approved anonymized S1-MME, S11
   and S1-U PCAPs plus manifest/checksums; run the same pipeline without live
   acquisition and compare UE/bearer/TEID/UL/DL ground truth.
2. **P0 — gates:** certify Grant V2 ownership/RBAC/CSRF/replay controls and
   isolation before any live LTE attempt.
3. **P1 — Playwright fixture:** seed the three expected derived/recovered
   datasets in an isolated test registry, then rerun all nine selected tests.
4. **P1 — scale:** execute the four ignored large import/aggregation tests in
   a dedicated resource window and retain RSS/duration artifacts.
5. **P1 — real certification:** only after explicit gate 4 authorisation, run
   the bounded 1 UE / 5 minute scenario and produce anonymized PCAP evidence.
6. **P0 — deployment:** do not deploy until gates 5–8, merge-base proof,
   backup and rollback plan are all present.

## Final status

`OFFLINE_PARTIAL`: the ANR3 offline LTE integration is implemented and its
targeted Rust/API/frontend tests pass, but the full Playwright fixture corpus
is incomplete and real/live/deployment certification remains blocked by the
declared gates.

— ANR3
