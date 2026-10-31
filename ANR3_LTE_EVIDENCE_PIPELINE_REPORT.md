# ANR3 LTE Evidence Pipeline Report

Date: 2026-10-31 UTC  
Agent: ANR3  
Verdict: **PARTIAL**

## Git and isolation

- Requested base: `integ/oiran-polaris-final-v1` at
  `671282b6e4b540722f82f896d2a95aece924fc51`.
- Isolated worktree: `/root/OIRAN_LTE_EVIDENCE_ANR3_V2`.
- Branch: `feat/anr3-lte-evidence-pipeline-v2`.
- Implementation commits: `f6c2ebe` (offline LTE API/Live Probe materialization)
  and `7a6846f` (contract, bundle verification, tests and changelog).
- `git merge-base --is-ancestor 671282b... HEAD` returned `0`.
- The shared `/root/OIRAN_POLARIS_FOUNDATION` worktree was already dirty and
  conflicted; it was inspected and left untouched.
- The tested ANR3 implementation from `b011432` was functionally cherry-picked
  as `f6c2ebe`; therefore `b011432` is not an ancestor, while its code delta is
  present without an `ours` merge.

## Safety gates

| Gate | Evidence | Result |
|---|---|---|
| Disk below 85% | `df -P /root` -> 77% preflight, 78% final | PASS |
| External dumpcap preserved | `pgrep -a dumpcap \| wc -l` -> 12 before and after | PASS |
| RAM >=4 GiB | preflight `MemAvailable=8.04 GiB`; final `3.33 GiB` while other isolated agents were compiling | PARTIAL |
| No live/deployment | no live, capture, traffic, Open5GS, gNB or production command executed | PASS |
| Identity leakage | tracked-source numeric identity assignment scan returned no match | PASS |

The final RAM measurement is below the required validation gate. The listed
processes belonged to other isolated worktrees, so ANR3 did not stop them or
force a global cache cleanup.

## Delivered pipeline

- OIRAN API `2.6.0` materializes LTE sessions from already-decoded offline
  events and exposes them through Session Explorer.
- Live Probe `0.3.0` creates bounded LTE call flows, with a hard maximum of 128
  materialized sessions per load.
- `oiran-decode 0.6.1` routes S1-MME/SCTP PPID 18, S11/UDP 2123 and S1-U/UDP
  2152 without aliasing N2/N3/N4.
- Existing Session Engine `0.5.0`, Correlation Engine `0.5.0` and Call Flow
  Schema `1.2.0` correlate explicit UE context, E-RAB/EPS bearer and F-TEID
  evidence. Timestamp-only identity joins remain forbidden.
- Analyzer `2.6.0-pre.1+lte.offline.1` publishes LTE technology filters,
  session summaries, exact packet references and call-flow evidence.
- Call Flow pages remain bounded to 1..256 events per cursor page; Session
  Explorer pages remain bounded to 1..100 rows.
- `OIRAN/docs/LTE_EVIDENCE_INGESTION_CONTRACT.md` defines admission, mapping,
  publication and verdict boundaries.

## Protocol and evidence matrix

| Plane | Selector | Extraction | Correlation | Synthetic result |
|---|---|---|---|---|
| S1-MME | SCTP PPID 18 | S1AP procedures, UE context, E-RAB | exact context/pseudonym or prepared bearer | PASS |
| S11 | UDP 2123 | GTPv2-C procedure, control/F-TEID, bearer | exact bearer/F-TEID | PASS |
| S1-U | UDP 2152 | GTP-U TEID, direction, packets/octets, timestamps | exact F-TEID + endpoint | PASS |
| N2/N3/N4 | existing selectors | unchanged | existing regression suite | PASS |

Synthetic fixture assertions: 1 UL packet, 1 DL packet and 2 distinct S1-U
TEIDs. The multi-UE session/correlation suites passed and reject ambiguous or
reused TEID associations.

## Anonymized PCAP bundle preparation

The manifest template remains an offline admission artifact; no real PCAP was
created or modified. New verification rejects absolute/traversing paths,
symlinks, non-regular files, missing files, byte-size differences and SHA-256
differences. SHA-256 is streamed in 1 MiB chunks. A real fixture additionally
requires `certification_state=SANITIZED_APPROVED`, ANR1 reference and approval
timestamp.

This verifier is deliberately not an anonymizer. Real certification remains
blocked until ANR1 supplies already-anonymized, approved S1-MME/S11/S1-U PCAPs.

## Manual tests and actual results

| Command | Result |
|---|---|
| `cargo test -p oiran-decode lte_fixture -- --nocapture` | PASS, 5/5 |
| `cargo test -p oiran-decode --test lte_pipeline_synthetic -- --nocapture` | PASS, 1/1 |
| `cargo test -p live-probe offline_lte -- --nocapture` | PASS, 1/1 |
| `cargo test -p oiran-api api_load_materialises_synthetic_lte_session_without_live_capture -- --nocapture` | PASS, 1/1 |
| `cargo test --workspace -- --test-threads=4` | PASS; Live Probe 48 passed/4 ignored, API 35, Session Engine 16, no failure |
| Node 22.23.4 + `vitest.mjs run` | PASS, 73/73 in 10 files |
| Node 22.23.4 + `tsc -b --pretty false` | PASS |
| Node 22.23.4 + `vite.js build` | PASS, 1,636 modules |
| Node 22.23.4 + `scripts/check-dist-leaks.mjs` | PASS, 3 files/2 markers |
| Playwright `s4.spec.ts v2_3_session_explorer.spec.ts` | initial 43/44; reproducible WEB-002 route-navigation failure |
| Playwright `--grep WEB-002 s4.spec.ts` after route-based correction | PASS, 1/1 in 10.3 s |
| `cargo fmt --all -- --check` | FAIL on pre-existing repository-wide formatting drift; no bulk reformat performed |
| `git diff --check` | PASS |

The first two `npm test` invocations failed before test collection because the
lockfile-local Node binary was absent and `npm ci --ignore-scripts` correctly
did not run the binary installer. Tests were then executed with the existing
Node 22.23.4 binary at `/root/POLARIS_CONTROL/apps/web/node_modules/node/bin/node`.

The Rust pagination regression
`streams_large_callflow_with_bounded_rss_and_cursor_pages` passed in the full
workspace suite. Four intentionally ignored high-volume Live Probe allocation
tests were not claimed as executed.

## Open blockers

1. `ANR1_LTE_ORCHESTRATION_CONTRACT.md` was not present: the ANR1 V2 worktree
   remained clean at the base SHA. OIRAN therefore accepts only the existing
   canonical `oiran-polaris.lte-e2e-evidence.v1` schema and fails closed on a
   new revision.
2. Final available RAM was 3.33 GiB, below the 4 GiB gate, due to concurrent
   worktree test processes. Re-measure before integration review.
3. No ANR1-approved real LTE PCAP bundle exists in this scope. `REAL_PASS` is
   impossible.
4. Repository-wide rustfmt drift remains outside the LTE change set.

## Next step

After ANR1 publishes the V2 orchestration contract, compare it field-by-field
with the ingestion contract, rerun the offline suites with >=4 GiB available,
and review this branch. Real PCAP ingestion and any deployment require separate
explicit authorization.

— ANR3
