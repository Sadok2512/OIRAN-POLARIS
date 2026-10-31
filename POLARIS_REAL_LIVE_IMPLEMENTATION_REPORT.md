# POLARIS real lab live implementation — ANR3 report

Date: 2026-10-31

Scope: OIRAN live-data frontend and read-only production audit

Base: `integ/oiran-polaris-lte-e2e-v2` / `87daa3445e3058352d21efeba21d05fefe3029d4`

Branch: `anr3/oiran-real-lab-ui-v1`

Production deployment: **not performed**

## Implemented

- The Analyzer header now reads `/probes`, `/datasets` and `/metrics`; it no
  longer claims `vProbe connected` when the real registry reports
  `online=false`, `PROBE_PENDING` and no heartbeat.
- Technology is derived from observed datasets. LTE is shown as observed only
  when an LTE dataset exists; otherwise the UI says `LTE · no observed dataset`.
- Interface chips display the backend state such as `REFERENCE_ONLY`, rather
  than a hardcoded online state.
- Call Flow Viewer now uses the real bounded cursor contract
  (`limit=100`, `cursor`, `next_cursor`) and displays the returned range and
  total. It no longer silently renders only the first 100 events of a
  1,394-event session.
- Existing subscriber/equipment identity withholding remains active in the
  Session/Call Flow UI.

Frontend version: `2.7.0-pre.1+real.lab.1`.

## Real laboratory evidence (GET only)

Commands used:

```text
curl --max-time 10 http://127.0.0.1:49152/api/v1/<endpoint>
jq (structure/count projections only; no subscriber values printed)
systemctl --type=service --state=running
ss -ltnp
ps -eo pid,comm,%cpu,%mem,rss,etime
df -h /root
free -b
pgrep -a dumpcap | wc -l
```

Observed API: OIRAN `2.5.4`, loopback `127.0.0.1:49152`.

| Endpoint | HTTP | Measured time | Result |
|---|---:|---:|---|
| `/api/v1/version` | 200 | 0.008738 s | API 2.5.4, web 2.3.0-dev |
| `/api/v1/metrics` | 200 | measured | historical mode, 0 active captures/sessions |
| `/api/v1/datasets` | 200 | measured | 11 datasets |
| `/api/v1/sessions` | 200 | measured | 11 reconstructed sessions |
| `/api/v1/probes` | 200 | measured | 1 registered, 0 online, PENDING |
| `/api/v1/captures` | 200 | measured | 14 records |
| `/api/v1/interfaces` | 200 | measured | N2/SBI/N4/N3; counters unavailable |
| `/api/v1/ues` | 200 | 0.013378 s | real reconstructed UE contexts |
| `/api/v1/packets` | 200 | 0.263541 s | persisted packet evidence |
| `/api/v1/correlation/edges` | 200 | 0.001531 s | persisted edges |
| `/api/v1/correlation/rules` | 200 | 0.001103 s | real rule catalogue |
| `/api/v1/modules` | 200 | 0.001448 s | navigation contract |
| `/api/v1/auth/me` | 200 | 0.000953 s | viewer state |
| `/api/v1/versions` | 404 | measured | wrong route; `/version` is canonical |

Dataset accounting measured from the API:

| Kind | Datasets | Sessions | Events | Errors | Technology |
|---|---:|---:|---:|---:|---|
| CAPTURED_LIVE | 8 | 1 | 25,771 | 30 | 5G SA |
| DERIVED | 1 | 1 | 92 | 0 | 5G SA |
| HISTORICAL | 1 | 1 | 54 | 0 | 5G SA |
| RECOVERED | 1 | 0 | 20 | 8 | 5G SA |

The largest returned session has 1,394 messages over N2/N3/N4. Call-flow page
1 and page 2 both returned 100 events with distinct cursors; total remained
1,394. The API reports 1,382 correlation edges for that session. Timestamps
were returned as UTC nanosecond strings and preserved without client sorting.

No LTE dataset or S1-MME/S11/S1-U evidence is currently returned by production.
The UI therefore does not claim LTE observation or LTE E2E PASS.

## Tests run manually

| Command | Result |
|---|---|
| initial `npm run typecheck` | FAIL: dependencies absent in isolated worktree; no compiler executed |
| `npm ci` | PASS; 141 packages, 0 vulnerabilities; host Node 18 engine warnings, project-pinned Node 22 used by scripts |
| targeted Vitest first pass | FAIL 1/12: pagination test mock omitted the undefined-path guard |
| targeted Vitest after correction | PASS: 3 files, 12 tests |
| `npm run typecheck && npm test && npm run build` first full pass | FAIL: new matchMedia test environment stub and superseded synthetic-label assertion |
| final `npm run typecheck && npm test && npm run build` | PASS: 11 files, 75 tests; build 1,636 modules; JS 360.19 kB / 106.58 kB gzip; leak check clean |

No CI result is used.

## Security and defects

1. **P0 API identity exposure:** the production call-flow JSON contains a
   `MaskedIMEISV` IE with a non-null value. The frontend withholds this IE, but
   the raw viewer API remains accessible and must sanitize it server-side
   before deployment can be certified.
2. The real vProbe is registered but `online=false`, `PROBE_PENDING`, with no
   heartbeat and no packet/decode/drop counters. The UI now reports this state.
3. Metrics report `HISTORICAL_DATASET_ANALYSIS`, zero active capture/session,
   null live rates, and N2/SBI/N4/N3 as `REFERENCE_ONLY`.
4. Several capture records are FAILED, PARTIAL, BLOCKED or recovered with
   missing source paths. No loss-free claim is possible.
5. Production exposes no LTE dataset; S1AP/S11/S1-U real certification remains
   blocked.
6. The RAM gate first failed at `3,956,572,160` available bytes and dropped to
   `2,587,959,296` bytes at the post-push control, both below 4 GiB. No
   additional Playwright/Rust load was started after the initial failure.

## Resource and safety evidence

- Disk: 49%, below 85%.
- External dumpcap processes: 12 before and after.
- No capture, UE, eNB/gNB, Grant V2, traffic or deployment was started.
- Open5GS, OIRAN services and external captures were not modified or restarted.
- No production write request was sent.

## Concurrent work protection

The shared repository was already conflicted and was not touched. During this
work, concurrent uncommitted backend changes appeared in the isolated worktree
under `OIRAN/apps/api`, `OIRAN/live-probe`, the root OIRAN changelog/manifests
and `OIRAN/docs/REAL_LAB_SESSION_API.md`. They are not authored by ANR3 and are
excluded from the ANR3 commit.

## Deployment plan

1. Restore RAM available to at least 4 GiB.
2. Integrate and test the server-side identity sanitizer, then verify raw API
   output contains only `IDENTITY_WITHHELD`/hashes.
3. Integrate ANR1/ANR2 backend contracts without `merge -s ours` and prove Git
   ancestry.
4. Run Rust API/pipeline tests, full frontend tests and real-data Playwright.
5. Prepare backup and rollback, request separate deployment authorization,
   deploy the Analyzer only, and roll back on any failed recette.

## Verdict

`BLOCKED` for real-lab PASS and deployment. The scoped UI implementation is
offline-tested and truthful, but the production API identity exposure, absent
LTE evidence, pending vProbe, failed/partial captures and RAM gate prevent the
requested platform-wide PASS.

— **ANR3**
