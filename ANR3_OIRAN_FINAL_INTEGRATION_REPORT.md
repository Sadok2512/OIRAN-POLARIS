# ANR3 — OIRAN 2.7.1 Final Integration P0

Date: 2026-11-01 UTC

Verdict: **READY (offline integration); real LTE certification remains BLOCKED**

Branch: `hermes/final-anr3-20261101`

Integration merge: `b57e2d36ffd65d03cfe7df70edb8800f8934cdee`

## Git and conflict resolution

The integration is a real two-parent merge:

```text
b57e2d36ffd65d03cfe7df70edb8800f8934cdee
  523524fd44b6bc2b6a4535bb093290f26b8135f4  API privacy 2.7.1
  b011432b17235d85a08aa21bf4afe1c65fa6eeba  LTE final pipeline
```

`git ls-files -u` is empty. Both parents pass
`git merge-base --is-ancestor`. The pre-existing working resolution and its
checkpoint report were preserved in `ANR3_RESULT.md`; no side of the merge was
replaced with an `ours` strategy.

Resolved versions:

| Component | Version |
|---|---:|
| OIRAN API | 2.7.1 |
| Live Probe | 0.4.0 |
| Analyzer web | 2.7.0 |
| oiran-decode | 0.6.0 |
| session-engine | 0.5.0 |
| correlation-engine | 0.5.0 |
| callflow-schema | 1.2.0 |

`OIRAN/CHANGELOG.md`, Cargo manifests and `Cargo.lock` are consistent with the
resolved versions.

## Integrated behavior

- S1-MME routes to S1AP and NAS-EPS; S11 routes to GTPv2-C; S1-U routes to
  GTP-U without aliasing N2/N3/N4.
- Offline Live Probe materializes LTE sessions and Call Flows from already
  decoded evidence, with a hard limit of 128 sessions per dataset.
- Session partitioning uses explicit S1AP context/pseudonym/F-TEID evidence;
  reused or ambiguous TEIDs fail closed.
- UL/DL direction and GTP-U packet/octet accounting remain covered by decoder
  and session-engine tests.
- API Session Explorer exposes LTE sessions and the version route reports the
  complete LTE and 5G decoder inventory.
- N2/NGAP, N3/GTP-U and N4/PFCP decoder and correlation regressions remain green.
- Live capture allowlists and execution gates were not expanded.

## Privacy

The API 2.7.1 privacy correction remains applied at the common JSON success and
pagination boundaries and to Call Flow JSON/HTML exports. Identity-bearing keys
and decoded information elements are removed rather than returned masked.

The raw-response regression covers datasets, sessions, events, packets,
Call Flow, JSON/HTML exports and both viewer/operator reads. Useful protocol
events, provenance and accounting fields remain present. The frontend bundle
leak scan is also clean.

No raw unapproved capture was opened. Tests used repository synthetic fixtures
and existing sanitized decoder fixtures only. JSON fixture validation passed and
the long numeric identity scan found zero candidate files.

## Manual test evidence

All commands were run from the isolated worktree with no production endpoint,
capture process or live traffic.

### Integrated Rust/API suite

```text
CARGO_BUILD_JOBS=1 cargo test --offline --locked \
  -p oiran-decode -p session-engine -p correlation-engine \
  -p callflow-schema -p live-probe -p oiran-api -- --test-threads=2
```

Result: **136 passed, 0 failed, 4 ignored**. The four ignored cases are the
explicit 300/500/512 MiB and 1.2 GiB stress fixtures. Notable results:

- API: 40/40, including LTE materialization, decoder inventory, privacy,
  pagination, RBAC and CSRF.
- Live Probe: 53 passed, including bounded LTE materialization and Call Flow
  streaming.
- Session/correlation/callflow/oiran-decode: 43 passed, including multi-UE,
  TEID ambiguity rejection and N2/N3/N4 regressions.

### Protocol decoder suite

```text
CARGO_BUILD_JOBS=1 cargo test --offline --locked \
  -p decoder-s1ap -p decoder-gtpv2c -p decoder-gtpu \
  -p decoder-ngap -p decoder-pfcp -p decoder-nas -- --test-threads=2
```

Result: **82 passed, 0 failed**. This directly covers S1 Setup and S1AP
procedures, E-RAB names, GTPv2-C bearer/F-TEID extraction, S1-U direction and
TEID, NAS EPS/5G privacy, NGAP transfer decoding and PFCP fields.

### Pagination and memory

```text
cargo test --offline --locked -p live-probe \
  streams_large_callflow_with_bounded_rss_and_cursor_pages \
  -- --nocapture --test-threads=1
```

Result: PASS; 8,192 events, two cursor pages of 100, peak RSS
`12,595,200` bytes, below the 256 MiB assertion.

### Frontend

Dependencies were installed from the lockfile and tested with the repository's
embedded Node `v22.23.4`.

| Command | Result |
|---|---|
| `npm run typecheck` | PASS |
| `npm run test` | 11 files / 75 tests PASS |
| `npm run build` | PASS; 1,636 modules |
| bundled `check-dist-leaks.mjs` | PASS; 3 files, 2 forbidden markers |

Build output: JS 360.19 kB (106.58 kB gzip), CSS 30.37 kB
(6.64 kB gzip).

### Static checks and resources

- `cargo metadata --offline --locked --no-deps`: PASS.
- `git diff --cached --check`: PASS before merge.
- Conflict-marker scan: PASS.
- Final disk: 56%, below 85%.
- Final available RAM: 5,081,370,624 bytes.
- External `dumpcap` count: 12, unchanged.
- `cargo fmt --all -- --check`: FAIL on the inherited repository-wide format
  debt (1,463 proposed diff lines across multiple untouched crates). No broad
  reformat was applied to shared work.

## Restrictions and remaining gates

- No deployment, service restart, new capture, UE, scenario or traffic.
- No Open5GS, OIRAN runtime, gNB/eNB or historical dataset modification.
- Real LTE certification is still blocked until an ANR1-approved anonymized
  S1-MME/S11/S1-U manifest and captures are supplied through the documented
  offline evidence contract.
- The four ignored large-volume tests require a dedicated resource window if
  their execution becomes a release requirement.

The integrated source is ready for review and offline promotion. It is not a
claim of real LTE E2E or production certification.

— ANR3
