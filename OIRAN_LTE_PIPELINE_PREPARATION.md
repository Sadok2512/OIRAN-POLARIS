# OIRAN LTE pipeline preparation

Mission: `OIRAN_LTE_PIPELINE_PREPARATION`
Agent: ANR3
Date: 2026-10-31 UTC
Branch: `feat/anr3-oiran-lte-pipeline-preparation`
Base SHA: `6464476a2ffd24324aecf0ab43ce60af3161f5f8`

## Verdict

The offline LTE preparation is implemented and regression-tested without changing production, Open5GS, POLARIS, capture services or external `dumpcap` processes. Explicit S1-MME, S11 and S1-U decoder routes, LTE session preparation, TEID correlation rules and Analyzer filters are present. Existing N2/N3/N4/SBI tests remain green.

This is **not real LTE certification**. The API/live-probe publication path and capture allowlist remain disabled for LTE, and no real LTE fixture has been ingested. Activation and certification remain blocked until ANR1 supplies and approves an anonymized fixture.

## Existing component audit

| Component | Version before | Coverage observed | Preparation result |
|---|---:|---|---|
| `decoder-s1ap` | 0.2.0 | S1 Setup, Initial UE, DL/UL NAS, Initial Context Setup, E-RAB procedure names, UE release; EPS NAS child events; identity pseudonymization | Reused unchanged |
| `decoder-nas` | 0.3.1 | EPS Attach/Detach, authentication/security, EPS bearer messages | Reused through S1AP unchanged |
| `decoder-gtpv2c` | 0.1.0 | S11 Create/Modify/Delete Session, bearer procedures, EBI/F-TEID and pseudonymized identities | Wired into pipeline UDP/2123 |
| `decoder-gtpu` | 0.1.0 | GTP-U header, TEID, inner IPv4, gNB/UPF direction | 0.2.0; adds eNB/SGW UL/DL direction |
| `oiran-decode` | 0.4.5 | N2/N3/N4/SBI only | 0.5.0; adds strict LTE routes |
| `session-engine` | 0.3.0 | 5G UE/PDU/PFCP/GTP-U reconstruction | 0.4.0; adds LTE preparation view and counters |
| `correlation-engine` | 0.3.1 | N2/SBI/N4/N3 evidence rules | 0.4.0; adds ambiguity-safe LTE bearer rules |
| Analyzer web | 2.5.0-dev (`package-lock` previously 2.3.0-dev) | 5G-only filters; LTE disabled | 2.6.0-pre.1; synthetic-only LTE filters |

## Decoder pipeline

The decoder now routes by both declared interface and transport signature:

| Declared interface | Transport | Decoder | Status |
|---|---|---|---|
| N2 | SCTP PPID 60 | NGAP | Preserved |
| N3 | UDP/2152 | GTP-U | Preserved |
| N4 | UDP/8805 | PFCP | Preserved |
| SBI | TCP | SBI/HTTP2 | Preserved and now interface-scoped |
| S1-MME | SCTP PPID 18 | S1AP + EPS NAS | Added |
| S11 | UDP/2123 | GTPv2-C | Added |
| S1-U | UDP/2152 | GTP-U | Added |

The interface is never guessed from a port alone. PPID 18 on N2 and PPID 60 on S1-MME are rejected by routing. UDP/2152 on S11 is not decoded as S1-U or N3. This preserves plane separation and avoids silently relabelling LTE as 5G.

## LTE session preparation

`session-engine::discover_lte_sessions` produces a deterministic preparation view containing:

- opaque UE pseudonym and S1AP eNB/MME context IDs;
- EPS bearer IDs and S11 bearer F-TEIDs;
- S1-U tunnels grouped by TEID;
- UL, DL, unknown-direction packet counts and captured-byte totals;
- procedures, interfaces, event provenance and lifecycle state;
- explicit limitations indicating synthetic-only evidence.

It never joins identities from timestamp proximity. Without S1AP evidence it returns no LTE session. Current preparation emits one view per supplied LTE evidence scope; multi-UE production partitioning remains an API integration task after certified evidence becomes available.

## LTE correlation preparation

`correlate_lte_evidence` adds two fail-closed rules:

| Rule | Evidence | Confidence | Ambiguity behavior |
|---|---|---|---|
| `gtpv2c-s1u-unique-teid` | Unique S11 bearer F-TEID equals S1-U TEID in the same capture scope and endpoint pair | EXACT tunnel-only | Reused S11 TEID produces no edge |
| `s1ap-gtpv2c-explicit-bearer-teid` | Explicit E-RAB TEID equals a unique S11 bearer F-TEID | STRONG bearer association | Requires future certified nested E-RAB extraction |

Multiple packets on one unique S1-U tunnel are accepted. TEID equality is never presented as subscriber identity proof. Rule version is `0.1.0-pre-certification`.

## Analyzer preparation

The UI now exposes, with explicit `Prepared (synthetic only)` wording:

- LTE technology in Session Explorer and the global selector;
- S1-MME, S11 and S1-U interface filters;
- S1AP, NAS-EPS-MM, NAS-EPS-SM and GTPv2-C protocol filters;
- LTE interface choices in Correlation Studio.

The generic message, pagination, provenance and Call Flow components can render normalized LTE event labels. The backend does not yet publish LTE sessions or LTE-specific correlation status through the production API, so these controls are preparation, not an operational claim.

## Fixtures and privacy

### Executable synthetic fixture

`OIRAN/tests/fixtures/lte-pipeline-synthetic-v1.json`

- SHA-256: `63f9a3d5186afebadfceeaeb9296a98b01069cec689faa068f4244cacc09e1dd`
- 4 decoded cases: S1AP S1 Setup, S11 Create Session Response, S1-U UL and DL;
- 2 S1-U packets, 1 UL, 1 DL, 2 distinct TEIDs;
- documentation addresses and no clear subscriber identity.

### Real anonymized fixture template

`OIRAN/tests/fixtures/lte-real-anonymized-manifest-template.json`

- SHA-256: `6bee76dea7820cf214177c430930d91841efae9258ee8940af9fe6afaf9446cd`
- requires three independently checksummed files: S1-MME, S11 and S1-U;
- requires anonymization method, reviewer, expected counts and ANR1 reference;
- contains no real path, capture, identity, checksum or result;
- marked `ANR1_APPROVAL_REQUIRED` and must not be populated or ingested before approval.

## Manual tests and actual results

Rust builds used `CARGO_TARGET_DIR=/dev/shm/anr3-lte-pipeline-target` and `CARGO_BUILD_JOBS=2`.

| Command | Result |
|---|---|
| `cargo test --offline -p decoder-s1ap -p decoder-gtpv2c -p decoder-gtpu -p oiran-decode -p session-engine -p correlation-engine` | PASS: 58 passed, 0 failed |
| `cargo test ...` first compilation | FAIL: new GTP-U test used obsolete `ExactTimestamp.resolution`; corrected to base/exponent and rerun PASS |
| `node 22.23.4 node_modules/typescript/bin/tsc -b --pretty false` | PASS, no diagnostics |
| `node 22.23.4 node_modules/vitest/vitest.mjs run` | PASS: 9 files, 71 tests |
| `node 22.23.4 node_modules/vite/bin/vite.js build` | PASS: 1,636 modules; JS 358.59 kB, gzip 106.16 kB |
| `node 22.23.4 scripts/check-dist-leaks.mjs` | PASS: 3 files scanned, no fixture marker leak |
| `jq empty` on both LTE JSON fixtures | PASS |
| Numeric clear-identity scan over LTE fixtures/tests | PASS: no match |
| `git diff --check` | PASS |
| `cargo fmt --all -- --check` | FAIL: repository-wide pre-existing formatting differences outside this change; no bulk rewrite performed |

Frontend environment attempts are also recorded: the first scripts did not run because the isolated worktree lacked `node_modules`; a cross-worktree Node 18 attempt failed dependency resolution/version requirements. `npm ci --offline --ignore-scripts` then restored the locked dependencies locally, and the final checks used an existing Node 22.23.4 binary. No network install was required.

## Safety observations

- OIRAN API disk metric after tests: 71.7%, below the 85% ceiling.
- Filesystem: 72%, approximately 110 GiB available.
- Active OIRAN captures: 0.
- External `dumpcap` processes before and after: 12.
- No live capture, UE, scenario, replay into production, generated network traffic, service restart, deployment, Open5GS change or POLARIS change.

## SemVer and changelog

| Artifact | New version |
|---|---:|
| `oiran-decode` | 0.5.0 |
| `decoder-gtpu` | 0.2.0 |
| `session-engine` | 0.4.0 |
| `correlation-engine` | 0.4.0 |
| Analyzer web | 2.6.0-pre.1 |
| LTE preparation/rules | 0.1.0 / 0.1.0-pre-certification |

Changes are documented in `OIRAN/CHANGELOG.md` and `OIRAN/apps/web/CHANGELOG.md`.

## Remaining blockers and next work

1. ANR1 must approve the anonymization method and fixture provenance.
2. A real, sanitized S1-MME/S11/S1-U fixture must populate the prepared manifest.
3. Nested S1AP E-RAB transport address/TEID extraction needs certified real evidence.
4. Multi-UE LTE partitioning and lifecycle validation must be proven on that fixture.
5. The API/live-probe dataset registry, session DTOs, rule registry and capture allowlist must be integrated only after offline fixture certification.
6. Live validation, capture enablement and deployment require separate explicit authorization.

— ANR3
