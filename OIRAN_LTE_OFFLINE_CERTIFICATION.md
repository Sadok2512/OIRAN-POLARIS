# OIRAN LTE offline certification V1

Agent: ANR3
Date: 2026-10-31 UTC
Base: `feat/anr3-oiran-lte-pipeline-preparation` / `c42973e4e48223be8a807299e59ecf8fca4b7331`
Certification mode: synthetic fixtures only; no live capture, traffic or production mutation.

## Verdict: OFFLINE_PASS

The synthetic offline contract passes for manifest validation, S1AP procedure extraction, E-RAB procedure classification, GTPv2-C/GTP-U/TEID extraction, two-UE partitioning, ambiguity-safe correlations, UL/DL counters, timestamp ordering, LTE Call Flow construction, privacy controls and Analyzer regressions.

This verdict is **not real LTE certification**. Nested E-RAB tunnel extraction from a real APER capture and the full live-probe/API publication path remain unvalidated until ANR1 provides approved anonymized S1-MME/S11/S1-U PCAPs.

## Mandatory fixture manifest

Machine-readable contract: `OIRAN/tests/fixtures/lte-fixture-manifest.schema.json`
Runtime validator: `oiran_decode::lte_fixture::validate_lte_fixture_manifest`

The validator separates:

- `structural_errors`: invalid or incomplete contract, unsafe identity flag, missing plane/procedure, duplicate plane, reversed timestamps;
- `readiness_blockers`: placeholders, missing checksums/counts/timestamps/expected values, or missing ANR1 approval for a real fixture.

### Global required fields

`schema_version`, `certification_state`, `fixture_id`, `technology=LTE`, `capture_mode`, `real_capture`, `anonymization`, `files`, `required_procedures`, `expected`, `approval`.

Anonymization requires a documented method/reviewer/address mapping, `clear_subscriber_identities_present=false`, and explicit rejection of IMSI, IMEI, IMEISV, MSISDN and GUTI.

### Required files

| Interface | Protocol signature | Required metadata |
|---|---|---|
| S1-MME | S1AP / SCTP PPID 18 | relative path, SHA-256, packets, bytes, first/last UTC timestamp |
| S11 | GTPv2-C / UDP 2123 | relative path, SHA-256, packets, bytes, first/last UTC timestamp |
| S1-U | GTP-U / UDP 2152 | relative path, SHA-256, packets, bytes, first/last UTC timestamp |

All three entries must be unique. The required procedure set is S1 Setup, Attach, Initial Context Setup, E-RAB Setup, Create Session, S1-U UL/DL G-PDU and Detach.

For real evidence, `approval.anr1_reference` and `approval.approved_at_utc` are mandatory. The template is structurally valid but deliberately reports readiness blockers.

## Synthetic fixtures

| Fixture | Purpose | SHA-256 |
|---|---|---|
| `lte-pipeline-synthetic-v1.json` | Raw synthetic S1AP, E-RAB procedure, GTPv2-C and S1-U decoder inputs | `e5887ffc6063db7c6f83b44146e6c86cd9d9adf99c2b91ac9c93c5eb4ad4b440` |
| `lte-offline-certification-synthetic-manifest.json` | Executable two-UE expected statistics | `6a7cb15ac747cbeee27f009921b16d7de3e6fdf1796029fa13b0449b005f6245` |
| `lte-real-anonymized-manifest-template.json` | ANR1-gated real evidence template | `13ddfb096710a4f6cb1b852f203a23fdebd7e73a84fe3089b22da8bc14aeb915` |
| `lte-fixture-manifest.schema.json` | Mandatory field contract | `85831363a23290419f1a7f8055c6a31b89aaef80318c959b21bcae354ae5231c` |

No fixture contains a real subscriber identity, authentication material, production address or external capture path.

## Extraction coverage

| Area | Synthetic result | Limitation |
|---|---:|---|
| S1AP envelope and S1 Setup | PASS | Real capture not tested |
| Initial Context / E-RAB procedure classification | PASS | Nested real APER E-RAB transport address/TEID not certified |
| EPS NAS identity protection | PASS | Only synthetic identity-shaped input |
| GTPv2-C Create Session, EBI, F-TEID | PASS | Real S11 variants not tested |
| GTP-U G-PDU and TEID | PASS | Application payload remains opaque |
| eNB↔SGW UL/DL direction | PASS | Depends on explicit endpoint roles |

The E-RAB-to-S11 correlation test uses the prepared normalized identifier `erab_teid`. It certifies the downstream contract and fail-closed correlation behavior, not real APER nested extraction.

## Multi-UE partitioning

The preparation defect that aggregated an entire LTE scope into one session was corrected. Partitioning now requires:

1. an explicit S1AP context key (`capture_id`, eNB UE S1AP ID, MME UE S1AP ID);
2. NAS events carrying the same parent S1AP identifiers;
3. S11 events sharing the exact opaque subscriber pseudonym;
4. S1-U events sharing an exact S11 bearer F-TEID.

No timestamp-only association is permitted. The two-UE fixture produces two sessions, two EPS bearers and two distinct tunnels without cross-association.

## Counters, timestamps and Call Flow

Synthetic expected statistics are asserted directly from the manifest:

| Metric | Expected / observed |
|---|---:|
| LTE UE sessions | 2 |
| EPS bearers | 2 |
| distinct S1-U TEIDs | 2 |
| S1-U uplink packets | 1 |
| S1-U downlink packets | 1 |
| LTE correlation edges | 4: two S1AP↔S11 and two S11↔S1-U |

Per-tunnel byte totals are derived from packet provenance. Session start/end/duration use normalized nanosecond timestamps. `build_lte_callflow` sorts events deterministically and emits LTE participants, procedures, interfaces, decoder versions, provenance, correlation status and accounting. An out-of-order input test confirms the Call Flow order and timestamp bounds.

## Correlation safety

- S11↔S1-U requires a unique S11 F-TEID, same capture scope and one endpoint pair.
- Multiple packets on the same tunnel are allowed.
- Reused/ambiguous S11 TEID produces no edge.
- S1AP↔S11 requires explicit E-RAB TEID evidence.
- TEID equality is tunnel evidence, never subscriber identity proof.
- Offline rule SemVer: `1.0.0-offline.1`.

## Analyzer validation

The Analyzer contract test verifies that:

- LTE remains labelled `Prepared (synthetic only)`;
- S1-MME, S11 and S1-U filters remain available;
- S1AP, NAS-EPS-MM, NAS-EPS-SM and GTPv2-C are present;
- NGAP, NAS-5GMM, NAS-5GSM, PFCP and GTP-U remain present.

Typecheck, all Vitest tests, production build and distribution leak scan pass with Node 22.23.4.

## Required live-probe integration contract

No live-probe change is included in this offline certification. A future authorized integration must provide:

1. explicit `S1-MME`, `S11`, `S1-U` interface IDs and device mappings;
2. strict PPID/port filters: 18/36412, UDP/2123 and UDP/2152;
3. bounded rotation, disk gate below 85%, immutable source checksum and first/last timestamp;
4. capture ownership that never adopts or stops external `dumpcap` processes;
5. independent per-plane segments tied to one fixture/capture group;
6. endpoint-role mapping for eNB, MME and SGW-C/U;
7. decoder invocation with the declared interface, never port-only inference;
8. packet/drop/decode-error counters and segment completion state;
9. fail-closed handling for missing S1-MME/S11/S1-U planes;
10. no start/stop enablement until separate authorization.

## Required OIRAN API integration contract

No production API change is included. A future offline-first API integration must expose:

- decoder versions for S1AP, EPS NAS, GTPv2-C and GTP-U;
- LTE dataset technology and manifest readiness/errors;
- LTE session identifiers, EPS bearer IDs, S1-U TEIDs and UL/DL packet/octet counters;
- LTE session pagination/filtering by technology and interface;
- LTE Call Flow participants/procedures and `S1_MME_S11`, `S11_S1_U`, `E2E` statuses;
- correlation rule/version/limitations and packet provenance;
- null/unknown values instead of fabricated zeroes;
- synthetic vs real/ANR1-certified evidence classification;
- exports that retain anonymization and omit raw identity-bearing bytes.

## Manual commands and results

Rust target: `/dev/shm/anr3-lte-offline-target`, jobs: 2.

| Command | Result |
|---|---|
| `cargo test --offline -p decoder-s1ap -p decoder-gtpv2c -p decoder-gtpu -p oiran-decode -p session-engine -p correlation-engine -p callflow-schema` | PASS: 66 tests, 0 failed |
| First full Rust run | FAIL: mono-UE fixture omitted parent S1AP IDs; engine correctly refused temporal association |
| Second full Rust run | FAIL: downlink fixture used raw timestamp `5` instead of absolute nanoseconds |
| Corrected Rust reruns | PASS |
| `tsc -b --pretty false` with Node 22.23.4 | PASS after replacing untyped `node:fs` test access with typed Vite raw imports |
| `vitest run` | PASS: 10 files, 73 tests |
| `vite build` | PASS: 1,636 modules; JS 358.59 kB, gzip 106.16 kB |
| `check-dist-leaks.mjs` | PASS: 3 files, no fixture marker leak |
| `jq empty` on all LTE manifests/schema | PASS |
| clear numeric subscriber-identity scan | PASS: no matches |
| `git diff --check` | PASS after removing one trailing blank line |

`npm ci --offline --ignore-scripts` restored locked dependencies locally. Its Node 18 engine warnings are environmental; all authoritative frontend commands ran with Node 22.23.4.

## SemVer

| Component | Version |
|---|---:|
| `oiran-decode` | 0.6.0 |
| `session-engine` | 0.5.0 |
| `correlation-engine` | 0.5.0 |
| `callflow-schema` | 1.2.0 |
| LTE offline rules/certification | 1.0.0-offline.1 |
| Analyzer | 2.6.0-pre.1+lte.offline.1 |

Changes are recorded in both OIRAN and Analyzer changelogs.

## Real-certification blockers

1. No ANR1-approved PCAP set exists.
2. Real nested E-RAB transport/TEID extraction is not proven.
3. Real multi-UE identity/pseudonym continuity is not proven.
4. Live-probe and OIRAN API contracts above are documented but not activated.
5. No live validation or deployment is authorized by this work.

— ANR3
