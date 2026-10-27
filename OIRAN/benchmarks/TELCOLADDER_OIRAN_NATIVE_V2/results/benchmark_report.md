# TELCOLADDER / OIRAN native benchmark V2

## Outcome

**FINAL_STATUS: PARTIAL.** The common-corpus execution is reproducible and OIRAN A/B packet-level parity is strong, but OIRAN cannot ingest the seven LAB_TESTBED fixtures because they use Linux cooked v2 (SLL2, link type 276). Independent multi-UE, procedure-duration, failure-cause and full-session parity therefore cannot be certified.

No production function, service, certified dataset, simulator or live capture was changed or started. All generated material is confined to `benchmarks/TELCOLADDER_OIRAN_NATIVE_V2`.

## Audited versions

- OIRAN source: commit `1fc0f9f375ac9b305bae5958a67830cf580a1617`, branch `feat/v2-3-multi-session-explorer`.
- TelcoLadder: exactly `0.1.0`, installed from the PyPI sdist; SHA256 `e0b3614a74724664452d5e85011cde0e608c4de8da0fe46c331ad2828c3f61fa`.
- TelcoLadder 0.1.0 license: Apache-2.0. Later PolyForm code was neither imported nor executed.
- TShark: `4.2.2`, invoked read-only in the existing laboratory controller container through stdin.

## Common corpus

The corpus contains 13 immutable files: seven self-generated LAB_TESTBED fixtures, three certified OIRAN_A interface captures, and three OIRAN_B live/recovered interface captures. OIRAN_A/B are benchmark-local labels because no upstream A/B naming contract was found. Original bytes, frames and timestamps were preserved. `corpus/SHA256SUMS` is the authoritative manifest.

Total corpus: 13 files, 4205 packets, 758864 bytes.

## Message parity

- OIRAN A: 14 NGAP, 30 PFCP and 10 GTP-U occurrences were decoded. Canonical occurrence counts align with TelcoLadder and TShark.
- Ten NGAP literal names match across the three. Four TelcoLadder labels are procedure-level (`InitialContextSetup`, `PDUSessionResourceSetup`, `UEContextRelease`, `UEContextReleaseResponse`) while OIRAN/TShark retain request/command/complete specificity; these are `MISMATCH`, not silently normalized away in the literal-name row.
- Four nested NAS messages are visible in TelcoLadder/TShark but not named by OIRAN. OIRAN preserves the NAS-PDU evidence as protected/partial.
- OIRAN B contains 20 PFCP heartbeat messages and no reconstructed UE/PDU session; all 20 align and no session was fabricated.
- LAB_TESTBED: TelcoLadder reports 1441 decoded messages. OIRAN emits zero because all 4,075 packets are rejected as unsupported SLL2. The decoder nevertheless returns exit code 0, which is an error-signaling quality gap.

The exact message score is 70 occurrences on the comparable non-empty OIRAN A/B captures (10 literal NGAP names, 10 GTP-U packets, and 50 PFCP messages after removing the presentational `PFCP ` prefix). It does not include empty captures, the four coarser TelcoLadder NGAP labels, or the inaccessible LAB corpus.

## Session and correlation parity

One non-empty session is independently count-aligned in OIRAN_A: UE context 1, PDU Session ID 1, AMF/RAN identifiers present, N2↔N4 `STRONG`, and N4↔N3 `EXACT`. TShark provides packet/field evidence rather than session reconstruction. Thus one PDU session is treated as proven; the eight TelcoLadder PDU sessions in LAB fixtures are not counted as three-engine proofs because OIRAN cannot ingest those captures.

Cross-UE contamination is `UNKNOWN`, not PASS: the only five-UE fixture is blocked in OIRAN. TelcoLadder separates five subscribers and five PDU sessions, but that cannot substitute for an independent OIRAN result.

Call-flow ordering is `PARTIAL` on OIRAN_A and `MISSING` on LAB_TESTBED. Procedure duration and failure-cause parity are `NOT_COMPARABLE` because the OIRAN decode CLI does not export common procedure boundaries and cannot parse the LAB fixtures.

## AMF → SCP → SMF UpdateSMContext audit

TelcoLadder identifies the relay explicitly:

- frame 494: AMF (`172.22.0.10`) → SCP (`172.22.0.35`), HTTP/2 stream 151;
- frame 497: SCP (`172.22.0.35`) → SMF (`172.22.0.7`), HTTP/2 stream 5;
- identical method/path: `POST /nsmf-pdusession/v1/sm-contexts/3/modify`;
- frames 522 and 523 carry the corresponding `204` responses.

TShark independently confirms the method, path, endpoints, stream IDs and the `3gpp-sbi-target-apiroot` toward the SMF. OIRAN has no SBI decoder, so this correlation is `MISSING` in OIRAN. A direct AMF→SMF edge must not be claimed when the SCP relay is observed.

## Performance

Method: one warm-up plus three measured executions per engine, same host and same 13 capture files. Medians:

| Engine | Total time | Packets/s | Observed peak RSS |
|---|---:|---:|---:|
| OIRAN | 0.07 s | 60071.4 | 3968 KiB |
| TelcoLadder 0.1.0 | 100.35 s | 41.9 | 28672 KiB* |
| TShark 4.2.2 | 14.36 s | 292.8 | 28288 KiB* |

`*` Host wrapper/Python RSS only; containerized TShark worker memory is excluded. TelcoLadder and direct TShark wall time also include one Docker exec/stdin transfer per file. Therefore `PERFORMANCE_RATIO = NOT_COMPARABLE`; the raw contextual ratios are retained in `performance_report.json`, not presented as native engine speedups. Parsing and reconstruction sub-times are `NOT_MEASURED` where the tool does not expose them.

Targeted Rust regression validation passed: 15/15 tests across `oiran-decode` and `session-engine`.

## Reproducibility

```bash
cd /root/OIRAN_VPROBE
benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/tools/extract_common_corpus.py
benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/tools/run_performance.py
benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/tools/build_reports.py
```

## Priority next action

Implement PCAP/PCAPNG SLL2 (link type 276) decoding in OIRAN with regression fixtures, then rerun this unchanged SHA256 corpus. That is the shortest path to an independent five-UE contamination check, procedure/failure parity, and a defensible native performance comparison.

## Safety declaration

- `PRODUCTION_CHANGED = FALSE`
- `LIVE_CAPTURE_EXECUTED = FALSE`
- `SIMULATOR_STARTED = FALSE`
- `POLARIS_CHANGED = FALSE`
- `ETV_OTV_CHANGED = FALSE`
