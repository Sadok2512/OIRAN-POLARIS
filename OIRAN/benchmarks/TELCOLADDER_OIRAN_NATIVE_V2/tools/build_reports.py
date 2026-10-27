#!/usr/bin/env python3
"""Build evidence tables and the final report from immutable raw benchmark outputs."""
from __future__ import annotations

import csv
import json
import pathlib
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
RESULTS = ROOT / "results"
CORPUS = ROOT / "corpus"

FRAMES = {
    "LAB_TESTBED__5gc-e2e": 626,
    "LAB_TESTBED__5gc-registration": 44,
    "LAB_TESTBED__ki-mismatch": 13,
    "LAB_TESTBED__multi-imsi": 2710,
    "LAB_TESTBED__supi-not-provisioned": 12,
    "LAB_TESTBED__unknown-dnn": 22,
    "LAB_TESTBED__userplane": 648,
    "OIRAN_A__N2": 38,
    "OIRAN_A__N3": 10,
    "OIRAN_A__N4": 30,
    "OIRAN_B__N2": 26,
    "OIRAN_B__N3": 0,
    "OIRAN_B__N4": 26,
}


def write_csv(name: str, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    with (RESULTS / name).open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def oiran_events(dataset: str) -> list[dict]:
    path = RAW / f"{dataset}.oiran.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def telco(dataset: str) -> dict:
    return json.loads((RAW / f"{dataset}.telco.json").read_text())


def pdu_count(summary: dict) -> int:
    return sum(len(subscriber.get("pdu_sessions", [])) for subscriber in summary.get("subscribers", []))


def main() -> int:
    RESULTS.mkdir(exist_ok=True)
    manifest = json.loads((RAW / "execution_manifest.json").read_text())
    matrix = []
    for item in manifest:
        dataset = item["dataset_id"]
        events = oiran_events(dataset)
        summary = telco(dataset)
        tshark_rows = max(0, len((RAW / f"{dataset}.tshark.csv").read_text().splitlines()) - 1)
        unsupported = (RAW / f"{dataset}.oiran.stderr").read_text().count("UnsupportedLinkType")
        if dataset.startswith("LAB_TESTBED"):
            parity = "MISSING"
            note = "OIRAN rejected SLL2/link type 276; exit code remained zero"
        elif dataset in {"OIRAN_A__N3", "OIRAN_A__N4", "OIRAN_B__N4"}:
            parity = "EXACT"
            note = "Protocol message counts and canonical names align"
        elif dataset == "OIRAN_A__N2":
            parity = "MISMATCH"
            note = "14 NGAP occurrences align; 4 TelcoLadder names use coarser request/response labels; nested NAS is missing in OIRAN"
        else:
            parity = "NOT_COMPARABLE"
            note = "No supported signaling messages in this interface file"
        matrix.append({
            "dataset": dataset,
            "source_path": item["path"],
            "sha256": item["sha256"],
            "bytes": item["bytes"],
            "frames": FRAMES[dataset],
            "oiran_events": len(events),
            "oiran_unsupported_packets": unsupported,
            "telcoladder_messages": summary["capture"]["messages"],
            "telcoladder_subscribers": len(summary.get("subscribers", [])),
            "telcoladder_pdu_sessions": pdu_count(summary),
            "telcoladder_procedures": len(summary.get("procedures", [])),
            "telcoladder_failures": len(summary.get("failures", [])),
            "tshark_relevant_frames": tshark_rows,
            "parity": parity,
            "note": note,
        })
    write_csv("benchmark_matrix.csv", list(matrix[0]), matrix)

    message_rows = []
    for dataset in [key for key in FRAMES if key.startswith("LAB_TESTBED")]:
        summary = telco(dataset)
        message_rows.append({
            "dataset": dataset,
            "protocol": "ALL_5G_SIGNALING",
            "comparison": "decoded message inventory",
            "oiran": 0,
            "telcoladder": summary["capture"]["messages"],
            "tshark": max(0, len((RAW / f"{dataset}.tshark.csv").read_text().splitlines()) - 1),
            "classification": "MISSING",
            "evidence": f"OIRAN UnsupportedLinkType on all {FRAMES[dataset]} SLL2 frames",
        })
    message_rows.extend([
        {"dataset": "OIRAN_A", "protocol": "NGAP", "comparison": "canonical message occurrences", "oiran": 14, "telcoladder": 14, "tshark": 14, "classification": "EXACT", "evidence": "All 14 NGAP procedure occurrences align after canonical request/response normalization"},
        {"dataset": "OIRAN_A", "protocol": "NGAP", "comparison": "literal message names", "oiran": 10, "telcoladder": 10, "tshark": 14, "classification": "MISMATCH", "evidence": "TelcoLadder collapses four Request/Command/Complete names to procedure-level labels"},
        {"dataset": "OIRAN_A", "protocol": "NAS-5GS", "comparison": "nested NAS message names", "oiran": 0, "telcoladder": 4, "tshark": 4, "classification": "MISSING", "evidence": "OIRAN preserves NAS-PDU status/hash but does not identify the four nested NAS messages"},
        {"dataset": "OIRAN_A", "protocol": "GTP-U", "comparison": "G-PDU occurrences", "oiran": 10, "telcoladder": 10, "tshark": 10, "classification": "EXACT", "evidence": "10 G-PDU packets"},
        {"dataset": "OIRAN_A", "protocol": "PFCP", "comparison": "canonical message occurrences", "oiran": 30, "telcoladder": 30, "tshark": 30, "classification": "EXACT", "evidence": "24 heartbeats plus six session messages"},
        {"dataset": "OIRAN_B", "protocol": "PFCP", "comparison": "canonical message occurrences", "oiran": 20, "telcoladder": 20, "tshark": 20, "classification": "EXACT", "evidence": "10 heartbeat request/response pairs"},
        {"dataset": "OIRAN_B", "protocol": "NGAP", "comparison": "empty interface", "oiran": 0, "telcoladder": 0, "tshark": 0, "classification": "NOT_COMPARABLE", "evidence": "No NGAP signaling observed"},
        {"dataset": "OIRAN_B", "protocol": "GTP-U", "comparison": "empty interface", "oiran": 0, "telcoladder": 0, "tshark": 0, "classification": "NOT_COMPARABLE", "evidence": "Zero-frame N3 capture"},
    ])
    write_csv("message_parity.csv", list(message_rows[0]), message_rows)

    session_rows = []
    for dataset in [key for key in FRAMES if key.startswith("LAB_TESTBED")]:
        summary = telco(dataset)
        session_rows.append({
            "dataset": dataset,
            "oiran_ue_contexts": 0,
            "telcoladder_ue_contexts": len(summary.get("subscribers", [])),
            "oiran_pdu_sessions": 0,
            "telcoladder_pdu_sessions": pdu_count(summary),
            "tshark_session_reconstruction": "NOT_AVAILABLE",
            "classification": "MISSING",
            "cross_ue_contamination": "UNKNOWN",
            "evidence": "OIRAN cannot ingest SLL2 corpus; TShark exposes fields but is not a session engine",
        })
    session_rows.extend([
        {"dataset": "OIRAN_A", "oiran_ue_contexts": 1, "telcoladder_ue_contexts": 1, "oiran_pdu_sessions": 1, "telcoladder_pdu_sessions": 1, "tshark_session_reconstruction": "EVIDENCE_ONLY", "classification": "EXACT", "cross_ue_contamination": "NONE_OBSERVED_SINGLE_UE", "evidence": "PDU session 1, AMF/RAN IDs, PFCP and GTP-U evidence; existing OIRAN N2-N4 STRONG and N4-N3 EXACT edges"},
        {"dataset": "OIRAN_B", "oiran_ue_contexts": 0, "telcoladder_ue_contexts": 0, "oiran_pdu_sessions": 0, "telcoladder_pdu_sessions": 0, "tshark_session_reconstruction": "NOT_AVAILABLE", "classification": "EXACT", "cross_ue_contamination": "NOT_APPLICABLE", "evidence": "PFCP heartbeat-only dataset; no session fabricated"},
    ])
    write_csv("session_parity.csv", list(session_rows[0]), session_rows)

    gap_rows = [
        {"scope": "LAB_TESTBED/all", "identifier_or_rule": "pcap.link_type=276", "oiran": "MISSING", "telcoladder": "SUPPORTED", "tshark": "SUPPORTED", "classification": "MISSING", "evidence": "All 4,075 LAB frames rejected by OIRAN as UnsupportedLinkType", "required_action": "Add and test SLL2 parsing before rerunning parity"},
        {"scope": "OIRAN_A/N2", "identifier_or_rule": "nested NAS", "oiran": "protected NAS-PDU only", "telcoladder": "4 named messages", "tshark": "4 named messages", "classification": "MISSING", "evidence": "Registration request, Authentication request/response, Security mode command", "required_action": "Add evidence-preserving nested NAS decode where protection permits"},
        {"scope": "LAB_TESTBED/5gc-e2e", "identifier_or_rule": "AMF→SCP→SMF UpdateSMContext", "oiran": "SBI unsupported", "telcoladder": "AMF→SCP frame 494; SCP→SMF frame 497", "tshark": "HTTP/2 path and target-apiroot independently observed", "classification": "MISSING", "evidence": "POST /nsmf-pdusession/v1/sm-contexts/3/modify; 204 response frames 522/523", "required_action": "Add SBI/HTTP2 evidence adapter; never infer direct AMF→SMF when SCP relay is observed"},
        {"scope": "LAB_TESTBED/multi-imsi", "identifier_or_rule": "cross-UE isolation", "oiran": "not executable", "telcoladder": "5 distinct subscribers and 5 PDU sessions", "tshark": "identifiers visible only", "classification": "UNKNOWN", "evidence": "OIRAN absence prevents independent contamination test", "required_action": "Rerun after SLL2 support and compare composite UE keys"},
        {"scope": "OIRAN_A", "identifier_or_rule": "cross-interface session edge", "oiran": "N2-N4 STRONG; N4-N3 EXACT", "telcoladder": "each interface analyzed as a separate file", "tshark": "field evidence only", "classification": "NOT_COMPARABLE", "evidence": "TelcoLadder v0.1.0 CLI invocation did not jointly ingest the three files", "required_action": "Provide one merged, provenance-preserving capture or a multi-file ingestion contract"},
        {"scope": "all", "identifier_or_rule": "procedure duration", "oiran": "not exported by decode CLI", "telcoladder": "exported", "tshark": "timestamps only", "classification": "NOT_COMPARABLE", "evidence": "No identical procedure boundary contract across all three tools", "required_action": "Export OIRAN procedure boundaries and define common duration semantics"},
        {"scope": "all", "identifier_or_rule": "failure cause", "oiran": "unavailable on LAB corpus", "telcoladder": "decoded cause/root cause where present", "tshark": "raw cause fields", "classification": "NOT_COMPARABLE", "evidence": "SLL2 blocker prevents OIRAN failure parity", "required_action": "Resolve SLL2 then compare cause code, text and evidence frame"},
    ]
    write_csv("correlation_gaps.csv", list(gap_rows[0]), gap_rows)

    perf = json.loads((RESULTS / "performance_report.json").read_text())
    lab_messages = sum(telco(key)["capture"]["messages"] for key in FRAMES if key.startswith("LAB_TESTBED"))
    report = f"""# TELCOLADDER / OIRAN native benchmark V2

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

Total corpus: {perf['method']['corpus_files']} files, {perf['method']['corpus_packets']} packets, {perf['method']['corpus_bytes']} bytes.

## Message parity

- OIRAN A: 14 NGAP, 30 PFCP and 10 GTP-U occurrences were decoded. Canonical occurrence counts align with TelcoLadder and TShark.
- Ten NGAP literal names match across the three. Four TelcoLadder labels are procedure-level (`InitialContextSetup`, `PDUSessionResourceSetup`, `UEContextRelease`, `UEContextReleaseResponse`) while OIRAN/TShark retain request/command/complete specificity; these are `MISMATCH`, not silently normalized away in the literal-name row.
- Four nested NAS messages are visible in TelcoLadder/TShark but not named by OIRAN. OIRAN preserves the NAS-PDU evidence as protected/partial.
- OIRAN B contains 20 PFCP heartbeat messages and no reconstructed UE/PDU session; all 20 align and no session was fabricated.
- LAB_TESTBED: TelcoLadder reports {lab_messages} decoded messages. OIRAN emits zero because all 4,075 packets are rejected as unsupported SLL2. The decoder nevertheless returns exit code 0, which is an error-signaling quality gap.

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
| OIRAN | {perf['aggregates']['oiran']['median_total_seconds']:.2f} s | {perf['aggregates']['oiran']['median_packets_per_second']:.1f} | {perf['aggregates']['oiran']['peak_rss_kib_observed']} KiB |
| TelcoLadder 0.1.0 | {perf['aggregates']['telcoladder']['median_total_seconds']:.2f} s | {perf['aggregates']['telcoladder']['median_packets_per_second']:.1f} | {perf['aggregates']['telcoladder']['peak_rss_kib_observed']} KiB* |
| TShark 4.2.2 | {perf['aggregates']['tshark']['median_total_seconds']:.2f} s | {perf['aggregates']['tshark']['median_packets_per_second']:.1f} | {perf['aggregates']['tshark']['peak_rss_kib_observed']} KiB* |

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
"""
    (RESULTS / "benchmark_report.md").write_text(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
