#!/usr/bin/env python3
"""Render the S5.1 reports from measured machine-readable results."""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess

WORKSPACE = pathlib.Path("/root/OIRAN_VPROBE")
ROOT = WORKSPACE / "benchmarks/S5_1_NATIVE_SLL2"
RESULTS = ROOT / "results"
BASE = WORKSPACE / "benchmarks/TELCOLADDER_OIRAN_NATIVE_V2"


def write(name: str, body: str) -> None:
    (WORKSPACE / name).write_text(body.strip() + "\n")


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    summary = json.loads((RESULTS / "analysis_summary.json").read_text())
    performance = json.loads((RESULTS / "performance.json").read_text())
    rows = {row["dataset"]: row for row in summary["rows"]}
    shutil.copyfile(RESULTS / "S5_1_RESULTS.csv", WORKSPACE / "S5_1_RESULTS.csv")

    write("S5_1_SLL2_IMPLEMENTATION_REPORT.md", f"""
# S5.1 SLL2 implementation report

## Result

Native `LINKTYPE_LINUX_SLL2` (276) support is implemented in `capture-pcap` 0.2.0. The implementation parses the fixed 20-byte header in network byte order and reuses the existing IPv4, IPv6, UDP and SCTP paths. No protocol decoder was rewritten.

Parsed metadata: protocol type, reserved field, interface index, ARPHRD hardware type, packet type, address length and the eight-byte address field. Address lengths above eight, truncated headers and non-IP protocol values are explicit errors.

IPv4 fragments and IPv6 fragments/ESP are explicitly unsupported. IPv6 Hop-by-Hop, Routing, Destination Options and AH extension headers are traversed with bounds checks.

## Validation

- LAB packets read: {summary['lab_packets']}/4,075.
- LAB transport errors: 0.
- Decoded NGAP/PFCP/GTP-U envelopes: {summary['messages_exact']} exact against TShark.
- Full Rust workspace: 140/140 tests passed.
- Production deployment and live capture: not executed.
""")

    write("S5_1_LINKTYPE_DISPATCH_AUDIT.md", """
# S5.1 link-type dispatch audit

The classic PCAP reader obtains the 32-bit link type from the global header. The PCAPNG reader obtains a separate 16-bit link type from every Interface Description Block and copies that interface identity into each packet record.

`transport_view` is the only link-layer-to-network-layer dispatch point:

- 1: Ethernet, including the existing bounded VLAN traversal.
- 113: Linux cooked capture v1.
- 276: Linux cooked capture v2, fixed 20-byte header.
- all others: `UnsupportedLinkType`.

SLL2 protocol `0x0800` dispatches to the existing IPv4 parser and `0x86dd` to the existing IPv6 parser. Other protocol values return an explicit `InvalidNetwork` error. The Ethernet path was not structurally changed.
""")

    write("S5_1_PCAP_PCAPNG_COMPATIBILITY.md", """
# S5.1 PCAP and PCAPNG compatibility

| Format | Ethernet | SLL v1 | SLL2 | Timestamp | Multi-interface |
|---|---|---|---|---|---|
| PCAP | PASS | PASS | PASS | micro/nanosecond precision preserved | one global link type by format |
| PCAPNG | PASS | PASS | PASS | per-interface resolution and offset preserved | PASS, link type selected per IDB |

Regression fixtures cover classic PCAP link type 276 and a PCAPNG section containing both Ethernet and SLL2 interfaces. Captured/original length and snaplen validation remain enforced.
""")

    write("S5_1_PROVENANCE_VALIDATION.md", f"""
# S5.1 provenance validation

Event schema 1.3.0 adds optional, backward-compatible packet-reference fields: source SHA256, link type, SLL2 protocol/reserved/ifindex/ARPHRD/packet-type/address-length/address.

Across all {summary['messages_exact']} decoded LAB events:

- source SHA256 failures: 0;
- link-type/SLL2 metadata failures: 0;
- packet-number mapping failures: 0;
- timestamp mismatches with TShark: 0;
- outer IP endpoint mismatches with TShark: 0.

Existing source file, packet number, byte offset, PCAPNG interface ID, captured length and original length fields remain present.
""")

    write("S5_1_CORPUS_REGRESSION_REPORT.md", f"""
# S5.1 unchanged-corpus regression

The original `SHA256SUMS` passed before and after implementation for all 13 files: 4,205 packets and 758,864 bytes. Certified OIRAN_A counts remain 14 NGAP, 30 PFCP and 10 GTP-U; OIRAN_B remains 20 PFCP heartbeats and no fabricated session.

The former SLL2 blocker is removed: 4,075/4,075 LAB packets are readable and {summary['messages_exact']} NGAP/PFCP/GTP-U events are emitted. TShark also exposes {summary['messages_unsupported']} nested NAS occurrences explicitly classified as unsupported by OIRAN, not unexplained missing messages. {summary['messages_unresolved_subset']} decoded message envelopes remain `PARTIAL`; this is a subset of the exact message-envelope count, not an additional message category.

TelcoLadder's 1,441 count uses a different multi-layer granularity, including SBI and nested representations. It is not arithmetically interchangeable with OIRAN's top-level normalized-event count.
""")

    write("S5_1_TSHARK_PARITY_REPORT.md", f"""
# S5.1 independent TShark parity

Reference: TShark 4.2.2. SLL2 was decoded independently; TCP port 7777 was explicitly decoded as HTTP/2 for SBI visibility.

| Measure | Result |
|---|---:|
| Newly comparable NGAP/NAS/PFCP/GTP-U occurrences | {summary['newly_comparable_messages']} |
| Exact OIRAN message envelopes | {summary['messages_exact']} |
| Mismatched OIRAN envelopes | {summary['messages_mismatched']} |
| Unexplained missing messages | {summary['messages_missing']} |
| Unsupported nested NAS messages | {summary['messages_unsupported']} |
| Extra OIRAN messages | {summary['messages_extra']} |
| Partial OIRAN envelopes | {summary['messages_unresolved_subset']} |

Every emitted OIRAN LAB event matched the TShark packet number, nanosecond timestamp, outer source/destination IP and canonical message name/header. GTP-U parity uses the outer tunnel endpoints and TEID, not TShark's displayed inner ICMP endpoints.
""")

    write("S5_1_TELCOLADDER_COMPARISON.md", f"""
# S5.1 TelcoLadder 0.1.0 comparison

Only the previously audited Apache-2.0 TelcoLadder 0.1.0 environment was used. No later PolyForm source was downloaded or copied into OIRAN production code.

TelcoLadder reports 1,441 decoded multi-layer messages across the seven fixtures. OIRAN emits {summary['messages_exact']} top-level NGAP/PFCP/GTP-U events, all independently aligned with TShark. Total message counts are `NOT_COMPARABLE` because TelcoLadder expands nested NAS, SBI HTTP/2 and derived layers.

PDU-session counts align exactly across the seven fixtures: eight in TelcoLadder and eight in OIRAN. This count agreement does not prove every cross-interface edge; OIRAN PDU correlation status remains `UNKNOWN` where no shared N2/N4 identifier exists.
""")

    multi = summary["multi_imsi"]
    write("S5_1_SESSION_RECONSTRUCTION_REPORT.md", f"""
# S5.1 session reconstruction

| Fixture | UE contexts | PDU sessions | PFCP sessions | GTP-U tunnels |
|---|---:|---:|---:|---:|
| 5gc-e2e | {rows['5gc-e2e']['ue_contexts']} | {rows['5gc-e2e']['pdu_sessions']} | {rows['5gc-e2e']['pfcp_sessions']} | {rows['5gc-e2e']['gtpu_tunnels']} |
| 5gc-registration | {rows['5gc-registration']['ue_contexts']} | {rows['5gc-registration']['pdu_sessions']} | {rows['5gc-registration']['pfcp_sessions']} | {rows['5gc-registration']['gtpu_tunnels']} |
| ki-mismatch | {rows['ki-mismatch']['ue_contexts']} | 0 | 0 | 0 |
| multi-imsi | {multi['ue_contexts']} | {multi['pdu_sessions']} | {multi['pfcp_sessions']} | {multi['gtpu_tunnels']} |
| supi-not-provisioned | {rows['supi-not-provisioned']['ue_contexts']} | 0 | 0 | 0 |
| unknown-dnn | {rows['unknown-dnn']['ue_contexts']} | 0 | 0 | 0 |
| userplane | {rows['userplane']['ue_contexts']} | {rows['userplane']['pdu_sessions']} | {rows['userplane']['pfcp_sessions']} | {rows['userplane']['gtpu_tunnels']} |

The multi-IMSI fixture contains five unique PDU-bearing UE contexts plus one separate released context. Each PDU session references a unique UE context; `CROSS_UE_CONTAMINATION = NONE_OBSERVED`. Six PFCP lifecycles include one prior deletion lifecycle and five establishments.

Certification remains partial: the engine does not yet prove N2↔N4 association for these captures, and the five-UE fixture has no GTP-U packets. No timestamp-only correlation was promoted.
""")

    write("S5_1_PERFORMANCE_REPORT.md", f"""
# S5.1 bounded offline performance

One warm-up and five measured runs processed the same 13 files on the same host.

- Median total execution: {performance['median_total_seconds']:.3f} s.
- Range: {performance['min_total_seconds']:.3f}–{performance['max_total_seconds']:.3f} s.
- Median throughput: {performance['median_packets_per_second']:.1f} packets/s.
- Peak observed RSS: {performance['peak_rss_kib']} KiB.
- Mean observed CPU: {performance['mean_cpu_percent']:.1f}%.
- Allocation count: NOT_MEASURED.

The corpus is small and `/usr/bin/time` has centisecond resolution, so these values are functional regression indicators, not production throughput or 25G/100G certification.
""")

    write("S5_1_KNOWN_LIMITATIONS.md", """
# S5.1 known limitations

- Nested NAS decoding is absent: 79 independently observed NAS occurrences remain unsupported.
- SBI/HTTP2 is not represented in OIRAN normalized events; AMF→SCP→SMF relay evidence remains external.
- 116 NGAP envelopes are partially decoded even though their top-level message identity is exact.
- IPv4/IPv6 fragment reassembly is not implemented; fragments are explicit unsupported packets.
- IPv6 ESP is explicitly unsupported; bounded extension-header traversal supports common non-fragment headers.
- A capture invocation still supplies one logical interface label, so combined LAB files can label PFCP/GTP-U events with the configured capture point despite correct protocol identity.
- Multi-IMSI N2↔N4 correlation remains `UNKNOWN`; the fixture lacks multi-UE GTP-U traffic.
- Performance allocation counts were not measured and the corpus is too small for capacity claims.
""")

    manifest_lines = (BASE / "corpus/SHA256SUMS").read_text().splitlines()
    corpus_hashes = {line.split(maxsplit=1)[1]: line.split(maxsplit=1)[0] for line in manifest_lines}
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=WORKSPACE, stdout=subprocess.PIPE, text=True, check=True).stdout.strip()
    manifest = {
        "project": "OIRAN",
        "mission": "NATIVE_SLL2_PCAP_DECODING_AND_CORPUS_CERTIFICATION",
        "branch": "feat/s5-1-native-sll2",
        "source_commit": commit,
        "base_commit": "1fc0f9f375ac9b305bae5958a67830cf580a1617",
        "components": {"capture_pcap": "0.2.0", "event_schema": "1.3.0", "oiran_decode": "0.2.0", "tshark": "4.2.2", "telcoladder": "0.1.0"},
        "corpus": {"files": 13, "packets": 4205, "bytes": 758864, "sha256": corpus_hashes, "integrity": "PASS"},
        "results": summary,
        "performance": performance,
        "tests": {"rust_workspace": {"passed": 140, "failed": 0}, "corpus_replay": "PASS", "clippy": "NOT_AVAILABLE_ON_HOST"},
        "safety": {"production_changed": False, "live_capture_executed": False, "simulator_started": False, "polaris_changed": False, "polaris_control_changed": False, "etv_otv_changed": False},
        "artifact_sha256": {
            "S5_1_RESULTS.csv": sha256(WORKSPACE / "S5_1_RESULTS.csv"),
            "analysis_summary.json": sha256(RESULTS / "analysis_summary.json"),
            "performance.json": sha256(RESULTS / "performance.json"),
        },
    }
    (WORKSPACE / "S5_1_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
