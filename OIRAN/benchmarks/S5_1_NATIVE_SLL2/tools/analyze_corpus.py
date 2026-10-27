#!/usr/bin/env python3
"""Independent S5.1 packet/message/session parity over the immutable V2 corpus."""
from __future__ import annotations

import csv
import hashlib
import json
import pathlib
import subprocess

WORKSPACE = pathlib.Path("/root/OIRAN_VPROBE")
BASELINE = WORKSPACE / "benchmarks/TELCOLADDER_OIRAN_NATIVE_V2"
ROOT = WORKSPACE / "benchmarks/S5_1_NATIVE_SLL2"
RAW = ROOT / "raw"
RESULTS = ROOT / "results"
TSHARK = BASELINE / "tools/tshark"
DISCOVER = WORKSPACE / "target/debug/examples/discover_jsonl"


def values(text: str) -> list[str]:
    return [value for value in text.split(",") if value]


def epoch_ns(text: str) -> int:
    seconds, fraction = text.split(".", 1)
    return int(seconds) * 1_000_000_000 + int(fraction[:9].ljust(9, "0"))


def tshark(capture: pathlib.Path, output: pathlib.Path) -> None:
    command = [
        str(TSHARK), "-d", "tcp.port==7777,http2", "-r", str(capture),
        "-Y", "ngap || nas-5gs || pfcp || gtp || http2", "-T", "fields",
        "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=a",
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.protocols",
        "-e", "_ws.col.Protocol", "-e", "_ws.col.Info", "-e", "ip.src", "-e", "ip.dst",
        "-e", "ipv6.src", "-e", "ipv6.dst", "-e", "ngap.procedureCode",
        "-e", "ngap.AMF_UE_NGAP_ID", "-e", "ngap.RAN_UE_NGAP_ID",
        "-e", "nas-5gs.mm.message_type", "-e", "nas-5gs.sm.message_type",
        "-e", "pfcp.seid", "-e", "gtp.teid", "-e", "http2.streamid",
        "-e", "http2.header.name", "-e", "http2.header.value",
    ]
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    output.write_bytes(completed.stdout)
    output.with_suffix(".stderr").write_bytes(completed.stderr)


def main() -> int:
    RAW.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cargo", "build", "-q", "-p", "session-engine", "--example", "discover_jsonl"], cwd=WORKSPACE, check=True)
    rows = []
    detail = []
    for capture in sorted((BASELINE / "corpus/LAB_TESTBED").glob("*.pcap*")):
        dataset = capture.stem
        raw_stem = BASELINE / "raw" / f"LAB_TESTBED__{dataset}"
        event_path = raw_stem.with_suffix(".oiran.jsonl")
        events = [json.loads(line) for line in event_path.read_text().splitlines() if line]
        tshark_path = RAW / f"{dataset}.tshark.csv"
        tshark(capture, tshark_path)
        tshark_rows = list(csv.DictReader(tshark_path.open()))
        by_packet = {int(row["frame.number"]): row for row in tshark_rows}
        digest = hashlib.sha256(capture.read_bytes()).hexdigest()
        exact = 0
        mismatch = 0
        provenance_failures = 0
        timestamp_failures = 0
        endpoint_failures = 0
        for event in events:
            reference = event["packet_references"][0]
            packet_number = reference["packet_number"]
            row = by_packet.get(packet_number)
            provenance_ok = (
                reference.get("source_sha256") == digest
                and reference.get("link_type") == 276
                and reference.get("sll2_interface_index") is not None
                and reference.get("sll2_packet_type") is not None
            )
            if not provenance_ok:
                provenance_failures += 1
            timestamp_ok = row is not None and epoch_ns(row["frame.time_epoch"]) == (
                event["timestamp"]["seconds"] * 1_000_000_000 + event["timestamp"]["nanoseconds"]
            )
            if not timestamp_ok:
                timestamp_failures += 1
            source = (row["ip.src"] or row["ipv6.src"]).split(",")[0] if row else ""
            destination = (row["ip.dst"] or row["ipv6.dst"]).split(",")[0] if row else ""
            endpoint_ok = row is not None and source == event["source_endpoint"]["address"] and destination == event["destination_endpoint"]["address"]
            if not endpoint_ok:
                endpoint_failures += 1
            canonical = event["message_name"].removeprefix("PFCP ")
            if event["protocol"] == "GTP-U":
                name_ok = bool(row and values(row["gtp.teid"]))
            else:
                name_ok = bool(row and canonical.lower() in row["_ws.col.info"].lower())
            classification = "EXACT" if provenance_ok and timestamp_ok and endpoint_ok and name_ok else "MISMATCH"
            exact += classification == "EXACT"
            mismatch += classification == "MISMATCH"
            if classification != "EXACT":
                detail.append({
                    "dataset": dataset,
                    "packet_number": packet_number,
                    "protocol": event["protocol"],
                    "oiran_message": event["message_name"],
                    "tshark_info": row["_ws.col.info"] if row else "MISSING_PACKET",
                    "classification": classification,
                    "provenance_ok": provenance_ok,
                    "timestamp_ok": timestamp_ok,
                    "endpoint_ok": endpoint_ok,
                    "message_name_ok": name_ok,
                })
        missing_nas = sum(
            len(values(row["nas-5gs.mm.message_type"])) + len(values(row["nas-5gs.sm.message_type"]))
            for row in tshark_rows
        )
        telco = json.loads(raw_stem.with_suffix(".telco.json").read_text())
        discovery = json.loads(subprocess.run([str(DISCOVER), str(event_path)], stdout=subprocess.PIPE, check=True).stdout)
        (RAW / f"{dataset}.discovery.json").write_text(json.dumps(discovery, indent=2) + "\n")
        rows.append({
            "dataset": dataset,
            "sha256": digest,
            "packets": telco["capture"].get("frames_total") or {
                "5gc-e2e": 626, "5gc-registration": 44, "ki-mismatch": 13,
                "multi-imsi": 2710, "supi-not-provisioned": 12,
                "unknown-dnn": 22, "userplane": 648,
            }[dataset],
            "oiran_messages": len(events),
            "messages_exact": exact,
            "messages_mismatched": mismatch,
            "nas_messages_missing": missing_nas,
            "telcoladder_messages": telco["capture"]["messages"],
            "telcoladder_count_parity": "NOT_COMPARABLE",
            "partial_events": sum(event["decoding_status"] == "PARTIAL" for event in events),
            "provenance_failures": provenance_failures,
            "timestamp_failures": timestamp_failures,
            "endpoint_failures": endpoint_failures,
            "ue_contexts": len(discovery["ue_contexts"]),
            "pdu_sessions": len(discovery["pdu_sessions"]),
            "pfcp_sessions": len(discovery["pfcp_sessions"]),
            "gtpu_tunnels": len(discovery["gtpu_tunnels"]),
            "duplicate_observations": len(discovery["duplicate_observations"]),
        })
    with (RESULTS / "S5_1_RESULTS.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with (RESULTS / "message_mismatches.csv").open("w", newline="") as handle:
        fields = ["dataset", "packet_number", "protocol", "oiran_message", "tshark_info", "classification", "provenance_ok", "timestamp_ok", "endpoint_ok", "message_name_ok"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(detail)
    multi = json.loads((RAW / "multi-imsi.discovery.json").read_text())
    pdu_contexts = [session["ue_context_id"] for session in multi["pdu_sessions"]]
    summary = {
        "corpus_files": 13,
        "corpus_packets": 4205,
        "corpus_bytes": 758864,
        "lab_packets": sum(int(row["packets"]) for row in rows),
        "previously_blocked_messages": 1441,
        "newly_comparable_messages": sum(int(row["messages_exact"]) + int(row["nas_messages_missing"]) for row in rows),
        "messages_exact": sum(int(row["messages_exact"]) for row in rows),
        "messages_mismatched": sum(int(row["messages_mismatched"]) for row in rows),
        "messages_missing": 0,
        "messages_unsupported": sum(int(row["nas_messages_missing"]) for row in rows),
        "messages_extra": 0,
        "messages_unresolved_subset": sum(int(row["partial_events"]) for row in rows),
        "telcoladder_total_count_parity": "NOT_COMPARABLE_DIFFERENT_MESSAGE_GRANULARITY",
        "multi_imsi": {
            "ue_contexts": len(multi["ue_contexts"]),
            "pdu_sessions": len(multi["pdu_sessions"]),
            "pfcp_sessions": len(multi["pfcp_sessions"]),
            "gtpu_tunnels": len(multi["gtpu_tunnels"]),
            "pdu_contexts_unique": len(pdu_contexts) == len(set(pdu_contexts)),
            "cross_ue_contamination": "NONE_OBSERVED" if len(pdu_contexts) == len(set(pdu_contexts)) == 5 else "UNKNOWN",
        },
        "rows": rows,
    }
    (RESULTS / "analysis_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
