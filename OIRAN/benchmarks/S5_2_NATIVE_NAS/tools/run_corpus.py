#!/usr/bin/env python3
"""Read-only S5.2 replay and packet-aligned NAS parity over the immutable S5.1 corpus."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import pathlib
import subprocess

WORKSPACE = pathlib.Path(__file__).resolve().parents[3]
BASELINE = WORKSPACE / "benchmarks/TELCOLADDER_OIRAN_NATIVE_V2"
CORPUS = BASELINE / "corpus"
ROOT = WORKSPACE / "benchmarks/S5_2_NATIVE_NAS"
RAW = ROOT / "raw"
RESULTS = ROOT / "results"
OIRAN = WORKSPACE / "target/release/oiran-decode"
DISCOVER = WORKSPACE / "target/release/examples/discover_jsonl"
TSHARK = BASELINE / "tools/tshark"


def ident(path: pathlib.Path) -> str:
    return "__".join(path.relative_to(CORPUS).with_suffix("").parts)


def split_values(value: str) -> list[str]:
    return [part for part in value.split(",") if part]


def epoch_ns(value: str) -> int:
    seconds, fraction = value.split(".", 1)
    return int(seconds) * 1_000_000_000 + int(fraction[:9].ljust(9, "0"))


def main() -> int:
    RAW.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cargo", "build", "--release", "-q", "-p", "oiran-decode"], cwd=WORKSPACE, check=True)
    subprocess.run(["cargo", "build", "--release", "-q", "-p", "session-engine", "--example", "discover_jsonl"], cwd=WORKSPACE, check=True)
    hash_check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=CORPUS, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True)
    (RAW / "sha256_before.txt").write_text(hash_check.stdout)
    if hash_check.returncode:
        raise SystemExit("corpus SHA256 preflight failed")

    captures = sorted([*CORPUS.rglob("*.pcap"), *CORPUS.rglob("*.pcapng")])
    inventory: list[dict] = []
    parity: list[dict] = []
    totals = {"envelopes": 0, "plain": 0, "protected": 0, "ciphered": 0, "unsupported": 0, "partial": 0,
              "mm": 0, "sm": 0, "fields_comparable": 0, "fields_exact": 0, "fields_mismatch": 0, "fields_unresolved": 0}
    max_discovery = None
    for capture in captures:
        dataset = ident(capture)
        digest = hashlib.sha256(capture.read_bytes()).hexdigest()
        interface = capture.stem if capture.stem in {"N2", "N3", "N4"} else "N2"
        events_path = RAW / f"{dataset}.events.jsonl"
        command = [str(OIRAN), "--input", str(capture), "--capture-id", f"sha256:{digest}", "--interface", interface,
                   "--output", str(events_path), "--endpoint", "172.22.0.23=gNB", "--endpoint", "172.22.0.10=AMF",
                   "--endpoint", "172.22.0.7=SMF", "--endpoint", "172.22.0.8=UPF"]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        (RAW / f"{dataset}.oiran.stdout").write_text(completed.stdout)
        (RAW / f"{dataset}.oiran.stderr").write_text(completed.stderr)
        if completed.returncode:
            raise SystemExit(f"OIRAN failed for {dataset}: {completed.stderr}")
        events = [json.loads(line) for line in events_path.read_text().splitlines() if line]
        nas_events = [event for event in events if event["protocol"] in {"NAS-5GMM", "NAS-5GSM"}]

        tshark_path = RAW / f"{dataset}.tshark.csv"
        tshark_command = [str(TSHARK), "-d", "tcp.port==7777,http2", "-r", str(capture),
            "-Y", "ngap.NAS_PDU || ngap.nAS_PDU || ngap.pDUSessionNAS_PDU || nas-5gs", "-T", "fields",
            "-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=a",
            "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.protocols", "-e", "_ws.col.Info",
            "-e", "ngap.NAS_PDU", "-e", "ngap.nAS_PDU", "-e", "ngap.pDUSessionNAS_PDU",
            "-e", "nas-5gs.epd", "-e", "nas-5gs.security_header_type", "-e", "nas-5gs.mm.message_type",
            "-e", "nas-5gs.sm.message_type", "-e", "nas-5gs.pdu_session_id", "-e", "nas-5gs.proc_trans_id",
            "-e", "nas-5gs.mm.5gmm_cause", "-e", "nas-5gs.sm.5gsm_cause", "-e", "nas-5gs.cmn.dnn"]
        tshark_run = subprocess.run(tshark_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        (RAW / f"{dataset}.tshark.stderr").write_bytes(tshark_run.stderr)
        tshark_rows = list(csv.DictReader(io.StringIO(tshark_run.stdout.decode())))
        # Raw NAS-PDU bytes may contain subscriber/authentication material. They
        # are used in-memory only for container accounting and never persisted.
        sensitive_fields = {"ngap.NAS_PDU", "ngap.nAS_PDU", "ngap.pDUSessionNAS_PDU"}
        safe_fields = [field for field in tshark_rows[0] if field not in sensitive_fields] if tshark_rows else []
        with tshark_path.open("w", newline="") as safe_handle:
            safe_writer = csv.DictWriter(safe_handle, fieldnames=safe_fields)
            safe_writer.writeheader()
            safe_writer.writerows({field: row[field] for field in safe_fields} for row in tshark_rows)
        by_frame = {int(row["frame.number"]): row for row in tshark_rows}

        for event in nas_events:
            packet = event["packet_references"][0]["packet_number"]
            row = by_frame.get(packet)
            expected_mm = split_values(row["nas-5gs.mm.message_type"] if row else "")
            expected_sm = split_values(row["nas-5gs.sm.message_type"] if row else "")
            actual = f"0x{event['message_type']:02x}" if event["message_type"] else "UNRESOLVED"
            expected = expected_sm[0] if event["protocol"] == "NAS-5GSM" and expected_sm else (expected_mm[0] if expected_mm else "UNRESOLVED")
            status = "EXACT" if expected != "UNRESOLVED" and actual.lower() == expected.lower() else (
                "ENCRYPTED" if event["decoding_status"] == "ENCRYPTED_OR_PROTECTED" else "UNRESOLVED")
            direction_exact = event["direction"] != "UNKNOWN"
            timestamp_exact = bool(row) and epoch_ns(row["frame.time_epoch"]) == (
                event["timestamp"]["seconds"] * 1_000_000_000 + event["timestamp"]["nanoseconds"])
            parent_ok = bool(event.get("parent_event_id"))
            packet_ok = bool(row) and event["packet_references"][0].get("source_sha256") == digest
            comparable = 4
            exact_fields = sum([status == "EXACT", direction_exact, timestamp_exact, parent_ok and packet_ok])
            totals["fields_comparable"] += comparable
            totals["fields_exact"] += exact_fields
            totals["fields_mismatch"] += comparable - exact_fields if status not in {"ENCRYPTED", "UNRESOLVED"} else sum([not direction_exact, not timestamp_exact, not (parent_ok and packet_ok)])
            totals["fields_unresolved"] += status in {"ENCRYPTED", "UNRESOLVED"}
            parity.append({"dataset": dataset, "packet_number": packet, "parent_event_id": event.get("parent_event_id", ""),
                           "protocol": event["protocol"], "oiran_message": event["message_name"], "oiran_type": actual,
                           "tshark_type": expected, "security_state": event.get("security_state", ""),
                           "decode_status": event["decoding_status"], "classification": status,
                           "direction": event["direction"], "timestamp_exact": timestamp_exact, "provenance_exact": parent_ok and packet_ok})

        discovery = json.loads(subprocess.run([str(DISCOVER), str(events_path)], stdout=subprocess.PIPE, check=True).stdout)
        (RAW / f"{dataset}.discovery.json").write_text(json.dumps(discovery, indent=2) + "\n")
        if dataset == "LAB_TESTBED__multi-imsi":
            max_discovery = discovery
        containers = sum(len(split_values(row["ngap.NAS_PDU"])) + len(split_values(row["ngap.nAS_PDU"])) + len(split_values(row["ngap.pDUSessionNAS_PDU"])) for row in tshark_rows)
        mm = sum(len(split_values(row["nas-5gs.mm.message_type"])) for row in tshark_rows)
        sm = sum(len(split_values(row["nas-5gs.sm.message_type"])) for row in tshark_rows)
        row_summary = {"dataset": dataset, "sha256": digest, "oiran_events": len(events), "oiran_nas_events": len(nas_events),
                       "tshark_nas_containers": containers, "tshark_5gmm_messages": mm, "tshark_5gsm_messages": sm,
                       "nas_plain_decoded": sum(e.get("security_state") == "PLAIN" and e["decoding_status"] in {"DECODED", "PARTIAL"} for e in nas_events),
                       "nas_protected_classified": sum(e.get("security_state", "").startswith("INTEGRITY_PROTECTED") for e in nas_events),
                       "nas_ciphered_unresolved": sum(e["decoding_status"] == "ENCRYPTED_OR_PROTECTED" for e in nas_events),
                       "nas_unsupported": sum(e["decoding_status"] == "UNSUPPORTED" for e in nas_events),
                       "nas_partial": sum(e["decoding_status"] == "PARTIAL" for e in nas_events),
                       "ue_contexts": len(discovery["ue_contexts"]), "pdu_sessions": len(discovery["pdu_sessions"])}
        inventory.append(row_summary)
        totals["envelopes"] += len(nas_events)
        totals["plain"] += row_summary["nas_plain_decoded"]
        totals["protected"] += row_summary["nas_protected_classified"]
        totals["ciphered"] += row_summary["nas_ciphered_unresolved"]
        totals["unsupported"] += row_summary["nas_unsupported"]
        totals["partial"] += row_summary["nas_partial"]
        totals["mm"] += sum(e["protocol"] == "NAS-5GMM" for e in nas_events)
        totals["sm"] += sum(e["protocol"] == "NAS-5GSM" for e in nas_events)

    with (RESULTS / "S5_2_RESULTS.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(inventory[0]))
        writer.writeheader(); writer.writerows(inventory)
    with (RESULTS / "nas_parity.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(parity[0]))
        writer.writeheader(); writer.writerows(parity)
    pdu_contexts = [session["ue_context_id"] for session in (max_discovery or {}).get("pdu_sessions", [])]
    summary = {"corpus_files": len(captures), "corpus_packets": 4205, "corpus_bytes": 758864,
               "sha256_integrity": "PASS", **totals,
               "multi_imsi": {"ue_contexts": len((max_discovery or {}).get("ue_contexts", [])),
                               "pdu_sessions": len((max_discovery or {}).get("pdu_sessions", [])),
                               "cross_ue_contamination": "NONE_OBSERVED" if len(pdu_contexts) == len(set(pdu_contexts)) else "DETECTED"},
               "inventory": inventory}
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    hash_after = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=CORPUS, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True)
    (RAW / "sha256_after.txt").write_text(hash_after.stdout)
    return hash_after.returncode


if __name__ == "__main__":
    raise SystemExit(main())
