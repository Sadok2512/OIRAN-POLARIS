#!/usr/bin/env python3
"""Run the three analyzers read-only over each immutable corpus file."""
from __future__ import annotations
import hashlib, json, os, pathlib, subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"
RAW = ROOT / "raw"
OIRAN = pathlib.Path("/root/OIRAN_VPROBE/target/release/oiran-decode")
TELCO = pathlib.Path("/tmp/telcoladder-bench-venv/bin/telcoladder")
TSHARK = ROOT / "tools/tshark"

def dataset_id(path: pathlib.Path) -> str:
    return "__".join(path.relative_to(CORPUS).with_suffix("").parts)

def run(command: list[str], stdout: pathlib.Path, stderr: pathlib.Path, env=None) -> int:
    with stdout.open("wb") as out, stderr.open("wb") as err:
        return subprocess.run(command, stdout=out, stderr=err, env=env, check=False).returncode

def main() -> int:
    RAW.mkdir(exist_ok=True)
    records = []
    env = os.environ.copy()
    env["TELCOLADDER_TSHARK"] = str(TSHARK)
    files = sorted([*CORPUS.rglob("*.pcap"), *CORPUS.rglob("*.pcapng")])
    for capture in files:
        ident = dataset_id(capture)
        digest = hashlib.sha256(capture.read_bytes()).hexdigest()
        interface = capture.stem if capture.stem in {"N2", "N3", "N4"} else "N2"
        oiran_events = RAW / f"{ident}.oiran.jsonl"
        oiran_rc = run([
            str(OIRAN), "--input", str(capture), "--capture-id", f"sha256:{digest}",
            "--interface", interface, "--output", str(oiran_events),
        ], RAW / f"{ident}.oiran.stdout", RAW / f"{ident}.oiran.stderr")
        tshark_rc = run([
            str(TSHARK), "-r", str(capture), "-Y", "ngap || nas-5gs || pfcp || gtp || http2",
            "-T", "fields", "-E", "header=y", "-E", "separator=,", "-E", "quote=d",
            "-E", "occurrence=a", "-e", "frame.number", "-e", "frame.time_epoch",
            "-e", "_ws.col.Protocol", "-e", "_ws.col.Info", "-e", "ngap.procedureCode",
            "-e", "ngap.AMF_UE_NGAP_ID", "-e", "ngap.RAN_UE_NGAP_ID",
            "-e", "nas-5gs.mm.message_type", "-e", "nas-5gs.sm.message_type",
            "-e", "pfcp.seid", "-e", "gtp.teid",
        ], RAW / f"{ident}.tshark.csv", RAW / f"{ident}.tshark.stderr")
        telco_rc = run([
            str(TELCO), "summarize", str(capture), "--json",
        ], RAW / f"{ident}.telco.json", RAW / f"{ident}.telco.stderr", env)
        telco_flow_rc = run([
            str(TELCO), "analyze", str(capture), "--flow", "--max-messages", "10000",
            "--xdr", str(RAW / f"{ident}.telco.xdr.json"),
            "-o", str(RAW / f"{ident}.telco.mmd"),
        ], RAW / f"{ident}.telco-flow.stdout", RAW / f"{ident}.telco-flow.stderr", env)
        records.append({
            "dataset_id": ident, "path": str(capture.relative_to(ROOT)), "sha256": digest,
            "bytes": capture.stat().st_size, "interface_hint": interface,
            "oiran_rc": oiran_rc, "tshark_rc": tshark_rc,
            "telcoladder_rc": telco_rc, "telcoladder_flow_rc": telco_flow_rc,
        })
    (RAW / "execution_manifest.json").write_text(json.dumps(records, indent=2) + "\n")
    return 0 if all(r["tshark_rc"] == r["telcoladder_rc"] == r["telcoladder_flow_rc"] == 0 for r in records) else 1

if __name__ == "__main__":
    raise SystemExit(main())
