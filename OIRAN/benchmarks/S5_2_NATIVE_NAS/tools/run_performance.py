#!/usr/bin/env python3
"""One warm-up plus five bounded full-corpus S5.2 measurements."""
from __future__ import annotations
import hashlib, json, pathlib, statistics, subprocess, tempfile

WORKSPACE = pathlib.Path(__file__).resolve().parents[3]
CORPUS = WORKSPACE / "benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus"
OUTPUT = WORKSPACE / "benchmarks/S5_2_NATIVE_NAS/results/performance.json"
OIRAN = WORKSPACE / "target/release/oiran-decode"

def one(index: int, warmup: bool) -> dict:
    elapsed, peak, nas = 0.0, 0, 0
    with tempfile.TemporaryDirectory(prefix="oiran-s5-2-") as temp:
        for number, capture in enumerate(sorted([*CORPUS.rglob("*.pcap"), *CORPUS.rglob("*.pcapng")])):
            digest = hashlib.sha256(capture.read_bytes()).hexdigest()
            interface = capture.stem if capture.stem in {"N2", "N3", "N4"} else "N2"
            output = pathlib.Path(temp) / f"{number}.jsonl"
            command = ["/usr/bin/time", "-f", "__METRIC__%e|%M", str(OIRAN), "--input", str(capture),
                       "--capture-id", f"sha256:{digest}", "--interface", interface, "--output", str(output)]
            run = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, text=True)
            for line in run.stderr.splitlines():
                if line.startswith("__METRIC__"):
                    seconds, rss = line.removeprefix("__METRIC__").split("|")
                    elapsed += float(seconds); peak = max(peak, int(rss))
            nas += sum(json.loads(line).get("protocol") in {"NAS-5GMM", "NAS-5GSM"} for line in output.read_text().splitlines())
    return {"iteration": index, "warmup": warmup, "seconds": elapsed, "peak_rss_kib": peak, "nas_events": nas}

def main() -> int:
    runs = [one(0, True)] + [one(i, False) for i in range(1, 6)]
    measured = runs[1:]; median = statistics.median(r["seconds"] for r in measured)
    result = {"method": {"warmup_runs": 1, "measured_runs": 5, "files": 13, "packets": 4205},
              "median_total_seconds": median, "median_packets_per_second": 4205 / median,
              "median_nas_messages_per_second": statistics.median(r["nas_events"] / r["seconds"] for r in measured),
              "peak_rss_kib": max(r["peak_rss_kib"] for r in measured), "runs": runs}
    OUTPUT.parent.mkdir(parents=True, exist_ok=True); OUTPUT.write_text(json.dumps(result, indent=2) + "\n")
    return 0

if __name__ == "__main__": raise SystemExit(main())
