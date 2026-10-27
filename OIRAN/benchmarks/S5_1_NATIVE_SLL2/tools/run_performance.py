#!/usr/bin/env python3
"""Bounded OIRAN S5.1 performance replay: one warm-up and five measured runs."""
from __future__ import annotations

import hashlib
import json
import pathlib
import statistics
import subprocess
import tempfile

WORKSPACE = pathlib.Path("/root/OIRAN_VPROBE")
ROOT = WORKSPACE / "benchmarks/S5_1_NATIVE_SLL2"
CORPUS = WORKSPACE / "benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus"
OIRAN = WORKSPACE / "target/release/oiran-decode"


def captures() -> list[pathlib.Path]:
    return sorted([*CORPUS.rglob("*.pcap"), *CORPUS.rglob("*.pcapng")])


def run(iteration: int, warmup: bool) -> dict:
    elapsed = 0.0
    peak_rss = 0
    cpu_percent = []
    with tempfile.TemporaryDirectory(prefix="oiran-s5-1-") as temporary:
        for index, capture in enumerate(captures()):
            digest = hashlib.sha256(capture.read_bytes()).hexdigest()
            interface = capture.stem if capture.stem in {"N2", "N3", "N4"} else "N2"
            command = [
                "/usr/bin/time", "-f", "__METRIC__%e|%M|%P", str(OIRAN),
                "--input", str(capture), "--capture-id", f"sha256:{digest}",
                "--interface", interface, "--output", f"{temporary}/{index}.jsonl",
            ]
            completed = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
            for line in completed.stderr.decode(errors="replace").splitlines():
                if line.startswith("__METRIC__"):
                    seconds, rss, cpu = line.removeprefix("__METRIC__").split("|")
                    elapsed += float(seconds)
                    peak_rss = max(peak_rss, int(rss))
                    cpu_percent.append(float(cpu.removesuffix("%")))
    return {
        "iteration": iteration,
        "warmup": warmup,
        "total_seconds": elapsed,
        "peak_rss_kib": peak_rss,
        "mean_cpu_percent": statistics.mean(cpu_percent),
    }


def main() -> int:
    (ROOT / "results").mkdir(parents=True, exist_ok=True)
    runs = [run(0, True)] + [run(index, False) for index in range(1, 6)]
    measured = runs[1:]
    times = [item["total_seconds"] for item in measured]
    median = statistics.median(times)
    report = {
        "method": {"warmup_runs": 1, "measured_runs": 5, "packets": 4205, "files": 13, "memory_allocations": "NOT_MEASURED"},
        "median_total_seconds": median,
        "min_total_seconds": min(times),
        "max_total_seconds": max(times),
        "median_packets_per_second": 4205 / median,
        "peak_rss_kib": max(item["peak_rss_kib"] for item in measured),
        "mean_cpu_percent": statistics.mean(item["mean_cpu_percent"] for item in measured),
        "runs": runs,
    }
    (ROOT / "results/performance.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
