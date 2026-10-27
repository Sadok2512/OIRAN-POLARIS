#!/usr/bin/env python3
"""Bounded, repeatable performance measurements over the immutable common corpus."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import statistics
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"
RESULTS = ROOT / "results"
OIRAN = pathlib.Path("/root/OIRAN_VPROBE/target/release/oiran-decode")
TELCO = pathlib.Path("/tmp/telcoladder-bench-venv/bin/telcoladder")
TSHARK = ROOT / "tools/tshark"
TIME = pathlib.Path("/usr/bin/time")


def captures() -> list[pathlib.Path]:
    return sorted([*CORPUS.rglob("*.pcap"), *CORPUS.rglob("*.pcapng")])


def interface_for(path: pathlib.Path) -> str:
    return path.stem if path.stem in {"N2", "N3", "N4"} else "N2"


def invoke(command: list[str], env: dict[str, str], stderr_path: pathlib.Path) -> tuple[int, float, int]:
    marker = "__OIRAN_BENCH_TIME__"
    wrapped = [str(TIME), "-f", f"{marker}%e,%M", *command]
    started = time.perf_counter()
    completed = subprocess.run(wrapped, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, check=False)
    elapsed = time.perf_counter() - started
    decoded = completed.stderr.decode("utf-8", errors="replace")
    stderr_path.write_text(decoded)
    rss_kib = 0
    measured_seconds = elapsed
    for line in reversed(decoded.splitlines()):
        if line.startswith(marker):
            fields = line.removeprefix(marker).split(",")
            measured_seconds = float(fields[0])
            rss_kib = int(fields[1])
            break
    return completed.returncode, measured_seconds, rss_kib


def run_engine(engine: str, iteration: int, warmup: bool) -> dict[str, object]:
    env = os.environ.copy()
    env["TELCOLADDER_TSHARK"] = str(TSHARK)
    per_capture = []
    with tempfile.TemporaryDirectory(prefix="oiran-native-benchmark-") as temp_name:
        temp = pathlib.Path(temp_name)
        for index, capture in enumerate(captures()):
            digest = hashlib.sha256(capture.read_bytes()).hexdigest()
            if engine == "oiran":
                command = [
                    str(OIRAN), "--input", str(capture), "--capture-id", f"sha256:{digest}",
                    "--interface", interface_for(capture), "--output", str(temp / f"{index}.jsonl"),
                ]
            elif engine == "telcoladder":
                command = [str(TELCO), "summarize", str(capture), "--json"]
            elif engine == "tshark":
                command = [str(TSHARK), "-r", str(capture), "-T", "fields", "-e", "frame.number"]
            else:
                raise ValueError(engine)
            stderr_path = temp / f"{engine}-{index}.stderr"
            rc, seconds, rss_kib = invoke(command, env, stderr_path)
            per_capture.append({
                "capture": str(capture.relative_to(ROOT)),
                "return_code": rc,
                "wall_seconds": seconds,
                "peak_rss_kib": rss_kib,
            })
    total_seconds = sum(float(item["wall_seconds"]) for item in per_capture)
    return {
        "engine": engine,
        "iteration": iteration,
        "warmup": warmup,
        "total_seconds": total_seconds,
        "peak_rss_kib": max(int(item["peak_rss_kib"]) for item in per_capture),
        "all_return_codes_zero": all(item["return_code"] == 0 for item in per_capture),
        "per_capture": per_capture,
    }


def main() -> int:
    RESULTS.mkdir(exist_ok=True)
    corpus_bytes = sum(path.stat().st_size for path in captures())
    # Count physical packets independently; the wrapper streams each immutable file to TShark.
    packet_count = 0
    for capture in captures():
        output = subprocess.run(
            [str(TSHARK), "-r", str(capture), "-T", "fields", "-e", "frame.number"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
        ).stdout
        packet_count += len(output.splitlines())

    runs = []
    for engine in ("oiran", "telcoladder", "tshark"):
        runs.append(run_engine(engine, 0, True))
        for iteration in range(1, 4):
            runs.append(run_engine(engine, iteration, False))

    aggregates = {}
    for engine in ("oiran", "telcoladder", "tshark"):
        measured = [run for run in runs if run["engine"] == engine and not run["warmup"]]
        totals = [float(run["total_seconds"]) for run in measured]
        rss = [int(run["peak_rss_kib"]) for run in measured]
        median_seconds = statistics.median(totals)
        aggregates[engine] = {
            "runs": len(measured),
            "warmup_runs": 1,
            "median_total_seconds": median_seconds,
            "min_total_seconds": min(totals),
            "max_total_seconds": max(totals),
            "median_packets_per_second": packet_count / median_seconds,
            "peak_rss_kib_observed": max(rss),
            "all_return_codes_zero": all(bool(run["all_return_codes_zero"]) for run in measured),
        }

    report = {
        "benchmark": "TELCOLADDER_OIRAN_NATIVE_BENCHMARK_V2",
        "method": {
            "warmup_runs": 1,
            "measured_runs": 3,
            "corpus_files": len(captures()),
            "corpus_bytes": corpus_bytes,
            "corpus_packets": packet_count,
            "same_host": True,
            "oiran_phase_detail": "decode/normalize total only; session reconstruction is a separate S3.3 artifact and is not exposed by this CLI",
            "telcoladder_phase_detail": "summarize total only; internal parsing/reconstruction timers are not exposed by v0.1.0",
            "tshark_phase_detail": "dissection only; no session reconstruction",
            "tshark_isolation": "TShark 4.2.2 invoked inside the existing lab container through a stdin-streaming wrapper",
            "memory_caveat": "TShark/TelcoLadder peak RSS records the host process only and excludes the containerized TShark worker",
        },
        "aggregates": aggregates,
        "performance_ratio": {
            "status": "NOT_COMPARABLE",
            "reason": "TShark/TelcoLadder include Docker exec and stdin transport overhead, and container worker RSS is not observable from the host wrapper",
            "wall_clock_ratios_for_context_only": {
                "telcoladder_over_oiran": aggregates["telcoladder"]["median_total_seconds"] / aggregates["oiran"]["median_total_seconds"],
                "tshark_over_oiran": aggregates["tshark"]["median_total_seconds"] / aggregates["oiran"]["median_total_seconds"],
            },
        },
        "runs": runs,
    }
    (RESULTS / "performance_report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
