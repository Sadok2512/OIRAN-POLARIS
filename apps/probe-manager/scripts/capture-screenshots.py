#!/usr/bin/env python3
"""Capture Probe Manager screenshots (LOT 1 / 1.1).

Mocks the OIRAN API with stable fixtures so the UI renders real-looking
data without hitting a backend. Starts from a running dev server on
127.0.0.1:4310 (`npm run dev` in a side terminal).

Produces 8 PNGs under apps/probe-manager/docs/screenshots/:
  probes-{light,dark}.png
  register-probe-{light,dark}.png
  live-captures-{light,dark}.png
  capture-library-{light,dark}.png
"""

import json
import os
import time
from pathlib import Path
from playwright.sync_api import Page, sync_playwright

BASE = "http://127.0.0.1:4310"
OUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
OUT_DIR.mkdir(parents=True, exist_ok=True)

NOW = int(time.time())

FIXTURES = {
    "/api/v1/auth/me": {
        "authenticated": True,
        "role": "operator",
        "permissions": ["capture.read"],
        "capture_control": True,
        "capture_execution_enabled": True,
        "reason": "OK",
    },
    "/api/v1/probes": [
        {
            "probe_id": "oiran-vprobe-local-01",
            "name": "OIRAN Local vProbe",
            "host": "oiran-lab-ueransim-gnb-1",
            "probe_type": "Virtual",
            "version": "2.3.0",
            "online": True,
            "capture_state": "IDLE",
            "last_heartbeat": "2026-10-28T14:00:00Z",
            "last_heartbeat_epoch_s": NOW,
            "connected_interfaces": ["n2", "n3", "n4"],
            "packet_rate_pps": 42,
            "decode_rate_eps": 20,
            "packet_drops": 0,
            "cpu_usage_percent": 12.3,
            "memory_usage_bytes": 540_000_000,
            "disk_usage_percent": 68,
            "historical_packet_count": 2_830,
            "telemetry_status": "LIVE",
            "distributed": False,
            "capture_control_available": True,
        },
        {
            "probe_id": "edge-rack-03",
            "name": "Edge probe · rack 03",
            "host": "probe-dc01.corp",
            "probe_type": "Physical",
            "version": "2.2.1",
            "online": False,
            "capture_state": "UNKNOWN",
            "last_heartbeat": None,
            "last_heartbeat_epoch_s": None,
            "connected_interfaces": ["s1"],
            "packet_rate_pps": None,
            "decode_rate_eps": None,
            "packet_drops": None,
            "cpu_usage_percent": None,
            "memory_usage_bytes": None,
            "disk_usage_percent": None,
            "historical_packet_count": 0,
            "telemetry_status": "OFFLINE",
            "distributed": True,
            "capture_control_available": False,
        },
    ],
    "/api/v1/interfaces": [
        {"interface": "n2", "protocol": "NGAP", "capture_point": "N2", "source": "oiran-vprobe-local-01", "status": "AVAILABLE", "device": "ens3", "reason": None, "packet_count": 1380, "file_size": 540_000, "capture_start": None, "capture_end": None, "live_capture_available": True},
        {"interface": "n3", "protocol": "GTP-U", "capture_point": "N3", "source": "oiran-vprobe-local-01", "status": "AVAILABLE", "device": "ens4", "reason": None, "packet_count": 10, "file_size": 42_000, "capture_start": None, "capture_end": None, "live_capture_available": True},
        {"interface": "n4", "protocol": "PFCP", "capture_point": "N4", "source": "oiran-vprobe-local-01", "status": "AVAILABLE", "device": "ens5", "reason": None, "packet_count": 1308, "file_size": 320_000, "capture_start": None, "capture_end": None, "live_capture_available": True},
        {"interface": "s1", "protocol": "S1AP", "capture_point": "S1", "source": "edge-rack-03", "status": "UNAVAILABLE", "device": "eth0", "reason": "probe offline", "packet_count": None, "file_size": None, "capture_start": None, "capture_end": None, "live_capture_available": False},
    ],
    "/api/v1/metrics": {"packet_rate_pps": 142, "bits_per_second": 1_200_000, "storage_bytes": 1_200_000_000, "decode_errors": 0},
    "/api/v1/storage/safety": {
        "filesystem": {
            "total_bytes": 500 * 1024 ** 3,
            "used_bytes": 340 * 1024 ** 3,
            "available_bytes": 160 * 1024 ** 3,
            "usage_percent": 68,
            "total_inodes": 32_000_000,
            "available_inodes": 24_000_000,
        },
        "decision": {
            "state": "OK",
            "new_capture_allowed": True,
            "active_capture_must_finalize": False,
            "read_only_analysis_allowed": True,
            "reason": "HEALTHY",
        },
    },
}

CAPTURES = [
    {
        "capture_id": "sha256:aabbccddee112233445566778899001122334455",
        "name": "lab-n2-ngap",
        "probe_id": "oiran-vprobe-local-01",
        "interface": "n2",
        "interfaces": ["n2"],
        "protocol": "NGAP",
        "state": "CAPTURING",
        "status": "CAPTURING",
        "dataset_id": "ds-live-01",
        "size_bytes": 42_000_000,
        "packet_count": 1380,
        "metrics": {
            "packets_received": 1380,
            "bytes_received": 42_000_000,
            "packets_per_second": 42,
            "bits_per_second": 320_000,
            "decoded_events": 1210,
            "decode_errors": 0,
            "packet_drops": 0,
            "storage_bytes": 42_000_000,
        },
        "planes": [
            {"plane": "N2", "interface": "n2", "capture_job_id": "cj-1", "start_timestamp": NOW - 120, "end_timestamp": None, "packet_count": 1380, "byte_count": 42_000_000, "drop_count": 0, "storage_bytes": 42_000_000, "decode_status": "OK", "dataset_id": "ds-live-01", "source_sha256": [], "error": None},
        ],
    },
    {
        "capture_id": "sha256:eeeeeeeeeeff00112233",
        "name": "archive-n3-gtpu",
        "probe_id": "oiran-vprobe-local-01",
        "interface": "n3",
        "interfaces": ["n3"],
        "protocol": "GTP-U",
        "state": "COMPLETED",
        "status": "COMPLETED",
        "dataset_id": "ds-arch-02",
        "size_bytes": 128_000_000,
        "packet_count": 8200,
        "metrics": {
            "packets_received": 8200,
            "bytes_received": 128_000_000,
            "packets_per_second": None,
            "bits_per_second": None,
            "decoded_events": 7600,
            "decode_errors": 0,
            "packet_drops": 0,
            "storage_bytes": 128_000_000,
        },
        "planes": [
            {"plane": "N3", "interface": "n3", "capture_job_id": "cj-9", "start_timestamp": NOW - 3600, "end_timestamp": NOW - 2800, "packet_count": 8200, "byte_count": 128_000_000, "drop_count": 0, "storage_bytes": 128_000_000, "decode_status": "OK", "dataset_id": "ds-arch-02", "source_sha256": [], "error": None},
        ],
    },
]


def handle_api(route, request):
    url = request.url
    path = url.split("127.0.0.1:4310", 1)[-1].split("?", 1)[0]
    if path.startswith("/api/v1/captures") and "/download" not in path:
        body = {"data": CAPTURES, "meta": {"total": len(CAPTURES), "total_pages": 1, "api_version": "2.3.0"}}
    else:
        payload = None
        for key, value in FIXTURES.items():
            if path.startswith(key):
                payload = value
                break
        body = {"data": payload, "meta": {"api_version": "2.3.0"}}
    route.fulfill(status=200, content_type="application/json", body=json.dumps(body))


def shoot(page: Page, path: str, filename: str, theme: str, wait_for=None, after_load=None):
    # Probe Manager uses HashRouter — target the fragment, not the pathname.
    hash_url = f"{BASE}/#{path}"
    page.goto(hash_url, wait_until="domcontentloaded")
    if wait_for:
        page.wait_for_selector(wait_for, timeout=10_000)
    page.wait_for_timeout(500)
    if after_load:
        after_load(page)
        page.wait_for_timeout(400)
    target = OUT_DIR / f"{filename}-{theme}.png"
    page.screenshot(path=str(target), full_page=True)
    print(f"  -> {target}")


def main():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for theme in ("light", "dark"):
            print(f"== Theme: {theme} ==")
            context = browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=2)
            context.add_init_script(
                f"try {{ localStorage.setItem('telecom.theme', '{theme}'); document.documentElement.setAttribute('data-theme', '{theme}'); }} catch (e) {{}}"
            )
            context.route("**/api/v1/**", handle_api)
            page = context.new_page()
            page.on("console", lambda msg: print(f"  [console·{msg.type}] {msg.text}") if msg.type in ("error", "warning") else None)
            page.on("pageerror", lambda err: print(f"  [pageerror] {err}"))
            shoot(page, "/probes", "probes", theme, wait_for="[data-testid='register-probe-open']")
            shoot(
                page,
                "/probes",
                "register-probe",
                theme,
                wait_for="[data-testid='register-probe-open']",
                after_load=lambda p: p.get_by_test_id("register-probe-open").click(),
            )
            shoot(page, "/live-captures", "live-captures", theme, wait_for="[data-testid='live-capture-stats']")
            shoot(page, "/capture-library", "capture-library", theme, wait_for="[data-testid='download-locked-banner']")
            context.close()
        browser.close()
    print(f"\nSaved screenshots under {OUT_DIR}")


if __name__ == "__main__":
    main()
