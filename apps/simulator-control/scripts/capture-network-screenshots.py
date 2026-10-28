#!/usr/bin/env python3
"""Capture POLARIS Simulator Control screenshots for LOT 2 (Network section).

Starts from a running dev server on 127.0.0.1:4330 (`npm run dev` in a
side terminal). Mocks the POLARIS /lab + /nodes + /ues + /capabilities +
/ue-profiles/provisioning-slots routes with stable fixtures so the UI
renders real-looking data without hitting a backend.

Produces 6 PNGs under apps/simulator-control/docs/screenshots/:
  network-topology-{light,dark}.png
  network-core-{light,dark}.png
  network-gnbs-{light,dark}.png
"""

import json
import time
from pathlib import Path
from playwright.sync_api import Page, sync_playwright

BASE = "http://127.0.0.1:4330/simulator"
OUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "screenshots"
OUT_DIR.mkdir(parents=True, exist_ok=True)

NOW = int(time.time())

NODES = {
    "items": [
        {"id": "GNB-01", "name": "Primary gNB", "technology": "5G SA", "simulator": "UERANSIM", "plmn": "001/01", "cell_id": "0x000000010", "link_ip": "10.77.0.20", "n2_endpoint": "10.77.21.20", "n3_endpoint": "10.77.22.20", "process_state": "running", "health": "healthy", "configured": True, "controller_owned": False, "uptime_seconds": 1800, "actions": {"start": False, "stop": False, "reason": "SHARED_NODE_PROTECTED"}},
        {"id": "GNB-02", "name": "Second gNB plan", "technology": "5G SA", "simulator": "UERANSIM", "plmn": "001/01", "cell_id": "UNASSIGNED", "link_ip": "NOT_CONFIGURED", "n2_endpoint": None, "n3_endpoint": None, "process_state": "NOT_DEPLOYED", "health": "NOT_VALIDATED", "configured": False, "controller_owned": False, "uptime_seconds": None, "actions": {"start": False, "stop": False, "reason": "LIVE_005_APPROVAL_REQUIRED"}},
        {"id": "ENB-01", "name": "LTE eNB profile", "technology": "LTE", "simulator": "srsRAN", "plmn": "001/01", "cell_id": "NOT_AVAILABLE", "link_ip": "NOT_AVAILABLE", "n2_endpoint": None, "n3_endpoint": None, "process_state": "stopped", "health": "unknown", "configured": False, "controller_owned": False, "uptime_seconds": None, "actions": {"start": False, "stop": False, "reason": "LTE_ATTACH_NOT_CERTIFIED"}},
    ],
    "configured_count": 1,
    "running_count": 1,
    "observed_at_epoch_s": NOW,
    "source": "READ_ONLY_LAB_STATE",
}

UES = {
    "items": [
        {"id": "UE-01", "registration_state": "REGISTERED", "pdu_session": "ACTIVE", "ue_ip": None, "traffic_state": "IDLE", "serving_node": "GNB-01", "last_event": None, "controller_owned": True, "internal_ue_id": "imsi-ue-01"},
        {"id": "UE-12", "registration_state": "REGISTERED", "pdu_session": "ACTIVE", "ue_ip": None, "traffic_state": "IDLE", "serving_node": "GNB-01", "last_event": None, "controller_owned": True, "internal_ue_id": "imsi-ue-12"},
    ],
    "configured_profiles": [],
    "configured_count": 2,
    "active_count": 2,
    "registered_count": 2,
    "source": "test",
}

CAPABILITIES = {
    "live_control": False,
    "approval_state": "READ_ONLY",
    "max_ues": 10,
    "max_nodes": 2,
    "max_ues_live_certified": 10,
    "max_nodes_live_certified": 1,
    "registration_modes": ["5G_SA"],
    "traffic_protocols": ["UDP"],
    "approved_destinations": ["10.46.0.1"],
    "profiles": [],
    "technologies": [],
    "services": [],
}

LAB = {
    "source": "READ_ONLY_HOST_AUDIT",
    "configuration_changed": False,
    "observed": {
        "ueransim_ue_profile": True,
        "open5gs": {"process_state": "running", "health": "healthy", "observed": True},
        "ueransim_gnb": {"process_state": "running", "health": "healthy", "observed": True},
        "ueransim_ue": {"process_state": "running", "health": "healthy", "observed": True},
        "srsran_enb": {"process_state": "stopped", "health": "unknown", "observed": True},
        "srsran_ue": {"process_state": "stopped", "health": "unknown", "observed": True},
        "lte_attach": "NOT_CERTIFIED",
    },
}

SLOTS = {
    "items": [{"slot_id": f"UE-{i:02d}", "bound_ue_id": f"UE-{i:02d}" if i in (1, 12) else None} for i in range(1, 11)],
    "total": 10,
    "available": 8,
    "secrets_exposed": False,
}

AUTH = {"authenticated": False, "username": None, "role": "viewer", "can_start": False, "can_manage_permissions": False}


def handle_api(route, request):
    url = request.url
    path = url.split("127.0.0.1:4330", 1)[-1].split("?", 1)[0]
    # Strip the /simulator/ Vite base prefix.
    for prefix in ("/simulator",):
        if path.startswith(prefix):
            path = path[len(prefix) :] or "/"
            break
    if path.endswith("/auth/me"):
        body = AUTH
    elif path.endswith("/capabilities"):
        body = CAPABILITIES
    elif path.endswith("/ue-profiles/provisioning-slots"):
        body = SLOTS
    elif path.endswith("/nodes"):
        body = NODES
    elif path.endswith("/ues"):
        body = UES
    elif path.endswith("/lab"):
        body = LAB
    elif path.endswith("/traffic/status"):
        body = {"state": "IDLE", "packets_requested": 0, "packets_sent": None, "packets_received": None, "bytes": None, "accounting_source": "none", "last_result": None, "approved_destinations": []}
    elif path.endswith("/scenarios/status"):
        body = {"active_job": None, "latest_terminal_job": None, "active_count": 0, "history_count": 0, "observed_at_epoch_s": 0, "source": "test"}
    elif path.endswith("/scenarios/history"):
        body = {"items": [], "total": 0, "source": "test", "live_execution": False}
    elif path.endswith("/scenario-capabilities"):
        body = {"items": [], "execution_status": "READY_TO_START", "reason": "OK", "role": "viewer"}
    elif path.endswith("/system/health"):
        body = {"disk": None, "decision": {"state": "OK", "writes_allowed": True, "reason": "", "maximum_budget_bytes": 0}, "memory": {"total_bytes": None, "available_bytes": None, "used_bytes": None}, "load_average": "", "uptime_seconds": None}
    else:
        body = None
    route.fulfill(status=200, content_type="application/json", body=json.dumps(body))


def shoot(page: Page, path: str, filename: str, theme: str, wait_for=None):
    # Simulator Control uses BrowserRouter with basename "/simulator".
    page.goto(f"{BASE}{path}", wait_until="domcontentloaded")
    if wait_for:
        page.wait_for_selector(wait_for, timeout=10_000)
    page.wait_for_timeout(600)
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
            context.route("**/polaris-api/v1/**", handle_api)
            page = context.new_page()
            page.on("pageerror", lambda err: print(f"  [pageerror] {err}"))
            shoot(page, "/network/topology", "network-topology", theme, wait_for="[data-testid='topology-view']")
            shoot(page, "/network/core", "network-core", theme, wait_for="[data-testid='core-functions']")
            shoot(page, "/network/gnbs", "network-gnbs", theme, wait_for="[data-testid='gnbs-grid']")
            context.close()
        browser.close()
    print(f"\nSaved screenshots under {OUT_DIR}")


if __name__ == "__main__":
    main()
