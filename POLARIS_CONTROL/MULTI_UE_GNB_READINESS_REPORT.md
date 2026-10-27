# POLARIS-MULTI-UE-001 Readiness Report

Audit time: 2026-10-25 16:15 UTC. Mode: read-only audit and plan. No process or configuration was changed.

## Decision

`BLOCKED` for execution. The design is technically feasible, but three independent gates fail:

1. Open5GS has 1 synthetic subscriber; 5 unique subscribers are required.
2. Root filesystem usage is 85.01%; POLARIS Control reports `STOP_NEW_WRITES` and a zero-byte capture budget.
3. The controller advertises `max_nodes=1`, `max_ues=1`; only `bounded-existing-ue-udp-v1` is certified and it does not manage gNB/UE lifecycle.

## Sanitized observed inventory

| Resource | Observed state | Evidence |
|---|---|---|
| UERANSIM | v3.3.0, revision `6bf5a1a...`, `/usr/local/bin/nr-gnb`, `/usr/local/bin/nr-ue` | Image labels and read-only version commands |
| gNB-01 | Healthy, PID owned by `oiran-lab-ueransim-gnb-1`, no restart | Docker inspect |
| UE-01 | Healthy, registered, one active PDU session | Docker/API state and sanitized UE log |
| Open5GS | v2.8.0; AMF, SMF, UPF, NRF healthy | Docker health and version output |
| Capture | Healthy now, but restart count 20 | `oiran-lab-capture-1` inspect |
| N2 | Bridge up; SCTP/38412; closed hourly file observed 1,380 SCTP frames | Bridge state and TShark 4.2.2 |
| N3 | Bridge up; UDP/2152; current closed file empty | Bridge state and TShark 4.2.2 |
| N4 | Bridge up; UDP/8805; closed hourly file observed 1,308 PFCP frames | Bridge state and TShark 4.2.2 |

Existing certified OIRAN evidence remains one UE only: 14 NGAP messages, 30 PFCP messages and 10 GTP-U packets in `datasets/OIRAN_5G_PDU_SESSION_DATA_V1`.

## Status

- Two-gNB design: `DESIGNED_NOT_AUTHORIZED`.
- Five-UE profiles: `1/5 READY`.
- Capacity: CPU/RAM conditionally adequate; disk blocked.
- Execution: not authorized and not attempted.

