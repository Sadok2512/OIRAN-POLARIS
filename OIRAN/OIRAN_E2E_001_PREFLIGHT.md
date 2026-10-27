# OIRAN-E2E-001 Preflight

Status: **BLOCKED BEFORE LIVE APPROVAL**  
Observed: 2026-10-26 21:16–21:20 UTC. No live action was executed.

## OIRAN

- API and Capture Helper: active.
- API running SHA256: `1d928d0175d9cc4a40e76e600920d0dbe4630b476ce3531bf2badc6b8a7fd191`.
- Helper running SHA256: `b26963459cad9810cdda6ae31ff2ab446b842835cd5db14375746f206b6c5850`.
- IPC: `/run/oiran/capture-helper.sock`, mode 0660, `oiran-capture:oiran-capture`.
- Operator authentication policy is configured; anonymous access is Viewer. No operator secret was read or exposed.
- Active OIRAN captures: 0.
- Capture Helper child processes: 0.
- Four allowlisted capture points are UP: `br-oiran-n2`, `br-oiran-sbi`, `br-oiran-n4`, `br-oiran-n3`.

## Laboratory

- Open5GS 2.8.0: AMF, SMF, UPF, NRF, AUSF, UDM, UDR, PCF and NSSF containers running and healthy.
- UERANSIM 3.3.0: one shared gNB and three UE processes running.
- Controller inventory: 3 registered UEs and 3 active PDU Sessions.
- UE-04 subscriber/profile binding: PASS using a fresh read-only Open5GS export and dry-run attestation. No identity or authentication material was retained.
- UE-04 configured in current controller state: NO (`ue_count=3`).
- UE-04 lifecycle implementation gate: enabled globally, but Start remains unavailable until configuration is changed to four profiles.

## Blocking findings

1. The certified traffic handler enters the fixed shared namespace `oiran-lab-ueransim-ue-1`; it cannot generate the required five datagrams from UE-04. Running it would test the wrong UE.
2. The current controller configuration contains only UE-01 through UE-03.
3. OTV worker load was 101.96%, 101.82% and 101.51% over three samples on a host exposing one logical CPU. Live testing must not compete with this workload.
4. Explicit live operator approval has not been granted.

These conditions fail the execution preflight. Capture and UE start were not attempted.

