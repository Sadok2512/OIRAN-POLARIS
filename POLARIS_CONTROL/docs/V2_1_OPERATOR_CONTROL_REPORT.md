# POLARIS Control V2.1 Operator Control

## Outcome

The Web UI and Rust backend now support persistent role-based control. Anonymous users remain Viewer-only. Operators may validate, start, monitor, and stop the single certified scenario `bounded-existing-ue-udp-v1`. Administrators may enable or disable that policy.

## Certified execution boundary

- Reuses the existing healthy UERANSIM UE, gNB, registration, and PDU Session.
- Starts one controller-owned process in the existing UE network namespace.
- Sends exactly five UDP datagrams to `10.46.0.1:49001` at one packet per second.
- Does not create or terminate UE/gNB/Open5GS processes.
- Does not accept shell text, filesystem paths, destinations, packet counts, or process IDs from the browser.
- New UE creation, multi-UE, LTE, gNB lifecycle, ICMP, and TCP remain locked.

## Job lifecycle

Start performs authorization, certification, profile, Open5GS/gNB/UE/capture health, CPU, RAM, disk, conflict, and route checks before spawning the fixed process. Duplicate Start for the same job is idempotent. Stop targets the exact stored child handle and remains available without rerunning the Start resource gate. Terminal state and audit metadata are persisted. On controller restart, an interrupted metadata record becomes `RECOVERED_STOPPED`; systemd terminates the controller cgroup.

No live scenario was executed during V2.1 implementation.
