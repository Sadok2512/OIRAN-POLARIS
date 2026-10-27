# POLARIS-LIVE-001 Controlled UERANSIM Test

## Result

The explicitly approved bounded test completed successfully from 13:17:00 to 13:17:05 UTC on 2026-10-25. Execution used the POLARIS Control backend. Generic simulator Start/Stop remained locked.

## Safety gate

- Disk usage: 80.71%, below the 85% stop threshold.
- Available RAM before execution: approximately 15 GiB.
- CPU pressure: low; no full CPU or memory pressure was observed.
- ETV/OTV containers remained running; healthy states were preserved where health checks exist.
- Open5GS, the shared gNB, and the shared UE were not restarted.
- Existing UERANSIM state showed successful registration, PDU Session 1, and `uesimtun0` at `10.46.0.4`.
- The route to the controlled UPF endpoint `10.46.0.1` was verified through `uesimtun0`.

## Execution

The one-time approval file contained only `POLARIS-LIVE-001`. The backend consumed the approval in memory before launching a fixed command with a 15-second timeout. Five 19-byte UDP payloads were sent at one-second intervals to `10.46.0.1:49001`. The command exited with code 0 after five seconds.

The endpoint had no UDP listener, so each uplink datagram produced one downlink ICMP Port Unreachable response. This is expected and proves bidirectional N3 transport; it is not counted as an application-level UDP reply.

## Capture evidence

| Interface | Integrity | Observation |
|---|---|---|
| N2 | Valid PCAPNG | Capture active; 136 packets at inspection. No new registration was expected because the UE was already registered. |
| N3 | Valid PCAPNG | 10 GTP-U packets: 5 uplink UDP and 5 downlink ICMP responses. |
| N4 | Valid PCAPNG | Capture active; 132 packets at inspection. No new PFCP establishment was expected because the PDU Session already existed. |

N3 file: `n3_20261025T131153Z_00001_20261025131153.pcapng`  
N3 SHA256: `cae6d69a4a19a53422093fdcc2bf03fab652e37d623873398f07806d5c26a518`

Observed uplink TEID: `0x000096a8`. Observed downlink TEID: `0x00000003`. Timestamps and packet lengths were decoded successfully with TShark 4.2.2 in the capture container.

## Stop and relock validation

- The bounded traffic process finalized gracefully.
- Stop returned `STOPPED` idempotently with zero orphan processes.
- A second Start request returned HTTP 423 after removal of the approval file.
- Generic live execution remains disabled.

## Limitation

This run certified bounded user-plane activation over an existing registered UE and PDU Session. It did not create a fresh registration or PFCP Session Establishment, so it is not a new coherent N2/N4/N3 establishment dataset.

## Readiness

The controller is ready for planning a controlled multi-UE test, but that test requires separate approval, distinct synthetic UE profiles, collision checks, and a new disk/resource gate.
