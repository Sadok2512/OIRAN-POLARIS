# P0 UE-Targeted Traffic Security Report

## Enforced trust boundary

- Viewer sessions cannot validate, start, or stop traffic.
- Operator/Administrator requests require the existing authenticated session and CSRF token.
- Only `UE-02` through `UE-10` can enter the controller-owned target path; UE-01 remains protected.
- The selected UE must have a persisted approved runtime envelope and exact controller-owned container handle.
- Runtime inspection resolves the network namespace PID from the verified container, not from browser input.
- TUN names must match `uesimtun` followed only by digits and must uniquely carry the observed UE address.
- The route to `10.46.0.1` must use that exact TUN interface and UE source address.
- The executable, arguments, five-datagram loop, destination, port, packet count, size, and interval remain fixed server-side.
- Stop addresses only the exact traffic job and never terminates a UE, gNB, or shared core process.

## Safety gates

Existing disk, memory, laboratory-health, RBAC, audit, and ownership gates remain in the Start path. A new fail-closed CPU check rejects execution when one-minute load is at least the available logical CPU count or cannot be measured as a finite value. At audit time the host was experiencing sustained single-core contention, so a live request would remain blocked by the CPU gate.

Disk utilization was approximately 64%, below the 85% stop threshold. This observation did not authorize traffic execution.

## Secret handling

No subscriber identifier, authentication key, OP/OPc value, profile contents, access token, password, namespace supplied by a user, or arbitrary command is exposed by the API or UI.
