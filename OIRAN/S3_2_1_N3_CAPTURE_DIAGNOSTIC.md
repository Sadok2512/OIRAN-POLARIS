# S3.2.1 operational N3 diagnostic

## Finding

**Root cause: A — no UE user-plane traffic was generated (HIGH confidence).** Successful PDU Session establishment is present, but it was not followed by an ICMP/UDP/application flow. The diagnostic did not find evidence for a faulty filter, missing attachment, UPF failure, or rotation selecting the wrong file.

## Evidence chain

1. Five consecutive N3 files (19:53–21:11 UTC) are valid 292-byte PCAPNG containers with zero packets and identical SHA-256 `0bc683fedfd4c67b2fc5b6f9f2e0947a2a848fd5bee003298366d26db2a5ffa9`.
2. `scripts/capture-all.sh` selects `br-oiran-n3` with `udp port 2152`; the capture container uses host networking and the script bind is read-only.
3. The N3 bridge exists and connects gNB `10.77.22.20` and UPF `10.77.22.13`. UPF logs show its GTP-U endpoint on UDP/2152 and the peer endpoint.
4. UE/SMF/UPF evidence confirms PDU Session ID 1, UE address `10.46.0.4`, `uesimtun0`, and session creation. N2 frames 15/17 and N4 frames 7–10 confirm tunnel setup.
5. N3 and N6 capture counters/logs remain 0/0 across rotations, while N2/N4 captured traffic. No `ping`, `iperf`, `curl`, or equivalent UE user-plane execution evidence was found.

This supports “no payload generated” rather than “payload lost before the UPF”: the same absence on both N3 and N6 brackets the UPF path. Historical counters cannot absolutely exclude a transient packet outside retained windows, so the finding is evidence-based rather than metaphysical certainty.

## Classification

| Candidate | Result |
|---|---|
| A. No UE user-plane generated | SUPPORTED, high confidence |
| B. Traffic failed before UPF | NOT SUPPORTED by available evidence |
| C. Incorrect capture point | NOT SUPPORTED; bridge/endpoints match design |
| D. Filter excluded traffic | NOT SUPPORTED; UDP/2152 is correct for N3 |
| E. Rotation/file selection | NOT SUPPORTED; five consecutive files are empty |
| F. Other | UNKNOWN |

## Proposed correction — not executed

After explicit approval: keep the existing capture running; verify a fresh N3 file is active; run one bounded synthetic `ping -c 5 -W 2 10.45.0.1` (or the documented reachable N6 test endpoint) from the UE namespace/container through `uesimtun0`; stop only the test command; allow normal capture rotation; then record N2/N4/N3 checksums and TShark counts. If no packet appears, perform read-only namespace/route/counter inspection before proposing configuration changes.

No filter, service, network, route, container or capture file was changed during this mission.
