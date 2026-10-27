# N2/N3/N4 Capture Plan

## Observed readiness

| Interface | Point/filter | Current evidence | Readiness for new test |
|---|---|---|---|
| N2 | `br-oiran-n2`, SCTP/38412 | Bridge up; 1,380 SCTP frames in a closed hourly file | Infrastructure ready, writes blocked |
| N3 | `br-oiran-n3`, UDP/2152 | Bridge up; latest inspected file empty; earlier certified dataset has 10/10 GTP-U | Conditional on generated traffic and disk gate |
| N4 | `br-oiran-n4`, UDP/8805 | Bridge up; 1,308 PFCP frames in a closed hourly file | Infrastructure ready, writes blocked |

TShark 4.2.2 exists inside the capture container, not on the host.

## Proposed bounded run

- Scenario ID: `POLARIS-MULTI-UE-001-<UTC-start>`.
- Capture IDs: `N2-<scenario>`, `N3-<scenario>`, `N4-<scenario>`.
- Start boundary: all three writers confirmed ready before the first gNB/UE action.
- End boundary: after terminal UE state plus 10-second quiet period.
- Limit: 10 minutes; two 32 MiB files per interface; one concurrent scenario.
- Manifest: absolute time range, capture point, probe ID, packet count, byte size, SHA-256, decoder/TShark versions and terminal status.

Both gNBs are distinguishable on N2 by separate SCTP associations/source IPs and Global RAN Node IDs, and on N3 by separate outer endpoint IPs. N4 is shared core traffic; bind it to UE sessions through observed PFCP SEID/F-SEID, F-TEID and endpoint evidence rather than timestamp alone.

Validation after finalization: `capinfos`, TShark packet/message extraction, SHA-256, OIRAN decode, then packet-level reconciliation. Do not inspect an actively written file as final evidence.

