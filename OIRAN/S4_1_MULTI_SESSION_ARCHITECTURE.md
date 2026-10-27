# S4.1 multi-session architecture

## Outcome

S4.1 removes the one-flow process model. `session-engine` 0.2.0 performs deterministic discovery over normalized events, `dataset-registry` 0.1.0 indexes immutable allowlisted datasets, and API 1.1 serves a map of independent canonical Call Flows. The S4 certified flow remains the primary backward-compatible record.

```text
allowlisted immutable captures + manifest + normalized JSONL
                         |
             deterministic deduplication
                         |
 UE lifecycle scopes -- PDU sessions -- PFCP lifecycles -- GTP-U tunnels
                         |
    canonical flow sidecars, or conservative incomplete generated flows
                         |
       authenticated paginated API -> React multi-session views
```

## Identity boundaries

- NGAP: capture point, ordered gNB/AMF endpoints, RAN UE NGAP ID, AMF UE NGAP ID and lifecycle generation.
- PDU: UE context plus PDU Session ID. One UE may own several PDU sessions.
- PFCP: unordered SMF/UPF endpoint scope, transaction sequence, SEID/F-SEID continuity and lifecycle.
- GTP-U: source/destination endpoints, TEID, direction and observed time interval.

Stable IDs use a deterministic FNV-1a digest of the scoped composite key. They contain no subscriber identity. A released NGAP context creates a new lifecycle before reused IDs can be accepted.

## Conservative boundaries

The engine never joins UE contexts on time proximity. A GTP-U tunnel receives an automatic PFCP relation only if exactly one PFCP session exposes the same TEID and one of the directional endpoints. Ambiguous reuse remains unlinked. A discovered PDU session without a canonical correlation sidecar gets an independent, evidence-only incomplete Call Flow containing its observed UE/PDU events; PFCP/N3 events are not inserted without a proven bridge.

Incremental persistence and write APIs are deliberately absent in S4.1. Reprocessing occurs at read-only service startup, and identical capture-hash sets are idempotent in the registry.
