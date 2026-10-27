# S3.3 Call Flow validation

## Canonical model

The canonical export is [OIRAN_5G_E2E_CALLFLOW.json](OIRAN_5G_E2E_CALLFLOW.json), schema 1.0.0. The HTML consumes this embedded model and contains no separate correlation implementation.

| Check | Result |
|---|---|
| Source events | 54 |
| Unique exported event IDs | 54 |
| Session / background / unmatched | 26 / 28 / 0 |
| Extra / duplicate | 0 / 0 |
| Protocol distribution | NGAP 14, PFCP 30, GTP-U 10 |
| Provenance | 54/54 |
| Correlation edges | 12 |
| Timestamp ordering | deterministic PASS |
| Remote HTML dependencies | 0 |
| Inline JavaScript syntax | `node --check` PASS |
| Release build | PASS |
| Workspace tests | 63/63 PASS |

The 26-session-event timeline contains 10 UE registration/context events, two PDU Session Resource Setup events, four PFCP session events, and ten user-plane packets. Eleven NGAP events remain visibly PARTIAL. Twelve unresolved IE nodes are preserved; no opaque field is upgraded.

## UI validation

The standalone light-theme export provides four lifelines, actual endpoint-directed arrows, semantic colors, session/background filtering, protocol/interface filters, name search, procedure expansion, zoom, vertical scrolling, JSON export, and a resizable inspector containing IEs, raw reference, evidence and packet provenance. Decoded strings are inserted through DOM `textContent`; embedded JSON escapes `<`, `>`, `&`, and Unicode line separators.

No graphical browser was available on the VPS, so automated pixel/screenshot validation was not performed. Structural, serialization, security and JavaScript syntax checks passed.
