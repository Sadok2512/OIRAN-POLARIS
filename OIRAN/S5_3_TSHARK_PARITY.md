# S5.3 TShark parity

Reference: TShark 4.2.2. Comparison used exact packet references on the unchanged 13-file corpus and TCP port 7777 HTTP/2 dissection.

| Metric | Result |
|---|---:|
| OIRAN HTTP/2 frames | 2,316 |
| TShark HTTP/2 frames | 2,316 |
| Stable fields comparable | 766 |
| Exact | 766 |
| Mismatched | 0 |
| Unresolved | 26 |
| Exact transactions | 172 |
| Partial transactions | 26 |

Compared fields include frame/packet alignment, stream ID, method, sanitized URI and response status when visible. Unresolved fields are not counted exact. TShark was used as an independent reference, not as runtime decoder code.
