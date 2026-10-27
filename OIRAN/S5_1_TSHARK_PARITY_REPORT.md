# S5.1 independent TShark parity

Reference: TShark 4.2.2. SLL2 was decoded independently; TCP port 7777 was explicitly decoded as HTTP/2 for SBI visibility.

| Measure | Result |
|---|---:|
| Newly comparable NGAP/NAS/PFCP/GTP-U occurrences | 318 |
| Exact OIRAN message envelopes | 239 |
| Mismatched OIRAN envelopes | 0 |
| Unexplained missing messages | 0 |
| Unsupported nested NAS messages | 79 |
| Extra OIRAN messages | 0 |
| Partial OIRAN envelopes | 116 |

Every emitted OIRAN LAB event matched the TShark packet number, nanosecond timestamp, outer source/destination IP and canonical message name/header. GTP-U parity uses the outer tunnel endpoints and TEID, not TShark's displayed inner ICMP endpoints.
