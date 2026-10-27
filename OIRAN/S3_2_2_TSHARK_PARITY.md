# S3.2.2 TShark parity

Reference decoder: TShark 4.2.2, run read-only inside the existing capture container.

| Interface | TShark | OIRAN | Exact | Partial | Missing | Extra |
|---|---:|---:|---:|---:|---:|---:|
| N2 / NGAP | 14 messages | 14 | 3 | 11 | 0 | 0 |
| N4 / PFCP | 30 messages | 30 | 30 | 0 | 0 | 0 |
| N3 / GTP-U | 10 packets | 10 | 10 | 0 | 0 | 0 |

N3 packet number, nanosecond timestamp, outer endpoints, UDP/2152, message type, TEID and length match 10/10. N2's 11 PARTIAL events reflect the documented nested APER/protected NAS boundary, not missing messages. Every native event has source capture, packet number, byte offset and raw hash.

Machine-readable TShark extracts are stored as `tshark_n2.csv`, `tshark_n4.csv`, and `tshark_n3.csv` in the dataset.
