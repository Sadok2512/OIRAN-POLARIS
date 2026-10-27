# S5.2 Independent TShark Parity

Reference: TShark/Wireshark 4.2.2. Alignment uses source SHA256, packet number and exact capture timestamp.

| Metric | Result |
|---|---:|
| Comparable fields | 464 |
| Exact | 404 |
| Mismatched | 0 |
| Unresolved/encrypted | 60 |

The four evaluated fields per NAS event are message type, direction, exact timestamp, and parent/provenance relationship. All non-ciphered comparable fields are exact. Ciphered inner message types are `UNRESOLVED`, not counted as exact or mismatch.

TShark sees 5GSM messages in SBI and can dissect laboratory null-cipher content. OIRAN deliberately does neither without an authorized NAS security context. Detailed packet rows are in `benchmarks/S5_2_NATIVE_NAS/results/nas_parity.csv`.
