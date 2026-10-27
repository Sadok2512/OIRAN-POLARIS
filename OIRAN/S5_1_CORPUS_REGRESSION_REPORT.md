# S5.1 unchanged-corpus regression

The original `SHA256SUMS` passed before and after implementation for all 13 files: 4,205 packets and 758,864 bytes. Certified OIRAN_A counts remain 14 NGAP, 30 PFCP and 10 GTP-U; OIRAN_B remains 20 PFCP heartbeats and no fabricated session.

The former SLL2 blocker is removed: 4,075/4,075 LAB packets are readable and 239 NGAP/PFCP/GTP-U events are emitted. TShark also exposes 79 nested NAS occurrences explicitly classified as unsupported by OIRAN, not unexplained missing messages. 116 decoded message envelopes remain `PARTIAL`; this is a subset of the exact message-envelope count, not an additional message category.

TelcoLadder's 1,441 count uses a different multi-layer granularity, including SBI and nested representations. It is not arithmetically interchangeable with OIRAN's top-level normalized-event count.
