# S5.1 PCAP and PCAPNG compatibility

| Format | Ethernet | SLL v1 | SLL2 | Timestamp | Multi-interface |
|---|---|---|---|---|---|
| PCAP | PASS | PASS | PASS | micro/nanosecond precision preserved | one global link type by format |
| PCAPNG | PASS | PASS | PASS | per-interface resolution and offset preserved | PASS, link type selected per IDB |

Regression fixtures cover classic PCAP link type 276 and a PCAPNG section containing both Ethernet and SLL2 interfaces. Captured/original length and snaplen validation remain enforced.
