# OIRAN V2.3 Dataset Inventory

| Dataset | Kind | Capture | Packets | Events | UE contexts | PDU sessions | Reconstructed sessions | Accounting |
|---|---|---|---:|---:|---:|---:|---:|---|
| OIRAN_5G_PDU_SESSION_DATA_V1 | HISTORICAL | certified N2/N3/N4 set | 78 | 54 | 2 observed contexts | 1 | 1 | COMPLETE |
| dataset-live-1792966547779-0001 | CAPTURED_LIVE | live-1792966547779-0001 | 54 | 20 | NOT AVAILABLE | 0 | 0 | PARTIAL_NOT_RECONSTRUCTED |
| dataset-live-1793024746674-0002 | CAPTURED_LIVE | live-1793024746674-0002 | 52 | 20 | NOT AVAILABLE | 0 | 0 | PARTIAL_NOT_RECONSTRUCTED |
| recovered-dataset-live-1792964646320-0003 | RECOVERED | live-1792964646320-0003 | 50 | 20 | NOT AVAILABLE | 0 | 0 | PARTIAL_NOT_RECONSTRUCTED |

The three non-historical datasets contain supported PFCP background/heartbeat decoding but no UE/PDU session evidence. They remain visible and selectable with honest zero-session states. Failed captures with preserved PCAP evidence remain capture records rather than falsely registered sessions.

Certified PCAP checksums remained:

- N2: `2f23390dd619dda464ec8f2cfbd3b9fe59ca0587b043f6267a8ffc5a752cf54e`
- N3: `806a4ae1eb758a1b2c08ae10d7b7f54881c5e571c7f80ed047f564cb222cb35a`
- N4: `8fad2f3401e79ea1695aa26cba649c03711e24ee0602625ec569ef82c3e6cfe7`
