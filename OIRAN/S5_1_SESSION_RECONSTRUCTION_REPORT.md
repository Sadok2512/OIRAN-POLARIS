# S5.1 session reconstruction

| Fixture | UE contexts | PDU sessions | PFCP sessions | GTP-U tunnels |
|---|---:|---:|---:|---:|
| 5gc-e2e | 2 | 1 | 2 | 0 |
| 5gc-registration | 1 | 1 | 0 | 0 |
| ki-mismatch | 1 | 0 | 0 | 0 |
| multi-imsi | 6 | 5 | 6 | 0 |
| supi-not-provisioned | 1 | 0 | 0 | 0 |
| unknown-dnn | 2 | 0 | 0 | 0 |
| userplane | 2 | 1 | 2 | 1 |

The multi-IMSI fixture contains five unique PDU-bearing UE contexts plus one separate released context. Each PDU session references a unique UE context; `CROSS_UE_CONTAMINATION = NONE_OBSERVED`. Six PFCP lifecycles include one prior deletion lifecycle and five establishments.

Certification remains partial: the engine does not yet prove N2↔N4 association for these captures, and the five-UE fixture has no GTP-U packets. No timestamp-only correlation was promoted.
