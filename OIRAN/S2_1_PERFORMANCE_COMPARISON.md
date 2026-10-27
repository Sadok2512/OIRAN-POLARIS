# S2 versus S2.1 performance comparison

| Measurement | S2 | S2.1 |
|---|---:|---:|
| Comparable baseline Ethernet-equivalent | 2.694994 Gbit/s | NOT_RUN |
| Optimized Ethernet-equivalent | 3.037666 Gbit/s | NOT_RUN |
| Gain | 12.72% | NOT_RUN |
| Best worker count | 2 | NOT_RUN |
| Scaling efficiency | 52.94% | NOT_RUN |
| Maximum measured peak | 4.033931 Mpps | NOT_RUN |
| Best three-run median | 2.072607 Mpps | NOT_RUN |

S2.1 has removed the serial producer from processing-only mode, but that architectural fact is not a performance result. The mandatory stable observation gate failed, so no compatible before/after number exists and no scaling conclusion is made.

When resumed, compare S2 only to mode C with the identical historical profile. Mode A diagnoses generation/allocation/checksum capacity; mode B diagnoses preloaded parser/worker scaling. Neither may be substituted for mode C or presented as physical capture throughput. Certification still requires real ingress, NIC/driver drop counters, and dedicated controlled hardware.
