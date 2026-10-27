# S5.4 resource safety

Audit snapshot: 2026-10-26 19:11–19:31 UTC.

| Resource | Observation | Decision |
|---|---|---|
| Root/capture filesystem | 414,921,494,528 total; 253,047,046,144 used; 161,874,448,384 available; 60.98% | NORMAL |
| Inodes | 51,179,469 available; 3% used | PASS |
| OIRAN write budget | 2,147,483,648 maximum; 99,636,224,204 bytes headroom to 85%; 32 MiB reserve | PASS |
| Existing lab captures | 130,400,076 bytes | Informational |
| OIRAN capture storage | 846,760 bytes | Informational |
| RAM | 20,970,582,016 total; 15,298,248,704 available; no swap | PASS |
| CPU | 10 logical CPUs; sampled 34% idle, CPU PSI `some avg10=9.02` | CONDITIONAL |
| ETV/OTV | Containers remained running; OTV database sampled above two CPU cores and MongoDB was also busy | Protect workload; choose a quieter window |

The permanent disk policy remains 75% information, 80% warning, 85% stop/finalize and 90% hard limit. Monitoring is one second, fail-closed, with bounded reservations and no automatic cleanup.

For OIRAN-E2E-001 reserve only 256 MiB total plus 32 MiB, despite the larger platform ceiling. Recheck immediately before execution. Refuse or abort if disk measurement fails, usage reaches 85%, available memory falls below the approved controller threshold, CPU/IO pressure is sustained, or ETV/OTV health degrades. No benchmark or cleanup is part of this plan.
