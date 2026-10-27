# Resource Capacity Report

## Observed host state

| Metric | Observation |
|---|---|
| CPU | 10 KVM vCPU, one thread/core, CPUs 0-9, one NUMA node |
| Load | 1.77 / 3.35 / 3.43 initially; 1.29 / 2.73 / 3.20 final |
| CPU sample | 93-96% idle, 0% steal during bounded `vmstat` sample |
| CPU PSI | `some avg10=2.37`, `full=0` |
| RAM | 20.97 GB total; 15.64-15.78 GB available |
| Memory PSI | `some/full avg10=0`; nonzero historical avg300 |
| Swap | None |
| OOM | No kernel OOM event found in previous 24 hours |
| Cgroup | v2, effective CPUs 0-9; host cgroup showed no throttling |

ETV/OTV activity is material and variable. A bounded snapshot observed the OTV worker and databases consuming CPU; the lab MongoDB also briefly used about 77% of one core. Current utilization is not a guarantee of a quiet future window.

## Conservative incremental budget

| Addition | CPU ceiling | RAM ceiling |
|---|---:|---:|
| One gNB | 0.75 vCPU | 512 MiB |
| Four UEs | 3.00 vCPU | 2,048 MiB |
| Bounded traffic/controller overhead | 0.25 vCPU | 128 MiB |
| Existing N2/N3/N4 capture reserve | 1.00 vCPU | 512 MiB |

Incremental simulator requirement is approximately **4 vCPU and 2.7 GiB**, excluding existing core services. CPU/RAM are `CONDITIONALLY_READY` for phased execution, subject to a fresh 15-minute stability gate, no OOM, low PSI, at least 8 GiB available RAM, and no sustained ETV/OTV burst. No affinity or cgroup was changed.

Overall capacity status: `BLOCKED_DISK_SAFETY`, not `BLOCKED_CAPACITY` for CPU/RAM.

