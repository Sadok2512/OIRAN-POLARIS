# S2 resource safety report

## Pre-benchmark audit

| Resource | Observed before benchmark |
|---|---|
| CPU | 10 vCPU; load average 2.25 / 4.16 / 4.40 |
| CPU pressure | `some avg10=1.04%`; `full avg10=0.00%` |
| RAM | ~12 GiB available of 19 GiB visible; no swap |
| Memory pressure | `full avg10=0.11%` |
| Disk | 387 GiB total, 93 GiB available, 76% used |
| OOM events | None in the inspected 30-minute kernel window |
| systemd | Already degraded due only to `systemd-networkd-wait-online.service` |
| Concurrent benchmark | None |

No package was installed, no kernel/sysctl/global CPU setting changed, and no service was restarted by S2.

## Process-level guardrails

- Maximum requested workers: 4.
- Matrix duration: 100 ms per point; strict comparison: 250 ms per point.
- Hard virtual-memory limit: 1 GiB via `ulimit -v 1048576`.
- Wall timeout: 5 seconds per command.
- Process CPU affinity limited to CPU 0–4 via `taskset`; worker pinning remained internal and reported failures.
- Built-in benchmark guard stops below 2 GiB available RAM or above 5% full-memory-pressure avg10.
- No PCAP or other large data file generated; workloads were memory-only.

Post-matrix host observations remained without CPU full pressure or OOM, and available memory was approximately 16 GiB. The largest benchmark-process RSS recorded in the matrix was 8.09 MiB.

## Production safety stop

At the S2 start, the protected OTV state included:

- `otv-app-1` ID prefix `d9427760d97e`, started `2026-10-24T18:03:38Z`;
- `otv-worker-1` ID prefix `efc8c6b835d7`, running;
- `otv-candidate-110` ID prefix `aadffc2a2a5`, running.

After the optimized matrix, read-only inspection observed:

- `otv-app-1` replaced by ID prefix `f643a9463664`, started `2026-10-24T20:58:32Z`;
- `otv-worker-1` exited with code 137;
- `otv-candidate-110` no longer present in the active-container list;
- `otv-db-1` remained healthy and retained its original ID/start time;
- ETV database/app containers remained in their prior states.

No S2 command invoked `docker compose`, `docker start/stop/restart/rm`, Docker mutation APIs, PostgreSQL, or any ETV/OTV path. The benchmark only used CPU/memory in `/root/OIRAN_VPROBE`; Docker commands were read-only state checks. The timing proves an external lifecycle change occurred, but does not establish its cause. In accordance with the safety rule, all remaining benchmarks—including the A/B/C component profile—were cancelled.

Therefore:

- `ETV_OTV_CHANGED_BY_S2 = FALSE`
- `EXTERNAL_ETV_OTV_STATE_CHANGE_OBSERVED = TRUE`
- `POLARIS_CHANGED_BY_S2 = FALSE`
- `RESOURCE_SAFETY_STOP_TRIGGERED = TRUE`

## POLARIS protection evidence

The following read-only sentinels matched before and after the benchmark phase:

- `POLARIS_DEPLOYMENT_MANIFEST.json`: `e6eb79cf0f9acdcba67c1147de5273001869fb0e96e8935365074a6d9fdb37ef`
- `OIRAN_EVENT_SCHEMA_V1.json`: `7f0e2d39b7ae9c88be2c922de15c687e9ddd2c22379669c9a9ae60ee4d616ab2`

Active POLARIS capture files were not read, hashed or modified during S2.

## Resume condition

Before any further benchmark, an operator must confirm whether the OTV deployment/worker exit was expected and establish a stable observation window. S2 does not authorize starting or repairing OTV.

