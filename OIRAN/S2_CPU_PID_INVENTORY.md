# S2 CPU/PID inventory

## Scope

Read-only observation on 2026-10-24 UTC. Five one-second `pidstat` samples were used so the ranking does not depend on a single `ps` snapshot. CPU percentages below are averages across that five-second window; a process present for fewer samples is identified as transient. No benchmark process was running.

## Top active CPU consumers

| PID | PPID | User | Process | Avg / peak CPU | Memory | State / CPU | Threads | Affinity | Executable | Start | Cgroup/container |
|---:|---:|---|---|---:|---:|---|---:|---|---|---|---|
| 3010193 | 3010000 | root | `python3` | 99.81 / 101.00% | 11.3% at detail snapshot | `Rs` / CPU 3 | 1 | 0–9 | `/usr/bin/python3.11` | 21:02:05 | `otv-worker-1` |
| 3039115 | 1704 | UID 999 | `postgres` | 50.40 / 75.00% over 4 samples | 1.0% | `Rs` / CPU 4 | 1 | 0–9 | namespace path unavailable | 21:12:18 | `etv-test-db-1`; short-lived backend |
| 2987330 | 1704 | UID 999 | `postgres` | 17.12 / 21.00% | 0.8% | `Ss` / CPU 7 | 1 | 0–9 | namespace path unavailable | 20:55:46 | `etv-test-db-1` |
| 1328459 | 1328448 | root | `codex` | 9.74 / 10.00% | 1.7% | `Sl+` / CPU 5 | 18 | 0–9 | Codex binary | Oct 19 09:28 | host session 264 |
| 2477537 | 2477501 | root | `codex` | 7.95 / 8.00% | 0.6% | `Sl+` / CPU 7 | 18 | 0–9 | Codex binary | 17:30:35 | host session 1179 |
| 3014737 | 1704 | UID 999 | `postgres` | 7.95 / 9.00% | 0.5% | `Ss` / CPU 2 | 1 | 0–9 | namespace path unavailable | 21:03:38 | `etv-test-db-1` |
| 102 | 2 | root | `kswapd0` | 5.18 / 10.00% | n/a | kernel | 1 | scheduler | kernel | boot | host kernel |
| 82 | 2 | root | `kcompactd0` | 4.80 / 12.00% over 3 samples | n/a | kernel | 1 | scheduler | kernel | boot | host kernel |
| 1203 | 1 | root | `dockerd` | 2.78 / 4.00% over 4 samples | low | daemon | multi-thread | 0–9 | Docker daemon | boot | host system slice |

UID 999 resolves to a host account name unrelated to PostgreSQL; cgroup membership is used for container ownership. Transient PostgreSQL children ended or changed during inspection, which is expected for database query backends.

## Additional process observations

- `otv-worker-1` contained persistent `bun` PID 3010000 and Python child PID 3010193. Later container-level samples reached far above one core, indicating additional short-lived work that a single PID snapshot cannot retain.
- Multiple `dumpcap` processes belonged to the POLARIS capture container. Individually they remained near 0–1% CPU during the PID sample, although process creation and context switching were visible.
- Open5GS, UERANSIM and MongoDB processes were present. MongoDB averaged about 1% in the PID window but spiked in later Docker samples.
- Exact process-name scan found no running `benchmark-engine` process after S2.

## Scheduler activity during the five-second observation

- Runnable tasks: 1–5 per `vmstat` interval; blocked tasks: 0–1.
- Context switches: approximately 7,197–15,391/s in the short observation.
- All major user processes inspected had effective CPU affinity 0–9.
- Current process inventory is evidence of current contention only; it is not proof of PID activity during S2.

## Evidence commands

```text
pidstat -u -h 1 5
ps -p PID -o pid,ppid,user,pcpu,pmem,stat,psr,nlwp,lstart,comm
taskset -pc PID
readlink -f /proc/PID/exe
cat /proc/PID/cgroup
vmstat 1 6
```

