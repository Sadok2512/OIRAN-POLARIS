# S2 CPU contention analysis

## Host scheduling and virtualization

| Attribute | Evidence | Assessment |
|---|---|---|
| Logical CPUs | 10 online, CPU 0–9 | Available to host and unrestricted workloads |
| Topology | 1 socket, 10 cores, 1 thread/core | No SMT sibling contention |
| NUMA | One node containing CPU 0–9 | No cross-NUMA penalty exposed |
| Hypervisor | KVM full virtualization | Virtual scheduling applies |
| Frequency | ~1995.312 MHz reported on every vCPU | Guest cpufreq driver/governor not exposed |
| Cgroups | Unified cgroup v2 | Benchmark session and ETV/OTV are unlimited |
| Current five-second CPU | 21.67% user, 6.77% system, 1.31% iowait, 0.14% steal, 69.33% idle | Spare aggregate CPU existed, but individual cores 6/8 were intermittently busy |
| Current pressure at audit start | CPU `some avg10=12.79%`, `full=0%` | Runnable work experienced delay; no whole-machine CPU stall |
| Current runnable count | 1–5 during `vmstat`; initial `/proc/loadavg` 6 runnable / 1202 tasks | Dynamic contention, not continuous global saturation |

## Historical S2 window

The sysstat archive has one point spanning 20:50:10–21:00:19, which overlaps the short S2 matrix runs:

- CPU: 20.77% user, 10.47% system, 5.62% iowait, 0.31% steal, 62.82% idle.
- Per-core idle: 59.62–65.97%; CPU 0–4 specifically retained 59.62–64.04% idle over the aggregate interval.
- Run queue at 21:00: 2; load average 4.14/4.09/4.29; blocked tasks 0.
- Context switches: 18,667/s; process creations: 55.6/s.
- Kernel journal: no OOM, watchdog, soft-lockup or CPU-throttling warning in the inspected window.

This evidence rules out sustained whole-VM CPU exhaustion and material hypervisor steal. Its approximately ten-minute resolution cannot resolve individual 100 ms benchmark points or identify which PID ran on a worker core at that instant.

## Docker lifecycle correlation

Docker journal evidence during S2:

- 20:50:12: `otv-candidate-110` joined the OTV network.
- 20:58:29: prior `otv-app-1` and `otv-worker-1` exited with code 137 and `hasBeenManuallyStopped=true`.
- 20:58:31–20:58:32: replacement OTV init/app/worker containers joined.
- 20:59:26: replacement worker was manually stopped with exit 137.
- 21:02:03: current worker started, after the S2 measurement window.

No kernel OOM event accompanied these transitions. The lifecycle overlap can introduce scheduling and I/O noise, but the current high CPU worker did not exist during the benchmark. Historical per-container CPU statistics are unavailable, so OTV CPU consumption during the individual S2 points is UNKNOWN.

During this later diagnostic, the POLARIS capture container independently restarted at 21:11:42 with exit code 0 and no OOM, then returned healthy. The audit did not trigger it. Its process churn affects the current PID sample only, not the completed S2 window.

## Benchmark scheduling analysis

At reference commit `089aebe3a0ddc81c39866efed100663da89bec89`:

1. Outer `taskset -c 0-4` restricted the entire benchmark to CPUs 0–4.
2. Worker `N` called `sched_setaffinity` with absolute CPU `N`: workers used CPU 0, 1, 2, and 3 as their count increased.
3. The producer/main thread retained mask 0–4 and was not pinned to a dedicated CPU. It could migrate and could share CPU 0–3 with workers; historical thread-level scheduling was not recorded.
4. External ETV/OTV processes retained affinity 0–9, so CPU 0–4 were not exclusive.
5. The benchmark cgroup was unlimited and reported no throttling; worker affinity failures were zero.
6. No benchmark process remained after tests.

The design therefore contains a confirmed affinity-overlap risk, but not proof that producer/worker collision occurred during each run.

## Engine versus infrastructure evidence

At batch 256 / 1500 bytes, one worker achieved 2.999539 Gbit/s at 187.66% process CPU. Two workers achieved only 3.175694 Gbit/s at 197.52% CPU; three/four workers regressed. A one-worker process consuming nearly two cores means the producer and worker already account for most useful work. Adding workers without parallelizing packet generation did not materially increase process CPU or supply.

This is direct evidence of a producer-side ceiling. Shared-host contention adds variance, but sustained spare CPU and low steal during the historical aggregate make infrastructure contention insufficient as the primary explanation.

## What cannot be reconstructed

- Per-PID and per-container CPU during each 100 ms S2 point.
- Producer CPU residency/migration and involuntary context switches per run.
- Per-run cgroup CPU pressure and scheduler delay.
- CPU-frequency/turbo behavior at the hypervisor host.
- Old OTV worker cgroup usage after its removal.

Retrospective attribution of individual low-throughput rows to a specific external PID is therefore not possible.

