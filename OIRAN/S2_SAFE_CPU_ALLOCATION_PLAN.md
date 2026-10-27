# S2.1 safe CPU allocation plan

This is a proposal only. No affinity, cgroup, service or system setting was changed.

## Resume gates

Before S2.1, require all of the following:

- ETV/OTV owner confirms the deployment/worker cycle is expected and stable.
- No relevant Docker start/stop/die/recreate event for at least 15 minutes.
- All protected health checks remain healthy; no OOM/kernel warning.
- Five-minute CPU observation shows CPU PSI `some avg10 < 2%`, `full = 0%`, steal <1%, and at least three candidate CPUs >85% idle for a two-worker test.
- Available RAM >8 GiB and no sustained memory/IO full pressure.
- No other `benchmark-engine` process exists.

If these conditions are not met, postpone; do not stop ETV/OTV.

## Recommended benchmark topology

For the first S2.1 run, keep two workers because this was the measured optimum. Use three distinct logical CPUs on the single NUMA node:

```text
producer: one dedicated selected CPU
worker 0: second selected CPU
worker 1: third selected CPU
```

Do not hard-code CPU 0–2. Select the least busy three CPUs from a five-minute `mpstat -P ALL` window immediately before execution. Add benchmark options such as `--producer-cpu P --worker-cpus W0,W1`; the current `worker_id → absolute CPU ID` mapping cannot express this safely.

For an approved four-worker investigation, use five distinct CPUs (one producer + four workers), still within the user-approved four-worker maximum. Run two-worker validation first.

## Cgroup strategy requiring approval

A transient benchmark scope may enforce safety limits:

- memory maximum: 1 GiB;
- CPU maximum: 300% for producer + two workers;
- PIDs maximum: small bounded value;
- `AllowedCPUs`: the three selected CPUs;
- five-second wall timeout and existing internal pressure guard.

This constrains OIRAN but does not exclude unrestricted ETV/OTV from those CPUs. True exclusive CPU isolation requires an owner-approved cpuset partition for all workloads or, preferably, a dedicated benchmark VM. Do not change ETV/OTV cpusets without explicit owner approval.

## Per-run telemetry required

Capture small read-only snapshots immediately before/after every profile:

- `/proc/stat` CPU and steal deltas;
- `/proc/pressure/cpu`, memory and IO;
- benchmark cgroup `cpu.stat` and `cpu.pressure`;
- each benchmark thread ID, allowed mask, last CPU and voluntary/involuntary context switches;
- `mpstat -P ALL` and selected container CPU summaries;
- Docker lifecycle and health state.

Store timestamps alongside each CSV result. Reject a repetition if a protected-container lifecycle event, OOM, steal ≥1%, selected-core idle violation, or unexpected cgroup throttling occurs.

## Measurement order

After gates and approval:

1. Run generator-only, processing-only and full modes with identical frames/batches/distribution.
2. Use three repetitions and medians; start at 100–250 ms.
3. Confirm generated = processed + explicit drops and require zero drops for capacity claims.
4. Compare producer-dedicated placement with the original mask using the same quiet window.
5. Stop if PSI or protected-service health crosses the gate.

Only after these checks should S2 be reconsidered for certification. S3 must not start from this diagnostic.

