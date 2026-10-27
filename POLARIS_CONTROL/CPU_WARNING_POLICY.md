# CPU Warning Policy

States are `READY`, `WARNING_NON_BLOCKING`, `WARNING_BLOCKING`, and `BLOCKED`.

- A transient host-utilization, PSI, or throttling breach is `WARNING_NON_BLOCKING` while every mandatory capacity, freshness, and budget check passes.
- Three consecutive equivalent breaches become `BLOCKED` and latch.
- A latched condition remains `WARNING_BLOCKING` until three consecutive recovery samples pass the lower recovery thresholds.
- Unknown capacity, stale/invalid telemetry, and scenario resource overcommit block immediately.
- Host CPU, target cgroup capacity, PSI, throttling deltas, and scenario reservations remain independent mandatory checks.

This policy does not turn every warning into permission and does not weaken disk, memory, authorization, or ownership gates.
