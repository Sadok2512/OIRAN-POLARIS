# CPU Safety Regression

`cargo test -p polaris-control-api --no-fail-fast`: 54/54 passed.

Coverage includes transient and sustained throttling, host saturation, one-CPU API quota on an idle ten-CPU host, target cgroup exhaustion, PSI, resource overcommit, stale/missing telemetry, invalid `/proc/stat` deltas, recovery hysteresis, concurrent starts, exact traffic-job ownership, shared UE protection, protected atomic evidence storage, bounded retention, and evidence-bearing HTTP 503 semantics.

Frontend typecheck, unit tests, and production build are recorded in the final report. No live action or production change occurred.
