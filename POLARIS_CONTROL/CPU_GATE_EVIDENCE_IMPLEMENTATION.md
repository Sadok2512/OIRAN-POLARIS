# CPU Gate Decision Evidence

POLARIS now persists every admission decision used by a live start path as an atomic, mode `0600` JSON store. Records contain a monotonic decision ID, wall-clock timestamp, state/classification, blocking flag, exact trigger metric/value/threshold/comparator, sample window, host utilization, PSI, cgroup capacity and throttling deltas, scenario budget, telemetry age, and final reason.

The store is bounded to 256 records. Parent directories are created with restrictive permissions, temporary writes are fsynced and renamed atomically, and a persistence failure fails the admission request closed. Operator and Administrator roles can inspect the last 50 records at `GET /api/v1/system/cpu-decisions`; Viewer access is denied. HTTP 503 responses now include the exact decision evidence instead of only `WARNING`.

No authentication material or UE subscriber secret is recorded.
