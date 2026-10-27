# OIRAN-E2E-001 Resource Safety

Observed filesystem state:

- Utilization: 62.68% (NORMAL).
- Available bytes: 154,832,437,248.
- Available inodes: 51,124,967.
- OIRAN capture directory: 846,760 bytes.
- Requested future capture budget: 256 MiB.
- Poll interval: 1 second; reserved write headroom: 32 MiB; fail-closed monitoring.
- Available RAM: approximately 15.4 GB.

Resource status for live execution: **BLOCKED_CPU_CONTENTION**.

The OTV worker consumed approximately 101.5–102.0% CPU in three consecutive samples on the single logical CPU reported by POLARIS Control. ETV/OTV remained running, but the test will not be allowed to add simulator/capture load until repeated pre-execution samples demonstrate acceptable headroom and service health.

Disk thresholds remain 80% warning, 85% capture stop and 90% hard limit. No automatic deletion is permitted.

