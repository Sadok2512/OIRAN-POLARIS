# V3.2.1 CPU Safety Policy

Default sampling is once per second. A measurement is stale after five seconds. At least three valid samples are required. A blocking threshold must be breached for three consecutive samples; recovery also requires three consecutive samples.

| Evidence | Block threshold | Recovery threshold |
|---|---:|---:|
| Host CPU utilization | 90% | 80% |
| CPU PSI `some avg10` | 20% | 10% |
| API cgroup throttled-period ratio | 20% | 5% |
| Shared host headroom | scenario CPU + 1 CPU | same budget must fit |

States are `READY`, `WARNING`, `BLOCKED_HOST_CPU`, `BLOCKED_CGROUP_THROTTLING`, `BLOCKED_CPU_PRESSURE`, `BLOCKED_RESOURCE_BUDGET`, `BLOCKED_STALE_TELEMETRY`, and `BLOCKED_UNKNOWN_CAPACITY`.

Missing mandatory host, PSI or API-cgroup data fails closed. `WARNING` is not treated as permission to execute. The disk and RAM gates continue to apply independently. Scenario authorization, ownership and certification gates are unchanged.
