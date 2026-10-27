# V3.2.1 Scenario Resource Budgets

| Scenario | CPU | RAM | Storage | Execution cgroup/envelope |
|---|---:|---:|---:|---|
| Five bounded UDP datagrams | 0.10 CPU | 64 MiB | 0 | POLARIS controlled job |
| One additional UERANSIM UE | 0.75 CPU | 512 MiB | 0 | Docker `--cpus 0.75 --memory 512m` |
| Four-plane OIRAN capture | 2.00 CPUs | 512 MiB | 256 MiB | Two one-CPU OIRAN services |

The four-plane budget is published for evidence but is not charged to the POLARIS API cgroup. Multiple UE requests scale the UE budget and remain bounded by the controller orchestration and host-headroom checks. Existing disk, memory, job ownership and duplicate-execution controls remain mandatory.
