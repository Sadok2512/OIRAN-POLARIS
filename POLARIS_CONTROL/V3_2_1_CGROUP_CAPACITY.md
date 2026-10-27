# V3.2.1 Cgroup Capacity Validation

Production uses cgroup v2.

- POLARIS API cgroup: `/system.slice/polaris-control.service`
- `cpu.max`: `100000 100000` = 1.00 CPU
- Effective cpuset: `0-9` = 10 logical CPUs
- UE runtime envelope: Docker `--cpus 0.75 --memory 512m`
- OIRAN API capacity: 1.00 CPU
- OIRAN Capture Helper capacity: 1.00 CPU
- Combined configured OIRAN capture-worker ceiling: 2.00 CPUs

The API quota is evaluated only as API capacity/throttling evidence. It is never used as the denominator for host utilization. UE lifecycle admission uses the explicit 0.75-CPU target envelope and host headroom. Parent cgroup restrictions are walked and the most restrictive quota/cpuset is used.

No cgroup configuration, quota, affinity or systemd resource limit was modified.
