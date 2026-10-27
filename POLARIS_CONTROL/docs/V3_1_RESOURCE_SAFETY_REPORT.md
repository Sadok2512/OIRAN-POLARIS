# V3.1 Resource Safety Report

Audit date: 2026-10-25 UTC.

- Root filesystem: 387 GiB total, 185 GiB used, 203 GiB available, 48% utilized.
- Inodes: 2% utilized.
- Memory: 19 GiB total, approximately 14 GiB available.
- CPU pressure: some avg10 3.82%; full 0.00%.
- Memory pressure: some/full avg10 0.39%.
- Open5GS, shared UERANSIM and capture containers reported healthy during the audit.

Disk policy remains 75% information, 80% warning, 85% stop new capture writes and 90% hard limit. Every future Start must repeat live CPU, memory, disk, pressure and lab-health checks. No bypass or automatic cleanup was introduced.

These measurements support offline implementation only; they do not authorize five live UEs.

