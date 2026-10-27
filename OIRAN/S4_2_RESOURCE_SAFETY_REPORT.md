# S4.2 resource safety report

Observed before preparation:

- 10 logical CPUs; CPU PSI some avg10 3.46%, full avg10 0.00%.
- approximately 15 GiB memory available; no swap.
- root filesystem 387 GiB total, approximately 304 GiB used and 82–83 GiB available; rounded `df` utilization 79%.
- inode utilization 3%.
- ETV/OTV containers were running; relevant database containers reported healthy where health checks exist.
- POLARIS Open5GS, UERANSIM gNB/UE and capture containers were running; capture reported healthy.

No benchmark, traffic generation, service restart, container lifecycle operation, route/firewall edit or capture write was performed. The audit itself used bounded metadata queries.
