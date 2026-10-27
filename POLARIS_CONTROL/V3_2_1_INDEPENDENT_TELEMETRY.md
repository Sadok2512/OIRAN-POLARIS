# V3.2.1 Independent Telemetry Comparison

Independent `mpstat 1 5` at 2026-10-26T22:33:10Z measured an average 62.33% idle, 25.77% user, 8.79% system, 0.72% iowait and 1.10% steal across ten CPUs. The API sample taken immediately afterward reported 76.20% idle, 23.80% busy and 0.40% steal over its own one-second window. The values differ as expected because the observation windows differ, while both represent host-wide ten-CPU utilization.

The same API response reported:

- host logical CPUs: 10;
- API cgroup capacity: 1.00 CPU;
- effective cpuset: 10 CPUs;
- PSI some avg10: 3.87%;
- current throttling delta: zero;
- safety state: `READY`.

The final sample at 22:35:20Z was 17.33% busy, 76.95% idle, 0.80% steal, PSI some avg10 5.01%, zero current throttling and `READY`. This proves the one-CPU API quota is no longer mistaken for total host capacity.
