# S2 Docker CPU audit

## Summary

Three bounded `docker stats --no-stream` samples show a highly dynamic shared host. In the recorded window, grouped average CPU was ETV 89.88%, OTV 758.85%, and POLARIS 29.27%. The OTV value was dominated by a later burst in `otv-worker-1`; a prior three-sample window showed approximately 102% for that container. The POLARIS window coincided with an external capture-container restart and is not a steady-state value. These are current observations, not historical S2 measurements.

All ETV/OTV containers are unrestricted (`cpu.max=max`, effective CPUs 0–9, weight 100). POLARIS containers have explicit 0.25–1.0 CPU quotas but also use effective CPUs 0–9. None has an exclusive cpuset.

## Running-container inventory

CPU is three-sample average/peak. Memory and PIDs are from the last sample. `CPU max` is quota/period in microseconds; `max` means unrestricted. All effective cpusets are 0–9 and all CPU weights are 100.

| Container | ID | CPU avg/peak | Memory usage/limit | PIDs | CPU max | Weight | CPUs | Restarts | Started UTC | OOMKilled |
|---|---|---:|---|---:|---|---:|---|---:|---|---|
| `etv-local-app-1` | `4174c121568f` | 0.00 / 0.00 | 69.35MiB / 19.53GiB | 11 | `max/100000` | 100 | 0–9 | 0 | 2026-10-18 18:26:23 | false |
| `etv-local-db-1` | `c2377e578a17` | 2.20 / 6.57 | 25.7MiB / 19.53GiB | 7 | `max/100000` | 100 | 0–9 | 0 | 2026-10-17 21:33:17 | false |
| `etv-local-worker-1` | `5deee62c6133` | 0.21 / 0.28 | 67.4MiB / 19.53GiB | 17 | `max/100000` | 100 | 0–9 | 1 | 2026-10-17 21:33:18 | false |
| `etv-test-app-1` | `3e27d85805aa` | 0.00 / 0.00 | 136.8MiB / 19.53GiB | 11 | `max/100000` | 100 | 0–9 | 0 | 2026-10-23 17:07:31 | false |
| `etv-test-db-1` | `82e1ab0f3548` | 87.47 / 88.30 | 1.262GiB / 19.53GiB | 11 | `max/100000` | 100 | 0–9 | 0 | 2026-10-17 21:33:17 | false |
| `oiran-lab-amf-1` | `fa367e0536da` | 0.00 / 0.00 | 20.7MiB / 512MiB | 2 | `50000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:50:03 | false |
| `oiran-lab-ausf-1` | `650e3b1c9a48` | 0.02 / 0.06 | 6.172MiB / 256MiB | 2 | `25000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:49:37 | false |
| `oiran-lab-bsf-1` | `a06bb9c55f0f` | 0.00 / 0.00 | 5.906MiB / 256MiB | 2 | `25000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:51:40 | false |
| `oiran-lab-capture-1` | `5877da8e59e1` | 1.37 / 3.65 | 12.27MiB / 512MiB | 25 | `100000/100000` | 100 | 0–9 | 1 | 2026-10-24 21:11:42 | false |
| `oiran-lab-controller-1` | `a6d30c4ea7da` | 0.00 / 0.00 | 684KiB / 512MiB | 1 | `50000/100000` | 100 | 0–9 | 0 | 2026-10-24 20:07:32 | false |
| `oiran-lab-hss-1` | `83e54c1d4c86` | 0.06 / 0.07 | 9.125MiB / 512MiB | 39 | `50000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:53:39 | false |
| `oiran-lab-mme-1` | `188096b3f6d6` | 0.07 / 0.07 | 9.648MiB / 512MiB | 39 | `50000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:53:39 | false |
| `oiran-lab-mongodb-1` | `14b02a4c0262` | 25.92 / 75.93 | 286.2MiB / 1.5GiB | 67 | `75000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:49:14 | false |
| `oiran-lab-nrf-1` | `b5f541ee0d50` | 0.03 / 0.05 | 10.27MiB / 256MiB | 2 | `25000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:49:37 | false |
| `oiran-lab-nssf-1` | `2ae610e32eb9` | 0.00 / 0.00 | 5.77MiB / 256MiB | 2 | `25000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:50:03 | false |
| `oiran-lab-pcf-1` | `bd0ae1bef8b8` | 0.04 / 0.13 | 7.293MiB / 384MiB | 8 | `25000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:51:40 | false |
| `oiran-lab-pcrf-1` | `42c4d6ce32ff` | 0.06 / 0.07 | 8.965MiB / 384MiB | 39 | `25000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:54:00 | false |
| `oiran-lab-pgwc-1` | `2150bfd50bba` | 0.06 / 0.07 | 38.45MiB / 512MiB | 39 | `50000/100000` | 100 | 0–9 | 0 | 2026-10-24 20:08:44 | false |
| `oiran-lab-pgwu-1` | `3ed3882abd8f` | 0.00 / 0.00 | 25.6MiB / 768MiB | 2 | `75000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:53:39 | false |
| `oiran-lab-sgwc-1` | `943b0fce0799` | 1.25 / 3.68 | 25.43MiB / 384MiB | 2 | `35000/100000` | 100 | 0–9 | 0 | 2026-10-24 20:08:44 | false |
| `oiran-lab-sgwu-1` | `36783281801d` | 0.02 / 0.05 | 24.04MiB / 512MiB | 2 | `50000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:53:39 | false |
| `oiran-lab-smf-1` | `5007b5130686` | 0.04 / 0.13 | 34.66MiB / 512MiB | 2 | `50000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:52:17 | false |
| `oiran-lab-udm-1` | `72a11d30b3f3` | 0.00 / 0.00 | 6.371MiB / 256MiB | 2 | `25000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:49:37 | false |
| `oiran-lab-udr-1` | `ad1991327209` | 0.00 / 0.00 | 6.531MiB / 384MiB | 2 | `25000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:49:37 | false |
| `oiran-lab-ueransim-gnb-1` | `c9bddd91a8bc` | 0.14 / 0.14 | 3.895MiB / 512MiB | 12 | `75000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:50:27 | false |
| `oiran-lab-ueransim-ue-1` | `82ad4c418060` | 0.17 / 0.21 | 1.934MiB / 512MiB | 11 | `75000/100000` | 100 | 0–9 | 0 | 2026-10-24 20:07:40 | false |
| `oiran-lab-upf-1` | `bf9b18aa8cd6` | 0.02 / 0.05 | 25.78MiB / 768MiB | 2 | `100000/100000` | 100 | 0–9 | 0 | 2026-10-24 19:49:37 | false |
| `otv-app-1` | `f643a9463664` | 0.01 / 0.02 | 111.3MiB / 19.53GiB | 11 | `max/100000` | 100 | 0–9 | 0 | 2026-10-24 20:58:32 | false |
| `otv-db-1` | `e832f128a549` | 4.45 / 11.81 | 342.7MiB / 19.53GiB | 11 | `max/100000` | 100 | 0–9 | 0 | 2026-10-23 16:20:42 | false |
| `otv-worker-1` | `b6333e319e22` | 754.39 / 785.02 | 2.773GiB / 19.53GiB | 33 | `max/100000` | 100 | 0–9 | 0 | 2026-10-24 21:02:03 | false |

## Throttling evidence

- OIRAN benchmark session cgroup: `cpu.max=max 100000`, `nr_periods=0`, `nr_throttled=0`, `throttled_usec=0`.
- ETV/OTV selected cgroups: unrestricted and `nr_throttled=0`.
- POLARIS MongoDB is intentionally limited to 0.75 CPU and had cumulative `nr_throttled=6991`, `throttled_usec=494931565`; this limits MongoDB, not the benchmark.
- Capture container is limited to 1 CPU and showed four cumulative throttle events after its later restart.

Thus CPU quota/throttling did not limit the Rust benchmark. Container quota counters are cumulative and cannot attribute a specific event to the S2 window.

## Runtime transitions during this diagnostic

`oiran-lab-capture-1` restarted at 21:11:42 UTC with the same container ID, exit code 0, `OOMKilled=false`, and restart count 1. It was healthy afterward. The Docker journal records task deletion followed by a new host-network join; the audit issued no restart command. This transition explains short-lived `dumpcap` process churn in the PID sample and further demonstrates that current snapshots are not a stable proxy for S2 history.

