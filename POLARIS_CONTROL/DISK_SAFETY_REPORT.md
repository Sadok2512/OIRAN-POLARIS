# Disk Safety Report

## Measurement

The capture volume is on `/dev/sda1` (ext4), the same filesystem as `/var/lib/docker`.

| Metric | Observed |
|---|---:|
| Total | 414,921,494,528 bytes |
| Used | 352,753,250,304 bytes |
| Available | 62,168,244,224 bytes |
| Exact utilization | 85.01% |
| Available inodes | 50,764,779 |
| Capture volume allocated blocks | 57,233,408 bytes |
| Capture files | 281 across 12 interface directories |
| Observed 10-second capture growth | 8,192 bytes, about 819 B/s |
| Controller capture write budget | 0 bytes |

The filesystem crossed 85% during this audit despite the capture volume growing only 8 KiB in the sample. This demonstrates concurrent non-capture growth and makes a short sample unsuitable as a capacity guarantee.

## Rotation finding

Each active interface writer uses 256 MiB files, 8 files, and a one-hour timeout. There are 12 interface writers. Because each hourly/container restart creates a new timestamped basename, the per-process ring does not impose a global retention bound. The capture container restart count is 20. This is a `REVIEW_REQUIRED` retention gap; no file was deleted or rotated by this audit.

## Decision and required gate

`BLOCKED_DISK_SAFETY`: the 85% stop threshold is exceeded and POLARIS Control correctly reports `STOP_NEW_WRITES`.

Before any approved phase, require stable usage below 80% for 15 minutes and a measured nonzero budget. For the functional N2/N3/N4 run, propose two 32 MiB files per interface (192 MiB total), 64 MiB for logs/manifests, plus at least 1 GiB external-growth reserve. Fail closed if measurement fails or projected usage reaches 85%. No automatic cleanup is permitted.

