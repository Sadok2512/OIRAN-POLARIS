# V3.2 Resource Safety

Post-deployment observations:

- Root filesystem: 414,921,494,528 bytes total, 262,195,073,024 bytes used, 152,709,644,288 bytes free (approximately 63.2% used).
- Inodes: 51,110,540 free (3% used).
- Available RAM: approximately 14.7 GB.
- Load average observed near final verification: 2.59 / 2.78 / 2.56.
- The service is constrained to one logical CPU by `CPUQuota=100%`; the live start gate correctly reports `CPU_CONTENTION_LIMIT`.
- OTV remained running. A representative read-only sample showed `otv-app` around 22.12% CPU and `otv-worker` around 0.59%; neither was stopped or restarted.
- Disk thresholds remain warning 80%, stop 85%, hard limit 90%; current state is normal and writes are allowed.

The deployment itself was safe to complete, but new traffic must remain blocked until sustained CPU contention clears. No safety bypass or automatic deletion was used.

