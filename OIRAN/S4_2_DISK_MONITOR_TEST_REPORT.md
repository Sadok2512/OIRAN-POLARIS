# S4.2 disk monitor test report

Mocked filesystem tests do not allocate production disk space.

Validated cases:

- 74% NORMAL, exactly 75% INFORMATION, 80% WARNING, 85% STOP_NEW_CAPTURES and 90% DISK_HARD_LIMIT;
- measurement failure rejects writes and finalizes an active job;
- insufficient threshold headroom, write budget and inode capacity reject capture;
- 256 MiB × 8 bounded rotation with a 2 GiB maximum job;
- an active guard accepts warning-state writes only within budget, then finalizes at 85%;
- budget exhaustion and operator interruption prevent every subsequent write;
- read-only analysis remains allowed at stop and hard-limit states;
- the module contains no deletion operation.

Result: 7/7 `disk-safety` tests PASS. Current filesystem state during audit was approximately 78.73%, therefore INFORMATION, with about 82 GiB available and 3% inode utilization.

Full regression result: 93/93 Rust release tests, including 12/12 API tests; 9/9 frontend tests; and 29/29 browser workflows.
