# V3.2.1 Regression Tests

All tests used offline fixtures, mocks or read-only production requests.

- Rust workspace: **84/84 PASS**.
- POLARIS API crate: **50/50 PASS**, including 13 new deterministic CPU-safety tests.
- Frontend Vitest: **5/5 PASS**.
- TypeScript check: **PASS**.
- Frontend production build: **PASS**.
- UE-targeted offline E2E: **1/1 PASS**.
- Production read-only CPU/browser E2E: **1/1 PASS**.

Covered cases include ten CPUs with one busy process, a one-CPU API cgroup on an idle host, host saturation, target quota exhaustion, throttling, PSI pressure, transient spikes, sustained contention, stale data, missing cgroups, invalid counter deltas, overcommit, concurrent reservations, hysteresis, recovery, auth, shared UE protection and existing UDP lifecycle behavior.

No production stress test, live UE action, traffic action or capture action was executed.
