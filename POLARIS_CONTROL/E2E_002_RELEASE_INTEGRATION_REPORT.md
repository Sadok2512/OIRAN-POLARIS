# E2E-002 POLARIS Release Integration

Generated: 2026-10-27T00:12:47Z

The release candidate is based on CPU-evidence commit `c0a4369006b5b039110e2ef773a9d48a6b295450`, whose ancestry contains the certified V3.2/V3.2.1 implementation through `d865de0`, `7845580`, and `3894559`.

The candidate restores the existing V3.2 operational controls while retaining the CPU decision history, warning classification, PSI, cgroup throttling, resource budget, freshness, and hysteresis implementation. Configuration-only actions do not start a UE. Group lifecycle requests still use the authenticated typed Rust API and exact UE identifiers.

Work was performed in the isolated worktree `.worktrees/e2e_002_release`. No production binary, service, registry, UE, traffic job, Open5GS component, or ETV/OTV workload was changed.
