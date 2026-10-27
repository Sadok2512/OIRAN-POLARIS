# OIRAN V2.3 Test Report

| Suite | Result |
|---|---|
| Rust workspace | PASS — 134 tests |
| API crate | PASS — 18 tests |
| Frontend unit/component | PASS — 18 tests in 7 files |
| TypeScript | PASS |
| Production frontend build | PASS — 352.39 kB JS, 28.81 kB CSS |
| Browser E2E | PASS — 44 tests |
| V2.3 focused browser tests | PASS — 7 tests |

Reproducible commands:

```text
cargo test --workspace
cd apps/web && npm run typecheck
cd apps/web && npm test
cd apps/web && npm run build
cd apps/web && OIRAN_E2E_BASE_URL=http://127.0.0.1:4173 npm run test:e2e
```

E2E used an isolated candidate API on loopback port 49156 and Vite on loopback port 4173. Capture execution was disabled. Production port 49152 and its services were not restarted or modified.
