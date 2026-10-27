# POLARIS E2E-002 Regression Tests

| Suite | Result |
|---|---:|
| Rust workspace | 88/88 PASS |
| API | 54/54 PASS |
| Frontend unit | 5/5 PASS |
| TypeScript | PASS |
| Production build | PASS |
| Candidate browser E2E | 20/20 PASS |
| Authenticated browser cases | 3/3 PASS |

The browser candidate used port 49253, a copied non-production registry, disabled execution mode, and a dedicated injected Operator credential. Assertions cover 1/3/5/10 profile rendering, configuration persistence, shared UE protection, targeted traffic eligibility, and CPU safety evidence.
