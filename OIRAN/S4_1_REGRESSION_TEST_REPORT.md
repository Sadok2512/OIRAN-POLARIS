# S4.1 regression test report

## Results

| Suite | Result |
|---|---:|
| Rust workspace release tests | 85/85 PASS |
| API tests (included in Rust total) | 11/11 PASS |
| Frontend Vitest | 9/9 PASS |
| Browser/E2E workflows | 28/28 PASS |
| TypeScript check | PASS |
| React production build | PASS |

New coverage includes five UEs, multiple PDU sessions per UE, concurrent ordering, lifecycle identifier reuse, incomplete sessions, duplicate import, deterministic IDs, ambiguous TEID rejection, dataset/UE routes, API pagination, session-scoped procedures, independent Call Flow lookup, URL filter persistence and session selection.

The certified artifacts and captures have no Git diff from base commit `d3d92eae3d6883dba0d66aa9f0fc26ea3be1a5d2`. Reference SHA256 values:

- Call Flow JSON: `bc89ddd79d23af2ad53a5bc0b46e69c988fbc02d69b92c9462ece760b27432cb`
- N2: `2f23390dd619dda464ec8f2cfbd3b9fe59ca0587b043f6267a8ffc5a752cf54e`
- N3: `806a4ae1eb758a1b2c08ae10d7b7f54881c5e571c7f80ed047f564cb222cb35a`
- N4: `8fad2f3401e79ea1695aa26cba649c03711e24ee0602625ec569ef82c3e6cfe7`
