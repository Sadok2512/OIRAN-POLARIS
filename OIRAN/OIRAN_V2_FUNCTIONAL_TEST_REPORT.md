# OIRAN V2 Functional Test Report

## Results

| Suite | Result |
|---|---:|
| Rust workspace and API | 97/97 PASS |
| Frontend unit/component | 9/9 PASS |
| Browser end-to-end | 33/33 PASS |
| TypeScript | PASS |
| Frontend production build | PASS |
| Rust release API build | PASS |

Browser coverage includes both themes, seven primary views, 1440×900 and 1920×1080 overflow checks, session navigation, NGAP/PFCP/GTP-U inspection, evidence selection, exports, packet provenance, disk safety and capture-control refusal.

## Certified data accounting

- Source events: 54.
- Session events: 26.
- Background events: 28.
- Correlation edges: 12.
- N2↔N4: STRONG; N4↔N3: EXACT; E2E: STRONG.

## Bounded measurements

- Health API response: 0.001 seconds observed locally.
- Sessions API response: 0.001 seconds observed locally.
- Overview browser load event: 58 ms observed on the local listener.
- Frontend bundle: 331.14 kB JavaScript and 22.84 kB CSS before gzip.
- Backend current/peak memory after deployment: approximately 5.1/6.1 MiB.

These measurements use the 54-event dataset and are not scalability certification.
