# OIRAN E2E-002 Regression Tests

| Suite | Result |
|---|---:|
| Rust workspace | 178/178 PASS |
| API | 20/20 PASS |
| Frontend unit | 20/20 PASS |
| TypeScript | PASS |
| Production build | PASS |
| Browser E2E | 47/47 PASS |
| Authenticated candidate scenario | 1/1 PASS |

The new Rust cases cover atomic, idempotent registration and conflicting-ID rejection. API coverage verifies authorization and safe request-path handling. The complete browser suite ran against an isolated candidate API containing a copied read-only registry plus the derived import.
