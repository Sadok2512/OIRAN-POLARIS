# POLARIS-E2E-CORRELATION-UI-P0 — final report

API_STATUS = PASS — the session, paginated Call Flow, and correlation evidence endpoints returned HTTP 200 for a real 5G SA session.

UI_STATUS = PASS — the UI uses the explicit seven-state presentation contract and exposes reasons plus evidence identifiers.

N2_SBI = CORRELATED — raw STRONG plus one rule-backed N2↔SBI edge.

SBI_N4 = CORRELATED — raw STRONG plus one rule-backed SBI↔N4 edge.

N4_N3 = NO_DATA — N3 is absent from the observed session interfaces; no correlation is inferred.

E2E = NO_DATA — the required N4↔N3 bridge lacks data, so no E2E pass is shown.

BROWSER_TEST = PASS — authenticated Chromium 1440×900, detail expansion, hard reload, and fresh HTTP 200 reads passed.

DSN = PASS — immutable source-file/packet coordinates are visible per bridge with evidence and matching keys.

VERSION_COMMIT = @oiran/web 2.7.2 on branch fix/anr3-polaris-e2e-correlation-ui-p0; exact commit is the Git commit containing this report.

PRODUCTION_CHANGED = NO.

VERDICT = READY_FOR_INTEGRATION — not deployed.

## Manual guards

```text
npm run typecheck
PASS

npm test
12 files passed; 83 tests passed; 0 failed

npm run build
TypeScript PASS; Vite PASS; 1637 modules transformed
check-dist-leaks: clean (3 files scanned, 2 markers)

Authenticated Chromium against real session
PASS: auth HTTP 200/operator; API 200; reload_equal=true
```

## Rollback

Revert the integration commit or restore Analyzer web 2.7.1 assets. No API,
database, engine, decoder, capture, or production configuration migration is
required.
