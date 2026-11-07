# Authenticated browser evidence

Date: 2026-11-04 UTC. Candidate UI: `@oiran/web 2.7.2`, served only on
`127.0.0.1:4173`; API proxy: production OIRAN on `127.0.0.1:49152`. No
production asset or service was changed.

## Procedure

1. Start the candidate with
   `OIRAN_DEV_API_TARGET=http://127.0.0.1:49152 npm run dev`.
2. Start Chromium at 1440×900 and place the existing Operator bearer in
   `sessionStorage` from the root-only token file. The token value is never
   printed or written to the report.
3. Open
   `/investigation/callflow/5g-session-18fe28a814c4b094`.
4. Expand N2↔SBI details, capture the visible evidence, reload the page, and
   compare the complete bridge panel text.

## Results

- Authentication: HTTP 200, `authenticated=true`, `role=operator`.
- Session, Call Flow, and correlations requests: HTTP 200 before reload and
  HTTP 200 again after reload.
- Initial UI: N2↔SBI `CORRELATED`; SBI↔N4 `CORRELATED`; N4↔N3 `NO_DATA`;
  E2E `NO_DATA`.
- N2↔SBI detail displayed raw `STRONG`, the edge/event identifiers,
  `pdu_session_id=1`, and DSN packet coordinates from N2 and SBI sources.
- Reload comparison: exact panel text equality (`reload_equal=true`). This
  proves the candidate refetched and did not display a stale alternate state.
- Screenshot: [browser-evidence-1440.png](browser-evidence-1440.png).

No DEMO dataset was used. The session and all edges came from the running OIRAN
2.7.15 API.
