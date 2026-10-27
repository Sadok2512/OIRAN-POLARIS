# S5.6 Retry Web E2E Report

The Playwright suite ran against the deployed `http://127.0.0.1:49152` application, not a mock server.

- Tests: 46/46 PASS.
- Local Web: HTTP 200.
- Public gateway: HTTP 200.
- Probe Manager: four real planes visible.
- Capture Library: historical/live states and exact errors work.
- Session Explorer: exact dataset context and zero-session states work.
- Call Flow Viewer: directional NGAP/PFCP/GTP-U arrows and synchronized selection work.
- Message Inspector: actual decoded fields and provenance work.
- Themes: Light and Dark PASS.
- Viewports: 1440x900 and 1920x1080 PASS.

Twenty production screenshots are stored under `S5_6_RETRY_SCREENSHOTS/`. Visual review found no horizontal page overflow, clipped primary controls, duplicate page headers or fabricated metrics.

