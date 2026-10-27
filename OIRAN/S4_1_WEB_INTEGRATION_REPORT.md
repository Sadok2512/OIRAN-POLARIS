# S4.1 Web integration report

The existing S4 design system and shared shell are preserved.

- Session Explorer now queries datasets, UE contexts and paginated sessions; filters persist in the URL and session/event pagination are independent.
- Required dataset, UE, technology, interface and state filters are available.
- Each table row deep-links to its own session details and Call Flow.
- Call Flow Viewer no longer defaults to a literal session. Its selector resolves the chosen backend session, and rendering remains canonical-data only.
- Correlation Studio supports dataset, UE, session and interface selection and requests session-scoped evidence from Rust-backed API data.
- Background events remain a separate tab/toggle and are never counted as UE-session messages.

Real browser screenshots are stored in `S4_1_UI_SCREENSHOTS/` at 1440×900 and 1920×1080. Both layouts pass document-overflow checks. The compact session table preserves all required columns without page-level overflow.
