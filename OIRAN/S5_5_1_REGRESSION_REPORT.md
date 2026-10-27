# S5.5.1 regression report

| Suite | Result |
|---|---|
| Rust workspace | 172/172 PASS |
| Capture Helper | 21/21 PASS |
| Live Probe | 19/19 PASS |
| API | 19/19 PASS |
| Frontend unit | 19/19 PASS |
| TypeScript | PASS |
| Frontend production build | PASS |
| Browser E2E | 46/46 PASS |

The E2E browser suite ran against an isolated local API on port 49252 with an offline copy of the production registry evidence. The first run used an empty registry and correctly failed only registry-dependent historical tests; it was discarded and repeated with the required fixture, producing 46/46 PASS. The production API and services were not touched.

Historical dataset source files were unchanged. Reference hashes remain:

- `oiran_events.jsonl`: `2b304387dbf9d253fb139317d246b804b3fba13f56f720926a514ab68659608b`
- `scenario_manifest.json`: `2e331e1b219b48bdb1687fd0e079e14a7b9ce2500a3613cc8792c827f5704fcd`
