# S4 Implementation Report

## Outcome

S4 implements a working, localhost-only OIRAN investigation application over the certified S3.3 artifacts. The application displays 54 source events, 26 session events, 28 background events and 12 correlation edges without synthesizing sessions or messages.

## Implemented modules

| Module | Version | Result |
|---|---:|---|
| Platform Core | 1.0.0-dev | Shared shell, routing, authentication and module registry |
| Backend API | 1.0.0 | Axum read-only adapter under `/api/v1` |
| Web Frontend | 1.0.0-dev | React/TypeScript production build |
| Probe Manager | 1.0.0-dev | One observed vProbe, three interfaces and three real captures |
| Session Explorer | 1.0.0-dev | One certified session; background kept separate |
| Call Flow Viewer | 1.0.0-dev | Real SVG timeline, IE/provenance/evidence inspector and exports |
| Correlation Studio | 1.0.0-dev | All 12 engine edges, rule metadata and ambiguity tabs |

The API reuses `callflow-schema::CallFlow`; React performs no protocol decoding or correlation. Certified files are opened read-only and never rewritten.

## Resource and integration results

- Frontend distribution: 336 KiB on disk; main JS 307.39 KiB (93.61 KiB gzip).
- Backend RSS during bounded checks: 10,488 KiB.
- Mean call-flow API response: 3.985 ms over 20 localhost requests (3.573–4.374 ms).
- Authenticated initial render: 390.55 ms; session render: 128.09 ms; call-flow render: 148.35 ms.
- Browser JS heap observation: approximately 10,000,000 bytes on the 54-event dataset.

These small-dataset measurements are functional baselines, not production-scale claims.

## Protection

No ETV/OTV or POLARIS command, configuration, network, volume or database was modified. Certified JSON/HTML/PCAP and POLARIS sentinel hashes matched their baselines after testing. External OTV application and POLARIS capture-container lifecycle transitions were observed during final read-only inspection; S4 issued no Docker lifecycle operation and does not attribute those transitions.
