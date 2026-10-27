# OIRAN-POLARIS

Modular collaboration repository for the OIRAN and POLARIS application family.

## Target applications

- **Simulator Control** — UE/gNB simulation and bounded traffic generation.
- **Probe Manager** — probe inventory, interfaces, capture lifecycle, and PCAP management.
- **OIRAN Analyzer** — protocol decoding, session reconstruction, correlation, and Call Flow.
- **Portal** — application launcher only; it does not duplicate application logic.

The new foundation lives under [`apps/`](apps/), [`services/`](services/),
[`packages/`](packages/), [`infrastructure/`](infrastructure/), and [`docs/`](docs/).
These directories currently contain documentation placeholders only. No production
application has been migrated.

## Existing snapshots

`OIRAN/` and `POLARIS_CONTROL/` were already present on `main` before the modular
foundation branch was created. This foundation does not move, copy, refactor, or
otherwise modify those snapshots.

Their recorded provenance remains:

- OIRAN V1.1: `97e1195e3a9789a1c251836b7928e0d74799b971`
- POLARIS Control V1.1: `89e7687617a289f6ee6a7b96e6de6534f69e7c18`

## Documentation

- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Repository structure](docs/development/REPOSITORY_STRUCTURE.md)
- [Agent workflow](docs/development/AGENT_WORKFLOW.md)
- [Contributing](CONTRIBUTING.md)
- [Shared contract placeholders](packages/contracts/README.md)

All integration into `main` is performed through pull requests.
