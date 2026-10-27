# OIRAN Live V1 Implementation Report

Status: **IMPLEMENTATION_VALIDATED; live certification pending**.

Implemented:

- `live-probe` capture manager with real N2/N3/N4 device discovery, fixed protocol filters, bounded rotation, persistent jobs, exact ownership and recovery.
- `oiran-decode` library adapter reusing the existing native PCAP/PCAPNG, SCTP, NGAP, PFCP and GTP-U components.
- Automatic normalized-event output, session discovery, evidence-based tunnel correlation and Call Flow JSON/HTML generation after finalization.
- API 2.1 capture validation/start/stop/metrics, live dataset/session registration, server-enforced roles and audit records.
- Probe Manager with real interface state, capture form, polling, job history and truthful unavailable/gated states.

Observed capture points are `br-oiran-n2`, `br-oiran-n3`, and `br-oiran-n4`. All were UP during validation. The deployed API is healthy on localhost, but capture execution is intentionally disabled and Viewer is the current public role.

No live capture, traffic generation, decoder certification run or live session reconstruction was performed.
