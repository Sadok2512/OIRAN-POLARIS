# S5.6 Retry Dataset Regression

The pre-deployment manifest covered every file below `/var/lib/oiran/captures`. Post-deployment `sha256sum -c` reported no difference.

- Historical and live evidence files checked: 62 excluding the audit file.
- Certified S3.3 and existing capture datasets: unchanged.
- Recovered dataset `recovered-dataset-live-1792964646320-0003`: visible through the production API.
- Recovered dataset accounting: 20 events, zero sessions.
- No fabricated session or Call Flow was created.
- Existing Capture Library count: 10.
- Active capture jobs after validation: 0.

Rust regressions covering SLL2, NAS, SBI/HTTP2, PFCP, GTP-U, session isolation, atomic dataset finalization and provenance passed 172/172.

