# ANR3 — Integrated OIRAN privacy and offline LTE report

Date: 2026-11-01 UTC
Scope: source-only integration of OIRAN API privacy and the offline LTE pipeline
Source parents: `523524fd44b6bc2b6a4535bb093290f26b8135f4` and
`b011432b17235d85a08aa21bf4afe1c65fa6eeba`
Verdict: **SOURCE_RESOLVED / TEST_EXECUTION_PENDING / REAL_CERTIFICATION_BLOCKED**

## Integrated outcome

The merge retains the OIRAN 2.7 real-lab read model and the API 2.7.1 privacy
fix while adding the bounded offline LTE materialization implemented by the LTE
parent. It does not enable a live capture interface, deploy a component, start a
service, create traffic, or modify a capture or dataset.

The integrated reference path is:

```text
approved read-only PCAP copy (future) / explicit synthetic fixture (offline only)
  -> oiran-decode: S1AP + NAS-EPS / GTPv2-C / GTP-U
  -> normalized events with packet provenance
  -> session-engine: explicit S1AP context + pseudonym + F-TEID partition
  -> correlation-engine: ambiguity-safe S1-MME <-> S11 <-> S1-U evidence
  -> callflow-schema: chronological LTE procedures and correlations
  -> Live Probe: bounded persisted Call Flow materialization
  -> OIRAN API: sanitized Session Explorer, events, packets and exports
```

No timestamp-only UE identity join is accepted. A TEID match establishes a
tunnel association, not subscriber identity. Unknown or absent operational
evidence remains empty, `null`, or `UNKNOWN`; the integration does not create
sessions, events, counters, or topology state for operational views.

## Retained versions

| Component | Integrated version |
|---|---:|
| OIRAN API | 2.7.1 |
| OIRAN platform core | 2.7.0 |
| Analyzer | 2.7.0 |
| Live Probe | 0.4.0 |
| oiran-decode | 0.6.0 |
| session-engine | 0.5.0 |
| correlation-engine | 0.5.0 |
| callflow-schema | 1.2.0 |

The API version response retains the newer platform/frontend versions and now
uses the installed decoder inventory for S1AP, NAS-EPS-MM, NAS-EPS-SM,
GTPv2-C, GTP-U, NGAP, NAS-5GMM, NAS-5GSM, PFCP and SBI-HTTP2. API 2.6.0 and
Live Probe 0.3.0 were not selected during conflict resolution.

## Privacy behavior retained

The common success and pagination response boundaries remove subscriber and
equipment identity keys and identity-bearing decoded information elements. The
HTML Call Flow export is rendered from the sanitized `CallFlow`, rather than
serving a pre-rendered file that could bypass sanitization.

The named raw-route regression remains present for:

- `GET /api/v1/datasets`
- `GET /api/v1/sessions` and `GET /api/v1/sessions/:id`
- `GET /api/v1/sessions/:id/events`
- `GET /api/v1/sessions/:id/callflow`
- `GET /api/v1/events/:id` and `/provenance`
- `GET /api/v1/packets` and `GET /api/v1/packets/:id`
- `GET /api/v1/exports/callflow/:id?format=json|html`
- viewer and authenticated operator reads

The protocol procedure, accounting and sanitized capture provenance assertions
remain in `raw_read_routes_remove_identity_material_for_viewer_and_operator`.

## LTE and 5G behavior retained

| Plane | Decoder/materialization | Live acquisition |
|---|---|---|
| S1-MME / S1AP + NAS-EPS | retained | not enabled by this merge |
| S11 / GTPv2-C | retained | not enabled by this merge |
| S1-U / GTP-U | retained | not enabled by this merge |
| N2 / NGAP | retained | unchanged |
| N3 / GTP-U | retained | unchanged |
| N4 / PFCP | retained | unchanged |
| SBI / HTTP2 | retained | unchanged |

Offline LTE materialization remains bounded to 128 discovered LTE sessions per
dataset. Existing correlation rejects ambiguous/reused TEIDs. The API test
`api_load_materialises_synthetic_lte_session_without_live_capture` and the Live
Probe test `offline_lte_materialisation_is_bounded_and_correlates_planes` remain
present. Synthetic fixtures remain explicitly classified as offline and are not
evidence of a real run.

## Existing branch evidence

These results are inherited evidence from the parent reports; they were not
rerun during this conflict-resolution pass because no build lease was supplied:

- privacy parent: `cargo test -p oiran-api` reported 38 pass, 0 fail;
  `cargo test -p live-probe` reported 52 pass, 0 fail, 4 ignored;
- LTE parent: its selected Rust suites reported 126 pass, 0 fail, 4 ignored;
- LTE parent frontend checks reported 10 files / 73 Vitest tests passing,
  TypeScript and Vite build passing;
- LTE parent Playwright selection reported 3 pass / 6 fail because the clean
  registry lacked the historical recovered datasets; the failures remain open.

Current-tree validation and all commands actually run are recorded separately
in `ANR3_RESULT.md` so inherited evidence cannot be mistaken for a post-merge
green run.

## Real-data verification gate

A real verification may use only the read-only captures named by the parent's
safe manifest. Before ingestion, the manifest must provide, for each required
S1-MME, S11 and S1-U capture, an approved reference, `SANITIZED_APPROVED`
classification, SHA-256, size, packet/time bounds, and decoder-version binding.
The files must remain unchanged and outside Git.

The offline verification must fail closed on a missing plane, hash mismatch,
unapproved classification, identity leak, ambiguous correlation, or unsupported
decoder version. Outputs must contain only anonymized UE/session references,
packet provenance, procedures, TEID/bearer correlations, and measured UL/DL
counters. The pipeline must not turn absent observations into zero counters or
fabricated events.

No approved manifest was supplied in this pass, so no capture was opened and
real LTE/5G certification remains **BLOCKED**.

## Release and rollback status

This source is staged for parent review only. It is not built, deployed, or
activated. Before any release, the parent must run the named targeted tests
under the resource/build lease, verify the merge commit has both parents, and
obtain specific deployment authorization.

Rollback is release-artifact based: retain the current deployed binary/UI and
configuration, stage the candidate under a distinct versioned path, and on a
critical readback failure restore only the previously active OIRAN artifact and
configuration. Captures, datasets, collectors, Open5GS, POLARIS and unrelated
services are outside the rollback mutation set.

— ANR3
