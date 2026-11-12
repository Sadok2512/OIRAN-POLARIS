# OIRAN Real-Lab Session API 2.7

Operational mode exposes only persisted evidence. It never falls back to the bundled
reference dataset.

## Sources

- `CaptureManager`: recovered, derived, continuous and finalized N2/N3/N4/SBI datasets.
- `LteEvidenceStore`: atomic imports admitted under
  `oiran-polaris.lte-e2e-evidence.v1` for S1-MME/S11/S1-U.
- Bundled reference artifacts: disabled unless
  `OIRAN_REFERENCE_DATASET_ENABLED=1`; this switch is for tests/reference review and
  must not be enabled in the operational service.

The currently measured lab has N2/N3/N4 bridges but no running srsENB/srsUE. Therefore
no LTE dataset or session is returned until approved, sanitized evidence is admitted.

## Read contracts

- `GET /api/v1/datasets`: includes persisted datasets. LTE admissions use
  `dataset_kind=EVIDENCE`, `technology=LTE`, and
  `source=ADMITTED_SANITIZED_EVIDENCE`.
- `GET /api/v1/sessions`: server-side pagination/filtering across persisted 5G and LTE
  sources. Missing observations are JSON `null` or `UNKNOWN`, never inferred.
- `GET /api/v1/sessions/:id`: returns observed summary, procedures, accounting and
  capture references.
- `GET /api/v1/sessions/:id/events`: bounded event page; subscriber identities are
  withheld.
- `GET /api/v1/sessions/:id/callflow?limit=1..256&cursor=<event_id>`: bounded persisted
  Call Flow page. Cursor and limit errors fail closed.
- `GET /api/v1/health`: `session_count` and `queryable_session_count` equal the
  unfiltered union returned by `/sessions`. `published_session_count` counts only
  sessions present in static and continuous published callflows, so it can be lower
  when finalized LTE evidence contributes additional queryable sessions.

## Privacy and evidence rules

Raw IMSI/SUPI/SUCI/GUTI/TMSI/IMEI, authentication key and OPc fields are replaced by
`IDENTITY_WITHHELD`. Source paths are reduced to `capture://<basename>`. LTE imports
remain subject to required-plane, SHA-256, decoder/schema-version and
`SANITIZED_APPROVED` validation. Timestamp proximity alone never creates a correlation
edge.
