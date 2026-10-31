# LTE evidence ingestion contract

Status: `OFFLINE_ONLY`  
Contract revision: `oiran.lte-evidence-ingestion.v1`  
Canonical orchestration evidence: `infrastructure/lte-certification/lte-evidence-schema.json`

This contract connects POLARIS orchestration evidence to OIRAN without enabling
capture, traffic, deployment, or production ingestion. The ANR1 V2
orchestration contract was not published at the integration base SHA, so this
revision accepts only the already-versioned schema
`oiran-polaris.lte-e2e-evidence.v1` and fails closed on any other revision.

## Admission gates

OIRAN may prepare an offline import only when all of these conditions hold:

1. `profile_id=LTE-SRSUE-TEST-01` and
   `scenario_id=lte-e2e-certification-v1`.
2. The orchestration evidence validates against the canonical ANR1 JSON
   schema. Its `run_id` is the immutable external correlation key.
3. Real captures have `sanitization_state=SANITIZED_APPROVED` for each admitted
   capture reference. `RAW_PROTECTED` and `SANITIZED_PENDING_REVIEW` are never
   readable by OIRAN Analyzer.
4. The fixture manifest validates against
   `tests/fixtures/lte-fixture-manifest.schema.json`, has exactly one S1-MME,
   one S11 and one S1-U entry, and its real-capture
   `certification_state=SANITIZED_APPROVED`.
5. Every manifest path is relative and remains below the bundle root. Symlinks,
   missing files, size mismatches and SHA-256 mismatches reject the whole
   bundle. Verification is streaming and does not rewrite the PCAP.
6. ANR1 approval and its UTC timestamp are mandatory for real fixtures.
   Synthetic fixtures set `real_capture=false` and can only yield an offline
   verdict.

## Plane mapping

| Evidence plane | Transport selector | Decoder | Required normalized keys |
|---|---|---|---|
| S1-MME | SCTP PPID 18 | S1AP | procedure, MME/eNB UE context, E-RAB ID, pseudonym when present |
| S11 | UDP 2123 | GTPv2-C | procedure, control TEID, bearer ID, S1-U F-TEID/IP |
| S1-U | UDP 2152 | GTP-U | TEID, direction, packet/octet counters, first/last timestamp |

Decoder routing is interface-qualified. N2/N3/N4 routes are not aliases and
remain unchanged.

## Correlation rules

Correlation uses explicit identifiers only:

- S1AP to S11: exact pseudonym or prepared EPS-bearer context;
- S11 to S1-U: exact F-TEID and tunnel endpoint;
- UL/DL: decoder direction plus TEID, never timestamp proximity alone;
- ambiguous identifier matches remain uncorrelated and surface as partial
  evidence.

The resulting LTE session contains plane coverage, E-RAB/EPS-bearer evidence,
distinct TEIDs, UL/DL packets and octets, exact timestamp bounds, correlation
strength and packet references. Live Probe bounds materialization to 128 LTE
sessions per offline load.

## API and Analyzer publication

Offline materialization publishes LTE sessions through the existing bounded
endpoints:

- `GET /api/v1/sessions?technology=LTE&page=<n>&page_size=<1..100>`;
- `GET /api/v1/sessions/{id}/callflow?limit=<1..256>&cursor=<event_id>`;
- existing call-flow export, subject to the same authorization policy.

Subscriber display uses an opaque LTE UE pseudonym. Clear IMSI, IMEI, IMEISV,
MSISDN and GUTI are forbidden in fixtures and published evidence. This code
does not implement packet anonymization; it validates an already-anonymized,
ANR1-approved bundle.

## Verdict boundary

Synthetic tests can produce `OFFLINE_PASS`. `REAL_PASS` remains impossible
until approved real PCAPs are supplied, verified and exercised under a later
explicit live/deployment authorization. A missing ANR1 V2 contract, failed
digest, incomplete plane, ambiguous correlation or privacy failure stays open
and blocks real certification.
