# POLARIS / OIRAN HTTP final certification

Date: 2026-11-01 UTC

Scope: offline HTTP certification only. No LTE/5G traffic, grant, capture,
deployment, Open5GS change, service restart, or historical dataset access.

## Exact candidates

- POLARIS API `0.28.1`, source `8cb356a7e4264b80fb82e2f1c90b9511f581df41`, binary SHA-256 `3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450`.
- OIRAN API `2.7.2`, source `430a09454f36b92a5ddef40aabc29b305bb3c90d`, binary SHA-256 `8c99a76d037d6dc731f6c16349505f1f1b26e1381874c70f12d9baff450a28e1`.
- Isolated listeners: POLARIS `127.0.0.1:49183`, OIRAN `127.0.0.1:49182`. Both were stopped after the recipe.
- State and evidence used only `/tmp/anr3-http-e2e.BAOKDE`; fixtures contain synthetic documentation addresses and opaque pseudonyms.

## HTTP evidence

POLARIS health/version returned HTTP 200 and `0.28.1`; OIRAN health/version
returned HTTP 200 and `2.7.2`. Before import OIRAN reported no dataset, zero
sessions and zero source events.

POLARIS evidence publication:

```text
anonymous=403
operator_without_csrf=403
first_publication=200
exact_replay=200, byte-identical body
different_bundle=409 LTE_EVIDENCE_PUBLICATION_CONFLICT
capture planes=S1_MME,S11,S1_U; bindings=3
```

OIRAN ingestion of the exact body returned by POLARIS:

```text
anonymous=403 OPERATOR_REQUIRED
operator_without_csrf=403 CSRF_REQUIRED
first_import=201, idempotent=false
exact_replay=200, idempotent=true
different_bundle_same_run=409 LTE_INGESTION_CONFLICT
dataset=dataset-lte-run-envelope-http-01
events=3; sessions=1; correlation_edges=0
request_sha256=05d43c3766c8e80c7e11315a98580d63f1ccb9185359f2cc8b43b7667a6dca5d
manifest_sha256=c4e9bb63af13b6f92f12f09eaf39fae584ffc5815e21dfbff5aef04a71534315
```

Pagination rejected an unknown cursor and `limit=257` with HTTP 422. JSON and
HTML Call Flow exports returned HTTP 200.

## Failing functional result

The admitted dataset contains three independently hashed, valid plane
artifacts and three decoded events, but the reconstructed session is
`INCOMPLETE`: only the S1AP event is associated. S11 and S1-U are counted as
two unmatched source events. The returned Call Flow contains one event,
zero correlation edges and:

```text
S1_MME_S11=UNKNOWN
S11_S1_U=UNKNOWN
E2E=UNKNOWN
```

This is consistent with the implementation in
`OIRAN/session-engine/src/lib.rs`: LTE discovery requires S11 and S1-U events
to have the same `capture_id` as the S1-MME event. A capture ID is the SHA-256
of its individual plane file, so valid distinct S1-MME/S11/S1-U files normally
have different IDs. The test did not make the files artificially identical to
force a PASS.

## Privacy and safety

Across the raw recorded JSON/HTML responses:

```text
forbidden identity/secret keys=0
forbidden identity-shaped value markers=0
DEMO/mock/fake exposed as LIVE=0
proof files=38
proof-manifest SHA-256=2c60ad22cba25f934f3418880c1d6703b942e514b7f2d3de89953f4b59394d32
```

Peak recipe checks remained inside the required gates. Final in-run sample:
`4,984,954,880` bytes available RAM, `15,985,627,136` bytes used; root disk
59%; 12 dumpcap, PID/start snapshot
`be5749279937a7e72c9961fd25137f19a31a385d46adee9f7a574dbe5cd5ef25`.

Safety anomaly: synthetic srsRAN configuration files were bind-mounted
read-only over five hard-coded paths in the host mount namespace while the
isolated POLARIS process started. No underlying file was written. After both
candidate APIs stopped, two stacked layers per path were explicitly unmounted;
all five original files are visible again and no synthetic mount remains.

## Verdict

HTTP_E2E = `FAIL` — HTTP transport, controls and import pass, but the required cross-plane correlation and chronological E2E Call Flow do not.

CAPTURE_REFS = `PASS` — exact three planes, server-side rehashing, provenance, idempotence and POLARIS HTTP 409 verified.

IMPORT = `PASS` — real loopback POST of the POLARIS response into OIRAN; 201/200/409 semantics verified.

CALLFLOW = `FAIL` — one of three events associated, zero edges, both LTE bridges and E2E `UNKNOWN`.

PRIVACY = `PASS` — RBAC/CSRF and raw JSON/HTML leak scans passed; no DEMO data represented as LIVE.

RESOURCE_GATES = `PASS` — RAM/disk gates respected; 12 dumpcap untouched; both candidate listeners removed after test.

BLOCKERS = Fix LTE session discovery/correlation so independently hashed S1-MME, S11 and S1-U capture IDs can correlate through explicit pseudonym/E-RAB/F-TEID evidence without timestamp-only or fabricated joins; then repeat this exact HTTP recipe. This is not a REAL_PASS LTE certification.

— ANR3
