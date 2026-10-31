# POLARIS Grant V2 — production release preparation

Date: 2026-10-31 UTC  
Agent: ANR2  
Candidate received: `staging/polaris-real-lab-v1-anr2` at
`15a6904f8167e22433937e4a1ebca0bf58e02b2b`  
Preparation branch: `release/polaris-grant-v2-prep-anr2`  
Implementation commit: `a772ac4522a17293c78cccd1404ecbdb9d2c281c`
Verdict: **BLOCKED**

No production file, service, grant, simulator, traffic generator, Open5GS
component, or external capture was changed or restarted during this work.

## Executive result

The candidate is a descendant of both deployed POLARIS API 0.19.8 and the
deployed frontend lineage. Grant V2, LTE read routes, fail-closed staging,
real-data UI behaviour, and privacy checks pass offline. Two release-artifact
defects found during preparation were corrected:

1. the Compose-model digest used to omit profile-gated `srsenb` and `srsue`;
2. the frontend release directory exposed a historical standalone mock page.

Production release remains blocked. `/root/POLARIS/compose/versions.env`
references the absent image digest `9415af...b92`, whereas the locally present
ANR1-certified image is `69e094...d43`. With the corrected canonical renderer,
the current model digest is `66cdaf...04c`; the model rendered with the ANR1
image would be `308053...a19`. The latter is a **proposed** Compose-model
digest, not an ANR1-certified digest. It must be independently reproduced and
co-signed by ANR1 before any release authorization. RAM briefly crossed the
gate under concurrent host load, then passed on the final reading; it must be
treated as an immediate preflight gate rather than an assumed capacity.

## Git lineage and isolation

Initial inspection was performed before edits. The shared checkout
`/root/OIRAN_POLARIS_FOUNDATION` contained unrelated/conflicted work from other
agents and was not modified. Work was isolated in:

```text
/root/OIRAN_POLARIS_GRANT_V2_RELEASE_ANR2
release/polaris-grant-v2-prep-anr2
```

Commands and results:

```sh
git merge-base --is-ancestor \
  fef53408709580251c372c2253c28937f3efe852 \
  15a6904f8167e22433937e4a1ebca0bf58e02b2b
# exit 0 — deployed API 0.19.8 is an ancestor

git merge-base --is-ancestor \
  b0adf3b6c7dbd65cb674f2c06a9fcbff93b4c3bc \
  15a6904f8167e22433937e4a1ebca0bf58e02b2b
# exit 0 — deployed frontend 0.11.1 is an ancestor
```

Historical candidates `29f8ef5...` (API) and `a39e692...` (frontend) are also
ancestors. No `merge -s ours` is used as evidence of functional presence.

## Digest investigation

### Evidence

```sh
grep '^SRSRAN4G_IMAGE=' /root/POLARIS/compose/versions.env
# oiran/srsran4g@sha256:9415af3a48dcb8bf72ec835be281a21802895acc13f5d5d0beac41fe0f472b92

docker image inspect \
  oiran/srsran4g@sha256:9415af3a48dcb8bf72ec835be281a21802895acc13f5d5d0beac41fe0f472b92
# absent

docker image inspect \
  oiran/srsran4g@sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43
# present; created 2026-10-31T11:20:29Z
# source=srsRAN_4G, version=25.10
# revision=6bcbd9e5bf8686aa7085202cd847c5ddd64a9c16
```

The `versions.env` modification time is 2026-10-24, seven days before the
certified image build. The discrepancy is therefore a stale environment pin,
not an equivalent alias. The old digest is neither available nor accepted.

The previous code executed `docker compose ... config --format json` without
`--profile lte`. Changing only `SRSRAN4G_IMAGE` left its digest unchanged at
`e2bf10...42ac6`, proving the LTE services were absent from the hashed model.
The corrected fixed argv contains `--profile lte`; recursive JSON object keys
are also sorted before SHA-256 hashing.

| Subject | SHA-256 | Status |
|---|---|---|
| Image pinned by current `versions.env` | `9415af3a48dcb8bf72ec835be281a21802895acc13f5d5d0beac41fe0f472b92` | stale, absent, rejected |
| ANR1 image | `69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43` | image certified by ANR1 |
| Corrected current Compose model | `66cdaf252d5dcc8e0be9237fc359323b7c0e6cf26dbd227ec0e406021a80704c` | reproducible; includes LTE profile |
| Model rendered with ANR1 image | `308053a274844259c16da7751708b39e6559cfec2b8d958dc4fcafebecd0da19` | proposed; ANR1 co-sign required |

The canonical release subject must be the pair `(immutable image digest,
canonical Compose-model digest)`. A match on only one value cannot authorize
live control.

## Candidate API and Grant V2

Isolated read-only staging was bound only to loopback:

```text
UI  http://127.0.0.1:4337/simulator/
API http://127.0.0.1:49326
POLARIS_STAGING_READ_ONLY=true
```

`GET /polaris-api/v1/version` returned API `0.25.2`, platform `3.2.1`,
srsRAN controller `0.2.1`, and `staging_read_only: true`.

Read-route observations:

- `GET /lte/status`: HTTP 200; S1, Attach and session are `UNKNOWN`; UE IP is
  null; active sessions are 0; grant/live/traffic are false.
- `GET /lte/profiles/LTE-SRSUE-TEST-01`: HTTP 200; owner
  `POLARIS_CONTROLLER`; LTE 4G / srsUE; disabled; runtime `UNKNOWN`; corrected
  current model digest `66cdaf...04c`.
- `GET /live/grant`: HTTP 200 with no active grant.
- missing run: HTTP 404 `LTE_RUN_NOT_FOUND`.
- missing srsRAN services: HTTP 503 `SRSRAN_SERVICE_NOT_FOUND`, not a fabricated
  running state.

All staging mutations returned HTTP 423 `STAGING_READ_ONLY`: Grant create and
revoke, LTE run/stop, component start/stop, and LTE profile patch. No mutation
was forwarded to production services.

The Rust negative suite covers the live code path beneath the staging lock:

- RBAC and CSRF validation before grant-schema processing;
- persistent owner registry and owner-drift rejection;
- private persistent grant store with no plaintext nonce;
- expiry, revocation, subject/session binding, wrong nonce, and one-time
  consumption;
- idempotency conflict and replay rejection;
- no start without certification and no stop of an unowned runtime.

Legacy component start cannot authorize live work: it directs callers to the
Grant V2 `/lte/runs` flow. Cleanup stop remains grant-exempt by design, but is
ownership-bound.

## UI and confidentiality

The API-backed pages render the real read routes. Unobserved values remain
`UNKNOWN`; no LTE/NR running or attached state is inferred. The deployable
bundle contains only:

```text
dist/index.html
dist/assets/index-Bwcm9z8L.css
dist/assets/index-DePFJ2pi.js
```

`rg -i DEMO dist` returned 0 matches and no `polaris-mockup.html` is present.
The historical fixture remains source-only. Anonymous checks over subscribers,
UE profiles, and UE inventory found 0 subscriber-secret key paths, 0 strings
matching 14–16 digit subscriber identities, and 0 DEMO hits.

Artifact hashes:

```text
b0b1356ed47d72a508a325ebfe660dea9b70e773262893f0308ed4814a06344d  index.html
83ee901539c019a9db5d4366e884edf665a0acd95e26ca708c532ca5b9c6a472  index-Bwcm9z8L.css
a940acedea620085db0b94a128e26d91ab0d70bf51114b87dc1a302484b2e077  index-DePFJ2pi.js
```

## Manual tests

All tests were run manually; no CI result is claimed.

| Command | Result |
|---|---|
| `cargo test -p polaris-control-api` | PASS; 231 passed, 3 ignored; 234 total |
| targeted `lte_grant::tests` | PASS; 6 passed |
| targeted `srsran_controller::tests` | PASS; all controller tests |
| targeted `canonical_compose` | PASS; 2 passed |
| `CARGO_BUILD_JOBS=1 cargo build --release -p polaris-control-api --bin polaris-control-api` | PASS in 9m44s |
| `cargo fmt --all --check` | FAIL; inherited formatting drift outside the touched controller remains |
| scoped `rustfmt --check` on the changed controller | PASS |
| Node `v20.20.2`; `npm run typecheck` | PASS |
| `npm test -- --reporter=json ...` | PASS; 234/234 |
| `npm run build` | PASS; 1708 modules |
| Playwright with default port 4330 | FAIL 6/6, `ECONNREFUSED`; invalid invocation retained as evidence |
| Playwright with `POLARIS_SIM_E2E_BASE_URL=http://127.0.0.1:4337/simulator/` | PASS 6/6 in 43.0s; 1280/1440/1920, light/dark |

The first Playwright rerun was a test-command configuration error, not hidden
or reclassified. The corrected command targeted the verified staging server.
No simulator or traffic was started by either run.

## SemVer and changes

- POLARIS API: `0.25.1` -> `0.25.2`.
- POLARIS UI: `0.18.1` -> `0.18.2`.
- Both changelogs record the release-artifact changes.
- API correction: include the LTE profile and deterministically canonicalize
  JSON before hashing.
- UI correction: disable Vite public-directory copying for release builds.

## Resource and production invariants

Pre-Playwright gate:

```text
MemAvailable: 5,445,708 kB  (PASS >= 4 GiB)
filesystem /: 53%          (PASS < 85%)
dumpcap processes: 12      (preserved)
```

An intermediate post-test reading was `MemAvailable: 3,485,020 kB`,
approximately 3.32 GiB, with approximately 16.21 GiB non-available out of
19.53 GiB. It failed both RAM release gates at that instant. The largest
remaining processes belonged to shared host workloads; they were not killed
because they are outside this mission and may belong to other agents. The final
reading recovered to `MemAvailable: 5,141,928 kB` (4.90 GiB) and
15,705,247,744 non-available bytes (14.63 GiB): both RAM gates PASS. Disk
remained 53% and all 12 dumpcap processes remained present.

The production API stayed at 0.19.8 on `127.0.0.1:49153`; its process and the
production frontend on loopback port 8021 were not restarted or modified.

## Controlled deployment plan (not executed)

1. Obtain ANR1 reproduction and signature of the canonical pair, including
   model digest `308053...a19`, or update this plan if ANR1 obtains another
   reproducible value. Do not weaken or bypass either digest check.
2. Obtain distinct production-deployment authorization. Recheck disk, RAM,
   dumpcap count, no active Grant/run, and the production API/UI SHAs.
3. Re-run `git merge-base --is-ancestor` from the exact deployed API and UI
   commits to the final release commit.
4. Create a timestamped, mode-0700 backup on the same host filesystem and a
   SHA-256 manifest for:
   - API binary, environment file, systemd unit and drop-ins;
   - `/var/lib/polaris-control` and the audit log;
   - complete served frontend directory;
   - Compose file, `versions.env`, and referenced srsRAN configuration.
   Preserve ownership, permissions, and SELinux/xattrs where applicable.
5. Stage API and UI in versioned directories. Update `versions.env` to the
   ANR1-certified immutable image only inside the authorized window, then
   independently recompute the canonical model before activation.
6. Activate API and UI as one maintenance transaction using atomic symlink or
   rename switches. Restart only POLARIS API and its UI server. Never restart
   Open5GS, srsRAN, UERANSIM, OIRAN, or dumpcap as part of this release.
7. Read-only recipe: version, health, LTE profile/status, 13 scenario templates,
   topology, traffic sessions, operator/viewer IMSI policy, anonymous privacy,
   no-DEMO scan, Grant empty, mutation denial without valid Grant V2, and UI at
   1280/1440/1920. Do not create a grant or start a run for deployment smoke.
8. Any failed recipe item rolls back **both** API and UI plus configuration and
   `versions.env`; restore verified hashes, restart only POLARIS services, and
   repeat the old-version/read-only health checks.

## Blocking items

1. ANR1 must certify the corrected canonical Compose-model digest; image
   certification alone is insufficient.
2. The stale `9415af...b92` production pin must be replaced only in an
   authorized, backed-up release window.
3. RAM currently passes but fluctuated below the gate; it must be rechecked and
   satisfy both `available >= 4 GiB` and `used/non-available <= 16 GiB`
   immediately before build/activation/recipe.
4. Full-workspace Rust formatting drift should be resolved or explicitly
   accepted; the changed controller itself is formatted.
5. Explicit deployment authorization is absent. No production action is
   permitted.

— ANR2
