# POLARIS / OIRAN real-lab implementation report

Date: 2026-10-31 UTC

Agents: ANR1 / ANR2 / ANR3

Verdict: **PARTIAL — offline implementation integrated; production and LTE live certification blocked**

## Provenance

| Component | Branch / SHA | Version |
|---|---|---|
| Reference base | `87daa3445e3058352d21efeba21d05fefe3029d4` | — |
| ANR1 contract | `anr1/polaris-real-lab-live-v1` / `8fd3938583a6f76417560240c93ae194337c37a4` | contract v1 |
| ANR2 POLARIS | `anr2/polaris-real-lab-live-ui` / `84a7833c9b44cecb94e9a267dcd5180455b9ca2a` | API 0.24.0, Simulator 0.17.2 |
| ANR3 OIRAN | `anr3/oiran-real-lab-ui-v1` / `8c6630db010ea446bf36dc74d71b1783a767e4bf` | API 2.7.0, live-probe 0.4.0, Analyzer 2.7.0 |
| Integration | `integ/polaris-real-lab-live-v1` | final SHA reported by Git after this document commit |

All three source SHAs are Git ancestors of the integration branch. Merges used the normal `ort` strategy; no `ours` merge or hidden conflict was used.

## Real laboratory state

Read-only commands used: `docker ps/inspect`, `docker network inspect`, `ss`, `systemctl`, `curl` to loopback read endpoints, `df`, `free`, and `pgrep`. No write endpoint was called.

- Production remains POLARIS API `0.19.8` / platform `3.2.1` and OIRAN API `2.5.4`; neither candidate is deployed.
- Open5GS EPC/5GC NFs are running and healthy. UERANSIM gNB is running and healthy; no UERANSIM UE is running.
- POLARIS reports two configured profiles and zero active, registered or PDU-active UEs.
- No `srsenb` or `srsue` container exists. LTE attach/session state is therefore `UNKNOWN`, never `ATTACHED`.
- LTE data planes are physically prepared: S1-MME (`br-oiran-s1m`, MME `:36412/SCTP`), S1-U (`br-oiran-s1u`, SGW-U `:2152/UDP`) and S11 (`br-oiran-s11`, `:2123/UDP`). The eNB endpoints are absent.
- 5G planes are observed on `br-oiran-n2`, `br-oiran-n3`, `br-oiran-n4`, and `br-oiran-n6` with real AMF/gNB/SMF/UPF sockets.
- OIRAN production reports 11 datasets and 11 reconstructed sessions, all measured from persisted data. No LTE dataset exists.
- The registered vProbe is `PENDING` with no measured heartbeat; live counters remain null/reference-only.

The exact read-model and source rules are documented in `docs/contracts/POLARIS_REAL_LAB_READ_MODEL_V1.md`.

## Implemented POLARIS behavior

- Operational builds no longer enable browser/localStorage fixture branches; those paths remain available only under test mode.
- UE Manager consumes `/ues` and `/ue-profiles`; lifecycle, registration, PDU, traffic and ownership are independent observed fields.
- Topology joins `/lab`, `/nodes`, and `/ues`; configuration does not imply connection and missing facts render `NOT_AVAILABLE`.
- Scenario Library/Builder consumes the real immutable 13-template backend catalogue and durable scenario definitions. Status distribution remains 3 `SUPPORTED`, 2 `CERTIFICATION_REQUIRED`, 8 `BACKEND_REQUIRED`.
- Traffic Generator targets only real inventory entries and consumes `/traffic/sessions*`; the invented default UE target was removed.
- Grant V2, operator RBAC, CSRF, ownership, digest, expiry, anti-replay and backend execution gates remain authoritative.
- Historical traffic results are labelled historical and are not reused as live rates.

## Implemented OIRAN behavior

- Operational startup no longer preloads the bundled reference session; reference loading is explicit and disabled by default.
- Dataset, Session Explorer, Call Flow and correlation routes read persisted CaptureManager N2/N3/N4/SBI data and atomically finalized LTE S1-MME/S11/S1-U evidence.
- Missing observations are null/`UNKNOWN`; generated context identifiers and fixed technology labels were removed.
- Call Flow uses bounded cursor pagination; LTE catalogue enumeration and event responses are bounded.
- Subscriber/equipment identities and identity IEs are replaced by `IDENTITY_WITHHELD`; source paths are reduced to `capture://<basename>`.
- Contract: `OIRAN/docs/REAL_LAB_SESSION_API.md`.

## Manual tests

| Scope | Result |
|---|---|
| ANR1 Grant V2 | 6/6 PASS |
| ANR1 srsRAN controller | 8/8 PASS |
| POLARIS Rust workspace | API 228 PASS, 3 manual benchmarks ignored; 45 other crate tests PASS |
| Integrated POLARIS catalogue test | 1/1 PASS on merged HEAD |
| Integrated Simulator frontend | TypeScript PASS; 36 files / 225 tests PASS; build PASS |
| Integrated Playwright | 1/1 PASS at 1440 light; API mocked/offline, no live action |
| OIRAN API | 37/37 PASS on merged HEAD |
| OIRAN pipeline/correlation | 43/43 PASS on ANR3 branch |
| Integrated Analyzer frontend | TypeScript PASS; 11 files / 75 tests PASS; build and dist leak scan PASS |
| Dependency audit | Both production dependency audits report 0 vulnerabilities |

The standard OIRAN large-resource tests remain explicitly ignored and require their dedicated memory-test environment. React `act(...)` warnings and the host Node 18 engine warning are recorded; project-pinned Node is used by the OIRAN scripts.

## Resource and safety evidence

- Disk remained below the 85% gate (48–50% during this mission).
- External `dumpcap` count remained 12; PID-set SHA-256 remained `39f48afb57e037db9ac35e6671b98c8c2b91d618e417c449016ee103aeb09bc8`.
- RAM availability crossed below 4 GiB during concurrent builds. A future live preflight must observe stable available RAM at or above 4 GiB before proceeding.
- No UE/eNB/gNB/core lifecycle action, Grant V2, traffic, capture, Open5GS write, service restart or production deployment occurred.
- No historical dataset was deleted or overwritten.

## Confirmed blockers

1. **LTE real certification absent:** srsENB/srsUE are stopped/absent and no real S1AP/S11/S1-U dataset exists. `REAL_PASS` is impossible without a separately authorized LTE run.
2. **Production versions are old:** production `/lte/status` and `/scenario-templates` return HTTP 404; candidates are offline only.
3. **OIRAN production raw API identity exposure:** a production Call Flow response contains a non-null masked equipment-identity IE. The candidate sanitizer is tested, but production remains unchanged.
4. **vProbe liveness absent:** the registered probe is pending with no real heartbeat or live counters.
5. **Resource gate unstable:** available RAM was not stably at least 4 GiB throughout validation.
6. Some persisted capture records are failed/partial/recovered; no loss-free global claim is made.

## Controlled deployment plan

1. Restore stable available RAM to at least 4 GiB and recheck disk plus all 12 external capture PIDs.
2. Review the integrated diff and build exact release artifacts from the final integration SHA.
3. Back up POLARIS/OIRAN binaries, static assets, configuration and persistent registries; hash every rollback artifact.
4. Deploy POLARIS and OIRAN separately only after explicit authorization, with component-local rollback on failure.
5. Run authenticated, non-live browser validation against real API data; prove no raw identity leakage.
6. Request a separate Grant V2/live authorization for `LTE-SRSUE-TEST-01`; then certify S1 Setup, Attach, IP, bounded UL/DL, cleanup and OIRAN publication.

## Final status

The offline implementation is integrated, versioned and tested. It removes operational demo fallbacks and renders unobserved state honestly. Production remains unchanged, so the requested platform-wide real-lab PASS is **not** declared.

`FINAL_STATUS = PARTIAL`

— ANR1 / ANR2 / ANR3
