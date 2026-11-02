# LTE E2E Call Flow final preparation — ANR3

Date: 2026-11-02 UTC. This is preparation only; no Grant, LTE container, UE or traffic was started.

SRSENB = READY_OFFLINE. Canonical image `oiran/srsran4g@sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43` is present. `docker run --rm --network none ... srsenb --version` returned `25.10.0` at `/usr/local/bin/srsenb`.

SRSUE = READY_OFFLINE. The same immutable image contains `/usr/local/bin/srsue`; isolated `--version` returned `25.10.0`. Source tree `/root/POLARIS/src/srsran4g` is clean at `6bcbd9e5bf8686aa7085202cd847c5ddd64a9c16` (`release_25_10`). No rebuild was necessary.

POLARIS_INTEGRATION = PASS_OFFLINE. Compose resolves `srsenb` and `srsue` in profile `lte` to the certified digest; S1-MME=`10.77.10.20`, S1-U=`10.77.11.20`, ZMQ eNB/UE=`10.77.17.20/.21`. POLARIS production is healthy at API `0.29.0`, running binary SHA256 `cde36bd2451800104d6bce0758d2bc0f9f0eb38e872632006e887a5d3dc8b97e`. The two LTE containers are absent/stopped as required. `cargo test ... srsran_controller::tests::` passed 24/24.

OPEN5GS = READY. MME, HSS, SGW-C/U, PGW-C/U and PCRF were all running and healthy. MME listened on SCTP `10.77.10.10:36412`; GTPv2-C `:2123` and GTP-U `:2152` listeners were verified in their container namespaces. No Open5GS mutation occurred.

PFCP = READY. LTE SGW/PGW control/user containers and 5G SMF/UPF exposed the expected `:8805` PFCP listeners on their Sx/N4 networks.

FINALIZER = READY_OFFLINE / EMPTY_REAL_INPUT. POLARIS release and bundle roots exist mode `0700`; OIRAN evidence/inbox roots exist mode `0700`. All are root-owned. Finalizer tests passed 3/3, including immutable complete bundles, partial failed/cancelled evidence, privacy/hash/conflict rejection. No release/bundle currently exists, so no capture reference or Call Flow can truthfully be published yet.

RESOURCE_GATES = Source candidate policy PASS at 95/97/98 with an 8 GiB reserve. Production still reports `safety_guard=0.1.0` and `disk_safety=0.1.0`; deployment of the candidate policy was not authorized. Pre-cleanup measurement: disk total `414,921,494,528`, available `98,381,586,432` bytes (`df` 77%); RAM available `14,398,599,168` bytes; inode use 5%.

CAPTURES = 12 `dumpcap` processes observed. Real S1-MME, S11 and S1-U rotating paths exist. Their current newest files are header-only (292/332/292 bytes), consistent with no active LTE run; no PCAP was opened or processed. Future selection must bind the authorized run timestamps, copy only matching immutable segments, hash them, anonymize, and stop before `SANITIZED_APPROVED` pending user approval.

OPERATOR = Account registry mode `0600`, root-owned; `operator` is provisioned with role `operator`. No credential or hash was read or reported. Unauthenticated `/auth/me` correctly remained viewer/fail-closed.

LIVE_READY = NO. Technical components are prepared, but a renewed explicit live authorization is mandatory, and the requested 98% disk policy is not yet deployed in production.

BLOCKERS = (1) no renewed live authorization for LTE-SRSUE-TEST-01; (2) production still executes legacy disk-safety crates; (3) no run-bound real S1-MME/S11/S1-U evidence exists; (4) `SANITIZED_APPROVED` requires a distinct user approval after anonymization review.

NEXT_ACTION = Review and deploy the exact disk-policy candidate under a separate authorization; then request a renewed authorization limited to one UE and 300 seconds. Execute once only, stop/cleanup/revoke, select segments by proven run interval, anonymize and submit for approval before finalizer/OIRAN import.

— ANR3
