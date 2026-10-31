# ANR1 FINAL LTE E2E REPORT

Mission: `OIRAN_POLARIS_FINAL_INTEGRATION_V1`
Scope: infrastructure, LTE gates and certification tooling
Date: 2026-10-31
Branch: `anr1/lte-certification-v1`
Commit: `514359f`
Agent: **ANR1**

## Verdict

`OFFLINE_TOOLING = PASS`
`STATIC_LTE_COMPATIBILITY = PASS`
`GRANT_V2_CERTIFIED = PENDING_ANR2`
`LTE_E2E_REAL = BLOCKED_NOT_AUTHORIZED`
`REAL_LTE_PCAP_ANONYMIZED = BLOCKED_NO_LIVE_SOURCE`
`ANR1_FINAL_STATUS = PARTIAL`

No live UE/eNB, traffic, grant, production deployment, Open5GS mutation or
capture interruption was performed.

## Delivered tooling

The branch adds versioned component `infrastructure/lte-certification` 1.0.0:

- `lte-preflight.sh`: read-only, fail-closed gate for disk, RAM, 12 dumpcaps,
  protected configuration permissions, PLMN/TAC/APN/MME compatibility, EPC
  health and zero active srsRAN runtime;
- `lte-evidence-schema.json`: bounded cross-project evidence contract;
- `lte-pcap-release-gate.sh`: read-only, fail-closed decoded-identity scan;
- README and CHANGELOG.

Push result:

```text
514359f feat(infra): add fail-closed LTE certification tooling
origin/anr1/lte-certification-v1
```

## Offline/manual tests

Commands:

```bash
bash -n infrastructure/lte-certification/lte-preflight.sh \
  infrastructure/lte-certification/lte-pcap-release-gate.sh
jq empty infrastructure/lte-certification/lte-evidence-schema.json
LTE_MIN_MEMORY_BYTES=1 infrastructure/lte-certification/lte-preflight.sh
LTE_MIN_MEMORY_BYTES=1 LTE_MAX_DISK_PERCENT=1 \
  infrastructure/lte-certification/lte-preflight.sh
OIRAN_TSHARK_PATH=missing-tshark \
  infrastructure/lte-certification/lte-pcap-release-gate.sh \
  infrastructure/lte-certification/README.md
```

Measured results:

```text
syntax/schema validation: PASS
positive deterministic gate: READY, exit 0
forced disk violation: BLOCKED, exit 1
missing decoder: BLOCKED|DECODER_UNAVAILABLE, exit 3
```

The live-host preflight is intentionally dynamic. One measured run returned
`READY` with 5,732,741,120 bytes available RAM. A later run during concurrent
offline builds returned `BLOCKED` with 3,937,615,872 bytes, below the explicit
4,294,967,296-byte reserve. This is correct fail-closed behavior, not a test
failure.

## LTE static evidence

| Evidence | Result |
|---|---|
| srsRAN source | release_25_10, commit `6bcbd9e5bf8686aa7085202cd847c5ddd64a9c16` |
| Runtime image | pinned `sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43` |
| PLMN | srsRAN/Open5GS match |
| TAC | srsRAN `0x0064`, Open5GS `100`, match |
| APN | `internet`, IPv4, match |
| MME endpoint | `10.77.10.10:36412`, listening |
| EPC | MME/SGW-C/SGW-U/HSS/PGW-C/PGW-U/PCRF healthy in measured preflight |
| Profile | `LTE-SRSUE-TEST-01`, secret file mode `0600` |
| Protected subscriber check | found/authentication match/internet session, booleans only |

## Safety state

Measured command:

```bash
df -B1 --output=size,used,avail,pcent /
```

During the last tooling test the exact calculation was 73.2690%, below 85%.
The preflight recalculates this immediately before every future run.

Measured command:

```bash
pgrep -x dumpcap | wc -l
```

Result: 12. No process received a signal from ANR1.

## Gate status

| Gate | Status | Reason |
|---|---|---|
| 1 — code/tests offline | PARTIAL | ANR1 tooling passes; ANR2/ANR3 results pending |
| 2 — Grant V2/ownership | PENDING | implementation owned by ANR2 |
| 3 — security/isolation | PENDING | contract defined; implementation review pending |
| 4 — explicit LTE live approval | BLOCKED | not issued |
| 5 — LTE E2E real | BLOCKED | Gate 4 absent |
| 6 — real sanitized PCAP | BLOCKED | no authorized real LTE source; host tshark absent |
| 7 — OIRAN LTE REAL_PASS | BLOCKED | requires Gates 5-6 |
| 8 — deployment approval | BLOCKED | not issued |
| 9 — controlled deployment | NOT EXECUTED | prohibited by current mission state |

## Open defects

1. Grant V2 and persistent LTE ownership are not yet certified.
2. Real srsENB S1 Setup, srsUE attach, IP and bounded UL/DL have not run.
3. The raw-to-sanitized LTE PCAP transformation is not implemented by ANR1;
   the delivered gate only validates a candidate and correctly blocks without
   a decoder. Raw PCAP must remain protected.
4. Available RAM fluctuated below the 4 GiB preflight reserve during parallel
   builds; live execution must wait for a clean resource window.

## Required next gate

Merge/review ANR2 and ANR3 offline candidates, run their full manual suites,
then conduct the joint security review. Only after these pass may the operator
issue an explicit five-minute authorization for `LTE-SRSUE-TEST-01`.

— **ANR1**
