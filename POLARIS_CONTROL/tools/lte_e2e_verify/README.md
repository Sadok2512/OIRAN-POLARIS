# lte-e2e-verify 0.1.0

Mechanical, offline, Git-only verifier for the LTE E2E North Star gate.
A `REAL_PASS` is produced if — and only if — every gate's proof is present
in the input bundle. Any absent field becomes a `FAIL` with its gate code.

## Layout

```
POLARIS_CONTROL/tools/lte_e2e_verify/
├── Cargo.toml           # standalone package (has its own Cargo.lock)
├── src/
│   ├── lib.rs           # pure verdict functions + schema
│   └── main.rs          # CLI
├── tests/
│   └── fixtures.rs      # 4 fixture tests + 3 unit tests
├── fixtures/
│   ├── e0497/                       # reproduces lte-run-e0497fd986d8429e03c642cc7fae3de9
│   ├── synthetic-complete/          # expected FINAL_VERDICT=REAL_PASS
│   ├── teid-mismatch/               # expected FINAL_VERDICT=NO_LTE_E2E_REAL_PASS (S1U_GTPU)
│   └── missing-field/               # expected FINAL_VERDICT=NO_LTE_E2E_REAL_PASS (GRANT_REVOKED)
└── README.md
```

## Scope

The crate is intentionally **not** part of the POLARIS workspace. It has its
own `Cargo.lock` so it never touches the files modified by the ANR3 branch
`fix/polaris-0.29.4-lte-ul-route` (`srsran_controller.rs`, compose, image).

## Input contract (`pending-evidence/`)

```
pending-evidence/
├── manifests/
│   ├── S1_MME.json
│   ├── S11.json
│   └── S1_U.json
└── sanitized-summaries/
    └── RUN.control-proof.json
```

Schema is derived from:

- `POLARIS_CONTROL/docs/api/lte-evidence-envelope.contract.md`
- `POLARIS_CONTROL/apps/api/src/srsran_controller.rs`

Field names and semantics match the sanitized summaries Codex already
produces for each run (see Issue #10 comment 6585664173 for an example of
`manifests/*.json` and `sanitized-summaries/RUN.control-proof.json`).

## Verdict rules

| Gate | PASS condition |
| --- | --- |
| `S1_SETUP` | `S1_MME.json` contains at least one S1AP procedure 17 over SCTP PPID 18 |
| `ATTACH` | NAS Attach Request + Attach Complete (either in the NAS stream or via `lte_attach=COMPLETED`) |
| `EPS_BEARER` | S11 CSReq (type 32) + CSRsp (type 33, cause 16) + S1AP procedure 9 carrying an E-RAB id. Degrades to `PASS_CONTROL_PLANE_ONLY` when S1-U has zero packets |
| `S1U_GTPU` | S1-U packet count > 0 AND identical TEID across S1-U, S11 F-TEID and S1AP E-RAB TEID |
| `PING_UL` / `PING_DL` | `tx > 0` AND `rx > 0` for the direction |
| `UDP_UL` / `UDP_DL` | `bytes > 0` AND `rate_bps ≤ 1_000_000` for the direction |
| `CLEANUP` | all five cleanup observations true (srsue_stopped, srsenb_stopped, sidecars_removed, epc_healthy, dumpcaps_preserved) |
| `GRANT_REVOKED` | grant `state=REVOKED`, `use_count ≥ 1`, `run_state=CLEAN` |
| `DUMPCAP` | 12 PIDs before/after, identical set |

Missing field → FAIL with the exact gate code. Never silent pass.

## Output

Printed on stdout, newline-separated `KEY=VALUE` lines:

```
MISSION=LTE_E2E_NORTH_STAR
RUN_ID=<id>
S1_SETUP=PASS
ATTACH=PASS
EPS_BEARER=PASS_CONTROL_PLANE_ONLY
S1U_GTPU=FAIL
PING_UL=FAIL
PING_DL=FAIL
UDP_UL=FAIL
UDP_DL=FAIL
CLEANUP=PASS
GRANT_REVOKED=PASS
DUMPCAP=PASS
BLOCKERS=PING_UL,S1U_GTPU,PING_DL,UDP_UL,UDP_DL
FINAL_VERDICT=NO_LTE_E2E_REAL_PASS
```

Exit codes:

- `0` → `FINAL_VERDICT=REAL_PASS`
- `1` → `FINAL_VERDICT=NO_LTE_E2E_REAL_PASS` with concrete blockers
- `2` → IO/parse error (verifier could not read the pending-evidence bundle)

## Launch commands (no CI)

```sh
# Build + unit/fixture tests (release, deterministic locks)
cargo test --manifest-path POLARIS_CONTROL/tools/lte_e2e_verify/Cargo.toml --release

# Verify an arbitrary pending-evidence directory
cargo run --manifest-path POLARIS_CONTROL/tools/lte_e2e_verify/Cargo.toml --release -- \
  path/to/pending-evidence/

# Reproduce the e0497 verdict without a real run
cargo run --manifest-path POLARIS_CONTROL/tools/lte_e2e_verify/Cargo.toml --release -- \
  POLARIS_CONTROL/tools/lte_e2e_verify/fixtures/e0497
```

## Garde-fous

- Pure offline logic, no network, no shell exec, no file write outside the
  input directory.
- No raw PCAP read; the verifier consumes only sanitized JSON summaries.
- No subscriber identity is parsed or exposed; the schema deliberately omits
  IMSI/SUPI/TMSI/PEI fields.
- The crate does not touch `srsran_controller.rs`, the LTE compose or the
  srsRAN UE Dockerfile — those are owned by ANR3 on the 0.29.4 branch.
