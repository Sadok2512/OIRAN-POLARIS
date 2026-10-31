# OIRAN / POLARIS LTE E2E completion V2

Date: 2026-10-31 UTC  
Mode: offline implementation and validation only

## Integrated source

- Integration branch: `integ/oiran-polaris-lte-e2e-v2`
- ANR1 contract: `d22b1c1`
- ANR2 POLARIS: `d8876122e68348a37c3bbe1d4eabef892ef2d6e5`
- ANR3 OIRAN: `abaa56679644cf5cb9a87c0cdf8dec04f3687087`
- All three commits are ancestors of the integration commit. The merge uses
  the normal Git `ort` strategy; no `ours` strategy was used.

## Delivered behavior

POLARIS API 0.23.1 implements the bounded LTE state machine, durable ownership
and grant validation, evidence-backed S1/Attach/IP transitions, gated ping/UDP,
idempotent cancellation and cleanup, restart recovery, and operator UI state.
State publication occurs only after its observation is persisted.

OIRAN API 2.6.0-dev and live-probe 0.3.0-dev implement atomic and idempotent
ingestion of approved LTE evidence, S1AP/NAS, GTPv2-C and GTP-U reconstruction,
explicit TEID/bearer correlation, bounded Session/Call Flow pagination and a
pending-review export. Identity-bearing evidence is rejected.

The shared manifest requires decoder and event-schema versions on every
capture reference and exact equality with the OIRAN-owned binding.

## Validation evidence

| Component | Result |
|---|---|
| ANR1 JSON/state/deadline invariants | PASS |
| POLARIS Rust workspace | 269 passed, 0 failed, 3 manual benchmarks ignored |
| POLARIS LTE targeted | 21 passed |
| srsRAN runtime targeted | 8 passed |
| Simulator typecheck/build/audit | PASS / PASS / 0 production vulnerabilities |
| Simulator tests | 213 passed, 2 pre-existing timing failures |
| OIRAN Rust matrix | 153 passed, 0 failed, 4 pre-existing stress tests ignored |
| OIRAN LTE pipeline/API targeted | 5 passed / 2 passed |
| Analyzer tests/typecheck/build/leak scan | 73 passed / PASS / PASS / PASS |

The two open Simulator tests are the 10,000-profile search timeout and the
100,001-row asynchronous CSV timeout. They are offline timing defects, not
counted as PASS, and keep the overall verdict from `OFFLINE_PASS`.

## Current safety gates

At final review, `/` was 79% used, `MemAvailable` was 6,318,493,696 bytes and
12 exact `dumpcap` processes were present. No process was signalled or
restarted. No UE, traffic, capture or production deployment was performed.

## Open gates

1. Stabilize and rerun the two Simulator timing tests.
2. Obtain a separately approved `SANITIZED_APPROVED` LTE evidence bundle.
3. Pass the explicit LTE live authorization gate before any real run.
4. Only after real LTE S1/Attach/IP/UL/DL/cleanup evidence may `REAL_PASS` be
   considered.

`FINAL_VERDICT = PARTIAL`

— **ANR1**
