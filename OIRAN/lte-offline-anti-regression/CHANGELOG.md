# Changelog

## 0.2.0 — 2026-11-06

- `tests/lte_contract_drifts.rs` — new file.
- `d1_infra_schema_plane_enum_is_hyphenated` asserts that
  `infrastructure/lte-certification/lte-evidence-schema.json` 1.1.2 carries
  hyphenated plane identifiers (`S1-MME`, `S1-U`, `S5-C`, `S5-U`) that
  match the OIRAN runtime. BC3 audit #9 (comment 6696746387), drift D-1.
- D-2/D-3/D-4/D-5 tests ship with `oiran-decode` 0.7.0 validator unit
  tests (`OIRAN/oiran-decode/src/lte_fixture.rs`).

## 0.1.0 — 2026-11-06

- BC3 audit of `cert/anr3-oiran-lte-offline-v1` (issue #9).
- `tests/lte_capture_isolation.rs` — two anti-regression tests pinned on the
  OIRAN 2.8.2 LTE correlation rules (`correlation-engine` 0.6.0,
  `LTE_RULE_VERSION = "1.1.0-offline.1"`):
  - `two_distinct_captures_sharing_the_same_teid_produce_no_cross_capture_edge`
    — a TEID literal reused across two distinct `capture_id` values must
    never bridge two captures.
  - `same_capture_two_ues_sharing_one_f_teid_must_fail_closed` — when two
    UE contexts within one capture both claim the same F-TEID, the S1-U
    event must be rejected by `session-engine::discover_lte_sessions`
    (single-owner rule at `OIRAN/session-engine/src/lib.rs:443` and
    `:472`), so the correlator emits zero S11→S1-U edges on that tunnel.
- Both tests PASS on `72b8293` (OIRAN 2.8.2); they guard against the
  engine ever regressing to a lax ownership rule.
