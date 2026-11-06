# Changelog

## 1.1.2 — 2026-11-06

- Fix `lte-evidence-schema.json`: the `capture_refs[].plane` enum used
  underscores (`S1_MME`, `S1_U`, `S5_C`, `S5_U`) which never match the
  hyphenated plane identifiers emitted by the OIRAN runtime (grep
  `event.interface == "S1-MME"` in `OIRAN/session-engine/src/lib.rs`).
  Hyphens are now authoritative.
- Fix `lte-orchestration-v2.json` `required_planes` and `plane_aliases`
  to the same hyphenated convention; the alias map becomes identity,
  kept for downstream readers that still consult it.
- BC3 audit #9 (comment 6696746387), drift D-1.

## 1.1.1 — 2026-10-31

- Require decoder and event-schema versions on every LTE capture reference
  and exact equality with the OIRAN-owned binding.

## 1.1.0 — 2026-10-31

- Add the machine-readable LTE orchestration V2 state, deadline, resource and
  evidence contract for coordinated POLARIS/OIRAN offline implementation.

## 1.0.0 — 2026-10-31

- Add a read-only, fail-closed LTE certification preflight.
- Add the versioned evidence manifest schema shared by POLARIS and OIRAN.
- Add a fail-closed release gate for sanitized LTE PCAP derivatives.

