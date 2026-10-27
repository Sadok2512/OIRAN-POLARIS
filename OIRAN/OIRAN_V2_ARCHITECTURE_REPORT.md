# OIRAN V2 Architecture Report

## Outcome

OIRAN V2 extends the existing application rather than replacing its Rust engines. The deployed path is:

`Certified PCAP/PCAPNG → Rust decoders → normalized events → session engine → correlation engine → API v2 → React presentation`

## Modules

- Overview: measured host state plus explicitly separated historical evidence.
- Probe Manager: real registered local vProbe and immutable capture inventory; control is unavailable.
- Session Explorer: dataset-, UE-, interface- and state-scoped reconstructed sessions.
- Call Flow Viewer: Rust-generated event ordering, directions, procedure groups and evidence.
- Packet Analyzer: packet references projected from normalized events without browser decoding.
- Correlation Studio: the 12 native Rust evidence edges and rule metadata.
- Export & Reports: canonical Rust HTML/JSON exports.
- Live Monitoring: host measurements and null live counters when no source exists.

## Version boundaries

Backend API is 2.0.0; Web is 2.0.0-dev. Existing decoder, event, session, correlation and Call Flow schema versions are preserved. The certified dataset is immutable and no migration was performed.

## Capture lifecycle

`POST /captures/validate` measures storage but returns `valid=false` with exact blockers. Start returns 503 `LIVE_CAPTURE_UNAVAILABLE`; Stop returns 409 `CAPTURE_NOT_RUNNING`. No capture command execution exists in this release.
