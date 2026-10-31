# LTE certification tooling

This directory belongs to the ANR1 infrastructure/certification boundary. It
does not start containers, create grants, generate traffic, or alter Open5GS.

## Commands

```bash
./infrastructure/lte-certification/lte-preflight.sh

./infrastructure/lte-certification/lte-pcap-release-gate.sh \
  /path/to/sanitized-candidate.pcapng
```

The preflight emits one JSON document and exits non-zero unless every static
gate passes. The PCAP gate is deliberately fail-closed: it requires a packet
decoder and rejects any decoded subscriber identity. Passing this gate is
necessary but not sufficient for public release; byte-exact anonymization and
an independent second review remain mandatory.

The canonical evidence contract is `lte-evidence-schema.json`. Runtime code
must never put subscriber identities, authentication material, cookies, grant
nonces, or protected NAS payloads in this manifest.

