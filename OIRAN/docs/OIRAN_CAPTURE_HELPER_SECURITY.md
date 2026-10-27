# OIRAN Isolated Capture Helper Security Review

## Trust boundary

The Web API authenticates operators and orchestrates jobs but cannot open packet sockets. The helper has no HTTP listener and does not parse Web input directly. Its Unix peer credentials, fixed request schema, fixed interface enum, fixed capture root, global quota, and single-job policy form the privilege boundary.

## Capabilities

The native Linux AF_PACKET backend requires `CAP_NET_RAW` to create raw packet sockets. It does not enable promiscuous mode, change links, routes, namespaces, or firewall state, so `CAP_NET_ADMIN` is not required by the implementation. The proposed helper unit grants only `CAP_NET_RAW`.

The API drop-in explicitly clears ambient and bounding capabilities. Neither service receives `CAP_SETUID`, `CAP_SETGID`, `CAP_CHOWN`, unrestricted Docker access, or shell execution.

## Filesystem and data controls

- Helper writes are confined to `/var/lib/oiran/captures`.
- API access is through membership in the dedicated `oiran-capture` group.
- PCAP files use a global reserved budget, bounded rotation, duration limit, and continuous 75/80/85/90 disk policy.
- PCAP manifests are finalized with an atomic rename and contain SHA-256 checksums.
- Certified historical datasets remain outside the helper write path.
- There is no automatic cleanup.

## Remaining validation

AF_PACKET initialization and packet visibility require one separately approved bounded live test. Offline tests validate protocol security, lifecycle, PCAP structure, integrity metadata, quota handling, and failures; they do not certify live packet acquisition.
