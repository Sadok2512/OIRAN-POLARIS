# S5.4 capture topology

All bridges are in the host network namespace. Docker workloads attach through veth pairs; capture therefore occurs on the host bridge and observes both directions.

| Plane | Host interface | Endpoints | Transport/filter | Visibility | OIRAN helper |
|---|---|---|---|---|---|
| NG-C / N2 | `br-oiran-n2` | gNB `10.77.21.20` ↔ AMF `10.77.21.11` | SCTP/38412; `sctp port 38412` | Bidirectional, verified from completed PCAP | Allowlisted |
| NG-U / N3 | `br-oiran-n3` | gNB `10.77.22.20` ↔ UPF `10.77.22.13` | UDP/2152; `udp port 2152` | Bidirectional GTP-U verified in completed 18:12 UTC PCAP | Allowlisted |
| N4 | `br-oiran-n4` | SMF `10.77.23.12` ↔ UPF `10.77.23.13` | UDP/8805; `udp port 8805` | Bidirectional, verified from completed PCAP | Allowlisted |
| SBI | `br-oiran-sbi` | AMF `10.77.20.11` ↔ SMF `10.77.20.12` and other NFs | TCP/7777; `tcp port 7777` | Bidirectional plaintext HTTP/2 verified | **Not allowlisted** |

The dedicated helper runs as unprivileged `oiran-capture` with only `CAP_NET_RAW`, `AF_PACKET`/`AF_UNIX`, strict filesystem protection and no public port. Its IPC socket is `/run/oiran/capture-helper.sock`.

The separate laboratory capture container has host networking, `CAP_NET_RAW` and `CAP_NET_ADMIN`, a read-only root filesystem and a bounded writable capture volume. It currently runs `dumpcap` with 256 MiB rotation files and eight files per interface. This pre-existing process was neither started nor stopped by S5.4.

## Required correction before OIRAN-E2E-001

Add `SBI -> br-oiran-sbi` to the reviewed helper IPC enum, validation allowlist, filters, storage accounting and API schema, followed by offline tests and a separately authorized deployment. Silent fallback to the external capture container is not acceptable. Alternatively, formally designate the existing laboratory capture service as an authorized scenario capture provider and add immutable scenario/capture manifests. Either option requires a separate implementation and deployment authorization.
