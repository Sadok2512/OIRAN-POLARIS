# S3.1 native capture reader report

## Result

capture-pcap 0.1.0 reads classic PCAP and PCAPNG without invoking external decoders. Real validation covered three immutable PCAPNG files and 2,758 packets; classic PCAP behavior is covered by deterministic unit fixtures because no selected POLARIS reference is classic PCAP.

Supported capture features:

- PCAP little/big endian, microsecond and nanosecond magic;
- PCAPNG section headers, per-section byte order, interface descriptions, enhanced and obsolete packet blocks;
- per-interface decimal or binary timestamp resolution and timestamp offset;
- multiple interfaces, exact raw timestamp ticks and resolution metadata;
- captured/original length, snaplen, block boundary, trailing-length and truncation checks;
- Ethernet, stacked 802.1Q/802.1ad VLAN and Linux cooked v1;
- IPv4, direct-header IPv6, UDP and SCTP classification.

Every packet carries capture ID, source path, ordinal, source block offset, exact timestamp tuple, captured/original length, interface ID and link type. A 256 MiB file bound and 16 MiB packet bound prevent accidental unbounded reads.

## Real evidence

| Capture | Bytes | Packets | Reader result |
|---|---:|---:|---|
| finalized N2 | 6,180 | 38 | PASS, Ethernet, ns timestamps |
| finalized N4 | 3,912 | 30 | PASS, Ethernet, ns timestamps |
| Open5GS 5g-roaming-lbo | 632,228 | 2,690 | PASS, Linux cooked v1 |

The reference capture contains four ARP frames. They produced explicit InvalidNetwork/unsupported EtherType diagnostics and no protocol events; this is expected because S3 targets IP/SCTP/UDP, not ARP.

## Reproduction

From /root/OIRAN_VPROBE:

    cargo test -p capture-pcap
    target/release/oiran-decode --input /var/lib/docker/volumes/oiran_lab_pcap/_data/n2/n2_20261024T200731Z_00001_20261024200732.pcapng \
      --capture-id sha256:2f23390dd619dda464ec8f2cfbd3b9fe59ca0587b043f6267a8ffc5a752cf54e \
      --interface N2 --endpoint 10.77.21.20=gNB --endpoint 10.77.21.11=AMF \
      --output S3_2_NORMALIZED_EVENTS.jsonl

## Boundaries

Simple Packet Blocks lack timestamps and are reported/omitted. IPv4 fragments and IPv6 extension-header chains require future IP reassembly. Linux cooked v2 and non-IP EtherTypes are explicit unsupported inputs. No capture file was copied, rewritten, renamed or permission-modified.
