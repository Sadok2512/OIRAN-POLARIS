# S3.2.1 multi-interface reference dataset

## Status

`MULTI_INTERFACE_DATASET = NOT_AVAILABLE`

The operational scenario supplies coherent N2 and N4 control-plane evidence but no N3 packets. The Open5GS documentation fixture contains NGAP, PFCP and GTP-U, but it is an immutable upstream example from 2023 and has no POLARIS scenario/controller ground truth; it must not be represented as the missing operational dataset.

## Captures

| Role | File | SHA-256 | Window / count |
|---|---|---|---|
| operational N2 | `/var/lib/docker/volumes/oiran_lab_pcap/_data/n2/n2_20261024T200731Z_00001_20261024200732.pcapng` | `2f23390dd619dda464ec8f2cfbd3b9fe59ca0587b043f6267a8ffc5a752cf54e` | 20:07:37–20:08:40 UTC; 38 packets; 14 NGAP messages |
| operational N4 | `/var/lib/docker/volumes/oiran_lab_pcap/_data/n4/n4_20261024T200731Z_00001_20261024200732.pcapng` | `8fad2f3401e79ea1695aa26cba649c03711e24ee0602625ec569ef82c3e6cfe7` | 20:07:40–20:08:36 UTC; 30 PFCP messages |
| operational N3 | `/var/lib/docker/volumes/oiran_lab_pcap/_data/n3/n3_20261024T200731Z_00001_20261024200732.pcapng` | `0bc683fedfd4c67b2fc5b6f9f2e0947a2a848fd5bee003298366d26db2a5ffa9` | zero packets |
| decoder fixture | `/root/POLARIS/src/open5gs/docs/assets/pcapng/5g-roaming-lbo.pcapng` | `d1250694017f99b4cddff820a1129c2decf864233f93a881c2a14611996f3ff1` | 2023-10-02; 2690 packets; 23 NGAP, 22 PFCP, 10 GTP-U selected events |

## Coherent evidence available today

The operational scenario is pseudonymized as `UE-A`: PDU Session ID 1 and UE address `10.46.0.4`. N4 supplies UPF F-TEID `0x000096a8` at `10.77.22.13`, matching the N2 setup request; the N2 response supplies gNB TEID `0x00000003` at `10.77.22.20`, matching PFCP outer-header creation. Those identifier equalities establish N2↔N4 linkage independently of time. There is no N3 packet carrying either TEID, so three-interface linkage cannot be certified.
