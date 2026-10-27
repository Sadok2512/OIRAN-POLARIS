# S3.2 independent TShark parity report

Reference decoder: TShark 4.2.2 from the existing oiran-lab-capture-1 image. It was invoked read-only. Nothing was installed and no container was restarted.

## Aligned result

| Protocol | Reference Messages | OIRAN Messages | Exact header/alignment | Mismatch | Missing | Partial/Unsupported IE content |
|---|---:|---:|---:|---:|---:|---:|
| NGAP | 37 | 37 | 37 | 0 | 0 | 33 |
| PFCP | 52 | 52 | 52 | 0 | 0 | 12 |
| GTP-U | 10 | 10 | 10 | 0 | 0 | 0 |

Exact header/alignment means packet or reassembled packet set, timestamp, endpoints, protocol message type/name, procedure code or sequence number, and TEID where applicable matched. It does not mean every nested IE was typed. NGAP/PFCP partial counts overlap exact header alignment and are deliberately not presented as full parity.

Checks performed:

- finalized N2: TShark 13 NGAP packets containing 14 messages; OIRAN 14 messages, including two DATA chunks in frame 13;
- finalized N4: 30 PFCP messages in both decoders;
- Open5GS reference: 23 NGAP, 22 PFCP and 10 GTP-U in both decoders;
- exact procedure-code sequence for all 37 NGAP messages;
- exact message-type/sequence sequence for all 52 PFCP messages;
- exact message-type/TEID sequence for all ten GTP-U packets;
- exact nanosecond source timestamps and outer endpoints;
- accessible NGAP AMF/RAN UE IDs and relevant PFCP identifiers checked at message level.

## Reproducibility

Operational reference:

    docker exec oiran-lab-capture-1 tshark \
      -r /captures/n2/n2_20261024T200731Z_00001_20261024200732.pcapng \
      -Y ngap -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
      -e ngap.procedureCode -e ngap.AMF_UE_NGAP_ID -e ngap.RAN_UE_NGAP_ID

Immutable source fixture streamed without copying into the container:

    docker exec -i oiran-lab-capture-1 tshark -r - \
      -Y 'ngap || pfcp || (gtp && udp.port==2152)' -T fields \
      -e frame.number -e frame.time_epoch -e ip.src -e ip.dst \
      -e ngap.procedureCode -e pfcp.msg_type -e pfcp.seqno -e pfcp.seid \
      -e gtp.message -e gtp.teid \
      < /root/POLARIS/src/open5gs/docs/assets/pcapng/5g-roaming-lbo.pcapng

Full NGAP IE parity is not claimed. The reference is independently implemented by Wireshark; OIRAN does not consume TShark output during decoding.
