//! Validate the bit-accurate APER walker against ground-truth fixtures produced
//! by the `asn1tools` Python library (codec `per`) on the minimal TS 38.413
//! subset in `OIRAN/decoder-ngap/tests/fixtures/minimal.asn`. Each fixture has
//! a value → bytes → decoder → value round-trip assertion so a byte-level drift
//! fails loudly.

use decoder_ngap::{
    decode_pdu_session_resource_setup_list_su_req, decode_pdu_session_resource_setup_list_su_res,
    decode_pdu_session_resource_setup_request_transfer,
    decode_pdu_session_resource_setup_response_transfer, AssociatedQosFlowMapping, CauseKind,
    QosCharacteristics, UpTransportLayerInformation,
};

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// ===== Response Transfer fixtures ========================================

#[test]
fn response_minimal_decodes_dl_tunnel_and_single_qfi() {
    // asn1tools-encoded: 1 QFI, no optionals, IPv4 192.0.2.1 TEID cafebabe
    let r = decode_pdu_session_resource_setup_response_transfer(&bytes(
        "0001f0c0000201cafebabe000a",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.dl.tunnel.ipv4_address().unwrap().to_string(), "192.0.2.1");
    assert_eq!(r.dl.tunnel.teid(), Some(0xcafebabe));
    assert_eq!(r.dl.qfis.len(), 1);
    assert_eq!(r.dl.qfis[0].qfi, 5);
    assert!(r.dl.qfis[0].mapping_indication.is_none());
    assert!(r.additional_dl.is_empty());
    assert!(r.security.is_none());
    assert!(r.failed.is_empty());
}

#[test]
fn response_three_qfi_with_mapping_decodes_each_mapping_indication() {
    let r = decode_pdu_session_resource_setup_response_transfer(&bytes(
        "0001f0c00002020000beef08028907e0",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.dl.tunnel.ipv4_address().unwrap().to_string(), "192.0.2.2");
    assert_eq!(r.dl.tunnel.teid(), Some(0x0000beef));
    let qfis: Vec<_> = r
        .dl
        .qfis
        .iter()
        .map(|q| (q.qfi, q.mapping_indication.clone()))
        .collect();
    assert_eq!(
        qfis,
        vec![
            (1, None),
            (9, Some(AssociatedQosFlowMapping::Ul)),
            (63, None),
        ]
    );
}

#[test]
fn response_additional_dl_list_exposes_two_extra_tunnels() {
    let r = decode_pdu_session_resource_setup_response_transfer(&bytes(
        "4001f0c0000203000000010004800f80c0000204000000020006003ec000020500000003040805",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.dl.tunnel.ipv4_address().unwrap().to_string(), "192.0.2.3");
    assert_eq!(r.additional_dl.len(), 2);
    assert_eq!(
        r.additional_dl[0]
            .tunnel
            .ipv4_address()
            .unwrap()
            .to_string(),
        "192.0.2.4"
    );
    assert_eq!(r.additional_dl[0].tunnel.teid(), Some(2));
    assert_eq!(r.additional_dl[0].qfis.len(), 1);
    assert_eq!(r.additional_dl[0].qfis[0].qfi, 3);
    assert_eq!(
        r.additional_dl[1]
            .tunnel
            .ipv4_address()
            .unwrap()
            .to_string(),
        "192.0.2.5"
    );
    assert_eq!(r.additional_dl[1].tunnel.teid(), Some(3));
    let qfis: Vec<u8> = r.additional_dl[1].qfis.iter().map(|q| q.qfi).collect();
    assert_eq!(qfis, vec![4, 5]);
}

#[test]
fn response_failed_list_exposes_qfi_cause_pairs() {
    let r = decode_pdu_session_resource_setup_response_transfer(&bytes(
        "1001f0c000020612345678000610200038818440",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.failed.len(), 3);
    assert_eq!(r.failed[0].qfi, 4);
    assert_eq!(r.failed[0].cause, CauseKind::RadioNetwork(0));
    assert_eq!(r.failed[1].qfi, 7);
    assert_eq!(r.failed[1].cause, CauseKind::Transport(0));
    assert_eq!(r.failed[2].qfi, 12);
    assert_eq!(r.failed[2].cause, CauseKind::Nas(1));
}

#[test]
fn response_security_result_exposes_integrity_and_confidentiality() {
    let r = decode_pdu_session_resource_setup_response_transfer(&bytes(
        "2001f0c000020700000101001e08",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    let sec = r.security.expect("security present");
    assert_eq!(sec.integrity, "performed");
    assert_eq!(sec.confidentiality, "not-performed");
}

#[test]
fn response_all_optionals_decode_in_a_single_pass() {
    let r = decode_pdu_session_resource_setup_response_transfer(&bytes(
        "7001f0c00002080000a0a00002000f80c00002090000a0a10004000288a0",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.dl.tunnel.ipv4_address().unwrap().to_string(), "192.0.2.8");
    assert_eq!(r.dl.qfis.len(), 1);
    assert_eq!(r.dl.qfis[0].qfi, 1);
    assert_eq!(r.additional_dl.len(), 1);
    assert_eq!(
        r.additional_dl[0]
            .tunnel
            .ipv4_address()
            .unwrap()
            .to_string(),
        "192.0.2.9"
    );
    assert_eq!(r.additional_dl[0].qfis[0].qfi, 2);
    assert_eq!(r.security.as_ref().unwrap().integrity, "performed");
    assert_eq!(r.security.unwrap().confidentiality, "performed");
    assert_eq!(r.failed.len(), 1);
    assert_eq!(r.failed[0].qfi, 20);
    assert!(matches!(r.failed[0].cause, CauseKind::Misc(_)));
}

// ===== Request Transfer fixtures =========================================

#[test]
fn request_minimal_decodes_ul_tunnel_and_single_qfi() {
    let r = decode_pdu_session_resource_setup_request_transfer(&bytes(
        "0003e00a4d0b16cafebabe00002000090c80",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.ul_tunnel.ipv4_address().unwrap().to_string(), "10.77.11.22");
    assert_eq!(r.ul_tunnel.teid(), Some(0xcafebabe));
    assert_eq!(r.pdu_session_type, Some("ipv4"));
    assert_eq!(r.qos_flows.len(), 1);
    let item = &r.qos_flows[0];
    assert_eq!(item.qfi, 1);
    match &item.qos_params.characteristics {
        QosCharacteristics::NonDynamic5QI { five_qi, .. } => assert_eq!(*five_qi, 9),
        other => panic!("expected NonDynamic5QI, got {other:?}"),
    }
    assert_eq!(item.qos_params.arp.priority, 7);
    assert_eq!(item.qos_params.arp.capability, "may-trigger-pre-emption");
    assert_eq!(item.qos_params.arp.vulnerability, "not-pre-emptable");
}

#[test]
fn request_three_qfi_non_dynamic_5qi_each_qfi_and_arp_match() {
    let r = decode_pdu_session_resource_setup_request_transfer(&bytes(
        "0003e00a4d0b170000beef10802000050020900000071ca3f00000ff0e80",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.pdu_session_type, Some("ipv6"));
    assert_eq!(r.qos_flows.len(), 3);
    let decoded: Vec<_> = r
        .qos_flows
        .iter()
        .map(|q| {
            let five_qi = match &q.qos_params.characteristics {
                QosCharacteristics::NonDynamic5QI { five_qi, .. } => *five_qi,
                _ => 0,
            };
            (
                q.qfi,
                five_qi,
                q.qos_params.arp.priority,
                q.qos_params.arp.capability,
                q.qos_params.arp.vulnerability,
            )
        })
        .collect();
    assert_eq!(
        decoded,
        vec![
            (1, 5, 1, "shall-not-trigger-pre-emption", "pre-emptable"),
            (9, 7, 15, "may-trigger-pre-emption", "pre-emptable"),
            (63, 255, 8, "may-trigger-pre-emption", "not-pre-emptable"),
        ]
    );
}

#[test]
fn request_with_gbr_decodes_flow_bitrates() {
    let r = decode_pdu_session_resource_setup_request_transfer(&bytes(
        "0003e00a4d0b18010203043000a800010480201e8480200f42402016e360200b71b0",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.pdu_session_type, Some("ethernet"));
    assert_eq!(r.qos_flows.len(), 1);
    let gbr = r.qos_flows[0].qos_params.gbr.as_ref().expect("gbr present");
    assert_eq!(gbr.maximum_flow_dl, 2_000_000);
    assert_eq!(gbr.maximum_flow_ul, 1_000_000);
    assert_eq!(gbr.guaranteed_flow_dl, 1_500_000);
    assert_eq!(gbr.guaranteed_flow_ul, 750_000);
}

#[test]
fn request_with_dynamic_5qi_decodes_pdb_and_packet_error_rate() {
    let r = decode_pdu_session_resource_setup_request_transfer(&bytes(
        "0003e00a4d0b19050607082001404052006402602a",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.pdu_session_type, Some("ipv4v6"));
    match &r.qos_flows[0].qos_params.characteristics {
        QosCharacteristics::Dynamic5QI {
            priority_level_qos,
            packet_delay_budget,
            per_scalar,
            per_exponent,
            ..
        } => {
            assert_eq!(*priority_level_qos, 42);
            assert_eq!(*packet_delay_budget, 100);
            assert_eq!(*per_scalar, 1);
            assert_eq!(*per_exponent, 6);
        }
        other => panic!("expected Dynamic5QI, got {other:?}"),
    }
}

#[test]
fn request_with_reflective_qos_exposes_reflective_attribute() {
    let r = decode_pdu_session_resource_setup_request_transfer(&bytes(
        "0003e00a4d0b1a090a0b0c400284000208a0",
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.pdu_session_type, Some("unstructured"));
    assert_eq!(r.qos_flows[0].qos_params.reflective_qos, Some("subject-to"));
}

// ===== Negative tests: unsupported fields surface in `errors` ============

#[test]
fn truncated_response_transfer_reports_specific_errors_not_silently_rejected() {
    // Mutilate the response_minimal fixture after the preamble so the DL tunnel
    // decode errors out mid-way; the walker must name the offending field in
    // `errors` instead of silently returning an empty structure.
    let r = decode_pdu_session_resource_setup_response_transfer(&bytes("0001f0c00002"));
    assert!(
        r.errors
            .iter()
            .any(|e| e.contains("TransportLayerAddress") || e.contains("GTP-TEID")),
        "errors should name the truncated primitive: {:?}",
        r.errors
    );
}

// ===== Outer list fixtures (PDUSessionResourceSetupListSUReq/SURes) ======

#[test]
fn list_sureq_1_session_sst_only_decodes_outer_envelope() {
    let list = decode_pdu_session_resource_setup_list_su_req(&bytes(
        "000005002001ab",
    ));
    assert!(list.errors.is_empty(), "errors: {:?}", list.errors);
    assert_eq!(list.items.len(), 1);
    let item = &list.items[0];
    assert_eq!(item.pdu_session_id, 5);
    assert_eq!(item.nas_pdu, None);
    assert_eq!(item.s_nssai.sst, 1);
    assert_eq!(item.s_nssai.sd, None);
    assert!(!item.ie_extensions_present);
    assert_eq!(item.transfer, vec![0xab]);
}

#[test]
fn list_sureq_1_session_with_nas_pdu_round_trips_nas_bytes() {
    let list = decode_pdu_session_resource_setup_list_su_req(&bytes(
        "004007047e00446f002001ab",
    ));
    assert!(list.errors.is_empty(), "errors: {:?}", list.errors);
    assert_eq!(list.items.len(), 1);
    let item = &list.items[0];
    assert_eq!(item.pdu_session_id, 7);
    assert_eq!(item.nas_pdu, Some(vec![0x7e, 0x00, 0x44, 0x6f]));
    assert_eq!(item.s_nssai.sst, 1);
    assert_eq!(item.transfer, vec![0xab]);
}

#[test]
fn list_sureq_1_session_sst_sd_exposes_slice_differentiator() {
    let list = decode_pdu_session_resource_setup_list_su_req(&bytes(
        "000009402002030401ab",
    ));
    assert!(list.errors.is_empty(), "errors: {:?}", list.errors);
    assert_eq!(list.items.len(), 1);
    let item = &list.items[0];
    assert_eq!(item.pdu_session_id, 9);
    assert_eq!(item.s_nssai.sst, 1);
    assert_eq!(item.s_nssai.sd, Some([0x02, 0x03, 0x04]));
    assert_eq!(item.transfer, vec![0xab]);
}

#[test]
fn list_sureq_1_session_item_ie_ext_is_flagged() {
    let list = decode_pdu_session_resource_setup_list_su_req(&bytes("00200b002001ab"));
    assert_eq!(list.items.len(), 1);
    let item = &list.items[0];
    assert_eq!(item.pdu_session_id, 11);
    assert!(item.ie_extensions_present);
    assert_eq!(item.transfer, vec![0xab]);
    assert!(
        list.errors
            .iter()
            .any(|e| e.contains("iE-Extensions present")),
        "errors should name the ext: {:?}",
        list.errors
    );
}

#[test]
fn list_sureq_3_sessions_mixed_walks_each_item_with_its_own_optionals() {
    let list = decode_pdu_session_resource_setup_list_su_req(&bytes(
        "024001047e00446f002001ab0002402001020301ab2003004001ab",
    ));
    assert_eq!(list.items.len(), 3);
    // Item 0: NAS-PDU present, SST only.
    assert_eq!(list.items[0].pdu_session_id, 1);
    assert_eq!(list.items[0].nas_pdu.as_deref(), Some(&[0x7e, 0x00, 0x44, 0x6f][..]));
    assert_eq!(list.items[0].s_nssai.sst, 1);
    assert_eq!(list.items[0].s_nssai.sd, None);
    assert!(!list.items[0].ie_extensions_present);
    assert_eq!(list.items[0].transfer, vec![0xab]);
    // Item 1: no NAS-PDU, SST+SD.
    assert_eq!(list.items[1].pdu_session_id, 2);
    assert_eq!(list.items[1].nas_pdu, None);
    assert_eq!(list.items[1].s_nssai.sst, 1);
    assert_eq!(list.items[1].s_nssai.sd, Some([0x01, 0x02, 0x03]));
    // Item 2: SST=2 and iE-Extensions present.
    assert_eq!(list.items[2].pdu_session_id, 3);
    assert_eq!(list.items[2].s_nssai.sst, 2);
    assert_eq!(list.items[2].s_nssai.sd, None);
    assert!(list.items[2].ie_extensions_present);
    assert_eq!(list.items[2].transfer, vec![0xab]);
}

#[test]
fn list_sures_1_session_decodes_pdu_session_id_and_transfer() {
    let list = decode_pdu_session_resource_setup_list_su_res(&bytes("00000501ab"));
    assert!(list.errors.is_empty(), "errors: {:?}", list.errors);
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].pdu_session_id, 5);
    assert_eq!(list.items[0].transfer, vec![0xab]);
    assert!(!list.items[0].ie_extensions_present);
}

#[test]
fn list_sures_3_sessions_item_ie_ext_flags_last_item() {
    let list = decode_pdu_session_resource_setup_list_su_res(&bytes(
        "02000101ab000201ab400301ab",
    ));
    assert_eq!(list.items.len(), 3);
    assert_eq!(list.items[0].pdu_session_id, 1);
    assert!(!list.items[0].ie_extensions_present);
    assert_eq!(list.items[1].pdu_session_id, 2);
    assert!(!list.items[1].ie_extensions_present);
    assert_eq!(list.items[2].pdu_session_id, 3);
    assert!(list.items[2].ie_extensions_present);
    for item in &list.items {
        assert_eq!(item.transfer, vec![0xab]);
    }
}

#[test]
fn qos_flow_mapping_indication_extension_decodes_normally_small_number() {
    // Hand-crafted response transfer where associatedQosFlowList has one item
    // whose qosFlowMappingIndication is in the extension additions. Encoding:
    //   SEQUENCE preamble (6 bits = 000000) + 2 pad.
    //   QosFlowPerTNLInformation preamble (2 bits = 00).
    //   UPTransportLayerInformation CHOICE ext=0; GTPTunnel preamble (2 bits);
    //   BIT STRING ext=0 + 8-bit size=31 → length byte 0x1f aligned.
    //   32 bits of IP + 32 bits of TEID.
    //   AssociatedQosFlowList size (6 bits = 000000 for 1 item).
    //   SEQUENCE preamble (3 bits: ext=0, mapping=1, iE-Ext=0).
    //   QFI (6 bits = 000010 for QFI=2).
    //   qosFlowMappingIndication ENUMERATED extension: ext bit = 1,
    //     NSNNWN prefix=0, 6 bits = 000011 → extension index 3.
    // Rather than hand-pack bits, we start from response_minimal and splice
    // the ext path by concatenating the first 11 bytes with our crafted tail.
    //
    // We rely on the aperreader bit-level decode: build the tail by writing
    // bits via a helper, then verify.
    let mut bits = BitBuffer::new();
    bits.push_bits(0, 6); // response preamble ext=0 + 5 opts=0 (6 bits)
    bits.push_bits(0, 2); // QosFlowPerTNLInformation preamble (ext + 1 opt)
    bits.push_bits(0, 1); // UPTransportLayerInformation CHOICE ext
    bits.push_bits(0, 2); // GTPTunnel preamble (ext + 1 opt)
    bits.push_bits(0, 1); // TransportLayerAddress BIT STRING ext
    bits.push_bits(31, 8); // size-1 (32 bits), unaligned bit-field
    bits.align();
    bits.push_octets(&[0xc0, 0x00, 0x02, 0x7f]); // IPv4
    bits.push_octets(&[0x00, 0x00, 0xca, 0xfe]); // TEID
    bits.push_bits(0, 6); // AssociatedQosFlowList size-1 (1 item)
    bits.push_bits(0, 1); // AssociatedQosFlowItem ext
    bits.push_bits(1, 1); // qosFlowMappingIndication present
    bits.push_bits(0, 1); // iE-Ext absent
    bits.push_bits(2, 6); // QFI = 2
    bits.push_bits(1, 1); // qosFlowMappingIndication ENUMERATED ext=1
    bits.push_bits(0, 1); // NSNNWN prefix: 0 → 6-bit value follows
    bits.push_bits(3, 6); // extension index = 3
    let payload = bits.finish();

    let r = decode_pdu_session_resource_setup_response_transfer(&payload);
    assert_eq!(r.dl.qfis.len(), 1);
    assert_eq!(r.dl.qfis[0].qfi, 2);
    assert_eq!(
        r.dl.qfis[0].mapping_indication,
        Some(AssociatedQosFlowMapping::UnknownExtension(3))
    );
}

/// Minimal MSB-first bit buffer used by the extension-mapping fixture test.
struct BitBuffer {
    data: Vec<u8>,
    cursor_bits: usize,
}

impl BitBuffer {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            cursor_bits: 0,
        }
    }

    fn push_bit(&mut self, bit: u64) {
        let bit = (bit & 1) as u8;
        if self.cursor_bits % 8 == 0 {
            self.data.push(0);
        }
        let byte_index = self.cursor_bits / 8;
        let bit_offset = 7 - (self.cursor_bits % 8);
        self.data[byte_index] |= bit << bit_offset;
        self.cursor_bits += 1;
    }

    fn push_bits(&mut self, value: u64, width: usize) {
        for i in (0..width).rev() {
            self.push_bit((value >> i) & 1);
        }
    }

    fn align(&mut self) {
        while self.cursor_bits % 8 != 0 {
            self.push_bit(0);
        }
    }

    fn push_octets(&mut self, octets: &[u8]) {
        self.align();
        self.data.extend_from_slice(octets);
        self.cursor_bits += octets.len() * 8;
    }

    fn finish(mut self) -> Vec<u8> {
        self.align();
        self.data
    }
}

#[test]
fn unsupported_up_transport_choice_extension_is_named_in_errors() {
    // CHOICE ext=1 at bit 8: byte 0 preamble=0x00, byte 1 bit 0 (MSB) = 1 → byte 1 = 0x80.
    let r = decode_pdu_session_resource_setup_response_transfer(&bytes("0080"));
    assert!(
        matches!(r.dl.tunnel, UpTransportLayerInformation::Unsupported(_)),
        "tunnel should be Unsupported, got {:?}",
        r.dl.tunnel
    );
    assert!(
        r.errors
            .iter()
            .any(|e| e.contains("UPTransportLayerInformation")),
        "errors should name the extension-alternative CHOICE: {:?}",
        r.errors
    );
}
