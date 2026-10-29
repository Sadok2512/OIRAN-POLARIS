//! Validate the bit-accurate APER walker against ground-truth fixtures produced
//! by the `asn1tools` Python library (codec `per`) on the minimal TS 38.413
//! subset in `OIRAN/decoder-ngap/tests/fixtures/minimal.asn`. Each fixture has
//! a value → bytes → decoder → value round-trip assertion so a byte-level drift
//! fails loudly.

use decoder_ngap::{
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
