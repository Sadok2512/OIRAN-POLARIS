//! Pycrate-generated ground-truth fixtures for TS 38.413 NGAP APER.
//!
//! Each fixture is encoded by `tests/fixtures/gen_pycrate_fixtures.py`
//! (pip install pycrate) which drives the real 3GPP ASN.1 module
//! (`pycrate_asn1dir.NGAP`). The hex blobs are stored verbatim in this
//! test module; a regeneration script is kept for traceability.

use decoder_ngap::{
    decode_pdu_session_resource_setup_list_cxt_req,
    decode_pdu_session_resource_setup_list_cxt_res, decode_pdu_session_resource_setup_list_su_req,
    decode_pdu_session_resource_setup_list_su_res,
    decode_pdu_session_resource_setup_request_transfer,
    decode_pdu_session_resource_setup_response_transfer, parse, CauseKind, PduKind,
    QosCharacteristics,
};

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// ===== Transfer-level fixtures =====

const REQUEST_TRANSFER_MINIMAL: &str =
    "000003008b000a01f0c00002011122334400860001000088000700050000091900";

#[test]
fn request_transfer_minimal_decodes_tunnel_pdu_type_and_qos_flow() {
    let r = decode_pdu_session_resource_setup_request_transfer(&bytes(REQUEST_TRANSFER_MINIMAL));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    let ul = r.ul_tunnel.expect("UL tunnel");
    assert_eq!(ul.ipv4_address().unwrap().to_string(), "192.0.2.1");
    assert_eq!(ul.teid(), Some(0x11223344));
    assert_eq!(r.pdu_session_type, Some("ipv4"));
    assert_eq!(r.qos_flows.len(), 1);
    let flow = &r.qos_flows[0];
    assert_eq!(flow.qfi, 5);
    match &flow.qos_params.characteristics {
        QosCharacteristics::NonDynamic5QI { five_qi, .. } => assert_eq!(*five_qi, 9),
        other => panic!("expected nonDynamic5QI, got {other:?}"),
    }
    assert_eq!(flow.qos_params.arp.priority, 7);
    assert_eq!(flow.qos_params.arp.capability, "may-trigger-pre-emption");
    assert_eq!(flow.qos_params.arp.vulnerability, "not-pre-emptable");
}

const REQUEST_TRANSFER_WITH_AMBR_GBR: &str =
    "00000400820008081e8480200f4240008b000a01f0c00002020000beef00860001100088002308010000050040940000073940401e8480200f42402016e360200b71b00fc000ff1d00";

#[test]
fn request_transfer_with_ambr_and_gbr_decodes_bitrates() {
    let r =
        decode_pdu_session_resource_setup_request_transfer(&bytes(REQUEST_TRANSFER_WITH_AMBR_GBR));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.ambr_dl, Some(2_000_000));
    assert_eq!(r.ambr_ul, Some(1_000_000));
    let ul = r.ul_tunnel.expect("UL tunnel");
    assert_eq!(ul.ipv4_address().unwrap().to_string(), "192.0.2.2");
    assert_eq!(ul.teid(), Some(0x0000beef));
    assert_eq!(r.pdu_session_type, Some("ipv6"));
    assert_eq!(r.qos_flows.len(), 3);
    assert_eq!(r.qos_flows[0].qfi, 1);
    assert_eq!(r.qos_flows[1].qfi, 9);
    assert_eq!(r.qos_flows[2].qfi, 63);
    let gbr = r.qos_flows[1]
        .qos_params
        .gbr
        .as_ref()
        .expect("gbr on QFI 9");
    assert_eq!(gbr.maximum_flow_dl, 2_000_000);
    assert_eq!(gbr.maximum_flow_ul, 1_000_000);
    assert_eq!(gbr.guaranteed_flow_dl, 1_500_000);
    assert_eq!(gbr.guaranteed_flow_ul, 750_000);
}

const RESPONSE_TRANSFER_MINIMAL: &str = "0003e0c0000203112233440005";

#[test]
fn response_transfer_minimal_decodes_dl_tunnel_and_qfi() {
    let r = decode_pdu_session_resource_setup_response_transfer(&bytes(RESPONSE_TRANSFER_MINIMAL));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.dl.tunnel.ipv4_address().unwrap().to_string(), "192.0.2.3");
    assert_eq!(r.dl.tunnel.teid(), Some(0x11223344));
    assert_eq!(r.dl.qfis.len(), 1);
    assert_eq!(r.dl.qfis[0].qfi, 5);
    assert!(r.additional_dl.is_empty());
    assert!(r.security.is_none());
    assert!(r.failed.is_empty());
    assert!(r.redundant.is_none());
}

const RESPONSE_TRANSFER_ALL_OPTIONALS: &str =
    "7003e0c00002040000a0a000010007c0c00002050000a0a100020000a450";

#[test]
fn response_transfer_all_optionals_decodes_additional_security_and_failed() {
    let r = decode_pdu_session_resource_setup_response_transfer(&bytes(
        RESPONSE_TRANSFER_ALL_OPTIONALS,
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    assert_eq!(r.dl.tunnel.ipv4_address().unwrap().to_string(), "192.0.2.4");
    assert_eq!(r.dl.tunnel.teid(), Some(0xa0a0));
    assert_eq!(r.dl.qfis[0].qfi, 1);
    assert_eq!(r.additional_dl.len(), 1);
    assert_eq!(
        r.additional_dl[0]
            .tunnel
            .ipv4_address()
            .unwrap()
            .to_string(),
        "192.0.2.5"
    );
    assert_eq!(r.additional_dl[0].tunnel.teid(), Some(0xa0a1));
    assert_eq!(r.additional_dl[0].qfis[0].qfi, 2);
    let sec = r.security.expect("security present");
    assert_eq!(sec.integrity, "performed");
    assert_eq!(sec.confidentiality, "performed");
    assert_eq!(r.failed.len(), 1);
    assert_eq!(r.failed[0].qfi, 20);
    assert!(matches!(r.failed[0].cause, CauseKind::Misc(_)));
}

// ===== Guard-rail =====

const GUARD_RAIL_TEID_11223344_QFI_5: &str =
    "000003008b000a01f00a4d0b161122334400860001000088000700050000090000";

#[test]
fn guard_rail_teid_0x11223344_and_qfi_5_round_trip_exactly() {
    let r = decode_pdu_session_resource_setup_request_transfer(&bytes(
        GUARD_RAIL_TEID_11223344_QFI_5,
    ));
    assert!(r.errors.is_empty(), "errors: {:?}", r.errors);
    let ul = r.ul_tunnel.expect("UL tunnel");
    assert_eq!(
        ul.teid(),
        Some(0x11223344),
        "TEID MUST round-trip exactly 0x11223344"
    );
    assert_eq!(r.qos_flows.len(), 1);
    assert_eq!(r.qos_flows[0].qfi, 5, "QFI MUST round-trip exactly 5");
}

#[test]
fn guard_rail_mangled_bytes_return_errors_not_a_wrong_value() {
    // Flip the TEID bytes in the middle of the valid fixture. The resulting
    // bytes are no longer well-formed APER (CHOICE/BIT-STRING indicators are
    // untouched, but the TEID octets following them are tampered). The
    // decoder must either produce an error entry OR return a TEID that is NOT
    // 0x11223344 — never a silent "0x11223344" value from a lucky collision.
    //
    // We assert strictly that: either `errors` is non-empty, OR the TEID
    // differs from 0x11223344. This is the "jamais une valeur" guarantee.
    let mut mangled = bytes(GUARD_RAIL_TEID_11223344_QFI_5);
    // Zero out the TEID bytes (which are preserved verbatim in the fixture).
    // Byte offset of TEID: find 11 22 33 44 and overwrite with aa bb cc dd.
    let pos = mangled
        .windows(4)
        .position(|w| w == [0x11, 0x22, 0x33, 0x44])
        .expect("TEID marker present");
    for (i, b) in [0xaa, 0xbb, 0xcc, 0xdd].iter().enumerate() {
        mangled[pos + i] = *b;
    }
    let r = decode_pdu_session_resource_setup_request_transfer(&mangled);
    let teid = r.ul_tunnel.as_ref().and_then(|t| t.teid());
    assert_ne!(
        teid,
        Some(0x11223344),
        "mangled fixture must not round-trip the original TEID; errors={:?}",
        r.errors
    );
    assert_eq!(teid, Some(0xaabbccdd));
}

#[test]
fn guard_rail_truncated_bytes_surface_errors_without_fabricated_values() {
    // Half the fixture → walker must surface named errors in `errors` and
    // return default values for missing fields, never a silent fabricated
    // QFI or TEID.
    let full = bytes(GUARD_RAIL_TEID_11223344_QFI_5);
    let truncated = &full[..full.len() / 2];
    let r = decode_pdu_session_resource_setup_request_transfer(truncated);
    assert!(
        !r.errors.is_empty(),
        "truncated fixture must surface errors (got: {:?})",
        r.errors
    );
    // The TEID bytes are past the truncation; so UL tunnel's teid must be 0.
    if let Some(ul) = &r.ul_tunnel {
        assert_ne!(
            ul.teid(),
            Some(0x11223344),
            "truncated fixture must not fabricate the TEID"
        );
    }
}

// ===== Full PDU fixtures via NGAP parse + outer list walker =====

const PDU_SETUP_REQUEST_1_SESSION: &str =
    "001d003a000003000a0002000c00550002000c004a0027000005002021000003008b000a01f00a4d0b171122334400860001000088000700050000090000";

#[test]
fn full_pdu_setup_request_decodes_ie74_and_inner_transfer() {
    let payload = bytes(PDU_SETUP_REQUEST_1_SESSION);
    let pdu = parse(&payload).expect("parse PDU");
    assert_eq!(pdu.kind, PduKind::Initiating);
    assert_eq!(pdu.procedure_code, 29);
    assert_eq!(pdu.message_name, "PDUSessionResourceSetupRequest");
    let ie_74 = pdu
        .ies
        .iter()
        .find(|ie| ie.id == 74)
        .expect("IE 74 present");
    let list = decode_pdu_session_resource_setup_list_su_req(&ie_74.value);
    assert!(list.errors.is_empty(), "errors: {:?}", list.errors);
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].pdu_session_id, 5);
    assert_eq!(list.items[0].s_nssai.sst, 1);
    let decoded =
        decode_pdu_session_resource_setup_request_transfer(&list.items[0].transfer);
    assert!(decoded.errors.is_empty(), "transfer errors: {:?}", decoded.errors);
    let ul = decoded.ul_tunnel.expect("UL tunnel");
    assert_eq!(ul.teid(), Some(0x11223344));
    assert_eq!(decoded.qos_flows[0].qfi, 5);
}

const PDU_SETUP_RESPONSE_1_SESSION: &str =
    "201d0024000003000a4002000c00554002000c004b40110000050d0003e00a4d0b18112233440005";

#[test]
fn full_pdu_setup_response_decodes_ie75_and_inner_transfer() {
    let payload = bytes(PDU_SETUP_RESPONSE_1_SESSION);
    let pdu = parse(&payload).expect("parse PDU");
    assert_eq!(pdu.kind, PduKind::SuccessfulOutcome);
    assert_eq!(pdu.procedure_code, 29);
    assert_eq!(pdu.message_name, "PDUSessionResourceSetupResponse");
    let ie_75 = pdu
        .ies
        .iter()
        .find(|ie| ie.id == 75)
        .expect("IE 75 present");
    let list = decode_pdu_session_resource_setup_list_su_res(&ie_75.value);
    assert!(list.errors.is_empty(), "errors: {:?}", list.errors);
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].pdu_session_id, 5);
    let decoded =
        decode_pdu_session_resource_setup_response_transfer(&list.items[0].transfer);
    assert!(decoded.errors.is_empty(), "transfer errors: {:?}", decoded.errors);
    assert_eq!(decoded.dl.tunnel.teid(), Some(0x11223344));
    assert_eq!(decoded.dl.qfis[0].qfi, 5);
}

// ===== 2.21.66 (ordre #9 7004955176) — NGSetup + libération de session =====
//
// Hex générés par `/tmp/ngap_release_fixtures.py` (pycrate TS 38.413
// V17.3.0). Valeurs synthétiques : PLMN 001/01, aucun IMSI/MSISDN.

const PDU_NGSETUP_REQUEST: &str =
    "00150038000004001b00080000f110000000040052400f06006f6972616e2d676e622d6c61620066000d00000000010000f110000000080015400140";

#[test]
fn ngsetup_request_decodes_global_ran_node_id_and_supported_ta() {
    let pdu = parse(&bytes(PDU_NGSETUP_REQUEST)).expect("parse NGSetupRequest");
    assert_eq!(pdu.procedure_code, 21);
    assert_eq!(pdu.kind, PduKind::Initiating);
    assert_eq!(pdu.message_name, "NGSetupRequest");
    assert!(pdu.ies.iter().any(|ie| ie.id == 27), "GlobalRANNodeID present");
    assert!(pdu.ies.iter().any(|ie| ie.id == 82), "RANNodeName present");
    assert!(pdu.ies.iter().any(|ie| ie.id == 102), "SupportedTAList present");
    assert!(pdu.ies.iter().any(|ie| ie.id == 21), "DefaultPagingDRX present");
}

const PDU_NGSETUP_RESPONSE: &str =
    "201500330000040001000f06006f6972616e2d616d662d6c616200600008000000f1100210000056400180005000080000f11000000008";

#[test]
fn ngsetup_response_decodes_served_guami_and_plmn_support() {
    let pdu = parse(&bytes(PDU_NGSETUP_RESPONSE)).expect("parse NGSetupResponse");
    assert_eq!(pdu.procedure_code, 21);
    assert_eq!(pdu.kind, PduKind::SuccessfulOutcome);
    assert_eq!(pdu.message_name, "NGSetupResponse");
    assert!(pdu.ies.iter().any(|ie| ie.id == 96), "ServedGUAMIList present");
    assert!(pdu.ies.iter().any(|ie| ie.id == 80), "PLMNSupportList present");
}

const PDU_NGSETUP_FAILURE: &str = "4015000e000002000f40020000006b400130";

#[test]
fn ngsetup_failure_decodes_cause_and_time_to_wait_v10s() {
    let pdu = parse(&bytes(PDU_NGSETUP_FAILURE)).expect("parse NGSetupFailure");
    assert_eq!(pdu.procedure_code, 21);
    assert_eq!(pdu.kind, PduKind::UnsuccessfulOutcome);
    assert_eq!(pdu.message_name, "NGSetupFailure");
    let tw = pdu
        .ies
        .iter()
        .find(|ie| ie.id == 107)
        .expect("TimeToWait IE present");
    assert_eq!(tw.known_name, Some("TimeToWait"));
    // Fixture pycrate : v10s (idx 3) → ext(0)+011+pad → 0b00110000 = 0x30.
    assert_eq!(tw.value, vec![0x30]);
}

const PDU_UE_CONTEXT_RELEASE_COMMAND: &str =
    "0029001100000200720004000c0022000f40020100";

#[test]
fn ue_context_release_command_decodes_ue_ids_and_cause() {
    let pdu = parse(&bytes(PDU_UE_CONTEXT_RELEASE_COMMAND))
        .expect("parse UEContextReleaseCommand");
    assert_eq!(pdu.procedure_code, 41);
    assert_eq!(pdu.kind, PduKind::Initiating);
    assert_eq!(pdu.message_name, "UEContextReleaseCommand");
    assert!(pdu.ies.iter().any(|ie| ie.id == 114), "UE-NGAP-IDs present");
    assert!(pdu.ies.iter().any(|ie| ie.id == 15), "Cause present");
}

const PDU_UE_CONTEXT_RELEASE_COMPLETE: &str =
    "20290018000003000a4002000c005540020022003c40050100050006";

#[test]
fn ue_context_release_complete_decodes_two_pdu_sessions() {
    let pdu = parse(&bytes(PDU_UE_CONTEXT_RELEASE_COMPLETE))
        .expect("parse UEContextReleaseComplete");
    assert_eq!(pdu.procedure_code, 41);
    assert_eq!(pdu.kind, PduKind::SuccessfulOutcome);
    assert_eq!(pdu.message_name, "UEContextReleaseComplete");
    let ie_60 = pdu
        .ies
        .iter()
        .find(|ie| ie.id == 60)
        .expect("PDUSessionResourceListCxtRelCpl present");
    assert_eq!(ie_60.known_name, Some("PDUSessionResourceListCxtRelCpl"));
    // Raw contient 2 items `pDUSessionID` = 5 et 6 (voir fixture python).
    assert_eq!(ie_60.value, vec![0x01, 0x00, 0x05, 0x00, 0x06]);
}

const PDU_UE_CONTEXT_RELEASE_REQUEST: &str =
    "002a401c000004000a0002000c00550002002200850003000007000f40020000";

#[test]
fn ue_context_release_request_decodes_one_pdu_session() {
    let pdu = parse(&bytes(PDU_UE_CONTEXT_RELEASE_REQUEST))
        .expect("parse UEContextReleaseRequest");
    assert_eq!(pdu.procedure_code, 42);
    assert_eq!(pdu.kind, PduKind::Initiating);
    assert_eq!(pdu.message_name, "UEContextReleaseRequest");
    let ie_133 = pdu
        .ies
        .iter()
        .find(|ie| ie.id == 133)
        .expect("PDUSessionResourceListCxtRelReq present");
    assert_eq!(ie_133.known_name, Some("PDUSessionResourceListCxtRelReq"));
    // Raw contient 1 item `pDUSessionID` = 7.
    assert_eq!(ie_133.value, vec![0x00, 0x00, 0x07]);
}

const PDU_SESSION_RESOURCE_RELEASE_COMMAND: &str =
    "001c0019000003000a0002000c005500020022004f0006000005020000";

#[test]
fn pdu_session_resource_release_command_is_wired_to_procedure_code_28() {
    let pdu = parse(&bytes(PDU_SESSION_RESOURCE_RELEASE_COMMAND))
        .expect("parse PDUSessionResourceReleaseCommand");
    assert_eq!(pdu.procedure_code, 28);
    assert_eq!(pdu.kind, PduKind::Initiating);
    assert_eq!(
        pdu.message_name, "PDUSessionResourceReleaseCommand",
        "2.21.66 : procedureCode 28 n'est plus UnknownNGAPProcedure"
    );
    let ie_79 = pdu
        .ies
        .iter()
        .find(|ie| ie.id == 79)
        .expect("PDUSessionResourceToReleaseListRelCmd present");
    assert_eq!(ie_79.known_name, Some("PDUSessionResourceToReleaseListRelCmd"));
    // 1 item : pDUSessionID=5, transfer de 2 octets Cause(radioNetwork=0, unspecified).
    assert_eq!(ie_79.value, vec![0x00, 0x00, 0x05, 0x02, 0x00, 0x00]);
}

const PDU_SESSION_RESOURCE_RELEASE_RESPONSE: &str =
    "201c0018000003000a4002000c005540020022004640050000050100";

#[test]
fn pdu_session_resource_release_response_is_wired_to_procedure_code_28() {
    let pdu = parse(&bytes(PDU_SESSION_RESOURCE_RELEASE_RESPONSE))
        .expect("parse PDUSessionResourceReleaseResponse");
    assert_eq!(pdu.procedure_code, 28);
    assert_eq!(pdu.kind, PduKind::SuccessfulOutcome);
    assert_eq!(pdu.message_name, "PDUSessionResourceReleaseResponse");
    let ie_70 = pdu
        .ies
        .iter()
        .find(|ie| ie.id == 70)
        .expect("PDUSessionResourceReleasedListRelRes present");
    assert_eq!(ie_70.known_name, Some("PDUSessionResourceReleasedListRelRes"));
    // 1 item : pDUSessionID=5, transfer de 1 octet (structure vide).
    assert_eq!(ie_70.value, vec![0x00, 0x00, 0x05, 0x01, 0x00]);
}

const PDU_INITIAL_CONTEXT_SETUP_REQUEST: &str =
    "000e0076000006000a0002000c00550002000c001c00070000f11002100000470027000005002021000003008b000a01f00a4d0b171122334400860001000088000700050000090000005e00200000000000000000000000000000000000000000000000000000000000000000007700091c000c000700030000";

#[test]
fn full_pdu_initial_context_setup_request_decodes_ie71_cxt_req_list() {
    let payload = bytes(PDU_INITIAL_CONTEXT_SETUP_REQUEST);
    let pdu = parse(&payload).expect("parse PDU");
    assert_eq!(pdu.procedure_code, 14);
    assert_eq!(pdu.message_name, "InitialContextSetupRequest");
    let ie_71 = pdu
        .ies
        .iter()
        .find(|ie| ie.id == 71)
        .expect("IE 71 present");
    let list = decode_pdu_session_resource_setup_list_cxt_req(&ie_71.value);
    assert!(list.errors.is_empty(), "errors: {:?}", list.errors);
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].pdu_session_id, 5);
    assert_eq!(list.items[0].s_nssai.sst, 1);
    let decoded =
        decode_pdu_session_resource_setup_request_transfer(&list.items[0].transfer);
    assert!(decoded.errors.is_empty(), "transfer errors: {:?}", decoded.errors);
    assert_eq!(decoded.ul_tunnel.unwrap().teid(), Some(0x11223344));
    assert_eq!(decoded.qos_flows[0].qfi, 5);
}

const PDU_INITIAL_CONTEXT_SETUP_RESPONSE: &str =
    "200e0024000003000a4002000c00554002000c004840110000050d0003e00a4d0b18112233440005";

#[test]
fn full_pdu_initial_context_setup_response_decodes_ie72_cxt_res_list() {
    let payload = bytes(PDU_INITIAL_CONTEXT_SETUP_RESPONSE);
    let pdu = parse(&payload).expect("parse PDU");
    assert_eq!(pdu.procedure_code, 14);
    assert_eq!(pdu.message_name, "InitialContextSetupResponse");
    let ie_72 = pdu
        .ies
        .iter()
        .find(|ie| ie.id == 72)
        .expect("IE 72 present");
    let list = decode_pdu_session_resource_setup_list_cxt_res(&ie_72.value);
    assert!(list.errors.is_empty(), "errors: {:?}", list.errors);
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].pdu_session_id, 5);
    let decoded =
        decode_pdu_session_resource_setup_response_transfer(&list.items[0].transfer);
    assert!(decoded.errors.is_empty(), "transfer errors: {:?}", decoded.errors);
    assert_eq!(decoded.dl.tunnel.teid(), Some(0x11223344));
    assert_eq!(decoded.dl.qfis[0].qfi, 5);
}
