// BC3 audit, issue #9 — offline anti-regression tests pinned on the ANR3
// LTE correlation rules (`correlation-engine` 0.6.0, LTE_RULE_VERSION
// "1.1.0-offline.1"). These tests touch nothing in the engine; they only
// compose synthetic `EventRecord` values and call `correlate_lte_evidence`.

use callflow_schema::CorrelationEdge;
use correlation_engine::correlate_lte_evidence;
use serde_json::json;
use session_engine::{EventRecord, PacketRef};
use std::collections::HashMap;

fn mk(
    event_id: &str,
    capture_id: &str,
    interface: &str,
    protocol: &str,
    message_name: &str,
    packet: u64,
    identifiers: &[(&str, &str)],
) -> EventRecord {
    EventRecord {
        event_id: event_id.into(),
        parent_event_id: None,
        capture_id: capture_id.into(),
        capture_point_id: interface.into(),
        timestamp: format!("1.{packet:09}Z"),
        timestamp_ns: packet as i128,
        raw_ticks: packet,
        interface: interface.into(),
        protocol: protocol.into(),
        message_name: message_name.into(),
        source_address: "10.0.0.1".into(),
        destination_address: "10.0.0.2".into(),
        source_participant: "a".into(),
        destination_participant: "b".into(),
        direction: "UNKNOWN".into(),
        identifiers: identifiers
            .iter()
            .map(|(name, value)| ((*name).into(), (*value).into()))
            .collect(),
        information_elements: json!([]),
        decoding_status: "DECODED".into(),
        decoder_name: "anti-regression-fixture".into(),
        decoder_version: "0".into(),
        raw_payload_reference: "sha256:test".into(),
        packet_references: vec![PacketRef {
            source_file: format!("/captures/{capture_id}/{interface}.pcap"),
            packet_number: packet,
            byte_offset: 0,
            interface_id: 0,
            captured_length: 1,
            original_length: 1,
        }],
        errors: vec![],
        source_json: json!({}),
    }
}

fn capture_of<'a>(
    by_id: &'a HashMap<&'a str, &'a EventRecord>,
    event_id: &str,
) -> &'a str {
    by_id
        .get(event_id)
        .map(|event| event.capture_id.as_str())
        .unwrap_or("<unknown>")
}

/// Two distinct captures that happen to reuse the SAME S1-U / S11 TEID
/// literal MUST NOT produce any inter-capture correlation edge. The rule
/// invariant: `edge.source.capture_id == edge.target.capture_id` on every
/// emitted edge. The byte-identical TEID across captures is a collision,
/// not evidence of a shared tunnel.
#[test]
fn two_distinct_captures_sharing_the_same_teid_produce_no_cross_capture_edge() {
    let teid = "0x01020304";
    let events = vec![
        // Capture A — UE context (enb=41, mme=7).
        mk(
            "s1ap-A",
            "cap-A",
            "S1-MME",
            "S1AP",
            "InitialContextSetupResponse",
            10,
            &[
                ("enb_ue_s1ap_id", "41"),
                ("mme_ue_s1ap_id", "7"),
                ("imsi_pseudonym", "pseudo-A"),
                ("erab_teid", teid),
            ],
        ),
        mk(
            "s11-A",
            "cap-A",
            "S11",
            "GTPv2-C",
            "CreateSessionResponse",
            11,
            &[
                ("imsi_pseudonym", "pseudo-A"),
                ("bearer_f_teid", teid),
            ],
        ),
        mk(
            "s1u-A",
            "cap-A",
            "S1-U",
            "GTP-U",
            "G-PDU",
            12,
            &[("teid", teid)],
        ),
        // Capture B — a different UE, but the same TEID literal.
        mk(
            "s1ap-B",
            "cap-B",
            "S1-MME",
            "S1AP",
            "InitialContextSetupResponse",
            20,
            &[
                ("enb_ue_s1ap_id", "99"),
                ("mme_ue_s1ap_id", "33"),
                ("imsi_pseudonym", "pseudo-B"),
                ("erab_teid", teid),
            ],
        ),
        mk(
            "s11-B",
            "cap-B",
            "S11",
            "GTPv2-C",
            "CreateSessionResponse",
            21,
            &[
                ("imsi_pseudonym", "pseudo-B"),
                ("bearer_f_teid", teid),
            ],
        ),
        mk(
            "s1u-B",
            "cap-B",
            "S1-U",
            "GTP-U",
            "G-PDU",
            22,
            &[("teid", teid)],
        ),
    ];
    let edges: Vec<CorrelationEdge> = correlate_lte_evidence(&events);
    let by_id: HashMap<&str, &EventRecord> = events
        .iter()
        .map(|event| (event.event_id.as_str(), event))
        .collect();
    assert!(
        !edges.is_empty(),
        "sanity: each in-capture bearer should still produce at least one edge"
    );
    for edge in &edges {
        let source_capture = capture_of(&by_id, &edge.source_event_id);
        let target_capture = capture_of(&by_id, &edge.target_event_id);
        assert_eq!(
            source_capture, target_capture,
            "cross-capture edge detected: {} ({}) → {} ({}); shared TEID literal must never bridge two distinct captures",
            edge.source_event_id, source_capture, edge.target_event_id, target_capture
        );
    }
}

/// A single capture carrying two distinct UE contexts whose S11 bearers reuse
/// the SAME F-TEID MUST fail closed. The TEID uniqueness invariant is
/// destroyed by the collision, so the correlator cannot evidence a tunnel
/// ownership and MUST emit zero S11↔S1-U edges on that TEID.
///
/// The invariant is upheld at HEAD (OIRAN 2.8.2, `72b8293`) because
/// `OIRAN/session-engine/src/lib.rs:443` admits an S11 event to a context
/// only when exactly one context owns the TEID (`if let [owner] = owners`),
/// and `OIRAN/session-engine/src/lib.rs:472` applies the same single-owner
/// rule to S1-U binding. When two UE contexts both legitimately claim the
/// same TEID, the S1-U event is NOT admitted to either context and the
/// correlator emits zero S11→S1-U edges on that tunnel. This test defends
/// that behavior against future regressions.
#[test]
fn same_capture_two_ues_sharing_one_f_teid_must_fail_closed() {
    let teid = "0x0a0b0c0d";
    let events = vec![
        mk(
            "s1ap-ue1",
            "cap-1",
            "S1-MME",
            "S1AP",
            "InitialContextSetupResponse",
            10,
            &[
                ("enb_ue_s1ap_id", "41"),
                ("mme_ue_s1ap_id", "7"),
                ("imsi_pseudonym", "pseudo-A"),
                ("erab_teid", teid),
            ],
        ),
        mk(
            "s11-ue1",
            "cap-1",
            "S11",
            "GTPv2-C",
            "CreateSessionResponse",
            11,
            &[
                ("imsi_pseudonym", "pseudo-A"),
                ("bearer_f_teid", teid),
            ],
        ),
        mk(
            "s1ap-ue2",
            "cap-1",
            "S1-MME",
            "S1AP",
            "InitialContextSetupResponse",
            12,
            &[
                ("enb_ue_s1ap_id", "42"),
                ("mme_ue_s1ap_id", "8"),
                ("imsi_pseudonym", "pseudo-B"),
                ("erab_teid", teid),
            ],
        ),
        mk(
            "s11-ue2",
            "cap-1",
            "S11",
            "GTPv2-C",
            "CreateSessionResponse",
            13,
            &[
                ("imsi_pseudonym", "pseudo-B"),
                ("bearer_f_teid", teid),
            ],
        ),
        mk(
            "s1u",
            "cap-1",
            "S1-U",
            "GTP-U",
            "G-PDU",
            14,
            &[("teid", teid)],
        ),
    ];
    let edges = correlate_lte_evidence(&events);
    let s11_s1u = edges
        .iter()
        .filter(|edge| edge.source_interface == "S11" && edge.target_interface == "S1-U")
        .count();
    assert_eq!(
        s11_s1u, 0,
        "fail-closed violated: shared F-TEID across two UE sessions produced {} S11→S1-U edge(s); expected 0. edges={:#?}",
        s11_s1u,
        edges.iter().map(|edge| edge.edge_id.as_str()).collect::<Vec<_>>()
    );
}
