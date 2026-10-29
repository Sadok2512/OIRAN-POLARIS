use decoder_ngap::NgapDecoder;
use event_schema::{DecodeStatus, Endpoint, ExactTimestamp, PacketReference};
use plugin_runtime::{DecoderInput, ProtocolDecoder};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    fixture_version: u8,
    procedure_code: u32,
    message_name: String,
    expected_status: String,
    expected_reason: String,
    ngap_hex: String,
}

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn sanitized_e2e_frames_preserve_decoder_status_without_subscriber_material() {
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/e2e-20261029-sanitized.json")).unwrap();
    assert_eq!(fixtures.len(), 11);
    let timestamp = ExactTimestamp {
        seconds: 0,
        nanoseconds: 0,
        raw_ticks: 0,
        resolution_base: 10,
        resolution_exponent: 9,
    };
    for (index, fixture) in fixtures.iter().enumerate() {
        assert_eq!(fixture.fixture_version, 1);
        assert!(!fixture.expected_reason.is_empty());
        let payload = bytes(&fixture.ngap_hex);
        let packets = vec![PacketReference {
            source_file: "sanitized-fixture".into(),
            source_sha256: None,
            packet_number: index as u64 + 1,
            byte_offset: 0,
            interface_id: 0,
            link_type: None,
            sll2_protocol_type: None,
            sll2_reserved: None,
            sll2_interface_index: None,
            sll2_arphrd_type: None,
            sll2_packet_type: None,
            sll2_address_length: None,
            sll2_address: None,
            captured_length: payload.len() as u32,
            original_length: payload.len() as u32,
        }];
        let input = DecoderInput {
            capture_id: "sanitized",
            packet_references: &packets,
            timestamp: &timestamp,
            interface: "N2",
            source_endpoint: Endpoint {
                address: "192.0.2.1".into(),
                port: Some(38412),
                network_function: Some("gNB".into()),
            },
            destination_endpoint: Endpoint {
                address: "192.0.2.2".into(),
                port: Some(38412),
                network_function: Some("AMF".into()),
            },
            payload: &payload,
            raw_payload_reference: "sanitized",
        };
        let output = NgapDecoder.decode(&input);
        let expected = match fixture.expected_status.as_str() {
            "PARTIAL" => DecodeStatus::Partial,
            "MALFORMED" => DecodeStatus::Malformed,
            other => panic!("unexpected status {other}"),
        };
        assert_eq!(output.status, expected, "fixture {}", index + 1);
        assert_eq!(
            output.events[0].procedure_code,
            Some(fixture.procedure_code)
        );
        assert_eq!(output.events[0].message_name, fixture.message_name);
    }
}
