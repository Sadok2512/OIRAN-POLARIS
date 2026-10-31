use decoder_gtpu::GtpuDecoder;
use decoder_gtpv2c::Gtpv2cDecoder;
use decoder_s1ap::S1apDecoder;
use event_schema::{Direction, Endpoint, ExactTimestamp, PacketReference};
use plugin_runtime::{DecoderInput, ProtocolDecoder};
use serde_json::Value;
use std::collections::BTreeSet;

fn bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

#[test]
fn synthetic_lte_decoders_preserve_planes_direction_and_privacy() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/lte-pipeline-synthetic-v1.json"
    ))
    .expect("valid fixture");
    assert_eq!(fixture["real_capture"], false);
    let serialized = fixture.to_string().to_ascii_lowercase();
    for forbidden in ["imsi=", "imei=", "msisdn=", "supi="] {
        assert!(!serialized.contains(forbidden));
    }
    let packet = PacketReference {
        source_file: "synthetic-offline.pcap".into(),
        source_sha256: Some("0".repeat(64)),
        packet_number: 1,
        byte_offset: 0,
        interface_id: 0,
        link_type: Some(1),
        sll2_protocol_type: None,
        sll2_reserved: None,
        sll2_interface_index: None,
        sll2_arphrd_type: None,
        sll2_packet_type: None,
        sll2_address_length: None,
        sll2_address: None,
        captured_length: 64,
        original_length: 64,
    };
    let timestamp = ExactTimestamp {
        seconds: 1,
        nanoseconds: 0,
        raw_ticks: 1_000_000_000,
        resolution_base: 10,
        resolution_exponent: 9,
    };
    let mut decoded = 0usize;
    let mut uplink = 0usize;
    let mut downlink = 0usize;
    let mut teids = BTreeSet::new();
    for case in fixture["cases"].as_array().expect("cases") {
        let payload = bytes(case["payload_hex"].as_str().expect("hex"));
        let input = DecoderInput {
            capture_id: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            packet_references: std::slice::from_ref(&packet),
            timestamp: &timestamp,
            interface: case["interface"].as_str().expect("interface"),
            source_endpoint: Endpoint {
                address: "192.0.2.1".into(),
                port: None,
                network_function: Some(case["source_role"].as_str().unwrap().into()),
            },
            destination_endpoint: Endpoint {
                address: "192.0.2.2".into(),
                port: None,
                network_function: Some(case["destination_role"].as_str().unwrap().into()),
            },
            payload: &payload,
            raw_payload_reference: "sha256:synthetic-offline",
        };
        let output = match case["decoder"].as_str().unwrap() {
            "S1AP" => S1apDecoder.decode(&input),
            "GTPv2-C" => Gtpv2cDecoder.decode(&input),
            "GTP-U" => GtpuDecoder.decode(&input),
            other => panic!("unexpected decoder {other}"),
        };
        assert_eq!(output.events[0].message_name, case["expected_event"]);
        assert_eq!(output.events[0].interface, case["interface"]);
        if case["decoder"] == "GTP-U" {
            let event = &output.events[0];
            let teid = event
                .session_identifiers
                .iter()
                .find(|value| value.name == "teid")
                .expect("TEID");
            assert_eq!(teid.value, case["expected_teid"]);
            teids.insert(teid.value.clone());
            match event.direction {
                Direction::Uplink => uplink += 1,
                Direction::Downlink => downlink += 1,
                _ => panic!("S1-U direction unresolved"),
            }
        }
        decoded += 1;
    }
    assert_eq!(decoded as u64, fixture["expected"]["decoded_cases"]);
    assert_eq!(uplink as u64, fixture["expected"]["s1u_uplink_packets"]);
    assert_eq!(downlink as u64, fixture["expected"]["s1u_downlink_packets"]);
    assert_eq!(
        teids.len() as u64,
        fixture["expected"]["distinct_s1u_teids"]
    );
}
