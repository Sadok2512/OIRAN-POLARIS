//! Diagnostic CLI: read a hex-encoded NGAP PDU from stdin and print the
//! decoded tree as JSON on stdout. Intended for side-by-side comparison with
//! `tshark -O ngap -J` on real captures.
//!
//! Usage:
//!   echo "001d0080b0000004..." | ngap-decode-hex
//!
//! The input accepts whitespace, `0x` prefixes and uppercase hex. Each IE
//! whose outer envelope is modeled (currently 74 PDUSessionResourceSetupList
//! SUReq and 75 PDUSessionResourceSetupListSURes) is walked and the embedded
//! transfer is decoded as well; other IEs are preserved by id, length and
//! SHA-256 provenance in the `information_elements` array.

use std::io::{self, Read};

use decoder_ngap::{
    decode_pdu_session_resource_setup_list_su_req, decode_pdu_session_resource_setup_list_su_res,
    decode_pdu_session_resource_setup_request_transfer,
    decode_pdu_session_resource_setup_response_transfer, parse, ListSURes, ListSUReq, NgapIe,
    NgapPdu, PduKind, RequestTransfer, ResponseTransfer,
};
use serde::Serialize;

#[derive(Serialize)]
struct DecodedNgap {
    pdu_kind: String,
    procedure_code: u8,
    message_name: String,
    criticality: u8,
    information_elements: Vec<DecodedIe>,
}

#[derive(Serialize)]
struct DecodedIe {
    id: u16,
    criticality: u8,
    known_name: Option<&'static str>,
    length_bytes: usize,
    raw_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    su_req_list: Option<ListSUReq>,
    #[serde(skip_serializing_if = "Option::is_none")]
    su_res_list: Option<ListSURes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_transfer: Option<RequestTransfer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_transfer: Option<ResponseTransfer>,
}

fn pdu_kind_name(kind: PduKind) -> &'static str {
    match kind {
        PduKind::Initiating => "InitiatingMessage",
        PduKind::SuccessfulOutcome => "SuccessfulOutcome",
        PduKind::UnsuccessfulOutcome => "UnsuccessfulOutcome",
    }
}

fn decode_ie(ie: &NgapIe) -> DecodedIe {
    let mut decoded = DecodedIe {
        id: ie.id,
        criticality: ie.criticality,
        known_name: ie.known_name,
        length_bytes: ie.value.len(),
        raw_hex: hex_encode(&ie.value),
        su_req_list: None,
        su_res_list: None,
        request_transfer: None,
        response_transfer: None,
    };
    match ie.id {
        74 => {
            let list = decode_pdu_session_resource_setup_list_su_req(&ie.value);
            // Also surface the per-item inner transfer decode so tshark side
            // comparison can inspect the full tree in one JSON blob.
            if let Some(first) = list.items.first() {
                decoded.request_transfer = Some(
                    decode_pdu_session_resource_setup_request_transfer(&first.transfer),
                );
            }
            decoded.su_req_list = Some(list);
        }
        75 => {
            let list = decode_pdu_session_resource_setup_list_su_res(&ie.value);
            if let Some(first) = list.items.first() {
                decoded.response_transfer = Some(
                    decode_pdu_session_resource_setup_response_transfer(&first.transfer),
                );
            }
            decoded.su_res_list = Some(list);
        }
        _ => {}
    }
    decoded
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_string();
    if cleaned.len() % 2 != 0 {
        return Err(format!("odd number of hex characters ({})", cleaned.len()));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[pair..pair + 2], 16)
            .map_err(|e| format!("invalid hex at offset {}: {}", pair, e))?;
        out.push(byte);
    }
    Ok(out)
}

fn main() -> io::Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let bytes = match hex_decode(&input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("hex decode error: {e}");
            std::process::exit(2);
        }
    };
    let NgapPdu {
        kind,
        procedure_code,
        criticality,
        message_name,
        ies,
    } = match parse(&bytes) {
        Ok(pdu) => pdu,
        Err(e) => {
            eprintln!("NGAP parse error: {e}");
            std::process::exit(3);
        }
    };
    let decoded = DecodedNgap {
        pdu_kind: pdu_kind_name(kind).to_string(),
        procedure_code,
        message_name: message_name.to_string(),
        criticality,
        information_elements: ies.iter().map(decode_ie).collect(),
    };
    let json = serde_json::to_string_pretty(&decoded)
        .expect("serialising decoded NGAP tree never fails");
    println!("{json}");
    Ok(())
}
