//! 2.21.0 — preuve hors ligne : HTTP/2 en clair capté côté libssl →
//! pcap vTAP → `oiran_decode::decode_capture` (chemin de production,
//! interface SBI) → transactions SBI décodées, sans changer le décodeur.

use std::collections::HashMap;

use polaris_vtap::conn::ConnTuple;
use polaris_vtap::pcap::{global_header, record};
use polaris_vtap::record::SslOp;
use polaris_vtap::synth::{HpackContext, Synthesizer, DEFAULT_SERVER_PORTS, H2_PREFACE};

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn amf() -> ConnTuple {
    ConnTuple {
        local: "172.22.0.10:40000".parse().unwrap(),
        remote: "172.22.0.12:7777".parse().unwrap(),
    }
}
fn nrf() -> ConnTuple {
    ConnTuple {
        local: "172.22.0.12:7777".parse().unwrap(),
        remote: "172.22.0.10:40000".parse().unwrap(),
    }
}

/// Échange NRF discovery (aucune identité abonné dans la fixture).
fn exchange(with_preface: bool) -> (Vec<u8>, Vec<u8>) {
    let mut enc_c = hpack::Encoder::new();
    let mut enc_s = hpack::Encoder::new();
    let req = enc_c.encode(vec![
        (&b":method"[..], &b"GET"[..]),
        (&b":scheme"[..], &b"http"[..]),
        (&b":authority"[..], &b"172.22.0.12:7777"[..]),
        (
            &b":path"[..],
            &b"/nnrf-disc/v1/nf-instances?target-nf-type=UDM&requester-nf-type=AMF"[..],
        ),
        (&b"accept"[..], &b"application/json"[..]),
    ]);
    let body = br#"{"validityPeriod":3600,"nfInstances":[]}"#;
    let resp = enc_s.encode(vec![
        (&b":status"[..], &b"200"[..]),
        (&b"content-type"[..], &b"application/json"[..]),
    ]);
    let mut c2s = Vec::new();
    if with_preface {
        c2s.extend_from_slice(H2_PREFACE);
        c2s.extend(frame(4, 0, 0, &[]));
    }
    c2s.extend(frame(1, 0x05, 1, &req));
    let mut s2c = Vec::new();
    if with_preface {
        s2c.extend(frame(4, 0, 0, &[]));
    }
    s2c.extend(frame(1, 0x04, 1, &resp));
    s2c.extend(frame(0, 0x01, 1, body));
    (c2s, s2c)
}

fn write_pcap(name: &str, synth: &mut Synthesizer, steps: &[(ConnTuple, SslOp, &str, Vec<u8>)]) -> std::path::PathBuf {
    let mut bytes = global_header().to_vec();
    let base = 1_763_305_200_000_000_000u64;
    for (i, (t, op, comm, data)) in steps.iter().enumerate() {
        for p in synth.push(base + i as u64 * 1_000_000, *t, *op, comm, false, data) {
            bytes.extend_from_slice(&record(&p));
        }
    }
    let path = std::env::temp_dir().join(format!("vtap-{name}-{}.pcap", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    path
}

fn decode(path: &std::path::Path) -> oiran_decode::DecodeOutput {
    oiran_decode::decode_capture(&oiran_decode::DecodeConfig {
        input: path.to_path_buf(),
        capture_id: format!("sha256:{}", "0".repeat(64)),
        interface: "SBI".into(),
        endpoints: HashMap::from([
            ("172.22.0.10".to_string(), "AMF".to_string()),
            ("172.22.0.12".to_string(), "NRF".to_string()),
        ]),
    })
    .expect("decode vtap pcap")
}

#[test]
fn vtap_pcap_is_decoded_as_sbi_by_unchanged_decoder() {
    let (c2s, s2c) = exchange(true);
    let mut synth = Synthesizer::new(DEFAULT_SERVER_PORTS);
    // Les deux bouts sont instrumentés : AMF écrit, NRF lit (doublon), NRF répond.
    let path = write_pcap(
        "rt",
        &mut synth,
        &[
            (amf(), SslOp::Write, "open5gs-amfd", c2s.clone()),
            (nrf(), SslOp::Read, "open5gs-nrfd", c2s),
            (nrf(), SslOp::Write, "open5gs-nrfd", s2c.clone()),
            (amf(), SslOp::Read, "open5gs-amfd", s2c),
        ],
    );
    assert_eq!(synth.counters.dedup_dropped_records, 2);
    assert_eq!(synth.manifest()[0].hpack_context, HpackContext::PrefaceSeen);
    let out = decode(&path);
    let _ = std::fs::remove_file(&path);
    assert_eq!(out.report.tcp_connections, 1, "report: {:?}", out.report);
    assert_eq!(out.report.tcp_errors, 0, "report: {:?}", out.report);
    assert!(out.report.sbi_transactions >= 1, "report: {:?}", out.report);
    let sbi: Vec<_> = out.events.iter().filter(|e| e.sbi.is_some()).collect();
    assert!(!sbi.is_empty(), "aucun event SBI");
    let meta = sbi[0].sbi.as_ref().unwrap();
    assert_eq!(meta.http_method.as_deref(), Some("GET"));
    assert!(
        meta.request_uri.as_deref().unwrap_or("").starts_with("/nnrf-disc/v1/nf-instances"),
        "uri: {:?}",
        meta.request_uri
    );
    assert_eq!(meta.http_status, Some(200));
    assert_eq!(meta.consumer_nf.as_deref(), Some("AMF"));
    assert_eq!(meta.producer_nf.as_deref(), Some("NRF"));
}

#[test]
fn mid_stream_connection_is_declared_open_in_manifest() {
    let (c2s, s2c) = exchange(false);
    let mut synth = Synthesizer::new(DEFAULT_SERVER_PORTS);
    let path = write_pcap(
        "mid",
        &mut synth,
        &[
            (amf(), SslOp::Write, "open5gs-amfd", c2s),
            (nrf(), SslOp::Write, "open5gs-nrfd", s2c),
        ],
    );
    let _ = std::fs::remove_file(&path);
    assert_eq!(synth.mid_stream_connections(), 1);
    let items = polaris_vtap::open_items(&synth);
    assert!(items.iter().any(|i| i.starts_with("HPACK_MID_STREAM")), "{items:?}");
}

/// 2.21.0 — chaque event issu d'un pcap vTAP porte `probe_type = "vtap"`
/// (sérialisation `write_jsonl_stamped`, lue par session-engine).
#[test]
fn every_event_from_vtap_pcap_is_stamped_probe_type_vtap() {
    let (c2s, s2c) = exchange(true);
    let mut synth = Synthesizer::new(DEFAULT_SERVER_PORTS);
    let path = write_pcap(
        "stamp",
        &mut synth,
        &[
            (amf(), SslOp::Write, "open5gs-amfd", c2s),
            (nrf(), SslOp::Write, "open5gs-nrfd", s2c),
        ],
    );
    let out = decode(&path);
    let jsonl = path.with_extension("jsonl");
    oiran_decode::write_jsonl_stamped(
        &jsonl,
        &out.events,
        false,
        &event_schema::ProbeStamp {
            probe_id: Some("lab-vtap".into()),
            probe_type: Some(polaris_vtap::PROBE_TYPE.into()),
            physical_link: None,
            timestamp_source: Some(polaris_vtap::TIMESTAMP_SOURCE.into()),
        },
    )
    .unwrap();
    let text = std::fs::read_to_string(&jsonl).unwrap();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&jsonl);
    assert!(!out.events.is_empty());
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["probe_type"], "vtap", "{line}");
        assert_eq!(v["probe_id"], "lab-vtap");
        assert_eq!(v["timestamp_source"], "ebpf_monotonic");
    }
}
