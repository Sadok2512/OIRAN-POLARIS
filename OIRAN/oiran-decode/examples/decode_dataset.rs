//! 2.7.18 helper: re-decode the shipped three-plane dataset with the current
//! decoder stack, so the embedded `oiran_events.jsonl` stays in lockstep with
//! `decoder-ngap` / `decoder-pfcp` / `decoder-gtpu`. The NGAP decoder has
//! surfaced structured tunnel IEs (`item_<i>_tunnel_ip_ul`,
//! `item_<i>_gtp_teid_ul`) since 0.6.0 but the dataset shipped with 2.7.0
//! still carried `nested_transfer_sha256`, which hid the N2↔N4 bridge from
//! `correlation-engine::correlate_cross_interface_evidence`.
//!
//! Usage:
//!   cargo run --release --example decode_dataset -- \
//!       <dataset-dir> <output events.jsonl>

use event_schema::PseudonymKey;
use oiran_decode::{decode_capture, DecodeConfig};
use std::{collections::HashMap, env, fs::File, io::Write, path::PathBuf};

fn endpoints() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (addr, nf) in [
        ("10.77.21.11", "AMF"),
        ("10.77.21.20", "gNB"),
        ("10.77.22.13", "UPF"),
        ("10.77.22.20", "gNB"),
        ("10.77.23.12", "SMF"),
        ("10.77.23.13", "UPF"),
        ("10.46.0.4", "UE"),
        ("10.46.0.1", "UE-DN"),
    ] {
        map.insert(addr.into(), nf.into());
    }
    map
}

fn capture_id_for(path: &std::path::Path) -> String {
    // Streaming SHA-256 of the capture file. Keeps RSS bounded to the 1 MiB
    // chunk size used by event_schema::sha256_hex_file.
    let bytes = std::fs::read(path).expect("read pcap");
    format!("sha256:{}", event_schema::sha256_hex(&bytes))
}

fn main() {
    let dataset_dir = PathBuf::from(env::args().nth(1).expect("<dataset-dir>"));
    let out = PathBuf::from(env::args().nth(2).expect("<output events.jsonl>"));
    let key_path = PathBuf::from("/tmp/oiran-decode-dataset.key");
    let _key = PseudonymKey::load_or_generate(&key_path).expect("pseudonym key");
    let mut file = File::create(&out).expect("create events.jsonl");
    for iface in ["N2", "N4", "N3"] {
        let pcap = dataset_dir.join(format!("{iface}.pcapng"));
        if !pcap.is_file() {
            eprintln!("skip {}: missing", pcap.display());
            continue;
        }
        let decode_output = decode_capture(&DecodeConfig {
            input: pcap.clone(),
            capture_id: capture_id_for(&pcap),
            interface: iface.into(),
            endpoints: endpoints(),
        })
        .expect("decode");
        println!("{iface}: {} events decoded", decode_output.events.len());
        for event in &decode_output.events {
            writeln!(file, "{}", event.to_json()).expect("write");
        }
    }
    file.sync_all().expect("sync");
}
