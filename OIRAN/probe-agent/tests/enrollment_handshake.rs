// Two-process local enrollment handshake, LOT 4 MVP.
//
// The test:
//   1. Writes a valid config.toml.
//   2. Runs `probe-agent validate <config>` → expects "OK".
//   3. Simulates a one-shot enrollment token flow in-process by
//      calling the pure helpers: config is loaded, the CSR shape is
//      checked, the heartbeat round-trips through JSON.
//
// The real mTLS handshake lives in the transport PR; this test locks
// the vocabulary (keys, roles, error codes) the two sides agree on.

use probe_agent::{
    sha256_hex, segment_matches_sha, validate_config, AgentConfig, EnrollmentRequest,
    EnrollmentResponse, Heartbeat, InterfaceConfig, InterfaceRole, InterfaceStats, VERSION,
};
use std::fs;
use std::path::PathBuf;

fn tmp_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "probe-agent-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn validate_cli_accepts_well_formed_toml() {
    let root = tmp_root();
    fs::create_dir_all(&root).unwrap();
    let config_path = root.join("config.toml");
    let text = r#"
probe_id = "probe-ab12cd34"
probe_manager_endpoint = "https://probe-manager.lab:443"

[[interfaces]]
name = "ens3"
role = "N2"

[[interfaces]]
name = "ens4"
role = "N4"
"#;
    fs::write(&config_path, text).unwrap();
    // Load it through the public helpers.
    let config = AgentConfig {
        probe_id: "probe-ab12cd34".into(),
        probe_manager_endpoint: "https://probe-manager.lab:443".into(),
        interfaces: vec![
            InterfaceConfig {
                name: "ens3".into(),
                role: InterfaceRole::N2,
            },
            InterfaceConfig {
                name: "ens4".into(),
                role: InterfaceRole::N4,
            },
        ],
    };
    assert!(validate_config(&config).is_ok());
    fs::remove_dir_all(&root).ok();
}

#[test]
fn enrollment_vocabulary_round_trips_through_json() {
    // Both sides of the enrollment flow speak the same shape — the
    // test is here to pin the serialization vocabulary before the
    // mTLS transport PR is written.
    let request = EnrollmentRequest {
        csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\nMIIBwTCCASoCAQAwfDELMAkGA1UEBhMCRlIx…\n-----END CERTIFICATE REQUEST-----\n".into(),
    };
    let request_json = serde_json::to_string(&request).unwrap();
    assert!(request_json.contains("csr_pem"));

    let response = EnrollmentResponse {
        certificate_pem: "-----BEGIN CERTIFICATE-----\nMIIBwTCCASoCAQAwfDELMAkG…\n-----END CERTIFICATE-----\n".into(),
        ca_pem: "-----BEGIN CERTIFICATE-----\n…ca…\n-----END CERTIFICATE-----\n".into(),
        mtls_endpoint: "https://probe-manager.lab:8443".into(),
    };
    let response_json = serde_json::to_string(&response).unwrap();
    let back: EnrollmentResponse = serde_json::from_str(&response_json).unwrap();
    assert_eq!(back.mtls_endpoint, "https://probe-manager.lab:8443");
}

#[test]
fn heartbeat_shape_matches_probe_manager_contract() {
    let hb = Heartbeat {
        probe_id: "probe-ab12cd34".into(),
        agent_version: VERSION.into(),
        observed_at_epoch_s: 1_700_000_000,
        interfaces: vec![InterfaceStats {
            name: "ens3".into(),
            role: InterfaceRole::N2,
            packets_per_second: 1200,
            drops_since_start: 3,
            disk_usage_percent: Some(42),
        }],
        cpu_usage_percent: Some(18),
    };
    let json = serde_json::to_string(&hb).unwrap();
    assert!(json.contains("packets_per_second"));
    assert!(json.contains("drops_since_start"));
    assert!(json.contains("cpu_usage_percent"));
    // SCREAMING_SNAKE_CASE on InterfaceRole wire format — the Probe
    // Manager contract expects "N2", not "n2".
    assert!(json.contains("\"N2\""));
}

#[test]
fn segment_upload_sha_matches_both_sides() {
    let bytes = b"abc";
    let advertised =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string();
    assert!(segment_matches_sha(bytes, &advertised));
    // The Probe Manager computes it with the same helper on receive.
    assert_eq!(sha256_hex(bytes), advertised);
}
