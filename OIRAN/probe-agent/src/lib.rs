// Probe Agent MVP (see docs/probe-agent/DESIGN.md).
//
// This crate exposes the pure logic — config loader, enrollment
// handshake, heartbeat payload, segment upload path — plus (since
// 0.1.1) the mTLS transport that talks to the Probe Manager and the
// IPC client that drives the capture-helper over a Unix socket.
// Both transports live in `transport::*` so unit tests of the pure
// state machine still run without a network stack.

use serde::{Deserialize, Serialize};

pub mod transport;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const HEARTBEAT_INTERVAL_SECS: u64 = 10;
pub const CONFIG_POLL_SECS: u64 = 30;
pub const SEGMENT_UPLOAD_MAX_RETRIES: u32 = 3;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InterfaceRole {
    N2,
    N3,
    N4,
    S1Mme,
    S1U,
    Unknown,
}

impl InterfaceRole {
    pub fn from_wire(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "N2" => Self::N2,
            "N3" => Self::N3,
            "N4" => Self::N4,
            "S1MME" => Self::S1Mme,
            "S1U" => Self::S1U,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InterfaceConfig {
    pub name: String,
    #[serde(default = "default_role")]
    pub role: InterfaceRole,
}

fn default_role() -> InterfaceRole {
    InterfaceRole::Unknown
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentConfig {
    pub probe_id: String,
    pub probe_manager_endpoint: String,
    #[serde(default)]
    pub interfaces: Vec<InterfaceConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnrollmentRequest {
    pub csr_pem: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EnrollmentResponse {
    pub certificate_pem: String,
    pub ca_pem: String,
    pub mtls_endpoint: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InterfaceStats {
    pub name: String,
    pub role: InterfaceRole,
    pub packets_per_second: u64,
    pub drops_since_start: u64,
    pub disk_usage_percent: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Heartbeat {
    pub probe_id: String,
    pub agent_version: String,
    pub observed_at_epoch_s: u64,
    pub interfaces: Vec<InterfaceStats>,
    pub cpu_usage_percent: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SegmentUpload {
    pub probe_id: String,
    pub capture_id: String,
    pub segment_id: String,
    pub sha256_hex: String,
    pub bytes: u64,
}

/// Validation performed before the agent accepts a config file. Pure
/// function so tests can drive it without touching the filesystem.
pub fn validate_config(config: &AgentConfig) -> Result<(), &'static str> {
    if config.probe_id.trim().is_empty() {
        return Err("CONFIG_PROBE_ID_REQUIRED");
    }
    if config.probe_manager_endpoint.trim().is_empty() {
        return Err("CONFIG_ENDPOINT_REQUIRED");
    }
    if !config.probe_manager_endpoint.starts_with("https://") {
        return Err("CONFIG_ENDPOINT_MUST_BE_HTTPS");
    }
    if config.interfaces.is_empty() {
        return Err("CONFIG_INTERFACES_REQUIRED");
    }
    for i in &config.interfaces {
        if i.name.trim().is_empty() {
            return Err("CONFIG_INTERFACE_NAME_REQUIRED");
        }
        if matches!(i.role, InterfaceRole::Unknown) {
            return Err("CONFIG_INTERFACE_ROLE_UNKNOWN");
        }
    }
    Ok(())
}

/// SHA-256 of the segment, in lower-case hex. The agent computes this
/// before uploading and the Probe Manager verifies it; a mismatch
/// surfaces as 422 and the agent retries up to `SEGMENT_UPLOAD_MAX_RETRIES`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    // Local SHA-256 so the agent does not pull a heavy crypto dependency
    // for the MVP. Matches `event_schema::sha256_hex` byte for byte.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut hash: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (bytes.len() as u64) * 8;
    let mut padded = Vec::with_capacity(bytes.len() + 72);
    padded.extend_from_slice(bytes);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        );
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }
    hash.iter().map(|w| format!("{w:08x}")).collect()
}

/// Verify a segment matches its advertised SHA-256. The Probe Manager
/// runs the exact same check on receive.
pub fn segment_matches_sha(bytes: &[u8], advertised: &str) -> bool {
    sha256_hex(bytes).eq_ignore_ascii_case(advertised)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AgentConfig {
        AgentConfig {
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
        }
    }

    #[test]
    fn validate_rejects_empty_probe_id() {
        let mut c = config();
        c.probe_id.clear();
        assert_eq!(validate_config(&c).unwrap_err(), "CONFIG_PROBE_ID_REQUIRED");
    }

    #[test]
    fn validate_rejects_non_https_endpoint() {
        let mut c = config();
        c.probe_manager_endpoint = "http://probe-manager.lab".into();
        assert_eq!(
            validate_config(&c).unwrap_err(),
            "CONFIG_ENDPOINT_MUST_BE_HTTPS"
        );
    }

    #[test]
    fn validate_rejects_no_interfaces() {
        let mut c = config();
        c.interfaces.clear();
        assert_eq!(
            validate_config(&c).unwrap_err(),
            "CONFIG_INTERFACES_REQUIRED"
        );
    }

    #[test]
    fn validate_rejects_unknown_role() {
        let mut c = config();
        c.interfaces[0].role = InterfaceRole::Unknown;
        assert_eq!(
            validate_config(&c).unwrap_err(),
            "CONFIG_INTERFACE_ROLE_UNKNOWN"
        );
    }

    #[test]
    fn validate_accepts_valid_config() {
        assert!(validate_config(&config()).is_ok());
    }

    #[test]
    fn interface_role_parser_normalises_dashes_and_case() {
        assert_eq!(InterfaceRole::from_wire("N2"), InterfaceRole::N2);
        assert_eq!(InterfaceRole::from_wire("n2"), InterfaceRole::N2);
        assert_eq!(InterfaceRole::from_wire("S1-MME"), InterfaceRole::S1Mme);
        assert_eq!(InterfaceRole::from_wire("S1-U"), InterfaceRole::S1U);
        assert_eq!(InterfaceRole::from_wire("s1u"), InterfaceRole::S1U);
        assert_eq!(InterfaceRole::from_wire("N7"), InterfaceRole::Unknown);
    }

    #[test]
    fn sha256_matches_rfc_vectors() {
        // RFC 6234 §8.5 Test 1: "abc" → ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Empty vector.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn segment_sha_match_is_case_insensitive() {
        let bytes = b"hello world";
        let expected = sha256_hex(bytes);
        assert!(segment_matches_sha(bytes, &expected));
        assert!(segment_matches_sha(bytes, &expected.to_uppercase()));
        assert!(!segment_matches_sha(bytes, &"0".repeat(64)));
    }

    #[test]
    fn heartbeat_round_trips_through_json() {
        let hb = Heartbeat {
            probe_id: "probe-ab12cd34".into(),
            agent_version: VERSION.into(),
            observed_at_epoch_s: 1_700_000_000,
            interfaces: vec![InterfaceStats {
                name: "ens3".into(),
                role: InterfaceRole::N2,
                packets_per_second: 420,
                drops_since_start: 0,
                disk_usage_percent: Some(12),
            }],
            cpu_usage_percent: Some(7),
        };
        let json = serde_json::to_string(&hb).unwrap();
        let back: Heartbeat = serde_json::from_str(&json).unwrap();
        assert_eq!(back.probe_id, "probe-ab12cd34");
        assert_eq!(back.interfaces.len(), 1);
        assert_eq!(back.interfaces[0].role, InterfaceRole::N2);
    }
}
