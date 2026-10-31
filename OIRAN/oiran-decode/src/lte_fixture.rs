use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LteFixtureFile {
    pub interface: String,
    pub protocol: String,
    pub path: String,
    pub sha256: String,
    pub packet_count: Option<u64>,
    pub size_bytes: Option<u64>,
    pub first_timestamp_utc: Option<String>,
    pub last_timestamp_utc: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LteAnonymization {
    pub method: String,
    pub reviewed_by: String,
    pub clear_subscriber_identities_present: bool,
    pub address_mapping: String,
    pub forbidden_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LteExpected {
    pub ue_sessions: Option<u64>,
    pub eps_bearers: Option<u64>,
    pub distinct_s1u_teids: Option<u64>,
    pub uplink_packets: Option<u64>,
    pub downlink_packets: Option<u64>,
    pub correlation_edges: Option<u64>,
    pub first_timestamp_utc: Option<String>,
    pub last_timestamp_utc: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LteApproval {
    pub anr1_reference: Option<String>,
    pub approved_at_utc: Option<String>,
    pub notes: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LteFixtureManifest {
    pub schema_version: String,
    pub certification_state: String,
    pub fixture_id: String,
    pub technology: String,
    pub capture_mode: String,
    pub real_capture: bool,
    pub anonymization: LteAnonymization,
    pub files: Vec<LteFixtureFile>,
    pub required_procedures: Vec<String>,
    pub expected: LteExpected,
    pub approval: LteApproval,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct LteManifestValidation {
    pub structural_errors: Vec<String>,
    pub readiness_blockers: Vec<String>,
}

impl LteManifestValidation {
    pub fn structurally_valid(&self) -> bool {
        self.structural_errors.is_empty()
    }

    pub fn ready(&self) -> bool {
        self.structural_errors.is_empty() && self.readiness_blockers.is_empty()
    }
}

const REQUIRED_POINTERS: &[&str] = &[
    "/schema_version",
    "/certification_state",
    "/fixture_id",
    "/technology",
    "/capture_mode",
    "/real_capture",
    "/anonymization/method",
    "/anonymization/reviewed_by",
    "/anonymization/clear_subscriber_identities_present",
    "/anonymization/address_mapping",
    "/anonymization/forbidden_fields",
    "/files",
    "/required_procedures",
    "/expected/ue_sessions",
    "/expected/eps_bearers",
    "/expected/distinct_s1u_teids",
    "/expected/uplink_packets",
    "/expected/downlink_packets",
    "/expected/correlation_edges",
    "/expected/first_timestamp_utc",
    "/expected/last_timestamp_utc",
    "/approval/anr1_reference",
    "/approval/approved_at_utc",
    "/approval/notes",
];

pub fn validate_lte_fixture_manifest(
    json: &str,
) -> Result<(LteFixtureManifest, LteManifestValidation), String> {
    let value: Value = serde_json::from_str(json).map_err(|error| error.to_string())?;
    let mut validation = LteManifestValidation::default();
    for pointer in REQUIRED_POINTERS {
        if value.pointer(pointer).is_none() {
            validation
                .structural_errors
                .push(format!("missing required field {pointer}"));
        }
    }
    let manifest: LteFixtureManifest =
        serde_json::from_value(value).map_err(|error| error.to_string())?;
    if manifest.schema_version != "1.0.0" {
        validation
            .structural_errors
            .push("schema_version must be 1.0.0".into());
    }
    if manifest.technology != "LTE" {
        validation
            .structural_errors
            .push("technology must be LTE".into());
    }
    if manifest.anonymization.clear_subscriber_identities_present {
        validation
            .structural_errors
            .push("clear subscriber identities must be absent".into());
    }
    for forbidden in ["IMSI", "IMEI", "IMEISV", "MSISDN", "GUTI"] {
        if !manifest
            .anonymization
            .forbidden_fields
            .iter()
            .any(|value| value == forbidden)
        {
            validation.structural_errors.push(format!(
                "anonymization.forbidden_fields must include {forbidden}"
            ));
        }
    }
    for procedure in [
        "S1Setup",
        "Attach",
        "InitialContextSetup",
        "E-RABSetup",
        "CreateSession",
        "S1-U-G-PDU-UL",
        "S1-U-G-PDU-DL",
        "Detach",
    ] {
        if !manifest
            .required_procedures
            .iter()
            .any(|value| value == procedure)
        {
            validation
                .structural_errors
                .push(format!("required_procedures must include {procedure}"));
        }
    }
    let expected_planes = [
        ("S1-MME", "S1AP_SCTP_PPID_18"),
        ("S11", "GTPV2_C_UDP_2123"),
        ("S1-U", "GTP_U_UDP_2152"),
    ];
    let observed = manifest
        .files
        .iter()
        .map(|file| (file.interface.as_str(), file.protocol.as_str()))
        .collect::<BTreeSet<_>>();
    for plane in expected_planes {
        if !observed.contains(&plane) {
            validation
                .structural_errors
                .push(format!("missing required plane {} / {}", plane.0, plane.1));
        }
    }
    if manifest.files.len() != observed.len() {
        validation
            .structural_errors
            .push("duplicate interface/protocol fixture entry".into());
    }
    let placeholder = |value: &str| value.is_empty() || value.contains("REPLACE_WITH");
    if placeholder(&manifest.fixture_id) {
        validation
            .readiness_blockers
            .push("fixture_id is not populated".into());
    }
    for (name, value) in [
        (
            "anonymization.method",
            manifest.anonymization.method.as_str(),
        ),
        (
            "anonymization.reviewed_by",
            manifest.anonymization.reviewed_by.as_str(),
        ),
        (
            "anonymization.address_mapping",
            manifest.anonymization.address_mapping.as_str(),
        ),
    ] {
        if placeholder(value) || value == "ANR1_REQUIRED" {
            validation
                .readiness_blockers
                .push(format!("{name} is not populated"));
        }
    }
    let valid_timestamp = |value: &str| value.contains('T') && value.ends_with('Z');
    for file in &manifest.files {
        if placeholder(&file.path) {
            validation
                .readiness_blockers
                .push(format!("{} path is not populated", file.interface));
        }
        if file.sha256.len() != 64 || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            validation.readiness_blockers.push(format!(
                "{} sha256 is not 64 hexadecimal characters",
                file.interface
            ));
        }
        if file.packet_count.unwrap_or(0) == 0 || file.size_bytes.unwrap_or(0) == 0 {
            validation.readiness_blockers.push(format!(
                "{} packet_count/size_bytes are not populated",
                file.interface
            ));
        }
        if file
            .first_timestamp_utc
            .as_deref()
            .map_or(true, |value| !valid_timestamp(value))
            || file
                .last_timestamp_utc
                .as_deref()
                .map_or(true, |value| !valid_timestamp(value))
        {
            validation.readiness_blockers.push(format!(
                "{} timestamp bounds are not populated",
                file.interface
            ));
        } else if file.first_timestamp_utc > file.last_timestamp_utc {
            validation
                .structural_errors
                .push(format!("{} timestamp bounds are reversed", file.interface));
        }
    }
    for (name, value) in [
        ("ue_sessions", manifest.expected.ue_sessions),
        ("eps_bearers", manifest.expected.eps_bearers),
        ("distinct_s1u_teids", manifest.expected.distinct_s1u_teids),
        ("uplink_packets", manifest.expected.uplink_packets),
        ("downlink_packets", manifest.expected.downlink_packets),
        ("correlation_edges", manifest.expected.correlation_edges),
    ] {
        if value.is_none() {
            validation
                .readiness_blockers
                .push(format!("expected.{name} is not populated"));
        }
    }
    if manifest
        .expected
        .first_timestamp_utc
        .as_deref()
        .map_or(true, |value| !valid_timestamp(value))
        || manifest
            .expected
            .last_timestamp_utc
            .as_deref()
            .map_or(true, |value| !valid_timestamp(value))
    {
        validation
            .readiness_blockers
            .push("expected timestamp bounds are not populated".into());
    } else if manifest.expected.first_timestamp_utc > manifest.expected.last_timestamp_utc {
        validation
            .structural_errors
            .push("expected timestamp bounds are reversed".into());
    }
    if manifest.real_capture
        && (manifest.approval.anr1_reference.is_none()
            || manifest.approval.approved_at_utc.is_none())
    {
        validation
            .readiness_blockers
            .push("real fixture requires ANR1 reference and approval timestamp".into());
    }
    Ok((manifest, validation))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_is_structurally_valid_but_not_ready() {
        let (_, validation) = validate_lte_fixture_manifest(include_str!(
            "../../tests/fixtures/lte-real-anonymized-manifest-template.json"
        ))
        .unwrap();
        assert!(validation.structurally_valid(), "{validation:?}");
        assert!(!validation.ready());
        assert!(validation
            .readiness_blockers
            .iter()
            .any(|value| value.contains("ANR1")));
    }

    #[test]
    fn synthetic_offline_manifest_is_ready_without_real_certification() {
        let (manifest, validation) = validate_lte_fixture_manifest(include_str!(
            "../../tests/fixtures/lte-offline-certification-synthetic-manifest.json"
        ))
        .unwrap();
        assert!(!manifest.real_capture);
        assert!(validation.ready(), "{validation:?}");
    }

    #[test]
    fn missing_plane_and_clear_identity_flag_fail_closed() {
        let mut value: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/lte-offline-certification-synthetic-manifest.json"
        ))
        .unwrap();
        value["files"]
            .as_array_mut()
            .unwrap()
            .retain(|file| file["interface"] != "S11");
        value["anonymization"]["clear_subscriber_identities_present"] = Value::Bool(true);
        let (_, validation) = validate_lte_fixture_manifest(&value.to_string()).unwrap();
        assert!(!validation.structurally_valid());
        assert!(validation
            .structural_errors
            .iter()
            .any(|error| error.contains("S11")));
        assert!(validation
            .structural_errors
            .iter()
            .any(|error| error.contains("clear subscriber identities")));
    }
}
