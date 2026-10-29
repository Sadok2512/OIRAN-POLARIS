use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
pub const VERSION: &str = "0.5.0";
/// Maximum number of persistent definitions. This is not a live execution limit.
pub const MAX_CONFIGURABLE_UES: usize = 100_000;
/// Certified maximum number of concurrently running controller-owned UEs.
pub const MAX_LIVE_UES: usize = 10;
pub const DEFAULT_PROFILE_SLOTS: usize = 10;
pub const LIVE_PROFILE_ROOT: &str = "/var/lib/polaris-control/ue-profiles";
pub const LIVE_START_SCRIPT: &str = "/root/POLARIS/scripts/start-ueransim-ue.sh";
pub const LIVE_DOCKER_NETWORK: &str = "oiran-lab-mgmt";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedUe {
    pub scenario_id: String,
    pub pseudonym: String,
    pub profile_basename: String,
    pub execution: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UeProfileSpec {
    pub ue_id: String,
    pub pseudonym: String,
    pub profile_name: String,
    pub serving_gnb: String,
    pub plmn_mcc: String,
    pub plmn_mnc: String,
    pub dnn: String,
    pub sst: u8,
    pub sd: Option<String>,
    pub configured: bool,
    pub subscription_verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveLaunchSpec {
    pub ue_id: String,
    pub profile_basename: String,
    pub container_name: String,
    pub owner_id: String,
    pub profile_sha256: String,
    pub script_sha256: String,
    pub image_id: String,
    pub docker_args: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UeObservation {
    pub process_state: String,
    pub registration_state: String,
    pub pdu_session_state: String,
    pub ue_ip: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisioningBinding {
    pub ue_id: String,
    pub profile_basename: String,
    pub profile_sha256: String,
    pub subscriber_identity_sha256: String,
    pub authority: String,
    pub authoritative_record_sha256: String,
}

/// Sanitized evidence derived from a profile without retaining its subscriber identity or keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionedProfileEvidence {
    pub ue_id: String,
    pub profile_basename: String,
    pub profile_sha256: String,
    pub subscriber_identity_sha256: String,
    pub plmn_mcc: String,
    pub plmn_mnc: String,
    pub dnn: String,
    pub sst: u8,
    pub sd: Option<String>,
    pub owner_uid: u32,
    pub mode: u32,
}

/// Authentication material is intentionally not Debug, Serialize or Clone.
/// It exists only long enough to render an administrator-approved profile.
pub struct UeSecrets<'a> {
    pub supi: &'a str,
    pub key: &'a str,
    pub opc: &'a str,
}

pub fn planned_profiles() -> Vec<UeProfileSpec> {
    (1..=DEFAULT_PROFILE_SLOTS)
        .map(|index| UeProfileSpec {
            ue_id: format!("UE-{index:02}"),
            pseudonym: format!("UE-PSEUDONYM-{index:02}"),
            profile_name: format!("ue-{index:02}.yaml"),
            serving_gnb: "GNB-01".into(),
            plmn_mcc: "001".into(),
            plmn_mnc: "01".into(),
            dnn: "internet".into(),
            sst: 1,
            sd: Some("010203".into()),
            configured: index == 1,
            subscription_verified: false,
        })
        .collect()
}

pub fn is_approved_controller_ue(ue_id: &str) -> bool {
    let suffix = ue_id
        .strip_prefix("UE-")
        .filter(|value| !value.is_empty() && value.len() <= 6);
    let index = suffix
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|index| (1..=MAX_CONFIGURABLE_UES).contains(index));
    index.is_some_and(|index| {
        let short = if index <= 99 {
            format!("UE-{index:02}")
        } else {
            format!("UE-{index}")
        };
        let padded = format!("UE-{index:05}");
        ue_id == short || ue_id == padded
    })
}

fn sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

/// Validates root-controlled, non-secret attestations against freshly derived profile evidence.
/// The attestation is expected to be produced from the authoritative subscriber provisioning
/// workflow; profile and subscriber digests bind that approval to the exact mounted content.
pub fn validate_provisioning_bindings(
    profiles: &[UeProfileSpec],
    evidence: &[ProvisionedProfileEvidence],
    bindings: &[ProvisioningBinding],
) -> Result<(), String> {
    let required = profiles
        .iter()
        .filter(|profile| profile.configured)
        .collect::<Vec<_>>();
    if required.is_empty() || evidence.len() != required.len() {
        return Err("PROVISIONING_ATTESTATION_INCOMPLETE".into());
    }
    let mut identities = BTreeSet::new();
    for profile in required {
        let ue_id = profile.ue_id.as_str();
        let observed = evidence
            .iter()
            .find(|item| item.ue_id == ue_id)
            .ok_or("PROVISIONING_EVIDENCE_MISSING")?;
        let binding = bindings
            .iter()
            .find(|item| item.ue_id == ue_id)
            .ok_or("PROVISIONING_BINDING_MISSING")?;
        if observed.owner_uid != 0 || observed.mode & 0o077 != 0 {
            return Err("PROVISIONING_PROFILE_PERMISSIONS_UNSAFE".into());
        }
        if !sha256_digest(&observed.profile_sha256)
            || !sha256_digest(&observed.subscriber_identity_sha256)
            || observed.profile_basename != profile.profile_name
            || binding.profile_basename != profile.profile_name
            || binding.profile_sha256 != observed.profile_sha256
            || binding.subscriber_identity_sha256 != observed.subscriber_identity_sha256
            || binding.authority != "OPEN5GS"
            || !sha256_digest(&binding.authoritative_record_sha256)
        {
            return Err("PROVISIONING_PROFILE_BINDING_MISMATCH".into());
        }
        if !identities.insert(observed.subscriber_identity_sha256.as_str()) {
            return Err("PROVISIONING_SUBSCRIBER_IDENTITY_NOT_UNIQUE".into());
        }
        if observed.plmn_mcc != profile.plmn_mcc
            || observed.plmn_mnc != profile.plmn_mnc
            || observed.dnn != profile.dnn
            || observed.sst != profile.sst
            || observed.sd != profile.sd
        {
            return Err("PROVISIONING_NETWORK_COMPATIBILITY_MISMATCH".into());
        }
    }
    Ok(())
}

pub fn validate_profile_set(profiles: &[UeProfileSpec]) -> Result<(), String> {
    if profiles.len() > MAX_CONFIGURABLE_UES {
        return Err("profile count must be between 0 and 100000".into());
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for profile in profiles {
        if !profile.ue_id.starts_with("UE-") || !ids.insert(profile.ue_id.as_str()) {
            return Err("UE IDs must be unique and use the UE- prefix".into());
        }
        if !profile.profile_name.ends_with(".yaml")
            || profile.profile_name.contains('/')
            || profile.profile_name.contains("..")
            || !names.insert(profile.profile_name.as_str())
        {
            return Err("profile names must be unique safe YAML basenames".into());
        }
        if profile.plmn_mcc.len() != 3
            || !matches!(profile.plmn_mnc.len(), 2 | 3)
            || !profile.plmn_mcc.chars().all(|value| value.is_ascii_digit())
            || !profile.plmn_mnc.chars().all(|value| value.is_ascii_digit())
        {
            return Err("invalid PLMN".into());
        }
        if profile.dnn.is_empty() || profile.serving_gnb.is_empty() {
            return Err("DNN and serving gNB are required".into());
        }
    }
    Ok(())
}

fn immutable_image_id(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| digest.len() == 64 && digest.chars().all(|ch| ch.is_ascii_hexdigit()))
}

/// Builds the complete, shell-free Docker argv for one of the two reviewed additions.
/// It does not execute the command or read the subscriber profile.
pub fn live_launch_spec(
    profile: &UeProfileSpec,
    profile_root: &Path,
    image_id: &str,
    start_script: &Path,
    owner_id: &str,
    profile_sha256: &str,
    script_sha256: &str,
) -> Result<LiveLaunchSpec, String> {
    if !is_approved_controller_ue(&profile.ue_id) {
        return Err("PROTECTED_OR_UNAPPROVED_UE".into());
    }
    if !profile.configured || !profile.subscription_verified {
        return Err("UE_PROFILE_NOT_READY".into());
    }
    if profile_root != Path::new(LIVE_PROFILE_ROOT)
        || start_script != Path::new(LIVE_START_SCRIPT)
        || !immutable_image_id(image_id)
        || !sha256_digest(owner_id)
        || !sha256_digest(profile_sha256)
        || !sha256_digest(script_sha256)
    {
        return Err("LIVE_RUNTIME_INPUT_NOT_ALLOWLISTED".into());
    }
    let expected_basename = format!("ue-{}.yaml", &profile.ue_id[3..]);
    if profile.profile_name != expected_basename {
        return Err("UE_PROFILE_ASSOCIATION_MISMATCH".into());
    }
    let container_name = format!("polaris-control-{}", profile.ue_id.to_ascii_lowercase());
    let profile_path = profile_root.join(&profile.profile_name);
    let docker_args = vec![
        "run".into(),
        "--detach".into(),
        "--name".into(),
        container_name.clone(),
        "--label".into(),
        "polaris.control.owner=polaris-control".into(),
        "--label".into(),
        format!("polaris.control.ue-id={}", profile.ue_id),
        "--label".into(),
        format!("polaris.control.profile={}", profile.profile_name),
        "--label".into(),
        format!("polaris.control.ownership-id={owner_id}"),
        "--label".into(),
        format!("polaris.control.profile-sha256={profile_sha256}"),
        "--label".into(),
        format!("polaris.control.script-sha256={script_sha256}"),
        "--read-only".into(),
        "--security-opt".into(),
        "no-new-privileges:true".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--cap-add".into(),
        "NET_ADMIN".into(),
        "--device".into(),
        "/dev/net/tun:/dev/net/tun".into(),
        "--pids-limit".into(),
        "128".into(),
        "--cpus".into(),
        "0.75".into(),
        "--memory".into(),
        "512m".into(),
        "--restart".into(),
        "no".into(),
        "--network".into(),
        LIVE_DOCKER_NETWORK.into(),
        "--user".into(),
        "0:0".into(),
        "--tmpfs".into(),
        "/tmp:size=64m".into(),
        "--tmpfs".into(),
        "/etc/iproute2:size=1m".into(),
        "--mount".into(),
        format!(
            "type=bind,src={},dst=/run/secrets/ue.yaml,readonly",
            profile_path.display()
        ),
        "--mount".into(),
        format!(
            "type=bind,src={},dst=/usr/local/bin/start-ueransim-ue,readonly",
            start_script.display()
        ),
        "--entrypoint".into(),
        "/usr/local/bin/start-ueransim-ue".into(),
        image_id.into(),
        "/run/secrets/ue.yaml".into(),
    ];
    Ok(LiveLaunchSpec {
        ue_id: profile.ue_id.clone(),
        profile_basename: profile.profile_name.clone(),
        container_name,
        owner_id: owner_id.into(),
        profile_sha256: profile_sha256.into(),
        script_sha256: script_sha256.into(),
        image_id: image_id.into(),
        docker_args,
    })
}

fn observed_tunnel_ips(output: &str) -> BTreeSet<String> {
    output
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let interface = fields.get(1)?.trim_end_matches(':');
            if !interface.starts_with("uesimtun")
                || !interface["uesimtun".len()..]
                    .chars()
                    .all(|ch| ch.is_ascii_digit())
            {
                return None;
            }
            let inet = fields.iter().position(|field| *field == "inet")?;
            let address = fields.get(inet + 1)?.split('/').next()?;
            address.parse::<std::net::Ipv4Addr>().ok()?;
            Some(address.to_string())
        })
        .collect()
}

fn active_session_ip(output: &str, tunnel_ips: &BTreeSet<String>) -> Option<String> {
    let pdu = output.split("---PDU---").nth(1)?;
    let mut current = Vec::new();
    let mut entries = Vec::new();
    for line in pdu.lines() {
        if line.trim_start().starts_with("PDU Session") && !current.is_empty() {
            entries.push(std::mem::take(&mut current));
        }
        if !line.trim().is_empty() {
            current.push(line.trim().to_string());
        }
    }
    if !current.is_empty() {
        entries.push(current);
    }
    entries.into_iter().find_map(|entry| {
        if !entry.iter().any(|line| line == "state: PS-ACTIVE") {
            return None;
        }
        entry.iter().find_map(|line| {
            let address = line.strip_prefix("address: ")?.trim();
            tunnel_ips.contains(address).then(|| address.to_string())
        })
    })
}

/// Reduces bounded UERANSIM evidence to public state. Container health alone never implies
/// Registration or an active PDU Session.
pub fn observe_ueransim(
    process_state: &str,
    current_cli: &str,
    tunnel_output: &str,
) -> UeObservation {
    let running = process_state.eq_ignore_ascii_case("running");
    let registered = running
        && current_cli
            .lines()
            .any(|line| line.trim() == "rm-state: RM-REGISTERED")
        && current_cli
            .lines()
            .any(|line| line.trim() == "mm-state: MM-REGISTERED/NORMAL-SERVICE");
    let tunnel_ips = observed_tunnel_ips(tunnel_output);
    let ue_ip = registered
        .then(|| active_session_ip(current_cli, &tunnel_ips))
        .flatten();
    let pdu_active = ue_ip.is_some();
    UeObservation {
        process_state: process_state.to_ascii_uppercase(),
        registration_state: if registered {
            "REGISTERED"
        } else {
            "NOT_OBSERVED"
        }
        .into(),
        pdu_session_state: if pdu_active { "ACTIVE" } else { "INACTIVE" }.into(),
        ue_ip: pdu_active.then_some(ue_ip).flatten(),
    }
}

/// A gNB the controller may name in a UE profile, and the address a UE must search for it on.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GnbEndpoint {
    pub gnb_id: String,
    pub link_ip: String,
}

/// Environment variable naming an optional JSON registry that replaces the laboratory default.
pub const GNB_REGISTRY_ENV: &str = "POLARIS_GNB_REGISTRY_PATH";
const MAX_GNB_REGISTRY_BYTES: u64 = 16_384;
const MAX_GNBS: usize = 16;

/// The deployed laboratory gNB (GNB_CONFIGURATION_AUDIT.md: gNB-01 link IP on oiran-lab-mgmt).
pub fn lab_gnb_registry() -> Vec<GnbEndpoint> {
    vec![GnbEndpoint {
        gnb_id: "GNB-01".into(),
        link_ip: "10.77.0.20".into(),
    }]
}

fn safe_gnb_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

pub fn validate_gnb_registry(registry: &[GnbEndpoint]) -> Result<(), String> {
    if registry.is_empty() || registry.len() > MAX_GNBS {
        return Err("GNB_REGISTRY_INVALID".into());
    }
    let mut ids = BTreeSet::new();
    for gnb in registry {
        if !safe_gnb_id(&gnb.gnb_id)
            || gnb.link_ip.parse::<std::net::Ipv4Addr>().is_err()
            || !ids.insert(gnb.gnb_id.as_str())
        {
            return Err("GNB_REGISTRY_INVALID".into());
        }
    }
    Ok(())
}

/// Loads the registry named by `POLARIS_GNB_REGISTRY_PATH`, or the laboratory default when unset.
/// A configured but unreadable or invalid registry is an error: it never falls back silently.
pub fn load_gnb_registry_from_env() -> Result<Vec<GnbEndpoint>, String> {
    match std::env::var_os(GNB_REGISTRY_ENV) {
        None => Ok(lab_gnb_registry()),
        Some(path) => load_gnb_registry(Path::new(&path)),
    }
}

pub fn load_gnb_registry(path: &Path) -> Result<Vec<GnbEndpoint>, String> {
    let metadata = std::fs::metadata(path).map_err(|_| "GNB_REGISTRY_UNREADABLE".to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_GNB_REGISTRY_BYTES {
        return Err("GNB_REGISTRY_INVALID".into());
    }
    let bytes = std::fs::read(path).map_err(|_| "GNB_REGISTRY_UNREADABLE".to_string())?;
    let registry: Vec<GnbEndpoint> =
        serde_json::from_slice(&bytes).map_err(|_| "GNB_REGISTRY_INVALID".to_string())?;
    validate_gnb_registry(&registry)?;
    Ok(registry)
}

/// Returns the address that feeds `gnbSearchList`. An unknown gNB is refused, never defaulted.
pub fn resolve_gnb_link_ip<'a>(
    registry: &'a [GnbEndpoint],
    serving_gnb: &str,
) -> Result<&'a str, String> {
    registry
        .iter()
        .find(|gnb| gnb.gnb_id == serving_gnb)
        .map(|gnb| gnb.link_ip.as_str())
        .ok_or_else(|| "UNKNOWN_SERVING_GNB".to_string())
}

/// Renders against the laboratory default registry.
pub fn render_profile(profile: &UeProfileSpec, secrets: UeSecrets<'_>) -> Result<String, String> {
    render_profile_with_gnbs(profile, secrets, &lab_gnb_registry())
}

pub fn render_profile_with_gnbs(
    profile: &UeProfileSpec,
    secrets: UeSecrets<'_>,
    gnbs: &[GnbEndpoint],
) -> Result<String, String> {
    validate_profile_set(std::slice::from_ref(profile))?;
    let gnb_link_ip = resolve_gnb_link_ip(gnbs, &profile.serving_gnb)?;
    if secrets.supi.len() < 10
        || secrets.key.len() != 32
        || secrets.opc.len() != 32
        || !secrets
            .key
            .chars()
            .chain(secrets.opc.chars())
            .all(|value| value.is_ascii_hexdigit())
    {
        return Err("invalid subscriber secret material".into());
    }
    Ok(format!(
        "supi: '{supi}'\nmcc: '{mcc}'\nmnc: '{mnc}'\nkey: '{key}'\nopType: 'OPC'\nop: '{opc}'\namf: '8000'\ngnbSearchList:\n  - {gnb_link_ip}\nconfigured-nssai: [{{sst: {sst}, sd: 0x{sd}}}]\ndefault-nssai: [{{sst: {sst}, sd: 0x{sd}}}]\nsessions:\n  - type: 'IPv4'\n    apn: '{dnn}'\n    slice:\n      sst: {sst}\n      sd: '{sd}'\n",
        gnb_link_ip = gnb_link_ip,
        supi = secrets.supi,
        mcc = profile.plmn_mcc,
        mnc = profile.plmn_mnc,
        key = secrets.key,
        opc = secrets.opc,
        dnn = profile.dnn,
        sst = profile.sst,
        sd = profile.sd.as_deref().unwrap_or("010203")
    ))
}
pub fn audit_profile(
    lab: &Path,
    basename: &str,
    scenario_id: &str,
    pseudonym: &str,
) -> Result<PreparedUe, String> {
    if basename.contains('/') || basename.contains("..") || !basename.ends_with(".yaml") {
        return Err("profile must be an allowlisted basename".into());
    }
    let root = lab.canonicalize().map_err(|e| e.to_string())?;
    let path: PathBuf = root.join("runtime/ueransim").join(basename);
    let canonical = path.canonicalize().map_err(|_| "profile not present")?;
    if !canonical.starts_with(&root) {
        return Err("profile escapes lab root".into());
    }
    Ok(PreparedUe {
        scenario_id: scenario_id.into(),
        pseudonym: pseudonym.into(),
        profile_basename: basename.into(),
        execution: "NOT_EXECUTED",
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_arbitrary_paths() {
        assert!(audit_profile(Path::new("/root/POLARIS"), "../../x", "s", "UE-1").is_err())
    }

    #[test]
    fn two_five_and_ten_profiles_are_unique_and_compatible() {
        let mut profiles = planned_profiles();
        profiles.iter_mut().take(4).for_each(|profile| {
            profile.configured = true;
            profile.subscription_verified = true;
        });
        validate_profile_set(&profiles[..2]).unwrap();
        validate_profile_set(&profiles).unwrap();
        assert_eq!(
            profiles
                .iter()
                .map(|value| &value.ue_id)
                .collect::<BTreeSet<_>>()
                .len(),
            10
        );
        assert!(profiles.iter().all(|value| value.plmn_mcc == "001"
            && value.dnn == "internet"
            && value.sd.as_deref() == Some("010203")));
    }

    #[test]
    fn empty_profile_set_is_a_valid_clean_controller_state() {
        validate_profile_set(&[]).unwrap();
    }

    #[test]
    fn duplicate_ue_profile_is_rejected() {
        let mut profiles = planned_profiles();
        profiles[1].ue_id = profiles[0].ue_id.clone();
        assert!(validate_profile_set(&profiles).is_err());
    }

    #[test]
    fn rendering_requires_valid_secret_material_without_logging_it() {
        let profile = planned_profiles().remove(0);
        let rendered = render_profile(
            &profile,
            UeSecrets {
                supi: "imsi-999990000000001",
                key: "00112233445566778899aabbccddeeff",
                opc: "ffeeddccbbaa99887766554433221100",
            },
        )
        .unwrap();
        assert!(!rendered.contains("UE-PSEUDONYM"));
        assert!(render_profile(
            &profile,
            UeSecrets {
                supi: "short",
                key: "x",
                opc: "x"
            }
        )
        .is_err());
    }

    fn test_secrets() -> UeSecrets<'static> {
        UeSecrets {
            supi: "imsi-999990000000001",
            key: "00112233445566778899aabbccddeeff",
            opc: "ffeeddccbbaa99887766554433221100",
        }
    }

    #[test]
    fn gnb01_rendering_is_byte_identical_to_the_attested_format() {
        // Existing provisioning attestations bind the SHA-256 of these exact bytes.
        let profile = planned_profiles().remove(0);
        let expected = "supi: 'imsi-999990000000001'\nmcc: '001'\nmnc: '01'\nkey: '00112233445566778899aabbccddeeff'\nopType: 'OPC'\nop: 'ffeeddccbbaa99887766554433221100'\namf: '8000'\ngnbSearchList:\n  - 10.77.0.20\nconfigured-nssai: [{sst: 1, sd: 0x010203}]\ndefault-nssai: [{sst: 1, sd: 0x010203}]\nsessions:\n  - type: 'IPv4'\n    apn: 'internet'\n    slice:\n      sst: 1\n      sd: '010203'\n";
        assert_eq!(render_profile(&profile, test_secrets()).unwrap(), expected);
    }

    #[test]
    fn serving_gnb_feeds_gnb_search_list() {
        let mut profile = planned_profiles().remove(0);
        profile.serving_gnb = "GNB-02".into();
        let registry = vec![
            GnbEndpoint {
                gnb_id: "GNB-01".into(),
                link_ip: "10.77.0.20".into(),
            },
            GnbEndpoint {
                gnb_id: "GNB-02".into(),
                link_ip: "10.77.0.22".into(),
            },
        ];
        let rendered = render_profile_with_gnbs(&profile, test_secrets(), &registry).unwrap();
        assert!(rendered.contains("gnbSearchList:\n  - 10.77.0.22\n"));
        assert!(!rendered.contains("10.77.0.20"));
    }

    #[test]
    fn unknown_serving_gnb_is_refused_without_default() {
        let mut profile = planned_profiles().remove(0);
        profile.serving_gnb = "GNB-99".into();
        assert_eq!(
            render_profile(&profile, test_secrets()).unwrap_err(),
            "UNKNOWN_SERVING_GNB"
        );
    }

    #[test]
    fn gnb_registry_rejects_invalid_or_duplicate_entries() {
        let bad_ip = vec![GnbEndpoint {
            gnb_id: "GNB-01".into(),
            link_ip: "not-an-ip".into(),
        }];
        assert!(validate_gnb_registry(&bad_ip).is_err());
        let duplicate = vec![lab_gnb_registry()[0].clone(), lab_gnb_registry()[0].clone()];
        assert!(validate_gnb_registry(&duplicate).is_err());
        let unsafe_id = vec![GnbEndpoint {
            gnb_id: "../GNB".into(),
            link_ip: "10.77.0.20".into(),
        }];
        assert!(validate_gnb_registry(&unsafe_id).is_err());
        assert!(validate_gnb_registry(&[]).is_err());
        assert!(validate_gnb_registry(&lab_gnb_registry()).is_ok());
    }

    #[test]
    fn gnb_registry_file_is_loaded_and_validated() {
        let dir = std::env::temp_dir().join(format!("gnb-registry-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.json");
        std::fs::write(
            &good,
            r#"[{"gnb_id":"GNB-01","link_ip":"10.77.0.20"},{"gnb_id":"GNB-02","link_ip":"10.77.0.22"}]"#,
        )
        .unwrap();
        assert_eq!(load_gnb_registry(&good).unwrap().len(), 2);
        let bad = dir.join("bad.json");
        std::fs::write(&bad, r#"[{"gnb_id":"GNB-01"}]"#).unwrap();
        assert_eq!(load_gnb_registry(&bad).unwrap_err(), "GNB_REGISTRY_INVALID");
        assert_eq!(
            load_gnb_registry(&dir.join("missing.json")).unwrap_err(),
            "GNB_REGISTRY_UNREADABLE"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn live_additions_use_stable_bounded_profile_allowlist() {
        let mut profiles = planned_profiles();
        profiles.iter_mut().take(10).for_each(|profile| {
            profile.configured = true;
            profile.subscription_verified = true;
        });
        for (id, basename) in [
            ("UE-02", "ue-02.yaml"),
            ("UE-05", "ue-05.yaml"),
            ("UE-10", "ue-10.yaml"),
        ] {
            let profile = profiles.iter().find(|profile| profile.ue_id == id).unwrap();
            let launch = live_launch_spec(
                profile,
                Path::new("/var/lib/polaris-control/ue-profiles"),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                Path::new("/root/POLARIS/scripts/start-ueransim-ue.sh"),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            )
            .unwrap();
            assert_eq!(launch.profile_basename, basename);
            assert_eq!(
                launch.container_name,
                format!("polaris-control-{}", id.to_lowercase())
            );
            assert!(launch
                .docker_args
                .windows(2)
                .any(|args| args == ["--network", "oiran-lab-mgmt"]));
            assert!(launch.docker_args.iter().any(|arg| arg == "--read-only"));
            assert!(!launch.docker_args.iter().any(|arg| arg.contains("sh -c")));
        }
        let ue01 = live_launch_spec(
            &profiles[0],
            Path::new("/var/lib/polaris-control/ue-profiles"),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Path::new("/root/POLARIS/scripts/start-ueransim-ue.sh"),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )
        .unwrap();
        assert_eq!(ue01.container_name, "polaris-control-ue-01");
        assert!(is_approved_controller_ue("UE-11"));
        assert!(is_approved_controller_ue("UE-201"));
        assert!(is_approved_controller_ue("UE-00201"));
        assert!(is_approved_controller_ue("UE-100000"));
        assert!(!is_approved_controller_ue("UE-100001"));
        assert!(!is_approved_controller_ue("UE-2"));
    }

    #[test]
    fn observation_requires_nas_and_tunnel_evidence() {
        let healthy_only = observe_ueransim("running", "", "");
        assert_eq!(healthy_only.registration_state, "NOT_OBSERVED");
        assert_eq!(healthy_only.pdu_session_state, "INACTIVE");
        assert_eq!(healthy_only.ue_ip, None);

        let registered = observe_ueransim(
            "running",
            "rm-state: RM-REGISTERED\nmm-state: MM-REGISTERED/NORMAL-SERVICE",
            "",
        );
        assert_eq!(registered.registration_state, "REGISTERED");
        assert_eq!(registered.pdu_session_state, "INACTIVE");

        let active = observe_ueransim(
            "running",
            "rm-state: RM-REGISTERED\nmm-state: MM-REGISTERED/NORMAL-SERVICE\n---PDU---\nPDU Session1:\n  state: PS-ACTIVE\n  address: 10.46.0.7",
            "7: uesimtun0    inet 10.46.0.7/16 scope global uesimtun0\n",
        );
        assert_eq!(active.registration_state, "REGISTERED");
        assert_eq!(active.pdu_session_state, "ACTIVE");
        assert_eq!(active.ue_ip.as_deref(), Some("10.46.0.7"));

        let historical_success_but_currently_deregistered = observe_ueransim(
            "running",
            "PDU Session establishment is successful\nrm-state: RM-DEREGISTERED\nmm-state: MM-DEREGISTERED/PLMN-SEARCH\n---PDU---\nPDU Session1:\n  state: PS-INACTIVE",
            "7: uesimtun0    inet 10.46.0.7/16 scope global uesimtun0\n",
        );
        assert_eq!(
            historical_success_but_currently_deregistered.registration_state,
            "NOT_OBSERVED"
        );
        assert_eq!(
            historical_success_but_currently_deregistered.pdu_session_state,
            "INACTIVE"
        );
        assert_eq!(historical_success_but_currently_deregistered.ue_ip, None);

        for state in ["paused", "restarting"] {
            let observation = observe_ueransim(
                state,
                "rm-state: RM-REGISTERED\nmm-state: MM-REGISTERED/NORMAL-SERVICE",
                "7: uesimtun0 inet 10.46.0.7/16 scope global uesimtun0\n",
            );
            assert_eq!(observation.process_state, state.to_ascii_uppercase());
            assert_eq!(observation.registration_state, "NOT_OBSERVED");
            assert_eq!(observation.pdu_session_state, "INACTIVE");
        }
    }

    #[test]
    fn profiles_are_unverified_until_authoritative_binding_is_validated() {
        assert!(planned_profiles()
            .iter()
            .all(|profile| !profile.subscription_verified));
    }

    #[test]
    fn provisioning_requires_exact_binding_compatibility_permissions_and_unique_identities() {
        let mut profiles = planned_profiles();
        profiles
            .iter_mut()
            .take(5)
            .for_each(|profile| profile.configured = true);
        let evidence = profiles[..5]
            .iter()
            .enumerate()
            .map(|(index, profile)| ProvisionedProfileEvidence {
                ue_id: profile.ue_id.clone(),
                profile_basename: profile.profile_name.clone(),
                profile_sha256: format!("{:064x}", index + 1),
                subscriber_identity_sha256: format!("{:064x}", index + 11),
                plmn_mcc: profile.plmn_mcc.clone(),
                plmn_mnc: profile.plmn_mnc.clone(),
                dnn: profile.dnn.clone(),
                sst: profile.sst,
                sd: profile.sd.clone(),
                owner_uid: 0,
                mode: 0o600,
            })
            .collect::<Vec<_>>();
        let bindings = evidence
            .iter()
            .map(|item| ProvisioningBinding {
                ue_id: item.ue_id.clone(),
                profile_basename: item.profile_basename.clone(),
                profile_sha256: item.profile_sha256.clone(),
                subscriber_identity_sha256: item.subscriber_identity_sha256.clone(),
                authority: "OPEN5GS".into(),
                authoritative_record_sha256: "a".repeat(64),
            })
            .collect::<Vec<_>>();
        validate_provisioning_bindings(&profiles, &evidence, &bindings).unwrap();

        let mut swapped = evidence.clone();
        let digest = swapped[1].profile_sha256.clone();
        swapped[1].profile_sha256 = swapped[2].profile_sha256.clone();
        swapped[2].profile_sha256 = digest;
        assert!(validate_provisioning_bindings(&profiles, &swapped, &bindings).is_err());
        let mut duplicate = evidence.clone();
        duplicate[2].subscriber_identity_sha256 = duplicate[1].subscriber_identity_sha256.clone();
        let mut duplicate_bindings = bindings.clone();
        duplicate_bindings[2].subscriber_identity_sha256 =
            duplicate[1].subscriber_identity_sha256.clone();
        assert_eq!(
            validate_provisioning_bindings(&profiles, &duplicate, &duplicate_bindings).unwrap_err(),
            "PROVISIONING_SUBSCRIBER_IDENTITY_NOT_UNIQUE"
        );
        let mut wrong_slice = evidence.clone();
        wrong_slice[1].sd = Some("112233".into());
        assert_eq!(
            validate_provisioning_bindings(&profiles, &wrong_slice, &bindings).unwrap_err(),
            "PROVISIONING_NETWORK_COMPATIBILITY_MISMATCH"
        );
        let mut unsafe_mode = evidence;
        unsafe_mode[1].mode = 0o644;
        assert_eq!(
            validate_provisioning_bindings(&profiles, &unsafe_mode, &bindings).unwrap_err(),
            "PROVISIONING_PROFILE_PERMISSIONS_UNSAFE"
        );
    }

    #[test]
    fn pdu_observation_binds_active_state_and_address_to_one_session_and_ue_tunnel() {
        let cli = "rm-state: RM-REGISTERED\nmm-state: MM-REGISTERED/NORMAL-SERVICE\n---PDU---\nPDU Session1:\n  state: PS-ACTIVE\n  address: 10.46.0.7\nPDU Session2:\n  state: PS-INACTIVE\n  address: 10.46.0.8";
        let wrong_interface = observe_ueransim(
            "running",
            cli,
            "2: eth0    inet 10.46.0.7/16 scope global eth0\n",
        );
        assert_eq!(wrong_interface.pdu_session_state, "INACTIVE");

        let split_evidence = observe_ueransim(
            "running",
            cli,
            "7: uesimtun0    inet 10.46.0.8/16 scope global uesimtun0\n",
        );
        assert_eq!(split_evidence.pdu_session_state, "INACTIVE");

        let authentic_multi = observe_ueransim(
            "running",
            "rm-state: RM-REGISTERED\nmm-state: MM-REGISTERED/NORMAL-SERVICE\n---PDU---\nPDU Session1:\n  state: PS-INACTIVE\n  session-type: IPv4\n  address: 10.46.0.7\nPDU Session2:\n  state: PS-ACTIVE\n  session-type: IPv4\n  address: 10.46.0.8",
            "7: uesimtun0    inet 10.46.0.8/16 scope global uesimtun0\n",
        );
        assert_eq!(authentic_multi.pdu_session_state, "ACTIVE");
        assert_eq!(authentic_multi.ue_ip.as_deref(), Some("10.46.0.8"));

        for state in ["restarting", "paused", "exited"] {
            let observed = observe_ueransim(
                state,
                cli,
                "7: uesimtun0    inet 10.46.0.7/16 scope global uesimtun0\n",
            );
            assert_eq!(observed.registration_state, "NOT_OBSERVED");
            assert_eq!(observed.pdu_session_state, "INACTIVE");
            assert_eq!(observed.ue_ip, None);
        }
    }
}
