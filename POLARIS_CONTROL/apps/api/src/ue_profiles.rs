use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use ueransim_adapter::{
    lab_gnb_registry, render_profile_with_gnbs, validate_profile_set, GnbEndpoint, UeProfileSpec,
    UeSecrets,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedUeProfile {
    #[serde(flatten)]
    pub profile: UeProfileSpec,
    pub subscriber_identity_sha256: String,
    #[serde(default)]
    pub scenario_id: Option<String>,
    #[serde(default)]
    pub auto_run_scenario: bool,
    pub revision: u64,
    pub created_at_epoch_s: u64,
    pub updated_at_epoch_s: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UeProfileRegistry {
    pub schema_version: u8,
    pub profiles: Vec<ManagedUeProfile>,
}

/// Intentionally does not derive Debug or Serialize: subscriber secrets must never enter logs or
/// API responses. Empty secret fields are accepted only for an edit that preserves the existing
/// restricted profile file.
#[derive(Deserialize)]
pub struct ProfileMutationInput {
    pub ue_id: String,
    pub name: String,
    pub supi: Option<String>,
    pub authentication_key: Option<String>,
    pub opc: Option<String>,
    pub plmn_mcc: String,
    pub plmn_mnc: String,
    pub dnn: String,
    pub sst: u8,
    pub sd: Option<String>,
    pub serving_gnb: String,
    pub scenario_id: Option<String>,
    #[serde(default)]
    pub auto_run_scenario: bool,
    /// Binds the profile to a subscriber already provisioned in Open5GS (for example `UE-03`).
    /// The backend reads SUPI/K/OPc from the protected server-side plan; the request must then
    /// leave `supi`, `authentication_key` and `opc` empty.
    #[serde(default)]
    pub provisioning_slot: Option<String>,
}

/// One subscriber already provisioned in Open5GS, as listed to operators (never its secrets).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ProvisioningSlot {
    pub slot_id: String,
    pub bound_ue_id: Option<String>,
}

/// Default location of the V3.2 subscriber plan written by `deployment/provision-ten-subscribers.sh`.
pub const DEFAULT_SUBSCRIBER_PLAN_PATH: &str =
    "/var/lib/polaris-control/subscriber-secrets/v3.2.plan";
const MAX_SUBSCRIBER_PLAN_BYTES: u64 = 65_536;

/// Bulk provisioning creates protected local material but never provisions Open5GS. Every
/// resulting profile therefore remains `PROVISIONING_REQUIRED` until independently attested.
#[derive(Deserialize)]
pub struct BulkProfileInput {
    pub count: usize,
    pub name_prefix: String,
    pub plmn_mcc: String,
    pub plmn_mnc: String,
    pub dnn: String,
    pub sst: u8,
    pub sd: Option<String>,
    pub serving_gnb: String,
    pub scenario_id: Option<String>,
}

#[derive(Clone)]
pub struct ProfileStore {
    registry_path: PathBuf,
    profile_root: PathBuf,
    gnbs: Vec<GnbEndpoint>,
    subscriber_plan_path: Option<PathBuf>,
}

impl ProfileStore {
    /// Uses the laboratory default gNB registry (production loads it from the environment).
    #[allow(dead_code)]
    pub fn new(registry_path: PathBuf, profile_root: PathBuf) -> Self {
        Self::with_gnbs(registry_path, profile_root, lab_gnb_registry())
    }

    pub fn with_gnbs(
        registry_path: PathBuf,
        profile_root: PathBuf,
        gnbs: Vec<GnbEndpoint>,
    ) -> Self {
        Self {
            registry_path,
            profile_root,
            gnbs,
            subscriber_plan_path: None,
        }
    }

    /// Enables binding profiles to already-provisioned subscribers read from `path`.
    pub fn with_subscriber_plan(mut self, path: PathBuf) -> Self {
        self.subscriber_plan_path = Some(path);
        self
    }

    /// Slot identifiers from the plan, each with the UE profile bound to it, if any.
    pub fn provisioning_slots(
        &self,
        registry: &UeProfileRegistry,
    ) -> Result<Vec<ProvisioningSlot>, String> {
        self.read_subscriber_plan()?
            .into_iter()
            .map(|(slot_id, supi, _, _)| {
                let identity = sha256(supi.as_bytes())?;
                Ok(ProvisioningSlot {
                    bound_ue_id: registry
                        .profiles
                        .iter()
                        .find(|record| record.subscriber_identity_sha256 == identity)
                        .map(|record| record.profile.ue_id.clone()),
                    slot_id,
                })
            })
            .collect()
    }

    fn slot_secrets(&self, slot_id: &str) -> Result<(String, String, String), String> {
        self.read_subscriber_plan()?
            .into_iter()
            .find(|(id, _, _, _)| id == slot_id)
            .map(|(_, supi, key, opc)| (supi, key, opc))
            .ok_or_else(|| "UNKNOWN_PROVISIONING_SLOT".to_string())
    }

    /// Reads `UE-NN|imsi(15 digits)|K(32 hex)|OPc(32 hex)|…` lines from a private plan file.
    fn read_subscriber_plan(&self) -> Result<Vec<(String, String, String, String)>, String> {
        let path = self
            .subscriber_plan_path
            .as_ref()
            .ok_or("PROVISIONING_SLOTS_UNAVAILABLE")?;
        let metadata =
            fs::symlink_metadata(path).map_err(|_| "PROVISIONING_SLOTS_UNAVAILABLE".to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("SUBSCRIBER_PLAN_UNSAFE".into());
            }
        }
        if !metadata.file_type().is_file() || metadata.len() > MAX_SUBSCRIBER_PLAN_BYTES {
            return Err("SUBSCRIBER_PLAN_UNSAFE".into());
        }
        let document =
            fs::read_to_string(path).map_err(|_| "PROVISIONING_SLOTS_UNAVAILABLE".to_string())?;
        let mut slots = Vec::new();
        let mut ids = BTreeSet::new();
        for line in document.lines().filter(|line| !line.trim().is_empty()) {
            let fields: Vec<&str> = line.split('|').collect();
            let valid = fields.len() >= 4
                && parse_ue_index(fields[0]).is_ok()
                && fields[1].len() == 15
                && fields[1].chars().all(|ch| ch.is_ascii_digit())
                && [fields[2], fields[3]].iter().all(|value| {
                    value.len() == 32 && value.chars().all(|ch| ch.is_ascii_hexdigit())
                });
            if !valid || !ids.insert(fields[0].to_string()) {
                return Err("SUBSCRIBER_PLAN_INVALID".into());
            }
            slots.push((
                fields[0].to_string(),
                format!("imsi-{}", fields[1]),
                fields[2].to_string(),
                fields[3].to_string(),
            ));
        }
        Ok(slots)
    }

    fn creation_secrets(
        &self,
        input: &ProfileMutationInput,
    ) -> Result<(String, String, String), String> {
        match input.provisioning_slot.as_deref() {
            None => required_secrets(input),
            Some(slot) => {
                if input.supi.is_some() || input.authentication_key.is_some() || input.opc.is_some()
                {
                    return Err("PROVISIONING_SLOT_EXCLUDES_SECRETS".into());
                }
                self.slot_secrets(slot)
            }
        }
    }

    pub fn gnbs(&self) -> &[GnbEndpoint] {
        &self.gnbs
    }

    pub fn load_or_bootstrap(
        &self,
        fallback: Vec<UeProfileSpec>,
    ) -> Result<UeProfileRegistry, String> {
        match fs::read(&self.registry_path) {
            Ok(bytes) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    let metadata = fs::symlink_metadata(&self.registry_path)
                        .map_err(|_| "UE_PROFILE_REGISTRY_UNREADABLE")?;
                    if !metadata.file_type().is_file()
                        || metadata.uid() != 0
                        || metadata.permissions().mode() & 0o077 != 0
                    {
                        return Err("UE_PROFILE_REGISTRY_PERMISSIONS_UNSAFE".into());
                    }
                }
                let registry: UeProfileRegistry = serde_json::from_slice(&bytes)
                    .map_err(|_| "UE_PROFILE_REGISTRY_INVALID".to_string())?;
                self.validate_registry(&registry)?;
                Ok(registry)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let now = epoch_seconds();
                let profiles = fallback
                    .into_iter()
                    .map(|profile| {
                        let identity = self
                            .read_existing_secrets(&profile.profile_name)
                            .ok()
                            .map(|secrets| sha256(secrets.0.as_bytes()))
                            .transpose()?
                            .unwrap_or_else(|| "0".repeat(64));
                        Ok(ManagedUeProfile {
                            profile,
                            subscriber_identity_sha256: identity,
                            scenario_id: None,
                            auto_run_scenario: false,
                            revision: 1,
                            created_at_epoch_s: now,
                            updated_at_epoch_s: now,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                let registry = UeProfileRegistry {
                    schema_version: 1,
                    profiles,
                };
                self.validate_registry(&registry)?;
                Ok(registry)
            }
            Err(_) => Err("UE_PROFILE_REGISTRY_UNREADABLE".into()),
        }
    }

    pub fn persist(&self, registry: &UeProfileRegistry) -> Result<(), String> {
        self.validate_registry(registry)?;
        atomic_private_write(
            &self.registry_path,
            &serde_json::to_vec_pretty(registry)
                .map_err(|_| "UE_PROFILE_REGISTRY_INVALID".to_string())?,
        )
    }

    pub fn create(
        &self,
        registry: &mut UeProfileRegistry,
        input: ProfileMutationInput,
    ) -> Result<ManagedUeProfile, String> {
        if registry.profiles.len() >= ueransim_adapter::MAX_CONFIGURABLE_UES {
            return Err("UE_PROFILE_CAPACITY_REACHED".into());
        }
        if registry
            .profiles
            .iter()
            .any(|record| record.profile.ue_id == input.ue_id)
        {
            return Err("UE_PROFILE_ALREADY_EXISTS".into());
        }
        let secrets = self.creation_secrets(&input)?;
        let record = self.build_record(input, &secrets, 1, epoch_seconds())?;
        self.ensure_identity_unique(registry, &record.subscriber_identity_sha256, None)?;
        let yaml = render_profile_with_gnbs(
            &record.profile,
            UeSecrets {
                supi: &secrets.0,
                key: &secrets.1,
                opc: &secrets.2,
            },
            &self.gnbs,
        )?;
        let profile_path = self.profile_root.join(&record.profile.profile_name);
        atomic_private_write(&profile_path, yaml.as_bytes())?;
        registry.profiles.push(record.clone());
        if let Err(error) = self.persist(registry) {
            let _ = fs::remove_file(profile_path);
            registry
                .profiles
                .retain(|item| item.profile.ue_id != record.profile.ue_id);
            return Err(error);
        }
        Ok(record)
    }

    /// Adds an approved batch in one registry generation. Profile files are staged before the
    /// registry swap; any pre-publication failure removes the staged/new files and leaves the
    /// caller's registry unchanged.
    pub fn create_bulk(
        &self,
        registry: &mut UeProfileRegistry,
        input: BulkProfileInput,
    ) -> Result<Vec<ManagedUeProfile>, String> {
        if !matches!(input.count, 10 | 100 | 1_000 | 10_000)
            || registry.profiles.len().saturating_add(input.count)
                > ueransim_adapter::MAX_CONFIGURABLE_UES
        {
            return Err("UE_BULK_COUNT_INVALID".into());
        }
        if input.name_prefix.trim().is_empty() || input.name_prefix.len() > 40 {
            return Err("UE_NAME_INVALID".into());
        }
        let occupied = registry
            .profiles
            .iter()
            .filter_map(|item| parse_ue_index(&item.profile.ue_id).ok())
            .collect::<BTreeSet<_>>();
        let indices = (1..=ueransim_adapter::MAX_CONFIGURABLE_UES)
            .filter(|index| !occupied.contains(index))
            .take(input.count)
            .collect::<Vec<_>>();
        if indices.len() != input.count {
            return Err("UE_PROFILE_CAPACITY_REACHED".into());
        }

        let original = registry.clone();
        let mut records = Vec::with_capacity(input.count);
        let mut staged = Vec::with_capacity(input.count);
        let generation = random_hex(8);
        for index in indices {
            let ue_id = if index <= 99 {
                format!("UE-{index:02}")
            } else {
                format!("UE-{index:05}")
            };
            let secrets = (
                format!("imsi-{}{}{:010}", input.plmn_mcc, input.plmn_mnc, index),
                random_hex(16),
                random_hex(16),
            );
            let mutation = ProfileMutationInput {
                ue_id,
                name: format!("{} {index}", input.name_prefix.trim()),
                supi: Some(secrets.0.clone()),
                authentication_key: Some(secrets.1.clone()),
                opc: Some(secrets.2.clone()),
                plmn_mcc: input.plmn_mcc.clone(),
                plmn_mnc: input.plmn_mnc.clone(),
                dnn: input.dnn.clone(),
                sst: input.sst,
                sd: input.sd.clone(),
                serving_gnb: input.serving_gnb.clone(),
                scenario_id: input.scenario_id.clone(),
                auto_run_scenario: false,
                provisioning_slot: None,
            };
            let record = self.build_record(mutation, &secrets, 1, epoch_seconds())?;
            let yaml = render_profile_with_gnbs(
                &record.profile,
                UeSecrets {
                    supi: &secrets.0,
                    key: &secrets.1,
                    opc: &secrets.2,
                },
                &self.gnbs,
            )?;
            let final_path = self.profile_root.join(&record.profile.profile_name);
            let stage_path = self.profile_root.join(format!(
                ".{}.{}.tmp",
                record.profile.profile_name, generation
            ));
            if let Err(error) = atomic_private_write(&stage_path, yaml.as_bytes()) {
                for (stage, _) in &staged {
                    let _ = fs::remove_file(stage);
                }
                return Err(error);
            }
            staged.push((stage_path, final_path));
            records.push(record);
        }
        let mut candidate = original.clone();
        candidate.profiles.extend(records.clone());
        self.validate_registry(&candidate)?;
        let mut published = Vec::new();
        for (stage, final_path) in &staged {
            if final_path.exists() || fs::rename(stage, final_path).is_err() {
                for path in &published {
                    let _ = fs::remove_file(path);
                }
                for (pending, _) in &staged {
                    let _ = fs::remove_file(pending);
                }
                return Err("UE_BULK_PROFILE_PUBLISH_FAILED".into());
            }
            published.push(final_path.clone());
        }
        if let Err(error) = self.persist(&candidate) {
            for path in published {
                let _ = fs::remove_file(path);
            }
            return Err(error);
        }
        *registry = candidate;
        Ok(records)
    }

    pub fn update(
        &self,
        registry: &mut UeProfileRegistry,
        ue_id: &str,
        input: ProfileMutationInput,
    ) -> Result<ManagedUeProfile, String> {
        if input.ue_id != ue_id {
            return Err("UE_ID_IMMUTABLE".into());
        }
        let index = registry
            .profiles
            .iter()
            .position(|record| record.profile.ue_id == ue_id)
            .ok_or("UNKNOWN_UE_PROFILE")?;
        let old = registry.profiles[index].clone();
        let secrets = match (
            input.supi.as_deref(),
            input.authentication_key.as_deref(),
            input.opc.as_deref(),
        ) {
            (None, None, None) => self.read_existing_secrets(&old.profile.profile_name)?,
            (Some(_), Some(_), Some(_)) => required_secrets(&input)?,
            _ => return Err("COMPLETE_SUBSCRIBER_SECRET_SET_REQUIRED".into()),
        };
        let mut record =
            self.build_record(input, &secrets, old.revision + 1, old.created_at_epoch_s)?;
        record.profile.subscription_verified = false;
        self.ensure_identity_unique(registry, &record.subscriber_identity_sha256, Some(ue_id))?;
        let yaml = render_profile_with_gnbs(
            &record.profile,
            UeSecrets {
                supi: &secrets.0,
                key: &secrets.1,
                opc: &secrets.2,
            },
            &self.gnbs,
        )?;
        let path = self.profile_root.join(&record.profile.profile_name);
        let backup = fs::read(&path).map_err(|_| "UE_PROFILE_SECRET_UNREADABLE")?;
        atomic_private_write(&path, yaml.as_bytes())?;
        registry.profiles[index] = record.clone();
        if let Err(error) = self.persist(registry) {
            let _ = atomic_private_write(&path, &backup);
            registry.profiles[index] = old;
            return Err(error);
        }
        Ok(record)
    }

    pub fn clone_profile(
        &self,
        registry: &mut UeProfileRegistry,
        source_ue_id: &str,
        target_ue_id: &str,
    ) -> Result<ManagedUeProfile, String> {
        let source = registry
            .profiles
            .iter()
            .find(|record| record.profile.ue_id == source_ue_id)
            .cloned()
            .ok_or("UNKNOWN_UE_PROFILE")?;
        let index = parse_ue_index(target_ue_id)?;
        let supi = format!(
            "imsi-{}{}{:010}",
            source.profile.plmn_mcc, source.profile.plmn_mnc, index
        );
        let input = ProfileMutationInput {
            ue_id: target_ue_id.into(),
            name: format!("{} CLONE", source.profile.pseudonym),
            supi: Some(supi),
            authentication_key: Some(random_hex(16)),
            opc: Some(random_hex(16)),
            plmn_mcc: source.profile.plmn_mcc,
            plmn_mnc: source.profile.plmn_mnc,
            dnn: source.profile.dnn,
            sst: source.profile.sst,
            sd: source.profile.sd,
            serving_gnb: source.profile.serving_gnb,
            scenario_id: source.scenario_id,
            auto_run_scenario: false,
            provisioning_slot: None,
        };
        self.create(registry, input)
    }

    pub fn delete(
        &self,
        registry: &mut UeProfileRegistry,
        ue_id: &str,
    ) -> Result<ManagedUeProfile, String> {
        let index = registry
            .profiles
            .iter()
            .position(|record| record.profile.ue_id == ue_id)
            .ok_or("UNKNOWN_UE_PROFILE")?;
        let record = registry.profiles.remove(index);
        let path = self.profile_root.join(&record.profile.profile_name);
        let bytes = fs::read(&path).map_err(|_| "UE_PROFILE_SECRET_UNREADABLE")?;
        let tombstone = path.with_extension("yaml.deleted");
        fs::rename(&path, &tombstone).map_err(|_| "UE_PROFILE_DELETE_FAILED")?;
        if let Err(error) = self.persist(registry) {
            let _ = fs::rename(&tombstone, &path);
            registry.profiles.insert(index, record.clone());
            return Err(error);
        }
        fs::remove_file(&tombstone).map_err(|_| "UE_PROFILE_DELETE_FINALIZE_FAILED")?;
        drop(bytes);
        Ok(record)
    }

    fn build_record(
        &self,
        input: ProfileMutationInput,
        secrets: &(String, String, String),
        revision: u64,
        created_at_epoch_s: u64,
    ) -> Result<ManagedUeProfile, String> {
        let index = parse_ue_index(&input.ue_id)?;
        validate_public_fields(&input)?;
        let profile = UeProfileSpec {
            ue_id: input.ue_id,
            pseudonym: input.name,
            profile_name: if index <= 99 {
                format!("ue-{index:02}.yaml")
            } else {
                format!("ue-{index:05}.yaml")
            },
            serving_gnb: input.serving_gnb,
            plmn_mcc: input.plmn_mcc,
            plmn_mnc: input.plmn_mnc,
            dnn: input.dnn,
            sst: input.sst,
            sd: input.sd,
            configured: true,
            subscription_verified: false,
        };
        validate_profile_set(std::slice::from_ref(&profile))?;
        Ok(ManagedUeProfile {
            profile,
            subscriber_identity_sha256: sha256(secrets.0.as_bytes())?,
            scenario_id: input.scenario_id,
            auto_run_scenario: input.auto_run_scenario,
            revision,
            created_at_epoch_s,
            updated_at_epoch_s: epoch_seconds(),
        })
    }

    fn validate_registry(&self, registry: &UeProfileRegistry) -> Result<(), String> {
        if registry.schema_version != 1 {
            return Err("UE_PROFILE_REGISTRY_VERSION_UNSUPPORTED".into());
        }
        validate_profile_set(
            &registry
                .profiles
                .iter()
                .map(|record| record.profile.clone())
                .collect::<Vec<_>>(),
        )?;
        let mut identities = BTreeSet::new();
        for record in &registry.profiles {
            if record.subscriber_identity_sha256 != "0".repeat(64)
                && !identities.insert(&record.subscriber_identity_sha256)
            {
                return Err("DUPLICATE_SUBSCRIBER_IDENTITY".into());
            }
        }
        Ok(())
    }

    fn ensure_identity_unique(
        &self,
        registry: &UeProfileRegistry,
        identity: &str,
        except_ue_id: Option<&str>,
    ) -> Result<(), String> {
        if registry.profiles.iter().any(|record| {
            record.profile.ue_id != except_ue_id.unwrap_or_default()
                && record.subscriber_identity_sha256 == identity
        }) {
            Err("DUPLICATE_SUBSCRIBER_IDENTITY".into())
        } else {
            Ok(())
        }
    }

    fn read_existing_secrets(&self, basename: &str) -> Result<(String, String, String), String> {
        if basename.contains('/') || basename.contains("..") {
            return Err("UE_PROFILE_PATH_INVALID".into());
        }
        let document = fs::read_to_string(self.profile_root.join(basename))
            .map_err(|_| "UE_PROFILE_SECRET_UNREADABLE")?;
        Ok((
            yaml_scalar(&document, "supi").ok_or("UE_PROFILE_SECRET_INVALID")?,
            yaml_scalar(&document, "key").ok_or("UE_PROFILE_SECRET_INVALID")?,
            yaml_scalar(&document, "op").ok_or("UE_PROFILE_SECRET_INVALID")?,
        ))
    }
}

fn validate_public_fields(input: &ProfileMutationInput) -> Result<(), String> {
    if input.name.trim().is_empty() || input.name.len() > 64 {
        return Err("UE_NAME_INVALID".into());
    }
    if input.sst == 0
        || input.sd.as_ref().is_some_and(|value| {
            value.len() != 6 || !value.chars().all(|ch| ch.is_ascii_hexdigit())
        })
        || !safe_token(&input.dnn)
        || !safe_token(&input.serving_gnb)
        || input
            .scenario_id
            .as_ref()
            .is_some_and(|value| !safe_token(value))
    {
        return Err("UE_PROFILE_FIELDS_INVALID".into());
    }
    Ok(())
}

fn required_secrets(input: &ProfileMutationInput) -> Result<(String, String, String), String> {
    let supi = input
        .supi
        .as_deref()
        .ok_or("SUBSCRIBER_IDENTITY_REQUIRED")?;
    let key = input
        .authentication_key
        .as_deref()
        .ok_or("AUTHENTICATION_KEY_REQUIRED")?;
    let opc = input.opc.as_deref().ok_or("OPC_REQUIRED")?;
    if !supi.starts_with("imsi-")
        || supi.len() < 10
        || !supi[5..].chars().all(|ch| ch.is_ascii_digit())
        || key.len() != 32
        || opc.len() != 32
        || !key
            .chars()
            .chain(opc.chars())
            .all(|ch| ch.is_ascii_hexdigit())
    {
        return Err("SUBSCRIBER_SECRET_MATERIAL_INVALID".into());
    }
    Ok((supi.into(), key.into(), opc.into()))
}

fn parse_ue_index(ue_id: &str) -> Result<usize, String> {
    let index = ue_id
        .strip_prefix("UE-")
        .filter(|value| !value.is_empty() && value.len() <= 5)
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or("UE_ID_INVALID")?;
    if !(1..=ueransim_adapter::MAX_CONFIGURABLE_UES).contains(&index) {
        return Err("UE_ID_INVALID".into());
    }
    let canonical = if index <= 99 {
        format!("UE-{index:02}")
    } else {
        format!("UE-{index:05}")
    };
    if ue_id != canonical {
        return Err("UE_ID_INVALID".into());
    }
    Ok(index)
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

fn yaml_scalar(document: &str, key: &str) -> Option<String> {
    document.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        (candidate.trim() == key).then(|| {
            value
                .trim()
                .trim_matches(|ch| ch == '\'' || ch == '"')
                .to_string()
        })
    })
}

fn sha256(bytes: &[u8]) -> Result<String, String> {
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "UE_PROFILE_STORAGE_UNWRITABLE")?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| "UE_PROFILE_STORAGE_UNWRITABLE")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "UE_PROFILE_STORAGE_UNWRITABLE")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|_| "UE_PROFILE_STORAGE_UNWRITABLE")?;
    }
    fs::rename(&temporary, path).map_err(|_| "UE_PROFILE_STORAGE_UNWRITABLE")?;
    Ok(())
}

fn random_hex(bytes: usize) -> String {
    let mut values = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut values);
    values.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(name: &str) -> ProfileStore {
        let root = std::env::temp_dir().join(format!("polaris-profile-{name}-{}", epoch_seconds()));
        let _ = fs::remove_dir_all(&root);
        ProfileStore::new(root.join("registry.json"), root.join("profiles"))
    }

    fn input(ue_id: &str, supi: &str) -> ProfileMutationInput {
        ProfileMutationInput {
            ue_id: ue_id.into(),
            name: format!("Test {ue_id}"),
            supi: Some(supi.into()),
            authentication_key: Some("11".repeat(16)),
            opc: Some("22".repeat(16)),
            plmn_mcc: "001".into(),
            plmn_mnc: "01".into(),
            dnn: "internet".into(),
            sst: 1,
            sd: Some("010203".into()),
            serving_gnb: "GNB-01".into(),
            scenario_id: Some("scenario-1".into()),
            auto_run_scenario: false,
            provisioning_slot: None,
        }
    }

    fn plan_store(name: &str, plan: &str, mode: u32) -> (ProfileStore, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("polaris-slots-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let plan_path = root.join("v3.2.plan");
        fs::write(&plan_path, plan).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&plan_path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let store = ProfileStore::new(root.join("registry.json"), root.join("profiles"))
            .with_subscriber_plan(plan_path);
        (store, root)
    }

    const TEST_PLAN: &str = "UE-01|001010000000001|00112233445566778899aabbccddeeff|ffeeddccbbaa99887766554433221100|1|1\nUE-02|001010000000002|0123456789abcdef0123456789abcdef|fedcba9876543210fedcba9876543210|2|2\n";

    fn slot_input(ue_id: &str, slot: &str) -> ProfileMutationInput {
        let mut value = input(ue_id, "imsi-000000000000000");
        value.supi = None;
        value.authentication_key = None;
        value.opc = None;
        value.provisioning_slot = Some(slot.into());
        value
    }

    #[test]
    fn provisioning_slot_binds_server_side_secrets_without_exposing_them() {
        let (store, root) = plan_store("bind", TEST_PLAN, 0o600);
        let mut registry = UeProfileRegistry {
            schema_version: 1,
            profiles: vec![],
        };
        let record = store
            .create(&mut registry, slot_input("UE-11", "UE-02"))
            .unwrap();
        assert_eq!(
            record.subscriber_identity_sha256,
            sha256(b"imsi-001010000000002").unwrap()
        );
        let yaml = fs::read_to_string(root.join("profiles").join("ue-11.yaml")).unwrap();
        assert!(yaml.contains("supi: 'imsi-001010000000002'"));
        assert!(yaml.contains("key: '0123456789abcdef0123456789abcdef'"));
        assert!(!serde_json::to_string(&registry)
            .unwrap()
            .contains("0123456789abcdef"));
        let slots = store.provisioning_slots(&registry).unwrap();
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[1].bound_ue_id.as_deref(), Some("UE-11"));
        assert_eq!(slots[0].bound_ue_id, None);
        assert!(!serde_json::to_string(&slots).unwrap().contains("00101"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn provisioning_slot_is_bound_at_most_once() {
        let (store, root) = plan_store("once", TEST_PLAN, 0o600);
        let mut registry = UeProfileRegistry {
            schema_version: 1,
            profiles: vec![],
        };
        store
            .create(&mut registry, slot_input("UE-11", "UE-01"))
            .unwrap();
        assert_eq!(
            store
                .create(&mut registry, slot_input("UE-12", "UE-01"))
                .unwrap_err(),
            "DUPLICATE_SUBSCRIBER_IDENTITY"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn provisioning_slot_rejects_mixed_secrets_unknown_slots_and_unsafe_plans() {
        let (store, root) = plan_store("reject", TEST_PLAN, 0o600);
        let mut registry = UeProfileRegistry {
            schema_version: 1,
            profiles: vec![],
        };
        let mut mixed = slot_input("UE-11", "UE-01");
        mixed.opc = Some("22".repeat(16));
        assert_eq!(
            store.create(&mut registry, mixed).unwrap_err(),
            "PROVISIONING_SLOT_EXCLUDES_SECRETS"
        );
        assert_eq!(
            store
                .create(&mut registry, slot_input("UE-11", "UE-09"))
                .unwrap_err(),
            "UNKNOWN_PROVISIONING_SLOT"
        );
        fs::remove_dir_all(root).unwrap();
        let (unsafe_store, unsafe_root) = plan_store("unsafe", TEST_PLAN, 0o644);
        assert_eq!(
            unsafe_store.provisioning_slots(&registry).unwrap_err(),
            "SUBSCRIBER_PLAN_UNSAFE"
        );
        fs::remove_dir_all(unsafe_root).unwrap();
        let (bad_store, bad_root) = plan_store("bad", "UE-01|123|x|y\n", 0o600);
        assert_eq!(
            bad_store.provisioning_slots(&registry).unwrap_err(),
            "SUBSCRIBER_PLAN_INVALID"
        );
        fs::remove_dir_all(bad_root).unwrap();
        let no_plan = temp_store("noplan");
        assert_eq!(
            no_plan
                .create(&mut registry, slot_input("UE-11", "UE-01"))
                .unwrap_err(),
            "PROVISIONING_SLOTS_UNAVAILABLE"
        );
    }

    #[test]
    fn create_edit_clone_delete_is_atomic_and_secrets_are_not_serialized() {
        let store = temp_store("crud");
        let mut registry = UeProfileRegistry {
            schema_version: 1,
            profiles: vec![],
        };
        let first = store
            .create(&mut registry, input("UE-02", "imsi-001010000000002"))
            .unwrap();
        assert!(!serde_json::to_string(&registry)
            .unwrap()
            .contains("11111111"));
        let mut edit = input("UE-02", "imsi-001010000000002");
        edit.supi = None;
        edit.authentication_key = None;
        edit.opc = None;
        edit.dnn = "ims".into();
        edit.scenario_id = Some("scenario-2".into());
        edit.auto_run_scenario = true;
        let edited = store.update(&mut registry, "UE-02", edit).unwrap();
        assert_eq!(edited.profile.dnn, "ims");
        assert_eq!(edited.scenario_id.as_deref(), Some("scenario-2"));
        assert!(edited.auto_run_scenario);
        assert_eq!(edited.revision, first.revision + 1);
        let cloned = store
            .clone_profile(&mut registry, "UE-02", "UE-03")
            .unwrap();
        assert_ne!(
            cloned.subscriber_identity_sha256,
            edited.subscriber_identity_sha256
        );
        store.delete(&mut registry, "UE-03").unwrap();
        assert!(!store.profile_root.join("ue-03.yaml").exists());
        store.delete(&mut registry, "UE-02").unwrap();
        assert!(registry.profiles.is_empty());
        let recovered = store.load_or_bootstrap(vec![]).unwrap();
        assert!(recovered.profiles.is_empty());
    }

    #[test]
    fn duplicate_identity_and_partial_secret_edits_are_rejected() {
        let store = temp_store("duplicates");
        let mut registry = UeProfileRegistry {
            schema_version: 1,
            profiles: vec![],
        };
        store
            .create(&mut registry, input("UE-02", "imsi-001010000000002"))
            .unwrap();
        assert_eq!(
            store
                .create(&mut registry, input("UE-03", "imsi-001010000000002"))
                .unwrap_err(),
            "DUPLICATE_SUBSCRIBER_IDENTITY"
        );
        let mut partial = input("UE-02", "imsi-001010000000002");
        partial.opc = None;
        assert_eq!(
            store.update(&mut registry, "UE-02", partial).unwrap_err(),
            "COMPLETE_SUBSCRIBER_SECRET_SET_REQUIRED"
        );
    }

    #[test]
    fn ten_thousand_profiles_are_created_once_and_survive_reload() {
        let store = temp_store("bulk-10k");
        let root = store.profile_root.parent().unwrap().to_path_buf();
        let mut registry = UeProfileRegistry {
            schema_version: 1,
            profiles: vec![],
        };
        let created = store
            .create_bulk(
                &mut registry,
                BulkProfileInput {
                    count: 10_000,
                    name_prefix: "LAB UE".into(),
                    plmn_mcc: "001".into(),
                    plmn_mnc: "01".into(),
                    dnn: "internet".into(),
                    sst: 1,
                    sd: Some("010203".into()),
                    serving_gnb: "GNB-01".into(),
                    scenario_id: Some("scenario-capacity".into()),
                },
            )
            .unwrap();
        assert_eq!(created.len(), 10_000);
        assert_eq!(registry.profiles.len(), 10_000);
        assert_eq!(registry.profiles[9_999].profile.ue_id, "UE-10000");
        assert!(store.profile_root.join("ue-10000.yaml").is_file());
        let recovered = store.load_or_bootstrap(vec![]).unwrap();
        assert_eq!(recovered.profiles.len(), 10_000);
        assert_eq!(
            recovered
                .profiles
                .iter()
                .map(|item| &item.subscriber_identity_sha256)
                .collect::<BTreeSet<_>>()
                .len(),
            10_000
        );
        fs::remove_dir_all(root).unwrap();
    }
}
