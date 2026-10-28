use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::RwLock,
    time::{SystemTime, UNIX_EPOCH},
};

const REGISTRY_SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisteredInterface {
    pub interface: String,
    pub role: String,
    pub bpf_filter: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeInput {
    pub probe_id: String,
    pub probe_type: String,
    pub name: String,
    pub host: String,
    pub mgmt_ip: String,
    pub site: String,
    pub interfaces: Vec<RegisteredInterface>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProbeRecord {
    pub probe_id: String,
    pub probe_type: String,
    pub name: String,
    pub host: String,
    pub mgmt_ip: String,
    pub site: String,
    pub interfaces: Vec<RegisteredInterface>,
    #[serde(default)]
    pub last_heartbeat_epoch_s: Option<u64>,
}

impl From<ProbeInput> for ProbeRecord {
    fn from(value: ProbeInput) -> Self {
        Self {
            probe_id: value.probe_id,
            probe_type: value.probe_type,
            name: value.name,
            host: value.host,
            mgmt_ip: value.mgmt_ip,
            site: value.site,
            interfaces: value.interfaces,
            last_heartbeat_epoch_s: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    schema_version: String,
    probes: Vec<ProbeRecord>,
}

pub struct ProbeRegistry {
    path: PathBuf,
    document: RwLock<RegistryDocument>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateError {
    Duplicate,
    Invalid,
    Storage,
}

impl ProbeRegistry {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let document = if path.exists() {
            let bytes = fs::read(&path).map_err(|error| error.to_string())?;
            let parsed: RegistryDocument =
                serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            validate_document(&parsed)?;
            enforce_private_mode(&path)?;
            parsed
        } else {
            let document = RegistryDocument {
                schema_version: REGISTRY_SCHEMA_VERSION.into(),
                probes: vec![initial_local_probe()],
            };
            write_atomic(&path, &document)?;
            document
        };
        Ok(Self {
            path,
            document: RwLock::new(document),
        })
    }

    pub fn list(&self) -> Vec<ProbeRecord> {
        self.document
            .read()
            .map(|document| document.probes.clone())
            .unwrap_or_default()
    }

    pub fn get(&self, probe_id: &str) -> Option<ProbeRecord> {
        self.document.read().ok().and_then(|document| {
            document
                .probes
                .iter()
                .find(|probe| probe.probe_id == probe_id)
                .cloned()
        })
    }

    pub fn create(&self, input: ProbeInput) -> Result<ProbeRecord, CreateError> {
        validate_input(&input).map_err(|_| CreateError::Invalid)?;
        let mut document = self.document.write().map_err(|_| CreateError::Storage)?;
        if document
            .probes
            .iter()
            .any(|probe| probe.probe_id == input.probe_id)
        {
            return Err(CreateError::Duplicate);
        }
        let record = ProbeRecord::from(input);
        let mut next = document.clone();
        next.probes.push(record.clone());
        next.probes
            .sort_by(|left, right| left.probe_id.cmp(&right.probe_id));
        write_atomic(&self.path, &next).map_err(|_| CreateError::Storage)?;
        *document = next;
        Ok(record)
    }
}

pub fn validate_input(input: &ProbeInput) -> Result<(), String> {
    if !(3..=48).contains(&input.probe_id.len())
        || !input
            .probe_id
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'-')
    {
        return Err("probe_id must match [a-z0-9-]{3,48}".into());
    }
    if input.probe_type != "virtual" && input.probe_type != "physical" {
        return Err("probe_type must be virtual or physical".into());
    }
    for (field, value) in [
        ("name", input.name.as_str()),
        ("host", input.host.as_str()),
        ("site", input.site.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > 128 || value.contains(['\n', '\r', '\0']) {
            return Err(format!("{field} is invalid"));
        }
    }
    input
        .mgmt_ip
        .parse::<IpAddr>()
        .map_err(|_| "mgmt_ip must be an IP address".to_string())?;
    if input.interfaces.is_empty() || input.interfaces.len() > 16 {
        return Err("interfaces must contain between 1 and 16 entries".into());
    }
    let mut unique_interfaces = BTreeSet::new();
    for interface in &input.interfaces {
        if interface.interface.is_empty()
            || interface.interface.len() > 64
            || !interface.interface.bytes().all(|value| {
                value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err("interface is invalid".into());
        }
        if !matches!(interface.role.as_str(), "N2" | "N3" | "N4" | "S1" | "N6") {
            return Err("interface role is invalid".into());
        }
        if interface.bpf_filter.trim().is_empty()
            || interface.bpf_filter.len() > 512
            || interface.bpf_filter.contains(['\n', '\r', '\0'])
        {
            return Err("bpf_filter is invalid".into());
        }
        if !unique_interfaces.insert(interface.interface.as_str()) {
            return Err("duplicate interface".into());
        }
    }
    Ok(())
}

fn validate_document(document: &RegistryDocument) -> Result<(), String> {
    if document.schema_version != REGISTRY_SCHEMA_VERSION {
        return Err("unsupported probe registry schema".into());
    }
    let mut unique = BTreeSet::new();
    for probe in &document.probes {
        validate_input(&ProbeInput {
            probe_id: probe.probe_id.clone(),
            probe_type: probe.probe_type.clone(),
            name: probe.name.clone(),
            host: probe.host.clone(),
            mgmt_ip: probe.mgmt_ip.clone(),
            site: probe.site.clone(),
            interfaces: probe.interfaces.clone(),
        })?;
        if !unique.insert(probe.probe_id.as_str()) {
            return Err("duplicate probe id in registry".into());
        }
    }
    Ok(())
}

fn initial_local_probe() -> ProbeRecord {
    ProbeRecord {
        probe_id: "oiran-vprobe-local-01".into(),
        probe_type: "virtual".into(),
        name: "OIRAN Local Rust vProbe".into(),
        host: "localhost".into(),
        mgmt_ip: "127.0.0.1".into(),
        site: "local-lab".into(),
        interfaces: vec![
            RegisteredInterface {
                interface: "br-oiran-n2".into(),
                role: "N2".into(),
                bpf_filter: "sctp and port 38412".into(),
            },
            RegisteredInterface {
                interface: "br-oiran-n3".into(),
                role: "N3".into(),
                bpf_filter: "udp port 2152".into(),
            },
            RegisteredInterface {
                interface: "br-oiran-n4".into(),
                role: "N4".into(),
                bpf_filter: "udp port 8805".into(),
            },
        ],
        last_heartbeat_epoch_s: None,
    }
}

fn write_atomic(path: &Path, document: &RegistryDocument) -> Result<(), String> {
    let parent = path.parent().ok_or("probe registry has no parent")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let generation = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("probe registry file name is invalid")?;
    let temporary = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        generation
    ));
    let bytes = serde_json::to_vec_pretty(document).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::rename(&temporary, path).map_err(|error| error.to_string())?;
    enforce_private_mode(path)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn enforce_private_mode(path: &Path) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| error.to_string())
}
