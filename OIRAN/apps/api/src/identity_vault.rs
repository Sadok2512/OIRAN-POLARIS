//! Root-only identity evidence kept outside every published dataset.
//!
//! Values in this module must never be formatted with `Debug` or written to
//! application logs.  The HTTP adapter exposes them only after the operator
//! role has been verified.

use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::RwLock,
};

const SCHEMA_VERSION: &str = "oiran.identity-vault.v1";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityObservation {
    pub session_id: String,
    pub subscriber_pseudonym: Option<String>,
    pub kind: String,
    pub value: String,
    pub value_type: Option<String>,
    pub role: String,
    pub event_id: String,
    pub capture_id: String,
    pub packet_number: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct VaultDocument {
    schema_version: String,
    observations: Vec<IdentityObservation>,
}

pub struct IdentityVault {
    path: PathBuf,
    document: RwLock<VaultDocument>,
}

impl IdentityVault {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let parent = path.parent().ok_or("identity vault path has no parent")?;
        if parent.exists() {
            ensure_private_directory(parent)?;
        } else {
            fs::create_dir_all(parent).map_err(|error| access_error(parent, &error))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| access_error(parent, &error))?;
            ensure_private_directory(parent)?;
        }
        let document = if path.exists() {
            ensure_private_file(&path)?;
            let bytes = fs::read(&path).map_err(|error| access_error(&path, &error))?;
            let parsed: VaultDocument =
                serde_json::from_slice(&bytes).map_err(|_| "identity vault is invalid")?;
            if parsed.schema_version != SCHEMA_VERSION {
                return Err("identity vault schema is unsupported".into());
            }
            parsed
        } else {
            let document = VaultDocument {
                schema_version: SCHEMA_VERSION.into(),
                observations: Vec::new(),
            };
            persist(&path, &document)?;
            document
        };
        Ok(Self {
            path,
            document: RwLock::new(document),
        })
    }

    pub fn upsert(&self, observations: Vec<IdentityObservation>) -> Result<(), String> {
        if observations.is_empty() {
            return Ok(());
        }
        let mut document = self
            .document
            .write()
            .map_err(|_| "identity vault lock poisoned")?;
        for observation in observations {
            let duplicate = document.observations.iter().any(|existing| {
                existing.session_id == observation.session_id
                    && existing.kind == observation.kind
                    && existing.value == observation.value
                    && existing.event_id == observation.event_id
                    && existing.packet_number == observation.packet_number
            });
            if !duplicate {
                document.observations.push(observation);
            }
        }
        document.observations.sort_by(|left, right| {
            left.capture_id
                .cmp(&right.capture_id)
                .then_with(|| left.packet_number.cmp(&right.packet_number))
                .then_with(|| left.kind.cmp(&right.kind))
        });
        persist(&self.path, &document)
    }

    pub fn for_session(&self, session_id: &str) -> Result<Vec<IdentityObservation>, String> {
        let document = self
            .document
            .read()
            .map_err(|_| "identity vault lock poisoned")?;
        Ok(document
            .observations
            .iter()
            .filter(|observation| observation.session_id == session_id)
            .cloned()
            .collect())
    }

    pub fn lookup(&self, query: &str) -> Result<Vec<IdentityObservation>, String> {
        let document = self
            .document
            .read()
            .map_err(|_| "identity vault lock poisoned")?;
        Ok(document
            .observations
            .iter()
            .filter(|observation| observation.value == query)
            .cloned()
            .collect())
    }

    pub fn pseudonyms_for_value(&self, query: &str) -> Result<Vec<String>, String> {
        let mut values = self
            .lookup(query)?
            .into_iter()
            .filter_map(|observation| observation.subscriber_pseudonym)
            .collect::<Vec<_>>();
        values.sort();
        values.dedup();
        Ok(values)
    }
}

fn access_error(path: &Path, error: &std::io::Error) -> String {
    let mode = fs::metadata(path)
        .map(|metadata| format!("{:04o}", metadata.permissions().mode() & 0o7777))
        .unwrap_or_else(|_| "UNAVAILABLE".into());
    format!(
        "ACCESS_CHECK_FAILED path={} mode={mode} error={error}",
        path.display()
    )
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| access_error(path, &error))?;
    let mode = metadata.permissions().mode() & 0o777;
    let service_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || mode != 0o700 || metadata.uid() != service_uid {
        return Err(format!(
            "ACCESS_CHECK_FAILED path={} mode={mode:04o} owner_uid={} service_uid={service_uid} required=directory-0700-service-owned",
            path.display(), metadata.uid()
        ));
    }
    Ok(())
}

fn access_error(path: &Path, error: &std::io::Error) -> String {
    let mode = fs::metadata(path)
        .map(|metadata| format!("{:04o}", metadata.permissions().mode() & 0o7777))
        .unwrap_or_else(|_| "UNAVAILABLE".into());
    format!(
        "ACCESS_CHECK_FAILED path={} mode={mode} error={error}",
        path.display()
    )
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| access_error(path, &error))?;
    let mode = metadata.permissions().mode() & 0o777;
    let service_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir() || mode != 0o700 || metadata.uid() != service_uid {
        return Err(format!(
            "ACCESS_CHECK_FAILED path={} mode={mode:04o} owner_uid={} service_uid={service_uid} required=directory-0700-service-owned",
            path.display(), metadata.uid()
        ));
    }
    Ok(())
}

fn ensure_private_file(path: &Path) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "ACCESS_CHECK_FAILED path={} mode={mode:04o} required=file-0600",
            path.display()
        ));
    }
    let service_uid = unsafe { libc::geteuid() };
    if metadata.uid() != service_uid {
        return Err(format!(
            "ACCESS_CHECK_FAILED path={} mode={mode:04o} owner_uid={} service_uid={service_uid} required=service-owned",
            path.display(),
            metadata.uid()
        ));
    }
    Ok(())
}

fn persist(path: &Path, document: &VaultDocument) -> Result<(), String> {
    let temporary = path.with_extension("json.next");
    let bytes = serde_json::to_vec(document).map_err(|_| "identity vault serialization failed")?;
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| access_error(&temporary, &error))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| access_error(&temporary, &error))?;
    file.write_all(&bytes).map_err(|error| access_error(&temporary, &error))?;
    file.sync_all().map_err(|error| access_error(&temporary, &error))?;
    fs::rename(&temporary, path).map_err(|error| access_error(path, &error))?;
    ensure_private_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root() -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("oiran-identity-vault-{suffix}"))
    }

    fn observation() -> IdentityObservation {
        IdentityObservation {
            session_id: "test-session".into(),
            subscriber_pseudonym: Some("psn-test-only".into()),
            kind: "imsi".into(),
            value: "001010123456789".into(),
            value_type: Some("IMSI".into()),
            role: "presented".into(),
            event_id: "event-test".into(),
            capture_id: "capture-test".into(),
            packet_number: 7,
        }
    }

    #[test]
    fn vault_is_0600_deduplicated_and_searchable() {
        let root = root();
        let path = root.join("identity-vault.json");
        let vault = IdentityVault::load(path.clone()).unwrap();
        vault.upsert(vec![observation(), observation()]).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(vault.for_session("test-session").unwrap().len(), 1);
        assert_eq!(vault.lookup("001010123456789").unwrap().len(), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn wider_existing_permissions_fail_closed() {
        let root = root();
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("identity-vault.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = match IdentityVault::load(path.clone()) {
            Ok(_) => panic!("insecure vault unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(error.contains("ACCESS_CHECK_FAILED"));
        assert!(error.contains(&format!("path={}", path.display())));
        assert!(error.contains("mode=0644"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn existing_parent_mode_is_never_rewritten() {
        let root = root();
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let error = match IdentityVault::load(root.join("vault.json")) {
            Ok(_) => panic!("insecure directory unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(error.contains("mode=0755"));
        assert_eq!(fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o755);
        let _ = fs::remove_dir_all(root);
    }
}
