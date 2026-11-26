//! Read-only inventory of continuous shards and their manifest references.
use super::LiveDataset;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    ffi::CString,
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

pub(super) const INTERVAL: Duration = Duration::from_secs(30 * 60);
#[derive(Default)]
pub(super) struct Report {
    trees_consulted: usize,
    archives_consulted: usize,
}

pub(super) struct InventoryError {
    path: Option<PathBuf>,
    reason: String,
}

impl InventoryError {
    pub(super) fn general(reason: impl Into<String>) -> Self {
        Self {
            path: None,
            reason: reason.into(),
        }
    }
}

impl Report {
    pub(super) fn snapshot(self, result: Result<(usize, u64), InventoryError>) -> Value {
        let (count, bytes, error) = match result {
            Ok((count, bytes)) => (Some(count), Some(bytes), None),
            Err(error) => (
                None,
                None,
                Some(json!({"path": error.path, "reason": error.reason})),
            ),
        };
        json!({
            "status": if error.is_some() { "unavailable" } else { "available" },
            "count": count,
            "bytes": bytes,
            "trees_consulted": self.trees_consulted,
            "archives_consulted": self.archives_consulted,
            "publication_lock_held_ns": 0,
            "error": error,
        })
    }
}

// The watch is armed before reading inputs. Any pending notification, including
// queue overflow or invalidation, discards the plan; no event is drained.
struct InventoryWatch {
    fd: OwnedFd,
    mounts: Vec<u8>,
}

impl InventoryWatch {
    fn new() -> Result<Self, InventoryError> {
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(InventoryError::general(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mounts = fs::read("/proc/self/mountinfo")
            .map_err(|error| unavailable(Path::new("/proc/self/mountinfo"), error))?;
        Ok(Self { fd, mounts })
    }

    fn add(&self, path: &Path, directory: bool) -> Result<(), InventoryError> {
        let changes = if directory {
            libc::IN_ONLYDIR
                | libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_MOVED_FROM
                | libc::IN_MOVED_TO
        } else {
            libc::IN_MODIFY | libc::IN_CLOSE_WRITE
        };
        self.add_mask(path, changes)
    }

    fn add_mask(&self, path: &Path, changes: u32) -> Result<(), InventoryError> {
        let name =
            CString::new(path.as_os_str().as_bytes()).map_err(|error| unavailable(path, error))?;
        let common = libc::IN_ATTRIB
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_UNMOUNT
            | libc::IN_MASK_ADD;
        if unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), name.as_ptr(), common | changes) }
            < 0
        {
            return Err(unavailable(path, std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn add_ancestors(&self, path: &Path) -> Result<(), InventoryError> {
        for directory in path.ancestors().skip(1) {
            self.add_mask(directory, libc::IN_ONLYDIR)?;
        }
        Ok(())
    }

    fn unchanged(&self) -> Result<(), InventoryError> {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        match unsafe { libc::poll(&mut poll, 1, 0) } {
            0 => Ok(()),
            1 => Err(InventoryError::general(
                "shard inventory changed during measurement",
            )),
            _ => Err(InventoryError::general(
                std::io::Error::last_os_error().to_string(),
            )),
        }
    }

    fn check_mounts(&self) -> Result<(), InventoryError> {
        if fs::read("/proc/self/mountinfo")
            .map_err(|error| unavailable(Path::new("/proc/self/mountinfo"), error))?
            != self.mounts
        {
            return Err(InventoryError::general(
                "mount topology changed during measurement",
            ));
        }
        Ok(())
    }
}

fn unavailable(path: &Path, error: impl std::fmt::Display) -> InventoryError {
    InventoryError {
        path: Some(path.to_owned()),
        reason: error.to_string(),
    }
}

fn excluded_ui_tree(path: &Path) -> bool {
    // These are the frontend build account's cache/home and secret store.
    // Neither is an Analyzer dataset or rollback tree.
    path.starts_with("/opt/polaris-ui/.home") || path.starts_with("/opt/polaris-ui/secrets")
}

fn manifest_name(name: &str) -> bool {
    name.starts_with("dataset_manifest") && name.ends_with(".json")
}

fn protect_manifest(value: &Value, names: &mut HashSet<String>) -> Result<(), String> {
    if !value.is_object() {
        return Err("manifest must be an object".into());
    }
    if let Some(shards) = value.get("event_shards") {
        for shard in shards.as_array().ok_or("invalid event_shards")? {
            let path = shard
                .get("path")
                .and_then(Value::as_str)
                .ok_or("invalid shard path")?;
            let name = Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("invalid shard basename")?;
            names.insert(name.into());
        }
    }
    Ok(())
}

fn archive_manifest(
    path: &Path,
    required_members: &[&str],
    names: &mut HashSet<String>,
) -> Result<(), String> {
    let tar = |mode| {
        let mut command = Command::new("/usr/bin/tar");
        command.env_remove("TAR_OPTIONS").arg(mode).arg(path);
        command
    };
    let listing = tar("-tf").output().map_err(|error| error.to_string())?;
    if !listing.status.success() {
        return Err("cannot list compressed backup".into());
    }
    let listing = std::str::from_utf8(&listing.stdout).map_err(|error| error.to_string())?;
    let members: Vec<_> = listing
        .lines()
        .filter(|entry| entry.rsplit('/').next().is_some_and(manifest_name))
        .collect();
    for required in required_members {
        if !members
            .iter()
            .any(|member| member.trim_start_matches("./") == *required)
        {
            return Err(format!("required archive member missing: {required}"));
        }
    }
    let expected = members.len();
    if expected == 0 {
        return Ok(());
    }
    let mut command = tar("-xOf");
    let bodies = command
        .args(["--wildcards", "--no-anchored", "dataset_manifest*.json"])
        .output()
        .map_err(|error| error.to_string())?;
    if !bodies.status.success() {
        return Err("cannot read backup manifests".into());
    }
    let mut count = 0;
    for value in serde_json::Deserializer::from_slice(&bodies.stdout).into_iter::<Value>() {
        let value = value.map_err(|error| error.to_string())?;
        if !required_members.is_empty() && value.get("dataset_id").and_then(Value::as_str).is_none()
        {
            return Err("required archive contains an invalid dataset manifest".into());
        }
        protect_manifest(&value, names)?;
        count += 1;
    }
    if count != expected {
        return Err("backup manifest inventory mismatch".into());
    }
    Ok(())
}

const CONTINUOUS_BACKUP_MEMBER: &str =
    "var/lib/oiran/captures/continuous-lab-import/dataset/dataset_manifest.json";
const LTE_BACKUP_MEMBER: &str =
    "var/lib/oiran/lte-evidence/datasets/dataset-lte-run-09913806240271269bd9d7e0d4d07eb2/dataset_manifest.json";
// The contents of the named rollback sources are part of the safety inventory.
// An empty member list denotes a plain manifest. None denotes a binary/config backup.
type Artifact = (&'static str, &'static [&'static str]);
pub(super) const REQUIRED_BACKUPS: [(&str, Option<Artifact>); 9] = [
    (
        "ANR2_oiran_2.7.26_backup_20261105T224027Z",
        Some((
            "oiran-production-complete.tar.zst",
            &[CONTINUOUS_BACKUP_MEMBER],
        )),
    ),
    (
        "ANR2_oiran_2.7.27_predeploy_backup_20261106T075717Z",
        Some((
            "oiran-production-complete.tar.zst",
            &[CONTINUOUS_BACKUP_MEMBER],
        )),
    ),
    (
        "ANR2_oiran_2.7.28_predeploy_backup_20261106T103354Z",
        Some((
            "oiran-production-complete.tar.zst",
            &[CONTINUOUS_BACKUP_MEMBER],
        )),
    ),
    (
        "ANR2_oiran_2.8.0_predeploy_backup_20261106T115119Z",
        Some((
            "oiran-2.7.28-full.tar.zst",
            &[CONTINUOUS_BACKUP_MEMBER, LTE_BACKUP_MEMBER],
        )),
    ),
    (
        "ANR2_oiran_2.8.1_predeploy_backup_20261106T142802Z",
        Some(("oiran-2.8.0-full.tar.zst", &[CONTINUOUS_BACKUP_MEMBER])),
    ),
    (
        "ANR2_oiran_2.8.2_predeploy_backup_20261106T205304Z",
        Some((
            "dataset-config-unit-watcher.tar.zst",
            &[CONTINUOUS_BACKUP_MEMBER],
        )),
    ),
    (
        "ANR2_oiran_2.8.3_backup_20261107T100830Z",
        Some((
            "data/continuous-lab-import/dataset/dataset_manifest.json",
            &[],
        )),
    ),
    ("ANR2_oiran_2.9.0_backup_20261107T142336Z", None),
    (
        "ANR2_oiran_2.9.0_backup_20261107T142417Z",
        Some((
            "state/continuous-lab-import/dataset/dataset_manifest.json",
            &[],
        )),
    ),
];

type ExpectedArtifacts = BTreeMap<PathBuf, &'static [&'static str]>;

fn roots(
    captures: &Path,
    watch: &InventoryWatch,
) -> Result<(Vec<PathBuf>, ExpectedArtifacts), InventoryError> {
    let (mut roots, backup_root) = if cfg!(test) {
        (vec![captures.to_owned()], captures.join(".gc-backups"))
    } else {
        (
            vec![
                captures.to_owned(),
                "/opt".into(),
                "/var/lib/oiran/releases".into(),
            ],
            PathBuf::from("/root"),
        )
    };
    watch.add_ancestors(&backup_root)?;
    watch.add(&backup_root, true)?;
    let mut identities = HashSet::new();
    let mut expected = BTreeMap::new();
    for (name, artifact) in REQUIRED_BACKUPS {
        let path = backup_root.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|error| unavailable(&path, error))?;
        if !metadata.is_dir() || !identities.insert((metadata.dev(), metadata.ino())) {
            return Err(unavailable(
                &path,
                "required backup must be a distinct directory",
            ));
        }
        if let Some((relative, members)) = artifact {
            expected.insert(path.join(relative), members);
        }
        roots.push(path);
    }
    // Extra backups expand the manifest union without satisfying a required identity.
    for entry in fs::read_dir(&backup_root).map_err(|error| unavailable(&backup_root, error))? {
        let entry = entry.map_err(|error| unavailable(&backup_root, error))?;
        let name = entry.file_name();
        if name.to_str().is_some_and(|name| {
            name.starts_with("ANR2_oiran_")
                && name.contains("_backup_")
                && !REQUIRED_BACKUPS
                    .iter()
                    .any(|(required, _)| *required == name)
        }) {
            roots.push(entry.path());
        }
    }
    Ok((roots, expected))
}

#[cfg(test)]
thread_local! {
    pub(super) static LOCK_PROBE: std::cell::RefCell<Option<(PathBuf, Duration)>> =
        const { std::cell::RefCell::new(None) };
}

fn inventory(
    captures: &Path,
    names: &mut HashSet<String>,
    report: &mut Report,
    watch: &InventoryWatch,
) -> Result<(), InventoryError> {
    #[cfg(test)]
    LOCK_PROBE.with(|probe| {
        if let Some((base, held)) = probe.borrow_mut().as_mut() {
            let locked = super::PublicationLock::try_acquire(base).is_err();
            let started = std::time::Instant::now();
            std::thread::sleep(Duration::from_millis(120));
            if locked {
                assert!(super::PublicationLock::try_acquire(base).is_err());
                *held += started.elapsed();
            }
        }
    });
    let (mut pending, mut expected) = roots(captures, watch)?;
    for root in &pending {
        watch.add_ancestors(root)?;
    }
    let mut seen = HashSet::new();
    while let Some(directory) = pending.pop() {
        if excluded_ui_tree(&directory) {
            continue;
        }
        let physical = directory
            .canonicalize()
            .map_err(|error| unavailable(&directory, error))?;
        if excluded_ui_tree(&physical) {
            continue;
        }
        watch.add(&physical, true)?;
        let metadata = fs::metadata(&directory).map_err(|error| unavailable(&directory, error))?;
        if !metadata.is_dir() {
            return Err(unavailable(&directory, "inventory root is not a directory"));
        }
        if !seen.insert((metadata.dev(), metadata.ino())) {
            continue;
        }
        let mut found_manifest = false;
        for entry in fs::read_dir(&directory).map_err(|error| unavailable(&directory, error))? {
            let entry = entry.map_err(|error| unavailable(&directory, error))?;
            let path = entry.path();
            if excluded_ui_tree(&path) {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|error| unavailable(&path, error))?;
            let required = expected.get(&path).copied();
            if required.is_some() && !kind.is_file() {
                return Err(unavailable(
                    &path,
                    "required backup artifact is not a regular file",
                ));
            }
            if kind.is_dir() {
                pending.push(path);
                continue;
            }
            if kind.is_symlink() {
                // Staging uses symlinks to immutable shards. Preserve their
                // names even when the staging manifest is not committed yet.
                if directory
                    .file_name()
                    .is_some_and(|name| name == "event-shards")
                {
                    if let Some(name) = entry.file_name().to_str() {
                        names.insert(name.into());
                    }
                    if let Ok(target) = path.canonicalize() {
                        if let Some(name) = target.file_name().and_then(|name| name.to_str()) {
                            names.insert(name.into());
                        }
                    }
                    continue;
                }
                match fs::metadata(&path) {
                    Ok(metadata) if metadata.is_dir() => {
                        let physical = path
                            .canonicalize()
                            .map_err(|error| unavailable(&path, error))?;
                        if !excluded_ui_tree(&physical) {
                            watch.add_ancestors(&physical)?;
                            pending.push(path);
                        }
                        continue;
                    }
                    Ok(_)
                        if entry.file_name().to_str().is_some_and(|name| {
                            manifest_name(name) || name.ends_with(".tar.zst")
                        }) =>
                    {
                        let physical = path
                            .canonicalize()
                            .map_err(|error| unavailable(&path, error))?;
                        if excluded_ui_tree(&physical) {
                            return Err(unavailable(
                                &path,
                                "inventory artifact resolves outside Analyzer data trees",
                            ));
                        }
                        watch.add_ancestors(&physical)?;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if !entry
                            .file_name()
                            .to_str()
                            .is_some_and(|name| manifest_name(name) || name.ends_with(".tar.zst"))
                        {
                            continue;
                        }
                    }
                    Err(error) => return Err(unavailable(&path, error)),
                }
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if manifest_name(name) {
                watch.add(&path, false)?;
                let bytes = fs::read(&path).map_err(|error| unavailable(&path, error))?;
                let value: Value =
                    serde_json::from_slice(&bytes).map_err(|error| unavailable(&path, error))?;
                if required.is_some() && value.get("dataset_id").and_then(Value::as_str).is_none() {
                    return Err(unavailable(&path, "required backup manifest is invalid"));
                }
                protect_manifest(&value, names).map_err(|error| unavailable(&path, error))?;
                found_manifest = true;
            } else if name.ends_with(".tar.zst") {
                watch.add(&path, false)?;
                archive_manifest(&path, required.unwrap_or_default(), names)
                    .map_err(|error| unavailable(&path, error))?;
                report.archives_consulted += 1;
            } else if required.is_some() {
                return Err(unavailable(&path, "unknown required backup artifact"));
            }
            if required.is_some() {
                expected.remove(&path);
            }
        }
        report.trees_consulted += usize::from(found_manifest);
    }
    if let Some((path, _)) = expected.first_key_value() {
        return Err(unavailable(&path, "required backup artifact missing"));
    }
    Ok(())
}

pub(super) fn measure(
    captures: &Path,
    current: &Path,
    served: &LiveDataset,
    served_is_current: impl FnOnce() -> bool,
    report: &mut Report,
) -> Result<(usize, u64), InventoryError> {
    let watch = InventoryWatch::new()?;
    let base = current
        .parent()
        .ok_or_else(|| unavailable(current, "dataset has no parent"))?;
    watch.add(base, true)?;
    watch.add(current, true)?;
    let manifest_path = current.join("dataset_manifest.json");
    watch.add(&manifest_path, false)?;
    let bytes = fs::read(&manifest_path).map_err(|error| unavailable(&manifest_path, error))?;
    let active: LiveDataset =
        serde_json::from_slice(&bytes).map_err(|error| unavailable(&manifest_path, error))?;
    if active.callflows_path.is_none()
        || served.callflows_path != active.callflows_path
        || served.event_count != active.event_count
        || served
            .event_shards
            .iter()
            .map(|shard| (&shard.path, &shard.sha256))
            .ne(active
                .event_shards
                .iter()
                .map(|shard| (&shard.path, &shard.sha256)))
        || active.event_shards.is_empty()
    {
        return Err(unavailable(
            &manifest_path,
            "served and disk generations disagree or are not sharded",
        ));
    }
    let shards = current.join("event-shards");
    for path in [current, shards.as_path()] {
        if !fs::symlink_metadata(path)
            .map_err(|error| unavailable(path, error))?
            .is_dir()
        {
            return Err(unavailable(
                path,
                "shard inventory requires a real directory",
            ));
        }
    }
    let mut names = HashSet::new();
    inventory(captures, &mut names, report, &watch)?;

    let (mut count, mut bytes) = (0usize, 0u64);
    for entry in fs::read_dir(&shards).map_err(|error| unavailable(&shards, error))? {
        let entry = entry.map_err(|error| unavailable(&shards, error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("shard-") || !name.ends_with(".jsonl") || names.contains(name) {
            continue;
        }
        let path = entry.path();
        watch.add(&path, false)?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| unavailable(&path, error))?;
        if metadata.is_file() {
            count += 1;
            bytes += metadata.len();
        }
    }
    watch.check_mounts()?;
    if !served_is_current() {
        return Err(unavailable(
            &manifest_path,
            "served generation changed during measurement",
        ));
    }
    watch.unchanged()?;
    Ok((count, bytes))
}
