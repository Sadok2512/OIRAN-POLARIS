//! Read-only inventory of continuous shards and their manifest references.
use super::{commit_seq, LiveDataset, PublicationLock};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::CString,
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

pub(super) const INTERVAL: Duration = Duration::from_secs(30 * 60);
#[derive(Default, serde::Serialize)]
struct ShardUsage {
    count: usize,
    bytes: u64,
}

impl ShardUsage {
    fn add(&mut self, bytes: u64) {
        self.count += 1;
        self.bytes += bytes;
    }
}

pub(super) struct Totals {
    commit_seq: u64,
    publication_lock_held_ns: u64,
    unreferenced: ShardUsage,
    rollback_held: ShardUsage,
    by_backup: BTreeMap<String, ShardUsage>,
    trees_consulted: usize,
    archives_consulted: usize,
    broken_links: usize,
}

pub(super) struct InventoryError {
    path: Option<PathBuf>,
    reason: String,
    commit_seq_change: Option<(u64, u64)>,
}

impl InventoryError {
    pub(super) fn general(reason: impl Into<String>) -> Self {
        Self {
            path: None,
            reason: reason.into(),
            commit_seq_change: None,
        }
    }
}

pub(super) fn snapshot(result: Result<&Totals, &InventoryError>) -> Value {
    let (totals, error) = match result {
        Ok(totals) => (Some(totals), None),
        Err(error) => (
            None,
            Some(json!({
                "path": error.path.as_deref().map(Path::to_string_lossy),
                "reason": error.reason,
                "commit_seq_before": error.commit_seq_change.map(|(before, _)| before),
                "commit_seq_after": error.commit_seq_change.map(|(_, after)| after),
            })),
        ),
    };
    json!({
        "status": if totals.is_some() { "available" } else { "unavailable" },
        "count": totals.map(|totals| totals.unreferenced.count),
        "bytes": totals.map(|totals| totals.unreferenced.bytes),
        "unreferenced": totals.map(|totals| json!({
            "count": totals.unreferenced.count,
            "bytes": totals.unreferenced.bytes,
            "commit_seq": totals.commit_seq,
        })),
        "rollback_held": totals.map(|totals| json!({
            "count": totals.rollback_held.count,
            "bytes": totals.rollback_held.bytes,
            "by_backup": totals.by_backup,
            "commit_seq": totals.commit_seq,
        })),
        "trees_consulted": totals.map(|totals| totals.trees_consulted),
        "archives_consulted": totals.map(|totals| totals.archives_consulted),
        "broken_links": totals.map(|totals| totals.broken_links),
        "commit_seq": totals.map(|totals| totals.commit_seq),
        "publication_lock_held_ns": totals.map(|totals| totals.publication_lock_held_ns),
        "error": error,
    })
}

#[cfg(test)]
#[test]
fn shard_inventory_serializes_errors_for_non_utf8_paths() {
    let path = Path::new(std::ffi::OsStr::from_bytes(b"/inventory/invalid-\xff"));
    let error = unavailable(path, "read failed");
    let published = snapshot(Err(&error));
    assert_eq!(published["status"], "unavailable");
    assert_eq!(published["error"]["path"], path.to_string_lossy().as_ref());
    assert!(published["count"].is_null());
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FailurePoint {
    ActiveManifest,
    BackupRoots,
    Directory,
    Link,
    Manifest,
    Archive,
    Shard,
    Finish,
}

#[cfg(test)]
thread_local! {
    pub(super) static FAIL_AT: std::cell::Cell<Option<FailurePoint>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn inject_failure(point: FailurePoint, path: &Path) -> Result<(), InventoryError> {
    if FAIL_AT.with(|setting| setting.get()) == Some(point) {
        return Err(unavailable(
            path,
            format!("injected read failure at {point:?}"),
        ));
    }
    Ok(())
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

    fn add(&self, path: &Path) -> Result<(), InventoryError> {
        let name =
            CString::new(path.as_os_str().as_bytes()).map_err(|error| unavailable(path, error))?;
        let changes = libc::IN_ATTRIB
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_UNMOUNT
            | libc::IN_MODIFY
            | libc::IN_CLOSE_WRITE;
        if unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), name.as_ptr(), changes) } < 0 {
            return Err(unavailable(path, std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn unchanged(&self, path: &Path) -> Result<(), InventoryError> {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        match unsafe { libc::poll(&mut poll, 1, 0) } {
            0 => Ok(()),
            1 => Err(unavailable(
                path,
                "served manifest or commit marker changed without advancing commit_seq",
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
        commit_seq_change: None,
    }
}

const DEPLOYMENT_BACKUPS: &str = "/var/lib/oiran/deployment-backups";
const RELEASES: &str = "/var/lib/oiran/releases";

fn deployment_backups(captures: &Path) -> PathBuf {
    if cfg!(test) {
        captures.join(".deployment-backups")
    } else {
        DEPLOYMENT_BACKUPS.into()
    }
}

fn backup_name(path: &Path, deployments: &Path) -> Option<String> {
    for root in [deployments, Path::new(RELEASES)] {
        if let Ok(relative) = path.strip_prefix(root) {
            return relative
                .components()
                .next()?
                .as_os_str()
                .to_str()
                .map(str::to_owned);
        }
    }
    path.components()
        .filter_map(|component| component.as_os_str().to_str())
        .find(|name| {
            name.starts_with(".dataset-rollback")
                || name.starts_with(".dataset-previous")
                || (name.starts_with("ANR2_oiran_") && name.contains("_backup_"))
        })
        .map(str::to_owned)
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

fn roots(captures: &Path) -> Result<(Vec<PathBuf>, ExpectedArtifacts), InventoryError> {
    let (mut roots, backup_root) = if cfg!(test) {
        (vec![captures.to_owned()], captures.join(".gc-backups"))
    } else {
        (
            vec![
                captures.to_owned(),
                "/opt".into(),
                RELEASES.into(),
                deployment_backups(captures),
            ],
            PathBuf::from("/root"),
        )
    };
    #[cfg(test)]
    inject_failure(FailurePoint::BackupRoots, &backup_root)?;
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

#[derive(Default)]
struct References {
    names: HashSet<String>,
    rollback_by_shard: BTreeMap<String, BTreeSet<String>>,
    trees_consulted: usize,
    archives_consulted: usize,
    broken_links: usize,
}

impl References {
    fn add(&mut self, names: HashSet<String>, backup: Option<&str>) {
        if let Some(backup) = backup {
            for name in names {
                self.rollback_by_shard
                    .entry(name)
                    .or_default()
                    .insert(backup.to_owned());
            }
        } else {
            self.names.extend(names);
        }
    }
}

fn inventory(
    captures: &Path,
    active_shards: &Path,
    current: &Path,
    population: &[PathBuf],
) -> Result<References, InventoryError> {
    let active_manifest = current.join("dataset_manifest.json");
    let deployments = deployment_backups(captures);
    let mut references = References::default();
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
    let (roots, mut expected) = roots(captures)?;
    let mut pending: Vec<_> = roots.into_iter().map(|path| (path, Vec::new())).collect();
    let mut seen = HashSet::new();
    while let Some((directory, mut ancestors)) = pending.pop() {
        let physical = directory
            .canonicalize()
            .map_err(|error| unavailable(&directory, error))?;
        let metadata = fs::metadata(&directory).map_err(|error| unavailable(&directory, error))?;
        if !metadata.is_dir() {
            return Err(unavailable(&directory, "inventory root is not a directory"));
        }
        let identity = (metadata.dev(), metadata.ino());
        if ancestors.contains(&identity) {
            return Err(unavailable(&directory, "inventory directory symlink loop"));
        }
        if !seen.insert((identity, backup_name(&directory, &deployments))) {
            continue;
        }
        ancestors.push(identity);
        #[cfg(test)]
        inject_failure(FailurePoint::Directory, &directory)?;
        let mut found_manifest = false;
        let paths = if physical == active_shards {
            population.to_vec()
        } else {
            fs::read_dir(&directory)
                .map_err(|error| unavailable(&directory, error))?
                .map(|entry| {
                    entry
                        .map(|entry| entry.path())
                        .map_err(|error| unavailable(&directory, error))
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        for path in paths {
            if path == active_manifest {
                found_manifest = true;
                continue;
            }
            let kind = fs::symlink_metadata(&path)
                .map_err(|error| unavailable(&path, error))?
                .file_type();
            let required = expected.get(&path).copied();
            if required.is_some() && !kind.is_file() {
                return Err(unavailable(
                    &path,
                    "required backup artifact is not a regular file",
                ));
            }
            if kind.is_dir() {
                pending.push((path, ancestors.clone()));
                continue;
            }
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| unavailable(&path, "inventory entry has a non-UTF-8 name"))?;
            if kind.is_symlink() {
                #[cfg(test)]
                inject_failure(FailurePoint::Link, &path)?;
                let physical = match path.canonicalize() {
                    Ok(target) => target,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        references.broken_links += 1;
                        continue;
                    }
                    Err(error) => return Err(unavailable(&path, error)),
                };
                if directory
                    .file_name()
                    .is_some_and(|name| name == "event-shards")
                {
                    // Both the alias and the resolved shard name are references.
                    let target = physical
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| unavailable(&path, "invalid shard link target name"))?;
                    references.names.extend([name.into(), target.into()]);
                    continue;
                }
                let target = fs::metadata(&physical).map_err(|error| unavailable(&path, error))?;
                if target.is_dir() {
                    pending.push((path, ancestors.clone()));
                    continue;
                }
            }
            if manifest_name(name) {
                #[cfg(test)]
                inject_failure(FailurePoint::Manifest, &path)?;
                let bytes = fs::read(&path).map_err(|error| unavailable(&path, error))?;
                let value: Value =
                    serde_json::from_slice(&bytes).map_err(|error| unavailable(&path, error))?;
                if required.is_some() && value.get("dataset_id").and_then(Value::as_str).is_none() {
                    return Err(unavailable(&path, "required backup manifest is invalid"));
                }
                let mut names = HashSet::new();
                protect_manifest(&value, &mut names).map_err(|error| unavailable(&path, error))?;
                references.add(names, backup_name(&path, &deployments).as_deref());
                found_manifest = true;
            } else if name.ends_with(".tar.zst") {
                #[cfg(test)]
                inject_failure(FailurePoint::Archive, &path)?;
                let mut names = HashSet::new();
                archive_manifest(&path, required.unwrap_or_default(), &mut names)
                    .map_err(|error| unavailable(&path, error))?;
                references.add(names, backup_name(&path, &deployments).as_deref());
                references.archives_consulted += 1;
            } else if required.is_some() {
                return Err(unavailable(&path, "unknown required backup artifact"));
            }
            if required.is_some() {
                expected.remove(&path);
            }
        }
        references.trees_consulted += usize::from(found_manifest);
    }
    if let Some((path, _)) = expected.first_key_value() {
        return Err(unavailable(&path, "required backup artifact missing"));
    }
    Ok(references)
}

fn read_sequence(path: &Path) -> Result<u64, InventoryError> {
    let text = fs::read_to_string(path).map_err(|error| unavailable(path, error))?;
    text.trim()
        .parse()
        .map_err(|error| unavailable(path, error))
}

fn same_manifest(served: &LiveDataset, active: &LiveDataset) -> bool {
    active.callflows_path.is_some()
        && served.callflows_path == active.callflows_path
        && served.event_count == active.event_count
        && !active.event_shards.is_empty()
        && served
            .event_shards
            .iter()
            .map(|shard| (&shard.path, &shard.sha256))
            .eq(active
                .event_shards
                .iter()
                .map(|shard| (&shard.path, &shard.sha256)))
}

fn shard_population(current: &Path) -> Result<Vec<PathBuf>, InventoryError> {
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
    fs::read_dir(&shards)
        .map_err(|error| unavailable(&shards, error))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| unavailable(&shards, error))
        })
        .collect()
}

pub(super) fn measure(
    captures: &Path,
    current: &Path,
    served: impl Fn() -> Option<LiveDataset>,
) -> Result<Totals, InventoryError> {
    let base = current
        .parent()
        .ok_or_else(|| unavailable(current, "dataset has no parent"))?;
    let manifest_path = current.join("dataset_manifest.json");
    let sequence_path = current.join(commit_seq::COMMIT_SEQ_FILENAME);
    let mut publication_lock_held_ns = 0u64;
    for retry in [false, true] {
        let watch = InventoryWatch::new()?;
        // Freeze membership against the collector. Stat, archive and manifest
        // traversal stay outside the lock. No directory events are subscribed to.
        let (commit_seq, population) = {
            let lock = PublicationLock::acquire_blocking(base)
                .map_err(|error| unavailable(base, error))?;
            let started = Instant::now();
            let commit_seq = read_sequence(&sequence_path)?;
            watch.add(&manifest_path)?;
            watch.add(&sequence_path)?;
            let population = shard_population(current)?;
            drop(lock);
            publication_lock_held_ns += started.elapsed().as_nanos() as u64;
            (commit_seq, population)
        };

        let scanned = (|| {
            #[cfg(test)]
            inject_failure(FailurePoint::ActiveManifest, &manifest_path)?;
            let manifest: Value = serde_json::from_slice(
                &fs::read(&manifest_path).map_err(|error| unavailable(&manifest_path, error))?,
            )
            .map_err(|error| unavailable(&manifest_path, error))?;
            let mut names = HashSet::new();
            protect_manifest(&manifest, &mut names)
                .map_err(|error| unavailable(&manifest_path, error))?;
            let active: LiveDataset = serde_json::from_value(manifest)
                .map_err(|error| unavailable(&manifest_path, error))?;
            if !served()
                .as_ref()
                .is_some_and(|published| same_manifest(published, &active))
            {
                return Err(unavailable(
                    &manifest_path,
                    "served and disk generations disagree or are not sharded",
                ));
            }
            let shards = current.join("event-shards");
            let physical_shards = shards
                .canonicalize()
                .map_err(|error| unavailable(&shards, error))?;
            let references = inventory(captures, &physical_shards, current, &population)?;
            #[cfg(test)]
            AFTER_TRAVERSAL.with(|hook| {
                if let Some(hook) = hook.borrow_mut().as_mut() {
                    hook(current);
                }
            });
            let mut unreferenced = ShardUsage::default();
            let mut rollback_held = ShardUsage::default();
            let mut by_backup = BTreeMap::<String, ShardUsage>::new();
            for path in population {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| unavailable(&path, "shard entry has a non-UTF-8 name"))?;
                if !name.starts_with("shard-") || !name.ends_with(".jsonl") || names.contains(name)
                {
                    continue;
                }
                #[cfg(test)]
                inject_failure(FailurePoint::Shard, &path)?;
                let metadata =
                    fs::symlink_metadata(&path).map_err(|error| unavailable(&path, error))?;
                if !metadata.is_file() {
                    continue;
                }
                if let Some(backups) = references.rollback_by_shard.get(name) {
                    rollback_held.add(metadata.len());
                    for backup in backups {
                        by_backup
                            .entry(backup.clone())
                            .or_default()
                            .add(metadata.len());
                    }
                } else if !references.names.contains(name) {
                    unreferenced.add(metadata.len());
                }
            }
            #[cfg(test)]
            inject_failure(FailurePoint::Finish, current)?;
            watch.check_mounts()?;
            Ok((active, unreferenced, rollback_held, by_backup, references))
        })();
        let watch_result = watch.unchanged(&manifest_path);
        let latest_seq = read_sequence(&sequence_path)?;
        if latest_seq != commit_seq {
            if retry {
                let mut error = unavailable(
                    &sequence_path,
                    "commit_seq changed during both inventory attempts",
                );
                error.commit_seq_change = Some((commit_seq, latest_seq));
                return Err(error);
            }
            continue;
        }
        let (active, unreferenced, rollback_held, by_backup, references) = scanned?;
        if !served()
            .as_ref()
            .is_some_and(|latest| same_manifest(latest, &active))
        {
            return Err(unavailable(
                &manifest_path,
                "served generation changed during measurement",
            ));
        }
        watch_result?;
        return Ok(Totals {
            commit_seq,
            publication_lock_held_ns,
            unreferenced,
            rollback_held,
            by_backup,
            trees_consulted: references.trees_consulted,
            archives_consulted: references.archives_consulted,
            broken_links: references.broken_links,
        });
    }
    unreachable!("inventory returns on its second attempt")
}

#[cfg(test)]
type TraversalHook = Box<dyn FnMut(&Path)>;

#[cfg(test)]
thread_local! {
    pub(super) static AFTER_TRAVERSAL: std::cell::RefCell<Option<TraversalHook>> =
        const { std::cell::RefCell::new(None) };
}
