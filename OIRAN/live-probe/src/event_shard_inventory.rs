//! Read-only inventory of continuous shards and their manifest references.
use super::{commit_seq, LiveDataset, PublicationLock};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::CString,
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
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
    rollback_error: Option<InventoryError>,
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
            "status": if totals.rollback_error.is_some() { "unavailable" } else { "available" },
            "count": totals.rollback_error.is_none().then_some(totals.rollback_held.count),
            "bytes": totals.rollback_error.is_none().then_some(totals.rollback_held.bytes),
            "by_backup": totals.rollback_error.is_none().then_some(&totals.by_backup),
            "error": totals.rollback_error.as_ref().map(|error| json!({
                "path": error.path.as_deref().map(Path::to_string_lossy),
                "reason": error.reason,
            })),
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
    Link,
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

/// One immutable rollback manifest and its configured protection declaration.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackTarget {
    name: String,
    manifest: PathBuf,
    shards: BTreeSet<String>,
}

#[cfg(not(test))]
const ALLOWLIST_ENV: &str = "OIRAN_ROLLBACK_ALLOWLIST";

#[cfg(test)]
thread_local! {
    pub(super) static TEST_ALLOWLIST: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
    pub(super) static LOCK_PROBE: std::cell::RefCell<Option<(PathBuf, Duration)>> =
        const { std::cell::RefCell::new(None) };
}

fn rollback_targets() -> Result<Vec<RollbackTarget>, InventoryError> {
    #[cfg(test)]
    let path = match TEST_ALLOWLIST.with(|path| path.borrow().clone()) {
        Some(path) => path,
        None => return Ok(Vec::new()),
    };
    #[cfg(not(test))]
    let path = std::env::var_os(ALLOWLIST_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| InventoryError::general(format!("{ALLOWLIST_ENV} is required")))?;
    if !path.is_absolute() {
        return Err(unavailable(
            &path,
            "OIRAN_ROLLBACK_ALLOWLIST must name an absolute path",
        ));
    }
    let targets: Vec<RollbackTarget> =
        serde_json::from_slice(&fs::read(&path).map_err(|error| unavailable(&path, error))?)
            .map_err(|error| unavailable(&path, error))?;
    let mut names = HashSet::new();
    let mut manifests = HashSet::new();
    for target in &targets {
        let manifest_name = target.manifest.file_name().and_then(|name| name.to_str());
        if target.name.trim().is_empty()
            || !names.insert(&target.name)
            || !manifests.insert(&target.manifest)
            || !target.manifest.is_absolute()
            || !manifest_name
                .is_some_and(|name| name.starts_with("dataset_manifest") && name.ends_with(".json"))
            || target
                .shards
                .iter()
                .any(|name| Path::new(name).file_name().and_then(|v| v.to_str()) != Some(name))
        {
            return Err(unavailable(
                &path,
                "invalid or duplicate authorized rollback target",
            ));
        }
    }
    Ok(targets)
}

enum ReferenceCheckError {
    Read(InventoryError),
    Invalid(InventoryError),
}

fn checked_references(target: &RollbackTarget) -> Result<(), ReferenceCheckError> {
    let path = &target.manifest;
    let bytes =
        fs::read(path).map_err(|error| ReferenceCheckError::Read(unavailable(path, error)))?;
    let value = serde_json::from_slice(&bytes).map_err(|error| {
        ReferenceCheckError::Invalid(unavailable(
            path,
            format!("invalid rollback manifest JSON: {error}"),
        ))
    })?;
    let mut names = HashSet::new();
    protect_manifest(&value, &mut names)
        .map_err(|error| ReferenceCheckError::Invalid(unavailable(path, error)))?;
    if names.len() != target.shards.len() || !target.shards.iter().all(|name| names.contains(name))
    {
        return Err(ReferenceCheckError::Invalid(unavailable(
            path,
            "rollback manifest disagrees with authorized shard declaration",
        )));
    }
    Ok(())
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
            #[cfg(test)]
            LOCK_PROBE.with(|probe| {
                if let Some((base, held)) = probe.borrow_mut().as_mut() {
                    let started = Instant::now();
                    if PublicationLock::try_acquire(base).is_err() {
                        *held += started.elapsed() + Duration::from_nanos(1);
                    }
                }
            });
            let targets = rollback_targets()?;
            let mut rollback_error = None;
            let mut trees_consulted = 1;
            let mut rollback_by_shard = BTreeMap::<_, BTreeSet<_>>::new();
            for target in &targets {
                match checked_references(target) {
                    Ok(()) => trees_consulted += 1,
                    Err(ReferenceCheckError::Read(error)) => {
                        rollback_error.get_or_insert(error);
                    }
                    Err(ReferenceCheckError::Invalid(error)) => return Err(error),
                }
                for name in &target.shards {
                    rollback_by_shard
                        .entry(name.as_str())
                        .or_default()
                        .insert(&target.name);
                }
            }
            #[cfg(test)]
            AFTER_TRAVERSAL.with(|hook| {
                if let Some(hook) = hook.borrow_mut().as_mut() {
                    hook(current);
                }
            });
            let mut unreferenced = ShardUsage::default();
            let mut rollback_held = ShardUsage::default();
            let mut by_backup = BTreeMap::<String, ShardUsage>::new();
            let mut broken_links = 0;
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
                if metadata.is_symlink() {
                    #[cfg(test)]
                    inject_failure(FailurePoint::Link, &path)?;
                    match path.canonicalize() {
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            broken_links += 1
                        }
                        Err(error) => return Err(unavailable(&path, error)),
                    }
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }
                if let Some(backups) = rollback_by_shard.get(name) {
                    rollback_held.add(metadata.len());
                    for backup in backups {
                        by_backup
                            .entry((*backup).clone())
                            .or_default()
                            .add(metadata.len());
                    }
                } else {
                    unreferenced.add(metadata.len());
                }
            }
            #[cfg(test)]
            inject_failure(FailurePoint::Finish, current)?;
            watch.check_mounts()?;
            Ok((
                active,
                unreferenced,
                rollback_held,
                by_backup,
                rollback_error,
                trees_consulted,
                broken_links,
            ))
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
        let (
            active,
            unreferenced,
            rollback_held,
            by_backup,
            rollback_error,
            trees_consulted,
            broken_links,
        ) = scanned?;
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
            rollback_error,
            trees_consulted,
            archives_consulted: 0,
            broken_links,
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
