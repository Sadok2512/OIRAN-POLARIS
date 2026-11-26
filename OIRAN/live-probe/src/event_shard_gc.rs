//! Continuous event shards are reclaimed only when the manifest inventory and
//! independent evidence for the contents both permit it.
use super::{sha256_hex, sha256_hex_file, LiveDataset};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    ffi::CString,
    fs,
    io::{BufRead, BufReader},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime},
};

pub(super) const INTERVAL: Duration = Duration::from_secs(30 * 60);
const GRACE: Duration = Duration::from_secs(60 * 60);
const SAFETY_BAND: usize = 2;
const MAX_CANDIDATES: usize = 8;
const LOCK_BUDGET: Duration = Duration::from_millis(50);
const MAX_EVENT_HASHES: usize = 1_000_000;

#[derive(Default)]
pub(super) struct Report {
    pub count: usize,
    pub bytes: u64,
    pub kept: usize,
    pub trees_consulted: usize,
    pub archives_consulted: usize,
    pub directories_read: usize,
    pub candidate_stats: usize,
    pub history_unproven: usize,
    pub lock_held: Duration,
}

// The watch is armed before reading inputs. Any pending notification, including
// queue overflow or invalidation, discards the plan; no event is drained.
struct InventoryWatch {
    fd: OwnedFd,
    mounts: Vec<u8>,
}

impl InventoryWatch {
    fn new() -> Result<Self, String> {
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mounts = fs::read("/proc/self/mountinfo").map_err(|error| error.to_string())?;
        Ok(Self { fd, mounts })
    }

    fn add(&self, path: &Path, directory: bool) -> Result<(), String> {
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

    fn add_mask(&self, path: &Path, changes: u32) -> Result<(), String> {
        let name = CString::new(path.as_os_str().as_bytes())
            .map_err(|error| format!("watch {}: {error}", path.display()))?;
        let common = libc::IN_ATTRIB
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_UNMOUNT
            | libc::IN_MASK_ADD;
        if unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), name.as_ptr(), common | changes) }
            < 0
        {
            return Err(format!(
                "watch {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn add_ancestors(&self, path: &Path) -> Result<(), String> {
        for directory in path.ancestors().skip(1) {
            self.add_mask(directory, libc::IN_ONLYDIR)?;
        }
        Ok(())
    }

    fn unchanged(&self) -> Result<(), String> {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        match unsafe { libc::poll(&mut poll, 1, 0) } {
            0 => Ok(()),
            1 => Err("shard inventory changed; sweep deferred".into()),
            _ => Err(std::io::Error::last_os_error().to_string()),
        }
    }

    fn check_mounts(&self) -> Result<(), String> {
        if fs::read("/proc/self/mountinfo").map_err(|error| error.to_string())? != self.mounts {
            return Err("mount topology changed; sweep deferred".into());
        }
        Ok(())
    }
}

fn unavailable(path: &Path, error: std::io::Error) -> String {
    format!("{}: {error}", path.display())
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
) -> Result<(Vec<PathBuf>, ExpectedArtifacts), String> {
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
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("required backup {name} unavailable: {error}"))?;
        if !metadata.is_dir() || !identities.insert((metadata.dev(), metadata.ino())) {
            return Err(format!(
                "required backup {name} must be a distinct directory"
            ));
        }
        if let Some((relative, members)) = artifact {
            expected.insert(path.join(relative), members);
        }
        roots.push(path);
    }
    // Extra backups expand the manifest union without satisfying a required identity.
    for entry in fs::read_dir(&backup_root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
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
) -> Result<(), String> {
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
            return Err("inventory root is not a directory".into());
        }
        if !seen.insert((metadata.dev(), metadata.ino())) {
            continue;
        }
        report.directories_read += 1;
        let mut found_manifest = false;
        for entry in fs::read_dir(&directory).map_err(|error| unavailable(&directory, error))? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            if excluded_ui_tree(&path) {
                continue;
            }
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            let required = expected.get(&path).copied();
            if required.is_some() && !kind.is_file() {
                return Err(format!(
                    "required backup artifact is not a regular file: {}",
                    path.display()
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
                    let target = path
                        .canonicalize()
                        .map_err(|error| unavailable(&path, error))?;
                    if let Some(name) = target.file_name().and_then(|name| name.to_str()) {
                        names.insert(name.into());
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
                            return Err(format!(
                                "inventory artifact resolves outside Analyzer data trees: {}",
                                path.display()
                            ));
                        }
                        watch.add_ancestors(&physical)?;
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        if !entry.file_name().to_str().is_some_and(manifest_name) {
                            continue;
                        }
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if manifest_name(name) {
                watch.add(&path, false)?;
                let bytes = fs::read(&path).map_err(|error| unavailable(&path, error))?;
                let value: Value =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                if required.is_some() && value.get("dataset_id").and_then(Value::as_str).is_none() {
                    return Err(format!(
                        "required backup manifest is invalid: {}",
                        path.display()
                    ));
                }
                protect_manifest(&value, names)?;
                found_manifest = true;
            } else if name.ends_with(".tar.zst") {
                watch.add(&path, false)?;
                archive_manifest(&path, required.unwrap_or_default(), names)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                report.archives_consulted += 1;
            } else if required.is_some() {
                return Err(format!(
                    "unknown required backup artifact: {}",
                    path.display()
                ));
            }
            if required.is_some() {
                expected.remove(&path);
            }
        }
        report.trees_consulted += usize::from(found_manifest);
    }
    if let Some((path, _)) = expected.first_key_value() {
        return Err(format!(
            "required backup artifact missing: {}",
            path.display()
        ));
    }
    Ok(())
}

fn visit_event_lines(path: &Path, mut visit: impl FnMut(&str) -> bool) -> Result<(), String> {
    let reader = BufReader::new(fs::File::open(path).map_err(|error| error.to_string())?);
    for line in reader.lines() {
        let line = line.map_err(|error| error.to_string())?;
        if !line.trim().is_empty() && !visit(&line) {
            break;
        }
    }
    Ok(())
}

fn history_is_preserved(
    candidate: &Path,
    current: &Path,
    active: &LiveDataset,
    watch: &InventoryWatch,
) -> Result<bool, String> {
    watch.add(candidate, false)?;
    let mut remaining = HashSet::new();
    let mut valid = true;
    visit_event_lines(candidate, |line| {
        valid = remaining.len() < MAX_EVENT_HASHES
            && serde_json::from_str::<Value>(line)
                .ok()
                .is_some_and(|event| event.get("event_id").and_then(Value::as_str).is_some())
            && remaining.insert(sha256_hex(line.as_bytes()));
        valid
    })?;
    if !valid || remaining.is_empty() {
        return Ok(false);
    }
    let mut match_file = |path: &Path, sha: &str| -> Result<bool, String> {
        watch.add(path, false)?;
        if sha256_hex_file(path)? != sha {
            return Err("history source checksum mismatch".into());
        }
        visit_event_lines(path, |line| {
            remaining.remove(&sha256_hex(line.as_bytes()));
            !remaining.is_empty()
        })?;
        Ok(remaining.is_empty())
    };
    for shard in &active.event_shards {
        let mut components = Path::new(&shard.path).components();
        use std::path::Component::Normal;
        match (components.next(), components.next(), components.next()) {
            (Some(Normal(name)), None, None) if name == "oiran_events.jsonl" => {}
            (Some(Normal(directory)), Some(Normal(_)), None) if directory == "event-shards" => {}
            _ => return Err("active shard path escapes its dataset".into()),
        }
        let path = current.join(&shard.path);
        if !fs::symlink_metadata(&path)
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("active shard must be a regular file".into());
        }
        if match_file(&path, &shard.sha256)? {
            return Ok(true);
        }
    }
    let archive_root = current.with_file_name("archive");
    let archives = match fs::read_dir(archive_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.to_string()),
    };
    for entry in archives {
        let entry = entry.map_err(|error| error.to_string())?;
        if !entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            continue;
        }
        let directory = entry.path();
        watch.add(&directory.join("manifest.json"), false)?;
        let manifest: Value = serde_json::from_slice(
            &fs::read(directory.join("manifest.json")).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let sha = manifest
            .get("events_sha256")
            .and_then(Value::as_str)
            .ok_or("archive checksum absent")?;
        if match_file(&directory.join("events.jsonl"), sha)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn identity(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

// Prepare with no publication lock. Refuse when the served or on-disk
// generation changes before the bounded commit section.
pub(super) fn sweep(
    captures: &Path,
    current: &Path,
    served: &LiveDataset,
    served_is_current: impl FnOnce() -> bool,
    report: &mut Report,
) -> Result<(), String> {
    let watch = InventoryWatch::new()?;
    let base = current.parent().ok_or("continuous dataset has no parent")?;
    watch.add(base, true)?;
    watch.add(current, true)?;
    let manifest_path = current.join("dataset_manifest.json");
    watch.add(&manifest_path, false)?;
    let active_bytes = fs::read(&manifest_path).map_err(|error| error.to_string())?;
    let active: LiveDataset =
        serde_json::from_slice(&active_bytes).map_err(|error| error.to_string())?;
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
        return Err("served and disk generations disagree or are not sharded".into());
    }
    let manifest = fs::metadata(&manifest_path).map_err(|error| error.to_string())?;
    let shards = current.join("event-shards");
    if !fs::symlink_metadata(current)
        .map_err(|error| error.to_string())?
        .is_dir()
        || !fs::symlink_metadata(&shards)
            .map_err(|error| error.to_string())?
            .is_dir()
    {
        return Err("dataset and shard paths must be real directories".into());
    }
    let mut names = HashSet::new();
    inventory(captures, &mut names, report, &watch)?;
    if report.trees_consulted == 0 {
        return Err("no manifest tree was consulted".into());
    }

    let mut orphans = Vec::new();
    report.directories_read += 1;
    for entry in fs::read_dir(shards).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("shard-") || !name.ends_with(".jsonl") {
            continue;
        }
        report.kept += 1;
        if names.contains(name) {
            continue;
        }
        report.candidate_stats += 1;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| error.to_string())?;
        if metadata.is_file() {
            let modified = metadata.modified().map_err(|error| error.to_string())?;
            orphans.push((modified, entry.path(), metadata));
        }
    }
    orphans.sort_by(|left, right| right.0.cmp(&left.0).then(right.1.cmp(&left.1)));
    let now = SystemTime::now();
    let mut confirmed = Vec::new();
    let eligible = orphans
        .into_iter()
        .skip(SAFETY_BAND)
        .filter(|(modified, _, metadata)| {
            (metadata.ctime(), metadata.ctime_nsec()) < (manifest.ctime(), manifest.ctime_nsec())
                && now.duration_since(*modified).unwrap_or_default() >= GRACE
        });
    for (_, path, metadata) in eligible.take(MAX_CANDIDATES) {
        if history_is_preserved(&path, current, &active, &watch)? {
            confirmed.push((path, metadata));
        } else {
            report.history_unproven += 1;
        }
    }
    if confirmed.is_empty() {
        return Ok(());
    }
    // Backups can be prepared independently of the publisher. Refresh the
    // entire union after the potentially long content proof.
    inventory(captures, &mut names, report, &watch)?;
    watch.unchanged()?;
    let lock = super::PublicationLock::try_acquire(base)?;
    let started = Instant::now();
    let result = (|| {
        watch.check_mounts()?;
        if !served_is_current()
            || identity(
                &fs::symlink_metadata(&manifest_path)
                    .map_err(|error| unavailable(&manifest_path, error))?,
            ) != identity(&manifest)
        {
            return Err("active or served generation changed during sweep".into());
        }
        watch.unchanged()?;
        // Validate the entire deletion batch first. Unlink generates its own
        // inotify events, so validate again just before the first unlink.
        let mut remove = Vec::new();
        for (path, before) in confirmed {
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| names.contains(name))
            {
                continue;
            }
            report.candidate_stats += 1;
            let after = fs::symlink_metadata(&path).map_err(|error| unavailable(&path, error))?;
            if after.is_file() && identity(&before) == identity(&after) {
                remove.push((path, after.len()));
            }
        }
        watch.unchanged()?;
        if started.elapsed() >= LOCK_BUDGET {
            return Err("publication lock budget exceeded before unlink".into());
        }
        // One unlink per fresh inventory keeps the checked batch and its
        // notification boundary indivisible from the publisher's perspective.
        if let Some((path, bytes)) = remove.into_iter().next() {
            fs::remove_file(&path).map_err(|error| unavailable(&path, error))?;
            report.count += 1;
            report.bytes += bytes;
            report.kept -= 1;
        }
        Ok(())
    })();
    drop(lock);
    report.lock_held = started.elapsed();
    #[cfg(test)]
    LOCK_PROBE.with(|probe| {
        if let Some((_, held)) = probe.borrow_mut().as_mut() {
            *held += report.lock_held;
        }
    });
    result
}
