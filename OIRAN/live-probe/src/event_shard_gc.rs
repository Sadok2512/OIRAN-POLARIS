//! Continuous event shards are reclaimed only when the manifest inventory and
//! independent evidence for the contents both permit it.
use super::{sha256_hex, sha256_hex_file, LiveDataset};
use serde_json::Value;
use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime},
};

pub(super) const INTERVAL: Duration = Duration::from_secs(30 * 60);
const GRACE: Duration = Duration::from_secs(60 * 60);
const SAFETY_BAND: usize = 2;
const MAX_CANDIDATES: usize = 8;
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

fn archive_manifest(path: &Path, names: &mut HashSet<String>) -> Result<(), String> {
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
    let expected = listing
        .lines()
        .filter(|entry| entry.rsplit('/').next().is_some_and(manifest_name))
        .count();
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
        protect_manifest(&value.map_err(|error| error.to_string())?, names)?;
        count += 1;
    }
    if count != expected {
        return Err("backup manifest inventory mismatch".into());
    }
    Ok(())
}

fn roots(captures: &Path) -> Result<Vec<PathBuf>, String> {
    if cfg!(test) {
        return Ok(vec![captures.to_owned()]);
    }
    let mut roots = vec![
        captures.to_owned(),
        "/opt".into(),
        "/var/lib/oiran/releases".into(),
    ];
    let mut backups = Vec::new();
    for entry in fs::read_dir("/root").map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("ANR2_oiran_") && name.contains("_backup_"))
        {
            backups.push(entry.path());
        }
    }
    if backups.len() < 9 {
        return Err("backup inventory incomplete".into());
    }
    roots.extend(backups);
    Ok(roots)
}

fn inventory(
    captures: &Path,
    names: &mut HashSet<String>,
    report: &mut Report,
) -> Result<(), String> {
    let mut pending = roots(captures)?;
    let mut seen = HashSet::new();
    while let Some(directory) = pending.pop() {
        let metadata = fs::metadata(&directory).map_err(|error| error.to_string())?;
        if !metadata.is_dir() {
            return Err("inventory root is not a directory".into());
        }
        if !seen.insert((metadata.dev(), metadata.ino())) {
            continue;
        }
        report.directories_read += 1;
        let mut found_manifest = false;
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|error| error.to_string())?;
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
                        pending.push(path);
                        continue;
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
                let bytes = fs::read(&path).map_err(|error| error.to_string())?;
                let value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                protect_manifest(&value, names)?;
                found_manifest = true;
            } else if name.ends_with(".tar.zst") {
                archive_manifest(&path, names)?;
                report.archives_consulted += 1;
            }
        }
        report.trees_consulted += usize::from(found_manifest);
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
) -> Result<bool, String> {
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

// Called with the publication lock held. In a disagreement between RAM and
// disk, keep every shard, including ones from the next on-disk generation.
pub(super) fn sweep(
    captures: &Path,
    current: &Path,
    served: &LiveDataset,
    report: &mut Report,
) -> Result<(), String> {
    let manifest_path = current.join("dataset_manifest.json");
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
    inventory(captures, &mut names, report)?;
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
        if history_is_preserved(&path, current, &active)? {
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
    inventory(captures, &mut names, report)?;
    if fs::read(&manifest_path).map_err(|error| error.to_string())? != active_bytes {
        return Err("active manifest changed during sweep".into());
    }
    for (path, before) in confirmed {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| names.contains(name))
        {
            continue;
        }
        report.candidate_stats += 1;
        let after = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if after.is_file() && identity(&before) == identity(&after) {
            fs::remove_file(path).map_err(|error| error.to_string())?;
            report.count += 1;
            report.bytes += after.len();
            report.kept -= 1;
        }
    }
    Ok(())
}
