//! Offset tables for immutable event shards.
use crate::EventShard;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub const DIRECTORY: &str = "pfcp-index";
static BACKFILLS: AtomicU64 = AtomicU64::new(0);
static BACKFILL_ERRORS: AtomicU64 = AtomicU64::new(0);

#[derive(Default, Deserialize, Serialize)]
pub struct Offsets(BTreeMap<String, Vec<u64>>);

impl Offsets {
    pub fn add(&mut self, event: &Value, offset: u64) {
        if event.get("protocol").and_then(Value::as_str) == Some("PFCP") {
            for key in keys(event) {
                self.0.entry(key).or_default().push(offset);
            }
        }
    }

    pub fn get(&self, key: &str) -> &[u64] {
        self.0.get(key).map(Vec::as_slice).unwrap_or_default()
    }
}

pub fn keys(value: &Value) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(seq) = value.get("pfcp_sequence").and_then(Value::as_str) {
        if !seq.is_empty() {
            keys.push(format!("seq:{seq}"));
        }
    }
    if let Some(ids) = value.get("session_identifiers").and_then(Value::as_array) {
        for id in ids {
            let val = id.get("value").and_then(Value::as_str).unwrap_or("");
            if val.is_empty() {
                continue;
            }
            match id.get("name").and_then(Value::as_str) {
                Some("pfcp_sequence") => keys.push(format!("seq:{val}")),
                Some("seid" | "f_seid") if val != "0x0000000000000000" => {
                    keys.push(format!("seid:{val}"));
                }
                _ => {}
            }
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

#[derive(Deserialize, Serialize)]
struct Table<T> {
    version: u8,
    sha256: String,
    bytes: u64,
    offsets: T,
}

pub fn path(root: &Path, shard: &EventShard) -> Option<PathBuf> {
    let relative = Path::new(&shard.path);
    if relative.parent()? != Path::new("event-shards") {
        return None;
    }
    let name = relative.file_name()?.to_str()?;
    Some(root.join(DIRECTORY).join(format!("{name}.json")))
}

pub fn write(root: &Path, shard: &EventShard, offsets: &Offsets) -> Result<u64, String> {
    let Some(target) = path(root, shard) else {
        return Ok(0);
    };
    let started = std::time::Instant::now();
    let bytes = serde_json::to_vec(&Table {
        version: 1,
        sha256: shard.sha256.clone(),
        bytes: shard.bytes,
        offsets,
    })
    .map_err(|error| error.to_string())?;
    std::fs::create_dir_all(root.join(DIRECTORY)).map_err(crate::display_error)?;
    crate::atomic_write(&target, &bytes)?;
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "PFCP_SHARD_TABLE_WRITTEN",
            "bytes": bytes.len(),
            "elapsed_us": started.elapsed().as_micros(),
        })
    );
    Ok(bytes.len() as u64)
}

pub fn load_or_backfill(root: &Path, shard: &EventShard) -> Result<Offsets, String> {
    let target = path(root, shard).ok_or("PFCP_INDEX_INVALID_SHARD_PATH")?;
    if let Ok(bytes) = std::fs::read(&target) {
        if let Ok(table) = serde_json::from_slice::<Table<Offsets>>(&bytes) {
            if table.version == 1 && table.sha256 == shard.sha256 && table.bytes == shard.bytes {
                return Ok(table.offsets);
            }
        }
    }

    let result = (|| {
        let source = root.join(&shard.path);
        let mut reader = BufReader::new(std::fs::File::open(source).map_err(crate::display_error)?);
        let mut offsets = Offsets::default();
        let mut line = String::new();
        let mut offset = 0;
        loop {
            line.clear();
            let read = reader.read_line(&mut line).map_err(crate::display_error)?;
            if read == 0 {
                break;
            }
            if line.contains("\"PFCP\"") {
                if let Ok(event) = serde_json::from_str(&line) {
                    offsets.add(&event, offset);
                }
            }
            offset += read as u64;
        }
        if offset != shard.bytes {
            return Err(format!("PFCP_INDEX_SHARD_SIZE_MISMATCH: {}", shard.path));
        }
        write(root, shard, &offsets)?;
        Ok(offsets)
    })();
    match &result {
        Ok(_) => {
            BACKFILLS.fetch_add(1, Relaxed);
        }
        Err(error) => {
            BACKFILL_ERRORS.fetch_add(1, Relaxed);
            eprintln!("PFCP_INDEX_BACKFILL_FAILED: {}: {error}", shard.path);
        }
    }
    result
}

pub fn health() -> Value {
    serde_json::json!({
        "backfills_total": BACKFILLS.load(Relaxed),
        "backfill_errors_total": BACKFILL_ERRORS.load(Relaxed),
    })
}

/// The raw shard remains the lifetime authority, including while an older
/// served manifest still refers to it. A removed raw shard leaves no table
/// after the next publication. Nothing enumerated here becomes an index input.
pub fn remove_orphan_tables(root: &Path) -> io::Result<()> {
    let tables = match std::fs::read_dir(root.join(DIRECTORY)) {
        Ok(tables) => tables,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for table in tables {
        let table = table?;
        let name = table.file_name();
        let Some(shard) = name
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
            .filter(|name| name.ends_with(".jsonl"))
        else {
            continue;
        };
        if let Err(error) = std::fs::metadata(root.join("event-shards").join(shard)) {
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
            match std::fs::remove_file(table.path()) {
                Ok(()) => (),
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}
