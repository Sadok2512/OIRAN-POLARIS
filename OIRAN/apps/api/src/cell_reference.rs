use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_CSV_BYTES: usize = 5 * 1024 * 1024;
pub const CSV_HEADERS: [&str; 11] = [
    "technology",
    "mcc",
    "mnc",
    "gnb_id",
    "gnb_id_length",
    "nci",
    "enb_id",
    "eci",
    "cell_id",
    "latitude",
    "longitude",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CellRecord {
    pub technology: String,
    pub mcc: String,
    pub mnc: String,
    pub gnb_id: Option<u64>,
    pub gnb_id_length: Option<u8>,
    pub nci: Option<u64>,
    pub enb_id: Option<u32>,
    pub eci: Option<u32>,
    pub cell_id: u32,
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationError {
    pub line: usize,
    pub column: String,
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationReport {
    pub valid_rows: usize,
    pub errors: Vec<ValidationError>,
    pub snapshot_id: String,
    pub cells_by_technology: BTreeMap<String, usize>,
    pub preview: Vec<CellRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotDocument {
    pub snapshot_id: String,
    pub imported_by: String,
    pub imported_epoch_ms: u128,
    pub cell_count: usize,
    pub cells_by_technology: BTreeMap<String, usize>,
    pub cells: Vec<CellRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveDocument {
    snapshot_id: String,
    activated_by: String,
    activated_epoch_ms: u128,
    cell_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AuditEntry {
    who: String,
    when_epoch_ms: u128,
    action: String,
    snapshot_id: String,
    cell_count: usize,
}

#[derive(Debug)]
pub struct StoreError {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug)]
pub enum ImportError {
    Validation(ValidationReport),
    Store(StoreError),
}

impl StoreError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub struct CellReferenceStore {
    root: PathBuf,
    mutation: Mutex<()>,
}

impl CellReferenceStore {
    pub fn new(root: PathBuf) -> Result<Self, StoreError> {
        if !root.exists() {
            fs::create_dir_all(&root).map_err(|error| {
                StoreError::new("CELL_REFERENCE_CREATE_FAILED", error.to_string())
            })?;
        }
        if !root.is_dir() {
            return Err(StoreError::new(
                "CELL_REFERENCE_UNAVAILABLE",
                format!("{} is not a directory", root.display()),
            ));
        }
        Ok(Self {
            root,
            mutation: Mutex::new(()),
        })
    }

    pub fn validate(&self, csv: &[u8]) -> ValidationReport {
        let snapshot_id = format!("snapshot-{}", &event_schema::sha256_hex(csv)[..24]);
        let mut report = parse_csv(csv, snapshot_id.clone());
        if self.snapshot_path(&snapshot_id).exists() {
            report.errors.push(validation_error(
                0,
                "snapshot_id",
                "SNAPSHOT_EXISTS",
                "a snapshot with this content already exists",
            ));
        }
        report
    }

    pub fn import(&self, csv: &[u8], actor: &str) -> Result<SnapshotDocument, ImportError> {
        let _guard = self.mutation.lock().unwrap();
        let report = self.validate(csv);
        if !report.errors.is_empty() {
            return Err(ImportError::Validation(report));
        }
        let document = SnapshotDocument {
            snapshot_id: report.snapshot_id.clone(),
            imported_by: actor.to_owned(),
            imported_epoch_ms: epoch_ms(),
            cell_count: report.preview.len(),
            cells_by_technology: report.cells_by_technology,
            cells: report.preview,
        };
        let bytes = serde_json::to_vec_pretty(&document).map_err(|error| {
            ImportError::Store(StoreError::new(
                "CELL_REFERENCE_WRITE_FAILED",
                error.to_string(),
            ))
        })?;
        if let Err(error) = write_new_atomic(&self.snapshot_path(&document.snapshot_id), &bytes) {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                let mut failed = parse_csv(csv, document.snapshot_id.clone());
                failed.errors.push(validation_error(
                    0,
                    "snapshot_id",
                    "SNAPSHOT_EXISTS",
                    "a snapshot with this content already exists",
                ));
                return Err(ImportError::Validation(failed));
            }
            return Err(ImportError::Store(StoreError::new(
                "CELL_REFERENCE_WRITE_FAILED",
                error.to_string(),
            )));
        }
        Ok(document)
    }

    pub fn activate(&self, snapshot_id: &str, actor: &str) -> Result<Value, StoreError> {
        if !safe_snapshot_id(snapshot_id) {
            return Err(StoreError::new("SNAPSHOT_NOT_FOUND", "invalid snapshot id"));
        }
        let _guard = self.mutation.lock().unwrap();
        let snapshot: SnapshotDocument = read_json(&self.snapshot_path(snapshot_id))?;
        let entry = AuditEntry {
            who: actor.to_owned(),
            when_epoch_ms: epoch_ms(),
            action: "CELL_REFERENCE_ACTIVATED".into(),
            snapshot_id: snapshot_id.to_owned(),
            cell_count: snapshot.cell_count,
        };
        let active = ActiveDocument {
            snapshot_id: snapshot_id.to_owned(),
            activated_by: actor.to_owned(),
            activated_epoch_ms: entry.when_epoch_ms,
            cell_count: snapshot.cell_count,
        };
        write_replace_atomic(
            &self.root.join("active.json"),
            &serde_json::to_vec_pretty(&active).map_err(|error| {
                StoreError::new("CELL_REFERENCE_ACTIVATE_FAILED", error.to_string())
            })?,
        )?;
        let audit_path = self.root.join("audit.json");
        let mut audit: Vec<AuditEntry> = if audit_path.exists() {
            read_json(&audit_path)?
        } else {
            Vec::new()
        };
        audit.push(entry.clone());
        write_replace_atomic(
            &self.root.join("audit.json"),
            &serde_json::to_vec_pretty(&audit).map_err(|error| {
                StoreError::new("CELL_REFERENCE_AUDIT_FAILED", error.to_string())
            })?,
        )?;
        serde_json::to_value(entry)
            .map_err(|error| StoreError::new("CELL_REFERENCE_ACTIVATE_FAILED", error.to_string()))
    }

    pub fn list(&self) -> Result<Value, StoreError> {
        let active_path = self.root.join("active.json");
        let active = if active_path.exists() {
            Some(read_json::<ActiveDocument>(&active_path)?)
        } else {
            None
        };
        let mut snapshots = Vec::new();
        let entries = fs::read_dir(&self.root)
            .map_err(|error| StoreError::new("CELL_REFERENCE_LIST_FAILED", error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                StoreError::new("CELL_REFERENCE_LIST_FAILED", error.to_string())
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("snapshot-") || !name.ends_with(".json") {
                continue;
            }
            let snapshot: SnapshotDocument = read_json(&entry.path())?;
            snapshots.push(serde_json::json!({
                "snapshot_id": snapshot.snapshot_id,
                "imported_by": snapshot.imported_by,
                "imported_epoch_ms": snapshot.imported_epoch_ms,
                "cell_count": snapshot.cell_count,
                "cells_by_technology": snapshot.cells_by_technology,
            }));
        }
        snapshots.sort_by(|a, b| a["snapshot_id"].as_str().cmp(&b["snapshot_id"].as_str()));
        Ok(serde_json::json!({
            "active_snapshot_id": active.as_ref().map(|value| value.snapshot_id.as_str()),
            "snapshots": snapshots,
        }))
    }

    pub fn active_snapshot(&self) -> Result<Option<SnapshotDocument>, StoreError> {
        let active_path = self.root.join("active.json");
        if !active_path.exists() {
            return Ok(None);
        }
        let active: ActiveDocument = read_json(&active_path)?;
        read_json(&self.snapshot_path(&active.snapshot_id)).map(Some)
    }

    fn snapshot_path(&self, snapshot_id: &str) -> PathBuf {
        self.root.join(format!("{snapshot_id}.json"))
    }
}

fn parse_csv(bytes: &[u8], snapshot_id: String) -> ValidationReport {
    let mut errors = Vec::new();
    let mut cells = Vec::new();
    let mut cells_by_technology = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .from_reader(bytes);
    match reader.headers() {
        Ok(headers) if headers.iter().eq(CSV_HEADERS) => {}
        Ok(headers) => errors.push(validation_error(
            1,
            "header",
            "HEADER_MISMATCH",
            &format!(
                "expected {}; received {}",
                CSV_HEADERS.join(","),
                headers.iter().collect::<Vec<_>>().join(",")
            ),
        )),
        Err(error) => errors.push(validation_error(
            1,
            "header",
            "HEADER_MISMATCH",
            &error.to_string(),
        )),
    }
    if errors.iter().any(|error| error.code == "HEADER_MISMATCH") {
        return ValidationReport {
            valid_rows: 0,
            errors,
            snapshot_id,
            cells_by_technology,
            preview: cells,
        };
    }
    for (offset, row) in reader.records().enumerate() {
        let line = offset + 2;
        let row = match row {
            Ok(row) if row.len() == CSV_HEADERS.len() => row,
            Ok(_) => {
                errors.push(validation_error(
                    line,
                    "row",
                    "MISSING_FIELD",
                    "row has the wrong number of columns",
                ));
                continue;
            }
            Err(error) => {
                errors.push(validation_error(
                    line,
                    "row",
                    "MISSING_FIELD",
                    &error.to_string(),
                ));
                continue;
            }
        };
        if let Some(cell) = parse_row(line, &row, &mut errors) {
            let identity = if cell.technology == "5G" {
                format!("{}-{}-nci-{}", cell.mcc, cell.mnc, cell.nci.unwrap())
            } else {
                format!("{}-{}-eci-{}", cell.mcc, cell.mnc, cell.eci.unwrap())
            };
            if !seen.insert(identity) {
                errors.push(validation_error(
                    line,
                    "nci/eci",
                    "DUPLICATE_CELL",
                    "cell already appears in this snapshot",
                ));
                continue;
            }
            *cells_by_technology
                .entry(cell.technology.clone())
                .or_insert(0) += 1;
            cells.push(cell);
        }
    }
    ValidationReport {
        valid_rows: cells.len(),
        errors,
        snapshot_id,
        cells_by_technology,
        preview: cells,
    }
}

fn parse_row(
    line: usize,
    row: &csv::StringRecord,
    errors: &mut Vec<ValidationError>,
) -> Option<CellRecord> {
    let value = |name: &str| {
        row.get(
            CSV_HEADERS
                .iter()
                .position(|header| *header == name)
                .unwrap(),
        )
        .unwrap_or("")
    };
    let required = |name: &str, errors: &mut Vec<ValidationError>| {
        let value = value(name);
        if value.is_empty() {
            errors.push(validation_error(
                line,
                name,
                "MISSING_FIELD",
                "required field is empty",
            ));
            None
        } else {
            Some(value)
        }
    };
    let technology = required("technology", errors)?.to_ascii_uppercase();
    let technology = match technology.as_str() {
        "5G" | "NR" => "5G".to_owned(),
        "LTE" | "4G" => "LTE".to_owned(),
        _ => {
            errors.push(validation_error(
                line,
                "technology",
                "MISSING_FIELD",
                "technology must be 5G or LTE",
            ));
            return None;
        }
    };
    let mcc = required("mcc", errors)?.to_owned();
    let mnc = required("mnc", errors)?.to_owned();
    if mcc.len() != 3
        || !mcc.chars().all(|ch| ch.is_ascii_digit())
        || !(2..=3).contains(&mnc.len())
        || !mnc.chars().all(|ch| ch.is_ascii_digit())
    {
        errors.push(validation_error(
            line,
            "mcc/mnc",
            "BAD_MCC_MNC",
            "MCC must have 3 digits and MNC 2 or 3 digits",
        ));
        return None;
    }
    let latitude = parse_f64(required("latitude", errors)?, line, "latitude", errors)?;
    let longitude = parse_f64(required("longitude", errors)?, line, "longitude", errors)?;
    if !(-90.0..=90.0).contains(&latitude) || !(-180.0..=180.0).contains(&longitude) {
        errors.push(validation_error(
            line,
            "latitude/longitude",
            "BAD_LAT_LON",
            "latitude or longitude is out of range",
        ));
        return None;
    }
    let cell_id = parse_u64(required("cell_id", errors)?, line, "cell_id", errors)?;
    if technology == "5G" {
        let gnb_id = parse_u64(required("gnb_id", errors)?, line, "gnb_id", errors)?;
        let length = parse_u64(
            required("gnb_id_length", errors)?,
            line,
            "gnb_id_length",
            errors,
        )?;
        if !(22..=32).contains(&length) || gnb_id >= (1u64 << length) {
            errors.push(validation_error(
                line,
                "gnb_id_length",
                "BAD_GNB_ID_LENGTH",
                "gNB ID length must be 22..32 and contain the gNB ID",
            ));
            return None;
        }
        let local_bits = 36 - length;
        if cell_id >= (1u64 << local_bits) {
            errors.push(validation_error(
                line,
                "cell_id",
                "NCI_MISMATCH",
                "cell ID does not fit the NCI local bits",
            ));
            return None;
        }
        let nci = parse_u64(required("nci", errors)?, line, "nci", errors)?;
        if nci != (gnb_id << local_bits) | cell_id || nci >= (1u64 << 36) {
            errors.push(validation_error(
                line,
                "nci",
                "NCI_MISMATCH",
                "NCI does not match gNB ID, length and cell ID",
            ));
            return None;
        }
        Some(CellRecord {
            technology,
            mcc,
            mnc,
            gnb_id: Some(gnb_id),
            gnb_id_length: Some(length as u8),
            nci: Some(nci),
            enb_id: None,
            eci: None,
            cell_id: cell_id as u32,
            latitude,
            longitude,
        })
    } else {
        let enb_id = parse_u64(required("enb_id", errors)?, line, "enb_id", errors)?;
        let eci = parse_u64(required("eci", errors)?, line, "eci", errors)?;
        if enb_id >= (1u64 << 20)
            || cell_id >= 256
            || eci != (enb_id << 8) | cell_id
            || eci >= (1u64 << 28)
        {
            errors.push(validation_error(
                line,
                "eci",
                "ECI_MISMATCH",
                "ECI does not match eNB ID and cell ID",
            ));
            return None;
        }
        Some(CellRecord {
            technology,
            mcc,
            mnc,
            gnb_id: None,
            gnb_id_length: None,
            nci: None,
            enb_id: Some(enb_id as u32),
            eci: Some(eci as u32),
            cell_id: cell_id as u32,
            latitude,
            longitude,
        })
    }
}

fn parse_u64(
    value: &str,
    line: usize,
    column: &str,
    errors: &mut Vec<ValidationError>,
) -> Option<u64> {
    let parsed = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map(|hex| u64::from_str_radix(hex, 16))
        .unwrap_or_else(|| value.parse::<u64>());
    parsed
        .map_err(|_| {
            errors.push(validation_error(
                line,
                column,
                "MISSING_FIELD",
                "expected an unsigned integer",
            ))
        })
        .ok()
}

fn parse_f64(
    value: &str,
    line: usize,
    column: &str,
    errors: &mut Vec<ValidationError>,
) -> Option<f64> {
    value
        .parse::<f64>()
        .map_err(|_| {
            errors.push(validation_error(
                line,
                column,
                "BAD_LAT_LON",
                "expected a decimal coordinate",
            ))
        })
        .ok()
}

fn validation_error(line: usize, column: &str, code: &str, message: &str) -> ValidationError {
    ValidationError {
        line,
        column: column.to_owned(),
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

fn safe_snapshot_id(value: &str) -> bool {
    value.starts_with("snapshot-")
        && value.len() == 33
        && value[9..].chars().all(|ch| ch.is_ascii_hexdigit())
}

fn epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, StoreError> {
    let bytes =
        fs::read(path).map_err(|error| StoreError::new("SNAPSHOT_NOT_FOUND", error.to_string()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| StoreError::new("CELL_REFERENCE_INVALID", error.to_string()))
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temporary, path)?;
        fs::remove_file(&temporary)?;
        fs::File::open(path.parent().unwrap())?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_replace_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let temporary = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(path.parent().unwrap())?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| StoreError::new("CELL_REFERENCE_WRITE_FAILED", error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    fn root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "oiran-cell-reference-{label}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn valid_csv() -> Vec<u8> {
        format!(
            "{}\n5G,001,01,100,22,1638407,,,7,48.1,2.1\nLTE,001,01,,,,200,51208,8,48.2,2.2\n",
            CSV_HEADERS.join(",")
        )
        .into_bytes()
    }

    #[test]
    fn valid_csv_contains_two_cells() {
        let root = root("valid");
        let store = CellReferenceStore::new(root.clone()).unwrap();
        let report = store.validate(&valid_csv());
        assert_eq!(report.valid_rows, 2);
        assert!(report.errors.is_empty());
        assert_eq!(report.cells_by_technology.get("5G"), Some(&1));
        assert_eq!(report.cells_by_technology.get("LTE"), Some(&1));
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            0,
            "dry run wrote files"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bad_nci_reports_line_two_and_writes_nothing() {
        let root = root("bad-nci");
        let store = CellReferenceStore::new(root.clone()).unwrap();
        let csv = format!(
            "{}\n5G,001,01,100,22,1638408,,,7,48.1,2.1\n",
            CSV_HEADERS.join(",")
        );
        let report = store.import(csv.as_bytes(), "operator").unwrap_err();
        let ImportError::Validation(report) = report else {
            panic!("expected validation")
        };
        assert!(report
            .errors
            .iter()
            .any(|error| error.line == 2 && error.code == "NCI_MISMATCH"));
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_cell_is_rejected() {
        let root = root("duplicate");
        let store = CellReferenceStore::new(root.clone()).unwrap();
        let csv = format!(
            "{}\n5G,001,01,100,22,1638407,,,7,48.1,2.1\n5G,001,01,100,22,1638407,,,7,48.2,2.2\n",
            CSV_HEADERS.join(",")
        );
        let report = store.validate(csv.as_bytes());
        assert!(report
            .errors
            .iter()
            .any(|error| error.code == "DUPLICATE_CELL"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_snapshot_is_never_overwritten() {
        let root = root("existing");
        let store = CellReferenceStore::new(root.clone()).unwrap();
        let csv = valid_csv();
        let first = store.import(&csv, "operator").unwrap();
        let before = fs::read(store.snapshot_path(&first.snapshot_id)).unwrap();
        let report = store.validate(&csv);
        assert!(report
            .errors
            .iter()
            .any(|error| error.code == "SNAPSHOT_EXISTS"));
        assert!(matches!(
            store.import(&csv, "operator"),
            Err(ImportError::Validation(_))
        ));
        assert_eq!(
            fs::read(store.snapshot_path(&first.snapshot_id)).unwrap(),
            before
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn activation_records_actor_time_snapshot_and_cell_count() {
        let root = root("activate");
        let store = CellReferenceStore::new(root.clone()).unwrap();
        let snapshot = store.import(&valid_csv(), "operator").unwrap();
        let audit = store.activate(&snapshot.snapshot_id, "operator").unwrap();
        assert_eq!(audit["who"], "operator");
        assert_eq!(audit["snapshot_id"], snapshot.snapshot_id);
        assert_eq!(audit["cell_count"], 2);
        assert!(audit["when_epoch_ms"].as_u64().is_some());
        let list = store.list().unwrap();
        assert_eq!(list["active_snapshot_id"], snapshot.snapshot_id);
        fs::remove_dir_all(root).unwrap();
    }
}
