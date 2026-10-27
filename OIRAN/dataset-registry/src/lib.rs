//! Deterministic, in-memory registry for immutable capture datasets.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: &str = "0.1.0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureRecord {
    pub capture_id: String,
    pub file_name: String,
    pub capture_point_id: String,
    pub probe_id: String,
    pub interface_type: String,
    pub start_timestamp: Option<String>,
    pub end_timestamp: Option<String>,
    pub sha256: String,
    pub packet_count: u64,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatasetRecord {
    pub dataset_id: String,
    pub display_name: String,
    pub captures: Vec<CaptureRecord>,
    pub decoder_versions: BTreeMap<String, String>,
    pub ingestion_status: String,
    pub ingestion_generation: u64,
    pub session_count: usize,
    pub ue_context_count: usize,
    pub event_count: usize,
    pub background_event_count: usize,
    pub unmatched_event_count: usize,
    pub duplicate_observation_count: usize,
    pub error_count: usize,
    pub read_only: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatasetComparison {
    pub left_dataset_id: String,
    pub right_dataset_id: String,
    pub shared_capture_hashes: Vec<String>,
    pub left_only_capture_hashes: Vec<String>,
    pub right_only_capture_hashes: Vec<String>,
    pub session_count_delta: i64,
    pub event_count_delta: i64,
}

#[derive(Clone, Debug, Default)]
pub struct DatasetRegistry {
    records: BTreeMap<String, DatasetRecord>,
    fingerprints: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterResult {
    Inserted(String),
    AlreadyRegistered(String),
}

impl DatasetRegistry {
    pub fn register(&mut self, mut record: DatasetRecord) -> Result<RegisterResult, String> {
        validate(&record)?;
        record
            .captures
            .sort_by(|a, b| a.capture_id.cmp(&b.capture_id));
        let fingerprint = fingerprint(&record);
        if let Some(existing) = self.fingerprints.get(&fingerprint) {
            return Ok(RegisterResult::AlreadyRegistered(existing.clone()));
        }
        if self.records.contains_key(&record.dataset_id) {
            return Err(format!(
                "dataset id {} already refers to different captures",
                record.dataset_id
            ));
        }
        self.fingerprints
            .insert(fingerprint, record.dataset_id.clone());
        self.records
            .insert(record.dataset_id.clone(), record.clone());
        Ok(RegisterResult::Inserted(record.dataset_id))
    }

    pub fn get(&self, id: &str) -> Option<&DatasetRecord> {
        self.records.get(id)
    }

    pub fn list(&self) -> Vec<&DatasetRecord> {
        self.records.values().collect()
    }

    pub fn search(&self, query: &str) -> Vec<&DatasetRecord> {
        let query = query.to_ascii_lowercase();
        self.records
            .values()
            .filter(|record| {
                record.dataset_id.to_ascii_lowercase().contains(&query)
                    || record.display_name.to_ascii_lowercase().contains(&query)
                    || record.captures.iter().any(|capture| {
                        capture.file_name.to_ascii_lowercase().contains(&query)
                            || capture.interface_type.to_ascii_lowercase().contains(&query)
                    })
            })
            .collect()
    }

    pub fn mark_reprocessed(&mut self, id: &str) -> Result<u64, String> {
        let record = self
            .records
            .get_mut(id)
            .ok_or_else(|| format!("unknown dataset {id}"))?;
        record.ingestion_generation += 1;
        record.ingestion_status = "INDEXED".into();
        Ok(record.ingestion_generation)
    }

    pub fn compare(&self, left: &str, right: &str) -> Result<DatasetComparison, String> {
        let left_record = self
            .get(left)
            .ok_or_else(|| format!("unknown dataset {left}"))?;
        let right_record = self
            .get(right)
            .ok_or_else(|| format!("unknown dataset {right}"))?;
        let left_hashes = hashes(left_record);
        let right_hashes = hashes(right_record);
        Ok(DatasetComparison {
            left_dataset_id: left.into(),
            right_dataset_id: right.into(),
            shared_capture_hashes: left_hashes.intersection(&right_hashes).cloned().collect(),
            left_only_capture_hashes: left_hashes.difference(&right_hashes).cloned().collect(),
            right_only_capture_hashes: right_hashes.difference(&left_hashes).cloned().collect(),
            session_count_delta: left_record.session_count as i64
                - right_record.session_count as i64,
            event_count_delta: left_record.event_count as i64 - right_record.event_count as i64,
        })
    }
}

fn validate(record: &DatasetRecord) -> Result<(), String> {
    if record.dataset_id.is_empty() || record.captures.is_empty() {
        return Err("dataset id and at least one capture are required".into());
    }
    if !record.read_only {
        return Err("S4.1 accepts immutable datasets only".into());
    }
    if record
        .captures
        .iter()
        .any(|capture| capture.sha256.len() != 64 || capture.file_name.contains('/'))
    {
        return Err("capture requires a SHA256 and basename-only file name".into());
    }
    Ok(())
}

fn fingerprint(record: &DatasetRecord) -> String {
    record
        .captures
        .iter()
        .map(|capture| capture.sha256.as_str())
        .collect::<Vec<_>>()
        .join(":")
}

fn hashes(record: &DatasetRecord) -> BTreeSet<String> {
    record
        .captures
        .iter()
        .map(|capture| capture.sha256.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, hash: char) -> DatasetRecord {
        DatasetRecord {
            dataset_id: id.into(),
            display_name: format!("Dataset {id}"),
            captures: vec![CaptureRecord {
                capture_id: format!("capture-{id}"),
                file_name: format!("{id}.pcapng"),
                capture_point_id: "probe:N2".into(),
                probe_id: "probe".into(),
                interface_type: "N2".into(),
                start_timestamp: None,
                end_timestamp: None,
                sha256: hash.to_string().repeat(64),
                packet_count: 1,
                size_bytes: 64,
            }],
            decoder_versions: BTreeMap::new(),
            ingestion_status: "INDEXED".into(),
            ingestion_generation: 1,
            session_count: 1,
            ue_context_count: 1,
            event_count: 2,
            background_event_count: 1,
            unmatched_event_count: 0,
            duplicate_observation_count: 0,
            error_count: 0,
            read_only: true,
        }
    }

    #[test]
    fn repeated_import_is_idempotent_even_with_different_id() {
        let mut registry = DatasetRegistry::default();
        assert_eq!(
            registry.register(record("one", 'a')).unwrap(),
            RegisterResult::Inserted("one".into())
        );
        assert_eq!(
            registry.register(record("alias", 'a')).unwrap(),
            RegisterResult::AlreadyRegistered("one".into())
        );
        assert_eq!(registry.list().len(), 1);
    }

    #[test]
    fn search_reprocess_and_compare_are_deterministic() {
        let mut registry = DatasetRegistry::default();
        registry.register(record("one", 'a')).unwrap();
        registry.register(record("two", 'b')).unwrap();
        assert_eq!(registry.search("N2").len(), 2);
        assert_eq!(registry.mark_reprocessed("one").unwrap(), 2);
        let comparison = registry.compare("one", "two").unwrap();
        assert!(comparison.shared_capture_hashes.is_empty());
        assert_eq!(comparison.left_only_capture_hashes, vec!["a".repeat(64)]);
    }

    #[test]
    fn mutable_or_unsafe_capture_records_are_rejected() {
        let mut registry = DatasetRegistry::default();
        let mut invalid = record("bad", 'c');
        invalid.read_only = false;
        assert!(registry.register(invalid).is_err());
        let mut unsafe_path = record("path", 'd');
        unsafe_path.captures[0].file_name = "../escape.pcapng".into();
        assert!(registry.register(unsafe_path).is_err());
    }
}
