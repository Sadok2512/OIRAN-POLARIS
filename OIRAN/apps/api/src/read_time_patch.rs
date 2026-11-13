//! 2.14.7 (ANR1 #10) — read-time rewrite of stale `CallFlowEvent`
//! fields using the richer raw `NormalizedEvent` records retained in
//! `oiran_events.jsonl`. The patcher does NOT mutate any file on disk:
//! only the in-memory `flow_values` map served by
//! `/api/v1/sessions/<id>/events`.
//!
//! The patcher is the "one source of truth" for the three ingestion-time
//! heuristics introduced by the 2.14.5 lot — it calls the exact public
//! helpers exposed by the decoder crates:
//!
//! - [`oiran_decode::infer_sctp_network_function`] (SCTP port-based
//!   `network_function` fallback: 36412 ↔ MME/eNB, 38412 ↔ AMF/gNB).
//! - [`decoder_s1ap::infer_direction_from_network_functions`] (direction
//!   derived strictly from the SCTP transport).
//! - [`decoder_s1ap::message_name`] (TS 36.413 §9.1 procedure table,
//!   procedureCode × PduKind).
//! - [`decoder_s1ap::combined_message_name`] (`<S1AP procedure> · <NAS>`).
//! - [`decoder_nas::mm_eps_name`] (TS 24.301 §9.8.1 EMM message types,
//!   notably 0x5D Security mode command).
//!
//! Every patched event carries a `read_time_patch` object recording the
//! patcher version and the list of fields that were rewritten. Idempotent
//! by design: an event already consistent with the 2.14.7 helpers is not
//! modified and is not counted.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use event_schema::Endpoint;
use serde_json::{json, Value};

/// Version exposed on each `read_time_patch` object. Bumped only when
/// the set of rewritten fields grows.
pub const PATCH_VERSION: &str = "2.14.7";

/// Snapshot of patch activity since the service started. Shared via
/// `Arc`; every field is atomic for lock-free reads from `/version`.
#[derive(Debug, Default)]
pub struct PatchCounters {
    pub callflows_loaded: AtomicU64,
    pub events_seen: AtomicU64,
    pub events_patched_source_participant: AtomicU64,
    pub events_patched_destination_participant: AtomicU64,
    pub events_patched_direction: AtomicU64,
    pub events_patched_message_name: AtomicU64,
    /// Events whose SCTP transport did not resolve to a known
    /// `network_function` (participant stays explicitly
    /// `"Unknown endpoint"`, ouvert et comptable).
    pub events_unresolved_participant: AtomicU64,
    /// Events where the JSONL did not expose a raw `NormalizedEvent`
    /// to cross-reference (e.g., the sidecar `oiran_events.jsonl` is
    /// absent). Surfaced so the gate cannot pass silently.
    pub events_without_raw_counterpart: AtomicU64,
}

impl PatchCounters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_json(&self) -> Value {
        json!({
            "version": PATCH_VERSION,
            "callflows_loaded": self.callflows_loaded.load(Ordering::Relaxed),
            "events_seen": self.events_seen.load(Ordering::Relaxed),
            "events_patched": {
                "source_participant": self
                    .events_patched_source_participant
                    .load(Ordering::Relaxed),
                "destination_participant": self
                    .events_patched_destination_participant
                    .load(Ordering::Relaxed),
                "direction": self.events_patched_direction.load(Ordering::Relaxed),
                "message_name": self.events_patched_message_name.load(Ordering::Relaxed),
            },
            "events_unresolved_participant": self
                .events_unresolved_participant
                .load(Ordering::Relaxed),
            "events_without_raw_counterpart": self
                .events_without_raw_counterpart
                .load(Ordering::Relaxed),
        })
    }
}

/// Index of raw `NormalizedEvent` records parsed from one
/// `oiran_events.jsonl`, keyed by `event_id`. Each value is the raw
/// JSON object; the patcher reads the port, procedure_code and
/// message_type from it. Reading the file once per flow keeps the cost
/// linear in events.
pub struct RawEventIndex {
    by_event_id: HashMap<String, Value>,
}

impl RawEventIndex {
    pub fn from_jsonl_path(path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
        let reader = BufReader::new(file);
        let mut by_event_id = HashMap::new();
        for (line_number, line) in reader.lines().enumerate() {
            let line = line.map_err(|error| error.to_string())?;
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(&line).map_err(|error| {
                format!("{}:{}: invalid JSONL: {error}", path.display(), line_number + 1)
            })?;
            if let Some(id) = value.get("event_id").and_then(Value::as_str) {
                by_event_id.insert(id.to_string(), value);
            }
        }
        Ok(Self { by_event_id })
    }

    pub fn get(&self, event_id: &str) -> Option<&Value> {
        self.by_event_id.get(event_id)
    }

    pub fn len(&self) -> usize {
        self.by_event_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_event_id.is_empty()
    }
}

fn endpoint_from_raw(value: Option<&Value>) -> (Option<Endpoint>, Option<u16>) {
    let object = match value.and_then(Value::as_object) {
        Some(object) => object,
        None => return (None, None),
    };
    let address = object
        .get("address")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let port = object
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok());
    let nf = object
        .get("network_function")
        .and_then(Value::as_str)
        .map(str::to_string);
    let endpoint = Endpoint {
        address,
        port,
        network_function: nf,
    };
    (Some(endpoint), port)
}

fn kind_from_u32(value: u32) -> decoder_s1ap::PduKind {
    match value {
        1 => decoder_s1ap::PduKind::SuccessfulOutcome,
        2 => decoder_s1ap::PduKind::UnsuccessfulOutcome,
        _ => decoder_s1ap::PduKind::Initiating,
    }
}

fn s1ap_name_for(raw: &Value) -> Option<String> {
    let protocol = raw.get("protocol").and_then(Value::as_str)?;
    if protocol != "S1AP" {
        return None;
    }
    let code = raw
        .get("procedure_code")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())?;
    let kind = raw
        .get("message_type")
        .and_then(Value::as_u64)
        .map(|value| kind_from_u32(value as u32))
        .unwrap_or(decoder_s1ap::PduKind::Initiating);
    Some(decoder_s1ap::message_name(code, kind))
}

fn nas_name_for(raw: &Value, parent_s1ap_name: &str) -> Option<String> {
    let protocol = raw.get("protocol").and_then(Value::as_str)?;
    let is_nas = matches!(
        protocol,
        "NAS-EPS-MM" | "NAS-EPS-SM" | "NasEpsMm" | "NasEpsSm"
    );
    if !is_nas {
        return None;
    }
    let message_type = raw
        .get("message_type")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    // 2.14.7 (ANR1 #10) : convention héritée de `decoder-s1ap` —
    // `message_type == 0` sur un événement NAS enfant signale un NAS
    // chiffré ; le décodeur ne peut pas lire le type interne. Le
    // libellé public est « NAS chiffré » (placeholder « Protected EPS
    // EMM message » de 2.14.3 remplacé par `combined_message_name`).
    let nas_name: &str = if message_type == 0 {
        "NAS chiffré"
    } else {
        // Même table que `decoder-nas` à l'ingestion : une seule source
        // de vérité.
        decoder_nas::mm_eps_name(message_type as u8).0
    };
    Some(decoder_s1ap::combined_message_name(parent_s1ap_name, nas_name))
}

/// Patch a vector of `CallFlowEvent` values in place. Returns the
/// number of events that were actually modified.
pub fn patch_flow_events(
    events: &mut Vec<Value>,
    raw_index: &RawEventIndex,
    endpoint_map: &HashMap<String, String>,
    counters: &Arc<PatchCounters>,
) -> usize {
    let mut rewritten = 0usize;
    for event in events.iter_mut() {
        counters.events_seen.fetch_add(1, Ordering::Relaxed);
        let event_id = event.get("event_id").and_then(Value::as_str).unwrap_or("");
        let raw = match raw_index.get(event_id) {
            Some(raw) => raw.clone(),
            None => {
                counters
                    .events_without_raw_counterpart
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        if patch_one(event, &raw, raw_index, endpoint_map, counters) {
            rewritten += 1;
        }
    }
    rewritten
}

fn patch_one(
    event: &mut Value,
    raw: &Value,
    raw_index: &RawEventIndex,
    endpoint_map: &HashMap<String, String>,
    counters: &Arc<PatchCounters>,
) -> bool {
    let interface = raw
        .get("interface")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let (source_opt, source_port) = endpoint_from_raw(raw.get("source_endpoint"));
    let (destination_opt, destination_port) = endpoint_from_raw(raw.get("destination_endpoint"));
    let mut source = match source_opt {
        Some(endpoint) => endpoint,
        None => return false,
    };
    let mut destination = match destination_opt {
        Some(endpoint) => endpoint,
        None => return false,
    };
    // 1) IP map (production endpoint_map) — ne remplit que si vide.
    if source.network_function.is_none() {
        source.network_function = endpoint_map.get(&source.address).cloned();
    }
    if destination.network_function.is_none() {
        destination.network_function = endpoint_map.get(&destination.address).cloned();
    }
    // 2) Port-based SCTP fallback — même fonction que l'ingestion
    //    (oiran-decode).
    if let (Some(src_port), Some(dst_port)) = (source_port, destination_port) {
        oiran_decode::infer_sctp_network_function(
            interface.as_str(),
            &mut source,
            &mut destination,
            src_port,
            dst_port,
        );
    }
    // 3) Direction via les deux NF — même fonction que decoder-s1ap
    //    (strict transport, pas de fallback procedureCode).
    let new_direction = decoder_s1ap::infer_direction_from_network_functions(
        source.network_function.as_deref(),
        destination.network_function.as_deref(),
    );

    // 4) message_name : d'abord le parent S1AP recalculé, puis le NAS
    //    combiné pour les enfants.
    let parent_s1ap_name = raw
        .get("parent_event_id")
        .and_then(Value::as_str)
        .and_then(|parent_id| raw_index.get(parent_id))
        .and_then(s1ap_name_for);
    let new_message_name = if let Some(parent_name) = parent_s1ap_name.as_deref() {
        nas_name_for(raw, parent_name)
    } else {
        s1ap_name_for(raw)
    };

    // Publier les nouvelles valeurs si elles diffèrent (idempotent).
    let mut patched_fields: Vec<&'static str> = Vec::new();

    let new_source = source
        .network_function
        .clone()
        .unwrap_or_else(|| "Unknown endpoint".to_string());
    let new_destination = destination
        .network_function
        .clone()
        .unwrap_or_else(|| "Unknown endpoint".to_string());

    let event_object = match event.as_object_mut() {
        Some(object) => object,
        None => return false,
    };

    let old_source = event_object
        .get("source_participant")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if old_source != new_source {
        event_object.insert(
            "source_participant".into(),
            Value::String(new_source.clone()),
        );
        counters
            .events_patched_source_participant
            .fetch_add(1, Ordering::Relaxed);
        patched_fields.push("source_participant");
    }
    if new_source == "Unknown endpoint" {
        counters
            .events_unresolved_participant
            .fetch_add(1, Ordering::Relaxed);
    }

    let old_destination = event_object
        .get("destination_participant")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if old_destination != new_destination {
        event_object.insert(
            "destination_participant".into(),
            Value::String(new_destination),
        );
        counters
            .events_patched_destination_participant
            .fetch_add(1, Ordering::Relaxed);
        patched_fields.push("destination_participant");
    }

    let new_direction_str = match new_direction {
        event_schema::Direction::RanToCore => "RAN_TO_CORE",
        event_schema::Direction::CoreToRan => "CORE_TO_RAN",
        _ => "UNKNOWN",
    };
    let old_direction = event_object
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    // On n'écrase la direction que si on dispose d'un transport résolu :
    // sinon on respecte la valeur stockée (évite d'écraser une bonne
    // direction héritée d'une autre heuristique par « UNKNOWN »).
    if new_direction != event_schema::Direction::Unknown && old_direction != new_direction_str {
        event_object.insert(
            "direction".into(),
            Value::String(new_direction_str.to_string()),
        );
        counters
            .events_patched_direction
            .fetch_add(1, Ordering::Relaxed);
        patched_fields.push("direction");
    }

    if let Some(new_name) = new_message_name {
        let old_name = event_object
            .get("message_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if old_name != new_name {
            event_object.insert("message_name".into(), Value::String(new_name));
            counters
                .events_patched_message_name
                .fetch_add(1, Ordering::Relaxed);
            patched_fields.push("message_name");
        }
    }

    if !patched_fields.is_empty() {
        event_object.insert(
            "read_time_patch".into(),
            json!({
                "version": PATCH_VERSION,
                "fields": patched_fields,
            }),
        );
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn write_jsonl(dir: &std::path::Path, lines: &[Value]) -> std::path::PathBuf {
        let path = dir.join("oiran_events.jsonl");
        let mut body = String::new();
        for line in lines {
            body.push_str(&serde_json::to_string(line).unwrap());
            body.push('\n');
        }
        std::fs::write(&path, body).unwrap();
        path
    }

    fn lab_endpoint_map() -> HashMap<String, String> {
        // Mêmes entrées que `live_probe::endpoint_map()` pour les IPs
        // du lab S1-MME du constat ANR2 #10 6853084865.
        HashMap::from([
            ("10.77.10.10".to_string(), "MME".to_string()),
            ("10.77.10.20".to_string(), "eNB".to_string()),
        ])
    }

    /// Fabrique un NormalizedEvent JSONL imitant exactement ce que
    /// l'ingestion 2.14.3 produirait pour la capture de référence :
    /// IPs et ports corrects (10.77.10.20 46859 ↔ 10.77.10.10 36412),
    /// mais `network_function = null` (la map endpoint_map n'avait pas
    /// encore les IPs à la date d'ingestion).
    fn raw_s1ap(
        event_id: &str,
        procedure_code: u8,
        kind: u32,
        from_enb: bool,
        parent_event_id: Option<&str>,
    ) -> Value {
        let (src, dst, src_port, dst_port) = if from_enb {
            ("10.77.10.20", "10.77.10.10", 46859u16, 36412u16)
        } else {
            ("10.77.10.10", "10.77.10.20", 36412u16, 46859u16)
        };
        json!({
            "event_id": event_id,
            "parent_event_id": parent_event_id,
            "interface": "S1-MME",
            "protocol": "S1AP",
            "message_name": "stale-stored-at-ingestion",
            "message_type": kind,
            "procedure_code": procedure_code,
            "source_endpoint": {"address": src, "port": src_port, "network_function": null},
            "destination_endpoint": {"address": dst, "port": dst_port, "network_function": null},
            "direction": "UNKNOWN",
        })
    }

    fn raw_nas(
        event_id: &str,
        parent_event_id: &str,
        message_type: u8,
        from_enb: bool,
    ) -> Value {
        let (src, dst, src_port, dst_port) = if from_enb {
            ("10.77.10.20", "10.77.10.10", 46859u16, 36412u16)
        } else {
            ("10.77.10.10", "10.77.10.20", 36412u16, 46859u16)
        };
        json!({
            "event_id": event_id,
            "parent_event_id": parent_event_id,
            "interface": "S1-MME",
            "protocol": "NAS-EPS-MM",
            "message_name": "stale-stored-at-ingestion",
            "message_type": message_type,
            "procedure_code": message_type,
            "source_endpoint": {"address": src, "port": src_port, "network_function": null},
            "destination_endpoint": {"address": dst, "port": dst_port, "network_function": null},
            "direction": "UNKNOWN",
        })
    }

    fn stale_callflow_event(
        event_id: &str,
        old_source: &str,
        old_destination: &str,
        old_direction: &str,
        old_name: &str,
    ) -> Value {
        json!({
            "event_id": event_id,
            "interface": "S1-MME",
            "protocol": "S1AP",
            "message_name": old_name,
            "source_participant": old_source,
            "destination_participant": old_destination,
            "direction": old_direction,
        })
    }

    #[test]
    fn patcher_rewrites_s1_mme_stale_fields_via_jsonl_cross_reference() {
        let dir = std::env::temp_dir().join(format!(
            "oiran-read-time-patch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // 5 événements : initialUEMessage(12,I) eNB→MME + enfant NAS
        // Attach Request (0x41), downlinkNASTransport(11,I) MME→eNB +
        // enfant NAS Security Mode Command (0x5D), et enfin
        // UECapabilityInfoIndication(22,I) eNB→MME.
        let raw = vec![
            raw_s1ap("evt-01", 12, 0, true, None),
            raw_nas("evt-02", "evt-01", 0x41, true),
            raw_s1ap("evt-03", 11, 0, false, None),
            raw_nas("evt-04", "evt-03", 0x5d, false),
            raw_s1ap("evt-05", 22, 0, true, None),
        ];
        let jsonl_path = write_jsonl(&dir, &raw);
        let index = RawEventIndex::from_jsonl_path(&jsonl_path).unwrap();

        // Callflow « stale 2.14.3 » : participants manquants, direction
        // via fallback procedureCode (12,13,18 → RAN_TO_CORE ;
        // 9,10,11,23 → CORE_TO_RAN — msg11 (InitialContextSetupResponse
        // eNB→MME) était donc inversé ; ici on vérifie aussi que la
        // direction 11 est corrigée).
        let mut events = vec![
            stale_callflow_event(
                "evt-01",
                "Unknown endpoint",
                "Unknown endpoint",
                "RAN_TO_CORE",
                "InitialUEMessage",
            ),
            stale_callflow_event(
                "evt-02",
                "Unknown endpoint",
                "Unknown endpoint",
                "UNKNOWN",
                "Attach Request",
            ),
            stale_callflow_event(
                "evt-03",
                "Unknown endpoint",
                "Unknown endpoint",
                "CORE_TO_RAN",
                "DownlinkNASTransport",
            ),
            stale_callflow_event(
                "evt-04",
                "Unknown endpoint",
                "Unknown endpoint",
                "UNKNOWN",
                "Security Mode Complete", // bug 2.14.3 → 0x5d mal mappé
            ),
            stale_callflow_event(
                "evt-05",
                "Unknown endpoint",
                "Unknown endpoint",
                "RAN_TO_CORE",
                "UnknownS1APProcedure", // (22,Initiating) absent de la table
            ),
        ];

        let map = lab_endpoint_map();
        let counters = Arc::new(PatchCounters::new());
        let rewritten = patch_flow_events(&mut events, &index, &map, &counters);
        assert_eq!(
            rewritten, 5,
            "chacun des 5 événements stale doit être réécrit au moins une fois"
        );

        // 1. participants résolus depuis la map (ou le port en fallback).
        assert_eq!(events[0]["source_participant"], "eNB");
        assert_eq!(events[0]["destination_participant"], "MME");
        assert_eq!(events[3]["source_participant"], "MME");
        assert_eq!(events[3]["destination_participant"], "eNB");
        assert_eq!(events[4]["source_participant"], "eNB");
        assert_eq!(events[4]["destination_participant"], "MME");

        // 2. Direction stricte transport.
        assert_eq!(events[0]["direction"], "RAN_TO_CORE");
        assert_eq!(events[2]["direction"], "CORE_TO_RAN");
        assert_eq!(events[4]["direction"], "RAN_TO_CORE");

        // 3. message_name : S1AP (table) et NAS combiné.
        assert_eq!(events[0]["message_name"], "InitialUEMessage");
        assert_eq!(
            events[1]["message_name"], "initialUEMessage · Attach Request",
            "NAS enfant doit porter la procédure S1AP porteuse en préfixe ASN.1"
        );
        assert_eq!(events[2]["message_name"], "DownlinkNASTransport");
        assert_eq!(
            events[3]["message_name"], "downlinkNASTransport · Security Mode Command",
            "0x5D correspond bien à Security Mode Command (TS 24.301 §9.8.1)"
        );
        assert_eq!(
            events[4]["message_name"], "UECapabilityInfoIndication",
            "procedureCode 22 initiating doit être étiqueté (ajout decoder-s1ap 0.3.0)"
        );

        // 4. Provenance : chaque événement patché porte `read_time_patch`.
        for event in &events {
            assert!(
                event.get("read_time_patch").is_some(),
                "event {} must carry read_time_patch provenance",
                event["event_id"]
            );
        }

        // 5. Compteurs.
        assert_eq!(counters.events_seen.load(Ordering::Relaxed), 5);
        assert!(counters
            .events_patched_source_participant
            .load(Ordering::Relaxed)
            >= 5);
        assert!(counters
            .events_patched_destination_participant
            .load(Ordering::Relaxed)
            >= 5);
        assert!(counters.events_patched_direction.load(Ordering::Relaxed) >= 1);
        assert!(counters.events_patched_message_name.load(Ordering::Relaxed) >= 3);
        assert_eq!(counters.events_unresolved_participant.load(Ordering::Relaxed), 0);

        std::fs::remove_file(&jsonl_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// Fixture « déjà correcte » (format 2.14.5+) : le patcher doit
    /// être idempotent — aucun champ n'est modifié, aucun compteur
    /// `events_patched_*` n'avance.
    #[test]
    fn patcher_is_idempotent_on_already_correct_events() {
        let dir = std::env::temp_dir().join(format!(
            "oiran-read-time-patch-idempotent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = vec![raw_s1ap("evt-01", 12, 0, true, None)];
        let jsonl_path = write_jsonl(&dir, &raw);
        let index = RawEventIndex::from_jsonl_path(&jsonl_path).unwrap();
        // CallFlowEvent déjà conforme 2.14.5 : NF résolus, direction
        // transport, nom via la table S1AP.
        let mut events = vec![json!({
            "event_id": "evt-01",
            "interface": "S1-MME",
            "protocol": "S1AP",
            "message_name": "InitialUEMessage",
            "source_participant": "eNB",
            "destination_participant": "MME",
            "direction": "RAN_TO_CORE",
        })];
        let map = lab_endpoint_map();
        let counters = Arc::new(PatchCounters::new());
        let rewritten = patch_flow_events(&mut events, &index, &map, &counters);
        assert_eq!(rewritten, 0, "aucun événement ne doit être marqué patché");
        assert!(events[0].get("read_time_patch").is_none());
        assert_eq!(
            counters
                .events_patched_source_participant
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            counters
                .events_patched_destination_participant
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(counters.events_patched_direction.load(Ordering::Relaxed), 0);
        assert_eq!(
            counters.events_patched_message_name.load(Ordering::Relaxed),
            0
        );
        std::fs::remove_file(&jsonl_path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
