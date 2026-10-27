//! Canonical, UI-independent OIRAN Call Flow schema.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use session_engine::{Association, PacketRef, Reconstruction};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: &str = "1.1.0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Participant {
    pub id: String,
    pub role: String,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallFlowEvent {
    pub event_id: String,
    pub timestamp: String,
    pub timestamp_ns: String,
    pub interface: String,
    pub protocol: String,
    pub message_name: String,
    pub source_participant: String,
    pub destination_participant: String,
    pub direction: String,
    pub decoded_ie_tree: Value,
    pub decoding_status: String,
    pub semantic_status: String,
    pub association: Association,
    pub procedure_group: String,
    pub packet_references: Vec<PacketRef>,
    pub capture_id: String,
    pub decoder_name: String,
    pub decoder_version: String,
    pub raw_payload_reference: String,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationEdge {
    pub edge_id: String,
    pub source_event_id: String,
    pub target_event_id: String,
    pub source_interface: String,
    pub target_interface: String,
    pub matching_identifiers: Vec<String>,
    pub rule_id: String,
    pub rule_version: String,
    pub evidence_description: String,
    pub packet_references: Vec<PacketRef>,
    pub confidence: String,
    /// Typed evidence keeps an exact tunnel observation distinct from an
    /// exact UE/session identity relationship.
    #[serde(default = "unknown_evidence_type")]
    pub evidence_type: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub limitations: Vec<String>,
}

fn unknown_evidence_type() -> String {
    "UNKNOWN".into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Procedure {
    pub id: String,
    pub name: String,
    pub event_ids: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventAccounting {
    pub source_events: usize,
    pub session_events: usize,
    pub background_events: usize,
    pub unmatched_events: usize,
    pub duplicate_events: usize,
    pub extra_events: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallFlow {
    pub callflow_id: String,
    pub session_id: String,
    pub technology: String,
    pub start_timestamp: String,
    pub end_timestamp: String,
    pub participants: Vec<Participant>,
    pub interfaces: Vec<String>,
    pub procedures: Vec<Procedure>,
    pub events: Vec<CallFlowEvent>,
    pub correlation_edges: Vec<CorrelationEdge>,
    pub correlation_status: BTreeMap<String, String>,
    pub decoder_versions: BTreeMap<String, String>,
    pub schema_version: String,
    pub capture_references: Vec<String>,
    pub accounting: EventAccounting,
    pub unresolved_fields: usize,
}

pub fn build_callflow(reconstruction: &Reconstruction, edges: Vec<CorrelationEdge>) -> CallFlow {
    let mut participants: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut interfaces = BTreeSet::new();
    let mut captures = BTreeSet::new();
    let mut decoder_versions = BTreeMap::new();
    let mut procedures: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unresolved_fields = 0usize;
    let mut events = Vec::new();
    for event in &reconstruction.events {
        participants
            .entry(event.source_participant.clone())
            .or_default()
            .insert(event.source_address.clone());
        participants
            .entry(event.destination_participant.clone())
            .or_default()
            .insert(event.destination_address.clone());
        interfaces.insert(event.interface.clone());
        captures.insert(event.capture_id.clone());
        decoder_versions.insert(event.decoder_name.clone(), event.decoder_version.clone());
        let group = procedure_group(&event.protocol, &event.message_name);
        procedures
            .entry(group.clone())
            .or_default()
            .push(event.event_id.clone());
        if let Some(items) = event.information_elements.as_array() {
            unresolved_fields += items
                .iter()
                .filter(|ie| ie.get("status").and_then(Value::as_str) != Some("DECODED"))
                .count();
        }
        let association = reconstruction
            .association
            .get(&event.event_id)
            .copied()
            .unwrap_or(Association::Unmatched);
        events.push(CallFlowEvent {
            event_id: event.event_id.clone(),
            timestamp: event.timestamp.clone(),
            timestamp_ns: event.timestamp_ns.to_string(),
            interface: event.interface.clone(),
            protocol: event.protocol.clone(),
            message_name: event.message_name.clone(),
            source_participant: event.source_participant.clone(),
            destination_participant: event.destination_participant.clone(),
            direction: event.direction.clone(),
            decoded_ie_tree: event.information_elements.clone(),
            decoding_status: event.decoding_status.clone(),
            semantic_status: semantic_status(
                &event.message_name,
                &event.decoding_status,
                &event.information_elements,
            ),
            association,
            procedure_group: group,
            packet_references: event.packet_references.clone(),
            capture_id: event.capture_id.clone(),
            decoder_name: event.decoder_name.clone(),
            decoder_version: event.decoder_version.clone(),
            raw_payload_reference: event.raw_payload_reference.clone(),
            errors: event.errors.clone(),
        });
    }
    let session_events = reconstruction
        .association
        .values()
        .filter(|x| **x == Association::Session)
        .count();
    let background_events = reconstruction
        .association
        .values()
        .filter(|x| **x == Association::Background)
        .count();
    let unmatched_events = reconstruction
        .association
        .values()
        .filter(|x| **x == Association::Unmatched)
        .count();
    let mut correlation_status = BTreeMap::new();
    correlation_status.insert("N2_N4".into(), confidence_for(&edges, "N2", "N4"));
    correlation_status.insert("N2_SBI".into(), confidence_for(&edges, "N2", "SBI"));
    correlation_status.insert("SBI_N4".into(), confidence_for(&edges, "SBI", "N4"));
    correlation_status.insert("N4_N3".into(), confidence_for(&edges, "N4", "N3"));
    let proven = |key: &str| {
        matches!(
            correlation_status.get(key).map(String::as_str),
            Some("EXACT" | "STRONG")
        )
    };
    let e2e = if proven("N2_SBI") && proven("SBI_N4") && proven("N4_N3") {
        "STRONG"
    } else {
        "UNKNOWN"
    };
    correlation_status.insert("E2E".into(), e2e.into());
    let session_timestamps: Vec<_> = events
        .iter()
        .filter(|e| e.association == Association::Session)
        .map(|e| e.timestamp.clone())
        .collect();
    let participant_list = participants
        .into_iter()
        .map(|(role, addresses)| Participant {
            id: role.to_ascii_lowercase().replace(' ', "-"),
            role,
            addresses: addresses.into_iter().collect(),
        })
        .collect();
    let procedure_list = procedures
        .into_iter()
        .map(|(name, event_ids)| Procedure {
            id: name.to_ascii_lowercase().replace(' ', "-"),
            name,
            event_ids,
            status: "OBSERVED".into(),
        })
        .collect();
    CallFlow {
        callflow_id: format!("cf-{}", reconstruction.session_id),
        session_id: reconstruction.session_id.clone(),
        technology: "5G SA".into(),
        start_timestamp: session_timestamps.first().cloned().unwrap_or_default(),
        end_timestamp: session_timestamps.last().cloned().unwrap_or_default(),
        participants: participant_list,
        interfaces: interfaces.into_iter().collect(),
        procedures: procedure_list,
        events,
        correlation_edges: edges,
        correlation_status,
        decoder_versions,
        schema_version: VERSION.into(),
        capture_references: captures.into_iter().collect(),
        accounting: EventAccounting {
            source_events: reconstruction.events.len(),
            session_events,
            background_events,
            unmatched_events,
            duplicate_events: reconstruction.duplicate_event_ids.len(),
            extra_events: 0,
        },
        unresolved_fields,
    }
}

fn confidence_for(edges: &[CorrelationEdge], a: &str, b: &str) -> String {
    let mut value = "UNKNOWN";
    for edge in edges {
        if edge.source_interface == a && edge.target_interface == b {
            value = match (value, edge.confidence.as_str()) {
                (_, "EXACT") => "EXACT",
                ("UNKNOWN", "STRONG") => "STRONG",
                ("UNKNOWN", "POSSIBLE") => "POSSIBLE",
                (x, _) => x,
            };
        }
    }
    value.into()
}

fn procedure_group(protocol: &str, name: &str) -> String {
    if protocol == "SBI-HTTP2" {
        if name.contains("SMContext") {
            "SM Context".into()
        } else if name.contains("N1N2") {
            "N1/N2 Transfer".into()
        } else {
            "SBI Services".into()
        }
    } else if protocol == "GTP-U" {
        "User Plane".into()
    } else if name.contains("Heartbeat") || name.contains("Deletion") || name.contains("Release") {
        "Background / Lifecycle".into()
    } else if name.contains("PFCP Session") {
        "PFCP Session".into()
    } else if name.contains("PDUSession") {
        "PDU Session Resource Setup".into()
    } else {
        "UE Registration and Context".into()
    }
}

fn semantic_status(name: &str, decoding: &str, information_elements: &Value) -> String {
    if decoding != "DECODED" {
        "PARTIAL".into()
    } else if name.contains("Reject") || name.contains("Failure") {
        "FAILURE".into()
    } else if information_elements
        .as_array()
        .into_iter()
        .flatten()
        .filter(|ie| {
            ie.get("name")
                .and_then(Value::as_str)
                .map(|n| n.ends_with("Cause") || n == "Cause")
                .unwrap_or(false)
        })
        .filter_map(|ie| ie.get("value").and_then(Value::as_str))
        .any(|value| value.starts_with("cause=") && value != "cause=1")
    {
        "FAILURE".into()
    } else if name.contains("Response") || name.contains("Complete") {
        "SUCCESS".into()
    } else {
        "NORMAL".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_round_trip_has_required_fields() {
        let accounting = EventAccounting {
            source_events: 0,
            session_events: 0,
            background_events: 0,
            unmatched_events: 0,
            duplicate_events: 0,
            extra_events: 0,
        };
        let flow = CallFlow {
            callflow_id: "c".into(),
            session_id: "s".into(),
            technology: "5G SA".into(),
            start_timestamp: "a".into(),
            end_timestamp: "b".into(),
            participants: vec![],
            interfaces: vec![],
            procedures: vec![],
            events: vec![],
            correlation_edges: vec![],
            correlation_status: BTreeMap::new(),
            decoder_versions: BTreeMap::new(),
            schema_version: VERSION.into(),
            capture_references: vec![],
            accounting,
            unresolved_fields: 0,
        };
        let json = serde_json::to_string(&flow).unwrap();
        let decoded: CallFlow = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.schema_version, VERSION);
        assert_eq!(decoded.technology, "5G SA");
    }

    #[test]
    fn partial_decode_is_not_colored_success() {
        assert_eq!(
            semantic_status("Response", "PARTIAL", &serde_json::json!([])),
            "PARTIAL"
        );
        assert_eq!(
            semantic_status("Response", "DECODED", &serde_json::json!([])),
            "SUCCESS"
        );
        assert_eq!(
            semantic_status(
                "Response",
                "DECODED",
                &serde_json::json!([{"name":"Cause","value":"cause=64"}])
            ),
            "FAILURE"
        );
    }
}
