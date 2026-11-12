//! Subscriber journey index.
//!
//! The index is deliberately built only from already-pseudonymised callflow
//! fields.  It never uses timestamps, cell identifiers, addresses or IMEI as
//! evidence.  Canonical ordering is `(capture_id, packet_number, event_id)`.

use callflow_schema::{CallFlow, CallFlowEvent};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const SUBSCRIBER_NAMES: &[&str] = &[
    "subscriber_pseudonym",
    "imsi_pseudonym",
    "ue_identity_pseudonym",
];
const TEMPORARY_NAMES: &[&str] = &[
    "temporary_identity_pseudonym",
    "tmsi_pseudonym",
    "guti_pseudonym",
    "s_tmsi_pseudonym",
    "m_tmsi_pseudonym",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CanonicalRef {
    pub capture_id: String,
    pub packet_number: u64,
    pub event_id: String,
    pub session_id: String,
    pub message_name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct JourneySession {
    pub session_id: String,
    pub anchor_capture_id: String,
    pub first_packet_number: u64,
    pub technology: String,
    pub procedures: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct JourneyLink {
    pub source_session_id: String,
    pub target_session_id: String,
    pub status: &'static str,
    pub rule: &'static str,
    pub proof: Option<&'static str>,
    pub reason: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TmsiRecord {
    pub tmsi_pseudonym: String,
    pub assigned: Option<CanonicalRef>,
    pub presented: Vec<CanonicalRef>,
    pub status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct SubscriberRecord {
    pub subscriber_pseudonym: String,
    pub session_count: usize,
    pub technologies: Vec<String>,
    pub anchor_capture_id: String,
    pub first_packet_number: u64,
}

#[derive(Clone, Debug)]
struct SessionNode {
    session: JourneySession,
    subscribers: BTreeSet<String>,
    assignments: BTreeMap<String, Vec<CanonicalRef>>,
    presentations: BTreeMap<String, Vec<CanonicalRef>>,
}

#[derive(Clone, Debug, Default)]
pub struct JourneyIndex {
    nodes: BTreeMap<String, SessionNode>,
    sessions_by_subscriber: BTreeMap<String, BTreeSet<String>>,
}

fn values_named(value: &Value, names: &[&str], out: &mut BTreeSet<String>) {
    match value {
        Value::Array(values) => values
            .iter()
            .for_each(|value| values_named(value, names, out)),
        Value::Object(map) => {
            let name = map.get("name").and_then(Value::as_str).unwrap_or_default();
            if names.contains(&name) {
                if let Some(value) = map.get("value").and_then(Value::as_str) {
                    if value.starts_with("psn-") {
                        out.insert(value.to_owned());
                    }
                }
            }
            map.values()
                .for_each(|value| values_named(value, names, out));
        }
        _ => {}
    }
}

fn event_ref(flow: &CallFlow, event: &CallFlowEvent) -> CanonicalRef {
    CanonicalRef {
        capture_id: event.capture_id.clone(),
        packet_number: event
            .packet_references
            .iter()
            .map(|reference| reference.packet_number)
            .min()
            .unwrap_or(0),
        event_id: event.event_id.clone(),
        session_id: flow.session_id.clone(),
        message_name: event.message_name.clone(),
    }
}

fn is_assignment(message: &str) -> bool {
    matches!(
        message,
        "Attach Accept"
            | "Tracking Area Update Accept"
            | "GUTI Reallocation Command"
            | "Registration Accept"
            | "Configuration Update Command"
    )
}

fn is_presentation(message: &str) -> bool {
    message.contains("Request") || message.contains("Response")
}

fn anchor(flow: &CallFlow) -> (String, u64) {
    flow.events
        .iter()
        .flat_map(|event| {
            event.packet_references.iter().map(move |reference| {
                (
                    event.capture_id.clone(),
                    reference.packet_number,
                    event.event_id.clone(),
                )
            })
        })
        .min()
        .map(|(capture, packet, _)| (capture, packet))
        .unwrap_or_default()
}

impl JourneyIndex {
    pub fn from_flows<'a>(flows: impl IntoIterator<Item = &'a CallFlow>) -> Self {
        let mut index = Self::default();
        for flow in flows {
            let (anchor_capture_id, first_packet_number) = anchor(flow);
            let mut node = SessionNode {
                session: JourneySession {
                    session_id: flow.session_id.clone(),
                    anchor_capture_id,
                    first_packet_number,
                    technology: flow.technology.clone(),
                    procedures: flow.procedures.iter().map(|p| p.name.clone()).collect(),
                },
                subscribers: BTreeSet::new(),
                assignments: BTreeMap::new(),
                presentations: BTreeMap::new(),
            };
            for event in &flow.events {
                values_named(
                    &event.decoded_ie_tree,
                    SUBSCRIBER_NAMES,
                    &mut node.subscribers,
                );
                let mut temporary = BTreeSet::new();
                values_named(&event.decoded_ie_tree, TEMPORARY_NAMES, &mut temporary);
                let reference = event_ref(flow, event);
                for value in temporary {
                    if is_assignment(&event.message_name) {
                        node.assignments
                            .entry(value)
                            .or_default()
                            .push(reference.clone());
                    } else if is_presentation(&event.message_name) {
                        node.presentations
                            .entry(value)
                            .or_default()
                            .push(reference.clone());
                    }
                }
            }
            index.nodes.insert(flow.session_id.clone(), node);
        }
        index.resolve();
        index
    }

    fn resolve(&mut self) {
        for (session_id, node) in &self.nodes {
            for pseudo in &node.subscribers {
                self.sessions_by_subscriber
                    .entry(pseudo.clone())
                    .or_default()
                    .insert(session_id.clone());
            }
        }

        // A temporary identity links a later presentation only when its
        // assignment was observed and the assigning component identifies one
        // and only one subscriber. Multiple subscribers fail closed.
        let mut assignments: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for node in self.nodes.values() {
            for temporary in node.assignments.keys() {
                assignments
                    .entry(temporary.clone())
                    .or_default()
                    .extend(node.subscribers.iter().cloned());
            }
        }
        for (temporary, subscribers) in assignments {
            if subscribers.len() != 1 {
                continue;
            }
            let subscriber = subscribers.into_iter().next().expect("one subscriber");
            for (session_id, node) in &self.nodes {
                if node.presentations.contains_key(&temporary)
                    || node.assignments.contains_key(&temporary)
                {
                    self.sessions_by_subscriber
                        .entry(subscriber.clone())
                        .or_default()
                        .insert(session_id.clone());
                }
            }
        }
    }

    pub fn subscribers(&self) -> Vec<SubscriberRecord> {
        self.sessions_by_subscriber
            .iter()
            .filter_map(|(pseudo, ids)| {
                let mut sessions = ids
                    .iter()
                    .filter_map(|id| self.nodes.get(id))
                    .collect::<Vec<_>>();
                sessions.sort_by_key(|node| {
                    (
                        &node.session.anchor_capture_id,
                        node.session.first_packet_number,
                        &node.session.session_id,
                    )
                });
                let first = sessions.first()?;
                let technologies = sessions
                    .iter()
                    .map(|node| node.session.technology.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                Some(SubscriberRecord {
                    subscriber_pseudonym: pseudo.clone(),
                    session_count: sessions.len(),
                    technologies,
                    anchor_capture_id: first.session.anchor_capture_id.clone(),
                    first_packet_number: first.session.first_packet_number,
                })
            })
            .collect()
    }

    pub fn subscriber_for_session(&self, session_id: &str) -> Option<&str> {
        let mut matches = self
            .sessions_by_subscriber
            .iter()
            .filter(|(_, sessions)| sessions.contains(session_id))
            .map(|(subscriber, _)| subscriber.as_str());
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }

    pub fn sessions(&self, subscriber: &str) -> Vec<JourneySession> {
        let mut sessions = self
            .sessions_by_subscriber
            .get(subscriber)
            .into_iter()
            .flatten()
            .filter_map(|id| self.nodes.get(id).map(|node| node.session.clone()))
            .collect::<Vec<_>>();
        sessions.sort_by_key(|session| {
            (
                session.anchor_capture_id.clone(),
                session.first_packet_number,
                session.session_id.clone(),
            )
        });
        sessions
    }

    fn shared_tmsi(&self, left: &str, right: &str) -> bool {
        let Some(left) = self.nodes.get(left) else {
            return false;
        };
        let Some(right) = self.nodes.get(right) else {
            return false;
        };
        left.assignments
            .keys()
            .any(|key| right.presentations.contains_key(key))
    }

    pub fn links(&self, subscriber: &str) -> Vec<JourneyLink> {
        self.sessions(subscriber)
            .windows(2)
            .map(|pair| {
                let left = &pair[0].session_id;
                let right = &pair[1].session_id;
                let direct = self
                    .nodes
                    .get(left)
                    .is_some_and(|n| n.subscribers.contains(subscriber))
                    && self
                        .nodes
                        .get(right)
                        .is_some_and(|n| n.subscribers.contains(subscriber));
                if direct {
                    JourneyLink {
                        source_session_id: left.clone(),
                        target_session_id: right.clone(),
                        status: "EXACT",
                        rule: "subscriber-pseudonym-equality",
                        proof: Some("subscriber_pseudonym"),
                        reason: None,
                    }
                } else if self.shared_tmsi(left, right) {
                    JourneyLink {
                        source_session_id: left.clone(),
                        target_session_id: right.clone(),
                        status: "EXACT",
                        rule: "assigned-then-presented-tmsi",
                        proof: Some("temporary_identity_pseudonym"),
                        reason: None,
                    }
                } else {
                    JourneyLink {
                        source_session_id: left.clone(),
                        target_session_id: right.clone(),
                        status: "OUVERT",
                        rule: "assigned-then-presented-tmsi",
                        proof: None,
                        reason: Some("attribution non capturée"),
                    }
                }
            })
            .collect()
    }

    pub fn tmsi(&self, subscriber: &str) -> Vec<TmsiRecord> {
        let ids = self.sessions_by_subscriber.get(subscriber);
        let mut grouped: BTreeMap<String, (Vec<CanonicalRef>, Vec<CanonicalRef>)> = BTreeMap::new();
        for node in ids
            .into_iter()
            .flatten()
            .filter_map(|id| self.nodes.get(id))
        {
            for (key, values) in &node.assignments {
                grouped
                    .entry(key.clone())
                    .or_default()
                    .0
                    .extend(values.clone());
            }
            for (key, values) in &node.presentations {
                grouped
                    .entry(key.clone())
                    .or_default()
                    .1
                    .extend(values.clone());
            }
        }
        let mut rows = grouped
            .into_iter()
            .map(|(pseudo, (mut assigned, mut presented))| {
                assigned.sort();
                assigned.dedup();
                presented.sort();
                presented.dedup();
                TmsiRecord {
                    tmsi_pseudonym: pseudo,
                    assigned: assigned.first().cloned(),
                    presented,
                    status: if assigned.is_empty() {
                        "attribution non capturée"
                    } else {
                        "active"
                    },
                }
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|row| row.assigned.clone());
        if rows.len() > 1 {
            for index in 0..rows.len() - 1 {
                if rows[index].assigned.is_some() {
                    rows[index].status = "remplacé";
                }
            }
        }
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use callflow_schema::{EventAccounting, Procedure};
    use session_engine::{Association, PacketRef};

    fn flow(
        id: &str,
        packet: u64,
        subscriber: Option<&str>,
        temporary: Option<(&str, &str)>,
    ) -> CallFlow {
        let mut ies = Vec::new();
        if let Some(value) = subscriber {
            ies.push(serde_json::json!({"name":"subscriber_pseudonym","value":value}));
        }
        if let Some((_, value)) = temporary {
            ies.push(serde_json::json!({"name":"temporary_identity_pseudonym","value":value}));
        }
        let message = temporary
            .map(|(role, _)| {
                if role == "assigned" {
                    "Attach Accept"
                } else {
                    "Attach Request"
                }
            })
            .unwrap_or("Attach Request");
        CallFlow {
            callflow_id: id.into(),
            session_id: id.into(),
            technology: "LTE".into(),
            start_timestamp: String::new(),
            end_timestamp: String::new(),
            participants: vec![],
            interfaces: vec!["S1-MME".into()],
            procedures: vec![Procedure {
                id: "attach".into(),
                name: "Attach".into(),
                event_ids: vec![],
                status: "SUCCESS".into(),
            }],
            events: vec![CallFlowEvent {
                event_id: format!("evt-{id}"),
                timestamp: String::new(),
                timestamp_ns: String::new(),
                interface: "S1-MME".into(),
                protocol: "NAS-EPS".into(),
                message_name: message.into(),
                source_participant: String::new(),
                destination_participant: String::new(),
                direction: String::new(),
                decoded_ie_tree: Value::Array(ies),
                decoding_status: "DECODED".into(),
                semantic_status: "SUCCESS".into(),
                association: Association::Session,
                procedure_group: "Attach".into(),
                packet_references: vec![PacketRef {
                    source_file: String::new(),
                    packet_number: packet,
                    byte_offset: 0,
                    interface_id: 0,
                    captured_length: 0,
                    original_length: 0,
                }],
                capture_id: "capture-a".into(),
                decoder_name: "decoder-nas".into(),
                decoder_version: String::new(),
                raw_payload_reference: String::new(),
                errors: vec![],
            }],
            correlation_edges: vec![],
            correlation_status: BTreeMap::new(),
            decoder_versions: BTreeMap::new(),
            schema_version: String::new(),
            capture_references: vec![],
            accounting: EventAccounting {
                source_events: 1,
                session_events: 1,
                background_events: 0,
                unmatched_events: 0,
                duplicate_events: 0,
                extra_events: 0,
            },
            unresolved_fields: 0,
        }
    }

    #[test]
    fn assigned_then_presented_tmsi_links_sessions_without_time_cell_or_ip() {
        let flows = vec![
            flow(
                "a",
                1,
                Some("psn-subscriber-a"),
                Some(("assigned", "psn-tmsi-a")),
            ),
            flow("b", 2, None, Some(("presented", "psn-tmsi-a"))),
        ];
        let index = JourneyIndex::from_flows(&flows);
        assert_eq!(index.sessions("psn-subscriber-a").len(), 2);
        assert_eq!(index.links("psn-subscriber-a")[0].status, "EXACT");
        assert_eq!(
            index.links("psn-subscriber-a")[0].rule,
            "assigned-then-presented-tmsi"
        );
    }

    #[test]
    fn presentation_without_assignment_is_not_linked() {
        let flows = vec![
            flow("a", 1, Some("psn-subscriber-a"), None),
            flow("b", 2, None, Some(("presented", "psn-tmsi-a"))),
        ];
        let index = JourneyIndex::from_flows(&flows);
        assert_eq!(index.sessions("psn-subscriber-a").len(), 1);
    }
}
