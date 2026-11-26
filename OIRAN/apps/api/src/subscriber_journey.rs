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
    /// 2.21.95 (défaut recette #10 7039298457, ordre #9 7039438165) —
    /// clé de corrélation live↔publi propagée depuis `CallFlowEvent`.
    /// `skip_serializing_if = "String::is_empty"` préserve la sortie
    /// pour les datasets pré-2.21.91 qui ne portent pas le champ.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stable_event_key: String,
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
    /// Identités d'abonné de la session. Après `resolve` : les
    /// représentants de leurs groupes d'alias.
    subscribers: BTreeSet<String>,
    assignments: BTreeMap<String, Vec<CanonicalRef>>,
    presentations: BTreeMap<String, Vec<CanonicalRef>>,
}

#[derive(Clone, Debug, Default)]
pub struct JourneyIndex {
    nodes: BTreeMap<String, SessionNode>,
    sessions_by_subscriber: BTreeMap<String, BTreeSet<String>>,
    /// 2.21.155 — jeton d'abonné → représentant de son groupe d'alias.
    alias_of: BTreeMap<String, String>,
    /// 2.21.155 — sessions qui portent les identités de plusieurs abonnés
    /// distincts : rangées sous aucun, et comptées.
    ambiguous_sessions: usize,
    /// 2.21.155 — groupes d'alias de plus d'un jeton (réunions faites).
    alias_groups_with_several_tokens: usize,
    /// 2.21.156 — paires typées écartées parce qu'un de leurs jetons
    /// figure dans une autre paire : aucune chaîne de réunions.
    alias_pairs_conflicting: usize,
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
        // 2.21.95 — propagation depuis CallFlowEvent (callflow-schema 1.5.0).
        stable_event_key: event.stable_event_key.clone(),
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

#[derive(Debug, Default)]
pub struct JourneyIndexBuilder {
    nodes: BTreeMap<String, SessionNode>,
    /// 2.21.156 — paires d'alias typées (AVP 1 + AVP 701 d'un même message
    /// Diameter) : lues dans les call flows non compactés et ajoutées depuis
    /// le manifeste. Sans elles, aucune réunion.
    alias_pairs: BTreeSet<(String, String)>,
}

impl JourneyIndexBuilder {
    pub fn observe(&mut self, flow: &CallFlow) {
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
        // 2.21.154 / 2.21.155 — jetons qui ne désignent pas un abonné :
        // l'IMEISV masqué (équipement) et la 5G-S-TMSI (identité
        // temporaire), quand leur IE NGAP est encore dans le call flow.
        // Ceux d'un call flow compacté arrivent déjà renommés par la
        // lecture (`CaptureManager::callflow`).
        let mut excluded = callflow_schema::masked_imeisv_tokens(flow.events.iter().map(|event| &event.decoded_ie_tree));
        excluded.extend(callflow_schema::s_tmsi_tokens(flow.events.iter().map(|event| &event.decoded_ie_tree)));
        for event in &flow.events {
            // 2.21.155 (ordre cœur #9 7102937368) — un message SIP porte
            // l'identité du PAIR (`From` de l'appelant, dans la session de
            // l'appelé aussi) : il n'apporte aucune identité à la session.
            // Avant : la session de B, appelé par A, comptait A parmi ses
            // abonnés, et l'entrée de A listait la session de B.
            if event.protocol == "SIP" {
                continue;
            }
            let mut in_event = BTreeSet::new();
            values_named(&event.decoded_ie_tree, SUBSCRIBER_NAMES, &mut in_event);
            in_event.retain(|token| !excluded.contains(token));
            // 2.21.156 (REFUS ANR1 #10 7105482150, ordre cœur #9
            // 7105668821) — la présence de deux identités dans un même
            // message n'est PAS une preuve : seule la paire typée AVP 1 +
            // AVP 701 d'un message Diameter réunit. En 2.21.155, toute
            // cooccurrence hors SIP réunissait, et une session portant deux
            // abonnés réels était attribuée à l'un d'eux.
            if let Some(pair) = session_engine::diameter_subscriber_alias_pair(&event.protocol, &event.decoded_ie_tree) {
                self.alias_pairs.insert(pair);
            }
            node.subscribers.extend(in_event);
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
        self.nodes.insert(flow.session_id.clone(), node);
    }

    /// 2.21.156 — ajoute les paires typées relevées avant compaction
    /// (`LiveDataset.subscriber_alias_pairs`). Additif : une liste vide
    /// laisse le parcours en sûreté.
    pub fn add_alias_pairs(&mut self, pairs: impl IntoIterator<Item = (String, String)>) {
        self.alias_pairs.extend(pairs);
    }

    pub fn finish(self) -> JourneyIndex {
        let alias_pairs = self.alias_pairs;
        let mut index = JourneyIndex {
            nodes: self.nodes,
            sessions_by_subscriber: BTreeMap::new(),
            alias_of: BTreeMap::new(),
            ambiguous_sessions: 0,
            alias_groups_with_several_tokens: 0,
            alias_pairs_conflicting: 0,
        };
        index.resolve(&alias_pairs);
        index
    }
}

impl JourneyIndex {
    pub fn builder() -> JourneyIndexBuilder {
        JourneyIndexBuilder::default()
    }

    pub fn from_flows<'a>(flows: impl IntoIterator<Item = &'a CallFlow>) -> Self {
        let mut builder = Self::builder();
        for flow in flows {
            builder.observe(flow);
        }
        builder.finish()
    }

    fn resolve(&mut self, alias_pairs: &BTreeSet<(String, String)>) {
        // 2.21.156 (ordre cœur #9 7105668821) — SÛRETÉ PAR DÉFAUT : chaque
        // jeton est son propre représentant. Seule une paire typée (AVP 1 +
        // AVP 701 d'un même message Diameter) réunit deux jetons, et
        // seulement si aucun des deux ne figure dans une autre paire : un
        // groupe compte au plus deux jetons, aucune chaîne. Le représentant
        // est le plus petit jeton de la paire.
        let mut uses: BTreeMap<&str, usize> = BTreeMap::new();
        for (a, b) in alias_pairs {
            *uses.entry(a.as_str()).or_default() += 1;
            *uses.entry(b.as_str()).or_default() += 1;
        }
        for (a, b) in alias_pairs {
            if uses.get(a.as_str()) == Some(&1) && uses.get(b.as_str()) == Some(&1) {
                let (low, high) = if a < b { (a, b) } else { (b, a) };
                self.alias_of.insert(high.clone(), low.clone());
                self.alias_of.insert(low.clone(), low.clone());
                self.alias_groups_with_several_tokens += 1;
            } else {
                self.alias_pairs_conflicting += 1;
            }
        }
        // Une session appartient à un abonné si toutes ses identités sont
        // des alias de ce seul abonné ; sinon elle est ambiguë : rangée
        // sous aucun, et comptée (2.21.155, ordre cœur #9 7102937368).
        for (session_id, node) in self.nodes.iter_mut() {
            let representatives: BTreeSet<String> = node
                .subscribers
                .iter()
                .map(|token| self.alias_of.get(token).cloned().unwrap_or_else(|| token.clone()))
                .collect();
            node.subscribers = representatives;
            match node.subscribers.len() {
                0 => {}
                1 => {
                    let only = node.subscribers.iter().next().expect("one").clone();
                    self.sessions_by_subscriber.entry(only).or_default().insert(session_id.clone());
                }
                _ => self.ambiguous_sessions += 1,
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

    /// 2.21.155 — sessions portant les identités de plusieurs abonnés
    /// distincts, rangées sous aucun.
    pub fn ambiguous_sessions(&self) -> usize {
        self.ambiguous_sessions
    }

    /// 2.21.155 — groupes d'alias de plus d'un jeton.
    pub fn alias_groups_with_several_tokens(&self) -> usize {
        self.alias_groups_with_several_tokens
    }

    /// 2.21.156 — paires typées écartées faute d'être exclusives.
    pub fn alias_pairs_conflicting(&self) -> usize {
        self.alias_pairs_conflicting
    }

    /// 2.21.155 — représentant du groupe d'alias d'un jeton d'abonné.
    fn canonical<'a>(&'a self, subscriber: &'a str) -> &'a str {
        self.alias_of.get(subscriber).map(String::as_str).unwrap_or(subscriber)
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
        let subscriber = self.canonical(subscriber);
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
        let subscriber = self.canonical(subscriber);
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
        let ids = self.sessions_by_subscriber.get(self.canonical(subscriber));
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
                stable_event_key: String::new(),
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
                    sctp_association: None,
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
                probe_id: None,
                probe_type: None,
                physical_link: None,
                timestamp_source: None,
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

    #[test]
    fn presentation_without_captured_assignment_is_open() {
        // Synthetic PLMN 001-01 context; only pseudonyms enter the journey.
        let flows = vec![flow(
            "a",
            1,
            Some("psn-subscriber-a"),
            Some(("presented", "psn-tmsi-a")),
        )];
        let index = JourneyIndex::from_flows(&flows);
        let tmsi = index.tmsi("psn-subscriber-a");
        assert_eq!(tmsi.len(), 1);
        assert_eq!(tmsi[0].status, "attribution non capturée");
        assert!(tmsi[0].assigned.is_none());
    }

    // 2.21.23 — règle #9 6947485672 : test d'équivalence entre
    // l'ancienne API `from_flows(IntoIterator)` (matérialise toutes les
    // références en RAM) et le builder streaming `observe` (utilisé par
    // `cached_journey_index` qui ne garde qu'UN callflow en RAM à la
    // fois). Le résultat observable (sessions / links / tmsi par
    // subscriber) doit être identique.
    #[test]
    fn builder_streaming_matches_from_flows() {
        let flows = vec![
            flow(
                "a",
                1,
                Some("psn-subscriber-a"),
                Some(("assigned", "psn-tmsi-a")),
            ),
            flow("b", 2, None, Some(("presented", "psn-tmsi-a"))),
            flow("c", 3, Some("psn-subscriber-b"), None),
            flow(
                "d",
                4,
                Some("psn-subscriber-a"),
                Some(("presented", "psn-tmsi-b")),
            ),
        ];

        let legacy = JourneyIndex::from_flows(&flows);

        let mut builder = JourneyIndex::builder();
        for flow in &flows {
            builder.observe(flow);
        }
        let streaming = builder.finish();

        for subscriber in ["psn-subscriber-a", "psn-subscriber-b"] {
            let legacy_sessions = legacy.sessions(subscriber);
            let streaming_sessions = streaming.sessions(subscriber);
            assert_eq!(
                serde_json::to_value(&legacy_sessions).unwrap(),
                serde_json::to_value(&streaming_sessions).unwrap(),
                "sessions({subscriber}) diverge entre from_flows et builder",
            );
            let legacy_links = legacy.links(subscriber);
            let streaming_links = streaming.links(subscriber);
            assert_eq!(
                serde_json::to_value(&legacy_links).unwrap(),
                serde_json::to_value(&streaming_links).unwrap(),
                "links({subscriber}) diverge entre from_flows et builder",
            );
            let legacy_tmsi = legacy.tmsi(subscriber);
            let streaming_tmsi = streaming.tmsi(subscriber);
            assert_eq!(
                serde_json::to_value(&legacy_tmsi).unwrap(),
                serde_json::to_value(&streaming_tmsi).unwrap(),
                "tmsi({subscriber}) diverge entre from_flows et builder",
            );
        }
        assert_eq!(
            serde_json::to_value(legacy.subscribers()).unwrap(),
            serde_json::to_value(streaming.subscribers()).unwrap(),
        );
    }
}

#[cfg(test)]
mod masked_imeisv_journey_tests_2_21_154 {
    use super::*;

    /// 2.21.154 (sonde #9 7098759157, devenue permanente) — deux sessions de
    /// deux UE qui ne partagent que l'IMEISV masqué ne forment pas un
    /// abonné, ni un parcours. Une session qui porte aussi son IMSI est
    /// rattachée à son seul abonné (avant : deux « abonnés », donc aucun).
    #[test]
    fn two_ues_sharing_only_the_masked_imeisv_are_not_one_subscriber_2_21_154() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().join("OIRAN_5G_E2E_CALLFLOW.json");
        let template: CallFlow = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let imeisv = "psn-0123456789abcdef0123456789abcdef";
        fn strip(value: &mut Value) {
            match value {
                Value::Array(items) => {
                    items.retain(|item| !item.to_string().contains("psn-"));
                    items.iter_mut().for_each(strip)
                }
                Value::Object(map) => map.values_mut().for_each(strip),
                _ => {}
            }
        }
        let flow = |session: &str, imsi: Option<&str>| {
            let mut flow = template.clone();
            flow.session_id = session.into();
            for event in &mut flow.events {
                strip(&mut event.decoded_ie_tree);
            }
            let event = flow.events.iter_mut().find(|e| e.protocol == "NGAP").unwrap();
            let mut tree = vec![
                serde_json::json!({"id": 34, "name": "identity_pseudonym", "value": format!("subscriber_pseudonym={imeisv}")}),
                serde_json::json!({"name": "subscriber_pseudonym", "value": imeisv, "source": "session_identifiers"}),
            ];
            if let Some(imsi) = imsi {
                tree.push(serde_json::json!({"name": "subscriber_pseudonym", "value": imsi, "source": "session_identifiers"}));
            }
            event.decoded_ie_tree = Value::Array(tree);
            flow
        };
        // Deux UE, seul l'IMEISV en commun.
        let (a, b) = (flow("5g-session-ue-a", None), flow("5g-session-ue-b", None));
        let index = JourneyIndex::from_flows([&a, &b]);
        assert!(index.subscribers().is_empty(), "l'IMEISV masqué n'est pas un abonné : {:?}", index.subscribers().iter().map(|r| &r.subscriber_pseudonym).collect::<Vec<_>>());
        assert_eq!(index.subscriber_for_session("5g-session-ue-a"), None);
        assert!(index.sessions(imeisv).is_empty(), "aucun parcours par ce jeton");
        // Avec l'IMSI de chacun : deux abonnés distincts, une session chacun.
        let imsi_a = "psn-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let imsi_b = "psn-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let (a, b) = (flow("5g-session-ue-a", Some(imsi_a)), flow("5g-session-ue-b", Some(imsi_b)));
        let index = JourneyIndex::from_flows([&a, &b]);
        assert_eq!(index.subscriber_for_session("5g-session-ue-a"), Some(imsi_a), "rattachée à son seul abonné");
        assert_eq!(index.subscriber_for_session("5g-session-ue-b"), Some(imsi_b));
        assert_eq!(index.sessions(imsi_a).len(), 1);
        assert_eq!(index.subscribers().len(), 2);
    }
}

#[cfg(test)]
mod journey_identity_tests_2_21_155 {
    use super::*;

    const IMSI_A: &str = "psn-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const IMSI_B: &str = "psn-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const MSISDN_A: &str = "psn-cccccccccccccccccccccccccccccccc";
    const TMSI: &str = "psn-dddddddddddddddddddddddddddddddd";

    fn template() -> CallFlow {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().join("OIRAN_5G_E2E_CALLFLOW.json");
        let mut flow: CallFlow = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        fn strip(value: &mut Value) {
            match value {
                Value::Array(items) => {
                    items.retain(|item| !item.to_string().contains("psn-"));
                    items.iter_mut().for_each(strip)
                }
                Value::Object(map) => map.values_mut().for_each(strip),
                _ => {}
            }
        }
        for event in &mut flow.events {
            strip(&mut event.decoded_ie_tree);
        }
        flow
    }

    /// Un call flow dont les events portent, dans l'ordre, les arbres donnés
    /// (protocole, arbre) ; les autres events n'ont aucune identité.
    fn flow(session: &str, trees: &[(&str, Value)]) -> CallFlow {
        let mut flow = template();
        flow.session_id = session.into();
        for (event, (protocol, tree)) in flow.events.iter_mut().zip(trees) {
            event.protocol = (*protocol).into();
            event.decoded_ie_tree = tree.clone();
        }
        flow
    }

    fn id(name: &str, value: &str) -> Value {
        serde_json::json!({"name": name, "value": value, "source": "session_identifiers"})
    }

    /// 2.21.155 (ordre cœur #9 7102937368, FAIL C d'ANR2 #10 7102867871) —
    /// test 1 : B est appelé par A ; la session IMS de B porte, sur ses
    /// messages SIP, le `From` de A. Avant : la session de B comptait A parmi
    /// ses abonnés, l'entrée de A listait la session de B, et la session de B
    /// n'était pas décorée (deux « abonnés »).
    #[test]
    fn a_sip_call_does_not_put_the_callee_session_under_the_caller_2_21_155() {
        let a = flow("5g-session-ue-a", &[("NGAP", serde_json::json!([id("subscriber_pseudonym", IMSI_A)]))]);
        let b = flow(
            "5g-session-ue-b",
            &[
                ("NGAP", serde_json::json!([id("subscriber_pseudonym", IMSI_B)])),
                ("SIP", serde_json::json!([id("subscriber_pseudonym", IMSI_A)])),
            ],
        );
        let index = JourneyIndex::from_flows([&a, &b]);
        assert_eq!(index.sessions(IMSI_A).iter().map(|s| s.session_id.as_str()).collect::<Vec<_>>(), vec!["5g-session-ue-a"]);
        assert_eq!(index.subscriber_for_session("5g-session-ue-b"), Some(IMSI_B), "la session de B est à B, et décorée");
        assert_eq!(index.ambiguous_sessions(), 0);
    }

    /// Test 2 : deux UE dont la 5G-S-TMSI (IE NGAP 26) a la même valeur, et
    /// aucune autre identité visible. Avant : un seul « abonné », deux
    /// sessions. Après : la TMSI n'est pas un abonné.
    #[test]
    fn a_reassigned_5g_s_tmsi_does_not_make_two_ues_one_subscriber_2_21_155() {
        let tree = || serde_json::json!([
            {"id": 26, "name": "identity_pseudonym", "value": format!("subscriber_pseudonym={TMSI}")},
            id("subscriber_pseudonym", TMSI)
        ]);
        let a = flow("5g-session-ue-a", &[("NGAP", tree())]);
        let b = flow("5g-session-ue-b", &[("NGAP", tree())]);
        let index = JourneyIndex::from_flows([&a, &b]);
        assert!(index.subscribers().is_empty(), "{:?}", index.subscribers().iter().map(|r| &r.subscriber_pseudonym).collect::<Vec<_>>());
        assert!(index.sessions(TMSI).is_empty());
    }

    /// Test 3 : une session qui porte, sur deux messages distincts, les
    /// IMSI de deux abonnés : ambiguë, rangée sous aucun, et comptée.
    #[test]
    fn a_session_carrying_two_subscribers_is_ambiguous_and_counted_2_21_155() {
        let mixed = flow(
            "5g-session-mixte",
            &[
                ("NGAP", serde_json::json!([id("subscriber_pseudonym", IMSI_A)])),
                ("NAS-5GMM", serde_json::json!([id("subscriber_pseudonym", IMSI_B)])),
            ],
        );
        let a = flow("5g-session-ue-a", &[("NGAP", serde_json::json!([id("subscriber_pseudonym", IMSI_A)]))]);
        let index = JourneyIndex::from_flows([&mixed, &a]);
        assert_eq!(index.ambiguous_sessions(), 1);
        assert_eq!(index.subscriber_for_session("5g-session-mixte"), None);
        assert_eq!(index.sessions(IMSI_A).len(), 1, "l'entrée de A ne compte pas la session ambiguë");
        assert!(index.sessions(IMSI_B).is_empty());
    }

    fn avp(code: u64, value: &str) -> Value {
        serde_json::json!({"id": code, "name": "identity_pseudonym", "value": format!("subscriber_pseudonym={value}")})
    }

    /// 2.21.156 (ordre cœur #9 7105668821) — IMSI (AVP 1) et MSISDN (AVP
    /// 701) d'un même message Diameter : la seule preuve typée. Une autre
    /// session ne porte que le MSISDN. Une seule entrée, deux sessions,
    /// toutes deux décorées ; on la retrouve par l'un ou l'autre jeton.
    #[test]
    fn user_name_and_msisdn_of_one_diameter_message_are_one_subscriber_2_21_156() {
        let attach = flow(
            "lte-session-1",
            &[("DIAMETER", serde_json::json!([avp(1, IMSI_A), avp(701, MSISDN_A), id("subscriber_pseudonym", IMSI_A), id("subscriber_pseudonym", MSISDN_A)]))],
        );
        let later = flow("lte-session-2", &[("DIAMETER", serde_json::json!([id("subscriber_pseudonym", MSISDN_A)]))]);
        let index = JourneyIndex::from_flows([&attach, &later]);
        assert_eq!(index.subscribers().len(), 1);
        let key = index.subscriber_for_session("lte-session-1").expect("décorée");
        assert_eq!(index.subscriber_for_session("lte-session-2"), Some(key));
        assert_eq!(index.sessions(IMSI_A).len(), 2, "chercher par l'IMSI");
        assert_eq!(index.sessions(MSISDN_A).len(), 2, "ou par le MSISDN");
        assert_eq!(index.ambiguous_sessions(), 0);
        assert_eq!(index.alias_groups_with_several_tokens(), 1);
    }

    /// 2.21.156 — contre-test d'ANR1 (#10 7105482150,
    /// `anr1_non_sip_message_with_two_distinct_subscribers_must_not_alias_them`),
    /// permanent : un même message NGAP, hors SIP, porte deux abonnés
    /// distincts. Sur 2.21.155 : la session était attribuée à A. Attendu :
    /// ambiguë, rangée sous aucun.
    #[test]
    fn anr1_non_sip_message_with_two_distinct_subscribers_must_not_alias_them_2_21_156() {
        let mixed = flow(
            "5g-session-mixte",
            &[("NGAP", serde_json::json!([id("subscriber_pseudonym", IMSI_A), id("subscriber_pseudonym", IMSI_B)]))],
        );
        let a = flow("5g-session-ue-a", &[("NGAP", serde_json::json!([id("subscriber_pseudonym", IMSI_A)]))]);
        let b = flow("5g-session-ue-b", &[("NGAP", serde_json::json!([id("subscriber_pseudonym", IMSI_B)]))]);
        let index = JourneyIndex::from_flows([&mixed, &a, &b]);
        assert_eq!(index.subscriber_for_session("5g-session-mixte"), None);
        assert_eq!(index.ambiguous_sessions(), 1);
        assert_eq!(index.subscribers().len(), 2);
        assert_eq!(index.sessions(IMSI_A).len(), 1);
        assert_eq!(index.sessions(IMSI_B).len(), 1);
        assert_eq!(index.alias_groups_with_several_tokens(), 0);
    }

    /// 2.21.156 — deux AVP 1 différentes dans un même message Diameter :
    /// aucune preuve, aucune réunion, session ambiguë.
    #[test]
    fn two_different_user_names_in_one_diameter_message_stay_apart_2_21_156() {
        let mixed = flow(
            "lte-session-mixte",
            &[("DIAMETER", serde_json::json!([avp(1, IMSI_A), avp(1, IMSI_B), avp(701, MSISDN_A), id("subscriber_pseudonym", IMSI_A), id("subscriber_pseudonym", IMSI_B)]))],
        );
        let index = JourneyIndex::from_flows([&mixed]);
        assert_eq!(index.subscriber_for_session("lte-session-mixte"), None);
        assert_eq!(index.ambiguous_sessions(), 1);
        assert_eq!(index.alias_groups_with_several_tokens(), 0);
    }

    /// 2.21.156 — liste d'alias vide ou absente (call flows compactés, sans
    /// IE Diameter, manifeste sans paires) : la session qui porte IMSI et
    /// MSISDN est ambiguë, jamais attribuée. La même paire fournie par le
    /// manifeste la rattache. Une paire en conflit (un jeton dans deux
    /// paires) ne réunit rien.
    #[test]
    fn without_a_typed_pair_a_mixed_session_is_ambiguous_and_the_manifest_pair_is_additive_2_21_156() {
        let compacted = || {
            flow(
                "lte-session-1",
                &[
                    ("DIAMETER", serde_json::json!([id("subscriber_pseudonym", IMSI_A)])),
                    ("DIAMETER", serde_json::json!([id("subscriber_pseudonym", MSISDN_A)])),
                ],
            )
        };
        let without = JourneyIndex::from_flows([&compacted()]);
        assert_eq!(without.subscriber_for_session("lte-session-1"), None);
        assert_eq!(without.ambiguous_sessions(), 1);
        let mut builder = JourneyIndex::builder();
        builder.add_alias_pairs(Vec::new());
        builder.observe(&compacted());
        assert_eq!(builder.finish().ambiguous_sessions(), 1, "liste vide : sûreté");
        let mut builder = JourneyIndex::builder();
        builder.add_alias_pairs([(IMSI_A.to_owned(), MSISDN_A.to_owned())]);
        builder.observe(&compacted());
        let with = builder.finish();
        assert_eq!(with.subscriber_for_session("lte-session-1"), Some(IMSI_A));
        assert_eq!(with.ambiguous_sessions(), 0);
        let mut builder = JourneyIndex::builder();
        builder.add_alias_pairs([(IMSI_A.to_owned(), MSISDN_A.to_owned()), (IMSI_B.to_owned(), MSISDN_A.to_owned())]);
        builder.observe(&compacted());
        let conflicting = builder.finish();
        assert_eq!(conflicting.subscriber_for_session("lte-session-1"), None);
        assert_eq!(conflicting.alias_pairs_conflicting(), 2);
        assert_eq!(conflicting.alias_groups_with_several_tokens(), 0);
    }

    /// 2.21.156 — cas légitime toujours vert : un abonné change de S-TMSI.
    /// La session 1 porte son IMSI et l'attribution de T ; la session 2 ne
    /// présente que T. Un abonné, deux sessions ; un second UE reste à part.
    #[test]
    fn a_subscriber_changing_tmsi_stays_one_subscriber_with_two_sessions_2_21_156() {
        let mut first = flow("5g-session-1", &[("NAS-5GMM", serde_json::json!([id("subscriber_pseudonym", IMSI_A), id("guti_pseudonym", TMSI)]))]);
        first.events[0].message_name = "Registration Accept".into();
        let mut second = flow("5g-session-2", &[("NAS-5GMM", serde_json::json!([id("guti_pseudonym", TMSI)]))]);
        second.events[0].message_name = "Service Request".into();
        let other = flow("5g-session-ue-b", &[("NGAP", serde_json::json!([id("subscriber_pseudonym", IMSI_B)]))]);
        let index = JourneyIndex::from_flows([&first, &second, &other]);
        assert_eq!(index.sessions(IMSI_A).len(), 2);
        assert_eq!(index.sessions(IMSI_B).len(), 1);
        assert_eq!(index.ambiguous_sessions(), 0);
    }

    /// Test 4 : non-régression sur la capture du banc lab à cinq abonnés,
    /// call flows construits comme la publication : cinq abonnés distincts,
    /// chaque session rattachée à un seul, aucune session ambiguë.
    #[test]
    fn five_subscribers_stay_five_distinct_subscribers_2_21_155() {
        let capture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus/LAB_TESTBED/multi-imsi.pcap");
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let mut jsonl = String::new();
        for interface in ["N2", "N4", "SBI"] {
            let config = oiran_decode::DecodeConfig {
                input: capture.clone(),
                capture_id: format!("sha256:{}", event_schema::sha256_hex(interface.as_bytes())),
                interface: interface.into(),
                endpoints: std::collections::HashMap::new(),
                stable_source_file: "multi-imsi.pcap".into(),
            };
            let _ = oiran_decode::decode_capture_streaming(&config, &key, |event| {
                jsonl.push_str(&event.to_json());
                jsonl.push('\n');
                Ok(())
            });
        }
        let mut events = session_engine::load_jsonl(std::io::Cursor::new(jsonl)).unwrap();
        let discovery = session_engine::discover_sessions(&mut events);
        assert_eq!(discovery.pdu_sessions.len(), 5);
        let flows: Vec<CallFlow> = discovery
            .pdu_sessions
            .iter()
            .map(|session| {
                let context = discovery.ue_contexts.iter().find(|c| c.context_id == session.ue_context_id);
                let wanted: BTreeSet<&String> = session.event_ids.iter().chain(context.into_iter().flat_map(|c| c.event_ids.iter())).collect();
                let selected = events.iter().filter(|e| wanted.contains(&e.event_id)).cloned().collect();
                let mut reconstruction = session_engine::reconstruct(selected, session_engine::ReconstructionHints::default());
                reconstruction.session_id = session.session_id.clone();
                callflow_schema::build_callflow(&reconstruction, Vec::new())
            })
            .collect();
        let index = JourneyIndex::from_flows(flows.iter());
        assert_eq!(index.ambiguous_sessions(), 0);
        assert_eq!(index.subscribers().len(), 5, "cinq abonnés distincts");
        let owners: BTreeSet<&str> = flows.iter().filter_map(|f| index.subscriber_for_session(&f.session_id)).collect();
        assert_eq!(owners.len(), 5, "chaque session à son propre abonné");
        for record in index.subscribers() {
            assert_eq!(record.session_count, 1);
        }
    }
}
