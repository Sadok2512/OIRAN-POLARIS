//! 2.10.0 (devmat) — index des filtres Session Explorer.
//!
//! Construit à partir des `CallFlow` déjà en RAM dans `AppState`, l'index
//! expose par session :
//! * `interfaces` — les plans observés (N2/N3/N4/SBI/S1-MME/S11/S1-U)
//! * `messages` — ensemble canonique `(interface, message_name)` observé
//! * `causes` — causes réellement présentes dans les IE décodés
//!   (NGAP/S1AP, 5GMM/EMM, 5GSM/ESM, GTPv2, PFCP, statut HTTP SBI)
//! * `pseudonyms` — pseudonymes d'identité rencontrés comme IE nommés
//!   `*_pseudonym` dans `decoded_ie_tree` (déjà anonymisés côté décodeur)
//! * `has_failure` — vrai si au moins un événement a `semantic_status =
//!   FAILURE`
//!
//! Mémoire : chaque entrée coûte O(messages uniques + causes uniques +
//! pseudonymes uniques) par session — de l'ordre du kilooctet. Pour
//! 10 000 sessions l'index tient sous les 10 MiB. Pas de nouvelle
//! structure disque ; aucune croissance avec le nombre d'événements
//! bruts (~1,5 M).

use callflow_schema::CallFlow;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Rôle d'identité accepté par le filtre POST. La valeur de surface est
/// pseudonymisée côté serveur avec le même label que le décodeur avant
/// toute comparaison. Aucune valeur brute ne sort de ce module.
#[derive(Clone, Copy, Debug)]
pub enum IdentityKind {
    /// SUPI / IMSI. Label décodeur : `subscriber`
    /// (`event_schema::SUBSCRIBER_PSEUDO_DOMAIN`).
    SupiOrImsi,
    /// IMEI / PEI. Label décodeur : `masked-imeisv` (NGAP).
    ImeiOrPei,
    /// 5G-GUTI / 5G-S-TMSI. Label décodeur : `five-g-s-tmsi` (NGAP).
    GutiOrFiveGsTmsi,
    /// S-TMSI LTE. Label décodeur : `s1ap-s-tmsi`.
    STmsi,
}

impl IdentityKind {
    pub fn pseudo_domain(self) -> &'static str {
        match self {
            Self::SupiOrImsi => "subscriber",
            Self::ImeiOrPei => "masked-imeisv",
            Self::GutiOrFiveGsTmsi => "five-g-s-tmsi",
            Self::STmsi => "s1ap-s-tmsi",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "supi_or_imsi" => Some(Self::SupiOrImsi),
            "imei_or_pei" => Some(Self::ImeiOrPei),
            "guti_or_tmsi" | "guti_or_five_g_s_tmsi" => Some(Self::GutiOrFiveGsTmsi),
            "s_tmsi" => Some(Self::STmsi),
            _ => None,
        }
    }
}

/// Noms d'IE qui portent un pseudonyme d'identité. Grep exhaustif sur
/// decoder-*/src et live-probe/session-engine. Toute autre IE est
/// ignorée par l'index — on ne collecte pas d'identité en clair, même
/// transitoirement.
const PSEUDONYM_IE_NAMES: &[&str] = &[
    "subscriber_pseudonym",
    "imsi_pseudonym",
    "mei_pseudonym",
    "msisdn_pseudonym",
    "identity_pseudonym",
    "ue_identity_pseudonym",
];

#[derive(Clone, Debug)]
pub struct SessionFilterEntry {
    pub session_id: String,
    pub interfaces: Vec<String>,
    pub messages: BTreeSet<(String, String)>, // (interface, message_name)
    pub causes: BTreeSet<(String, String, bool)>, // (domain, value, is_failure)
    pub pseudonyms: BTreeSet<String>,
    pub has_failure: bool,
    /// 2.10.1 (devmat review) : ancre de pagination canonique.
    /// `anchor_capture_id` = min capture_id string observé sur
    /// les événements de la session (lexicographique stable).
    /// `first_packet_number` = plus petit `packet_number` observé
    /// SUR cet anchor_capture_id. Clé de tri complète :
    /// `(anchor_capture_id, first_packet_number, session_id)`.
    /// Jamais de `ts` dans la clé (règle ANR2).
    pub anchor_capture_id: String,
    pub first_packet_number: u64,
}

pub struct SessionFilterIndex {
    sessions: BTreeMap<String, SessionFilterEntry>,
}

impl SessionFilterIndex {
    pub fn empty() -> Self {
        Self {
            sessions: BTreeMap::new(),
        }
    }

    pub fn from_flows<'a>(flows: impl IntoIterator<Item = &'a CallFlow>) -> Self {
        let mut index = Self::empty();
        for flow in flows {
            index.upsert_flow(flow);
        }
        index
    }

    pub fn upsert_flow(&mut self, flow: &CallFlow) {
        // Ancre canonique : min(capture_id) sur TOUS les events de
        // la session. `first_packet_number` = plus petit
        // packet_number OBSERVÉ sur cet anchor_capture_id.
        let anchor_capture_id = flow
            .events
            .iter()
            .map(|event| event.capture_id.as_str())
            .min()
            .unwrap_or("")
            .to_string();
        let first_packet_number = flow
            .events
            .iter()
            .filter(|event| event.capture_id == anchor_capture_id)
            .flat_map(|event| event.packet_references.iter().map(|p| p.packet_number))
            .min()
            .unwrap_or(0);
        let mut entry = SessionFilterEntry {
            session_id: flow.session_id.clone(),
            interfaces: flow.interfaces.clone(),
            messages: BTreeSet::new(),
            causes: BTreeSet::new(),
            pseudonyms: BTreeSet::new(),
            has_failure: false,
            anchor_capture_id,
            first_packet_number,
        };
        for event in &flow.events {
            if event.message_name.is_empty() {
                continue;
            }
            entry
                .messages
                .insert((event.interface.clone(), event.message_name.clone()));
            if event.semantic_status == "FAILURE" {
                entry.has_failure = true;
            }
            for cause in extract_causes(
                event.interface.as_str(),
                event.protocol.as_str(),
                &event.decoded_ie_tree,
                event.semantic_status.as_str(),
            ) {
                entry.causes.insert(cause);
            }
            collect_pseudonyms(&event.decoded_ie_tree, &mut entry.pseudonyms);
        }
        self.sessions.insert(flow.session_id.clone(), entry);
    }

    /// 2.10.1 : clé de tri canonique de pagination. Jamais de `ts`.
    pub fn pagination_key<'a>(&'a self, session_id: &str) -> Option<(&'a str, u64, &'a str)> {
        self.sessions
            .get(session_id)
            .map(|entry| (entry.anchor_capture_id.as_str(), entry.first_packet_number, entry.session_id.as_str()))
    }

    /// 2.10.1 : itération ordonnée par clé canonique pour
    /// pagination curseur. Retourne (session_id) dans l'ordre
    /// `(anchor_capture_id, first_packet_number, session_id)`.
    pub fn ids_sorted(&self) -> Vec<&str> {
        let mut rows: Vec<(&str, u64, &str)> = self
            .sessions
            .values()
            .map(|entry| (entry.anchor_capture_id.as_str(), entry.first_packet_number, entry.session_id.as_str()))
            .collect();
        rows.sort();
        rows.into_iter().map(|(_, _, id)| id).collect()
    }

    pub fn entry(&self, session_id: &str) -> Option<&SessionFilterEntry> {
        self.sessions.get(session_id)
    }

    /// Filtre les sessions en ET logique. `messages` et `causes`
    /// acceptent un filtre optionnel sur l'interface/domain
    /// (`Some(..)`) ou laissent la recherche ouverte (`None`).
    pub fn filter(
        &self,
        messages: &[(Option<String>, String)],
        causes: &[(Option<String>, String)],
        failures_only: bool,
        pseudonym_match: Option<&str>,
    ) -> Vec<&str> {
        self.sessions
            .values()
            .filter(|entry| {
                if failures_only && !entry.has_failure {
                    return false;
                }
                if !messages.is_empty()
                    && !messages.iter().any(|(iface, name)| {
                        entry.messages.iter().any(|(entry_iface, entry_name)| {
                            entry_name == name && iface.as_deref().map_or(true, |i| entry_iface == i)
                        })
                    })
                {
                    return false;
                }
                if !causes.is_empty()
                    && !causes.iter().any(|(domain, value)| {
                        entry.causes.iter().any(|(entry_domain, entry_value, _)| {
                            entry_value == value
                                && domain.as_deref().map_or(true, |d| entry_domain == d)
                        })
                    })
                {
                    return false;
                }
                if let Some(expected) = pseudonym_match {
                    if !entry.pseudonyms.contains(expected) {
                        return false;
                    }
                }
                true
            })
            .map(|entry| entry.session_id.as_str())
            .collect()
    }

    /// Agrégat des causes réellement présentes avec compteur de
    /// sessions touchées. Jamais d'identité en clair dans la réponse.
    pub fn available_causes(&self) -> Vec<Value> {
        let mut aggregate: BTreeMap<(String, String, bool), usize> = BTreeMap::new();
        for entry in self.sessions.values() {
            for (domain, value, is_failure) in &entry.causes {
                *aggregate
                    .entry((domain.clone(), value.clone(), *is_failure))
                    .or_insert(0) += 1;
            }
        }
        aggregate
            .into_iter()
            .map(|((domain, value, is_failure), session_count)| {
                serde_json::json!({
                    "domain": domain,
                    "value": value,
                    "is_failure": is_failure,
                    "session_count": session_count,
                })
            })
            .collect()
    }

    /// Nombre total de sessions indexées (pour métrique opérateur).
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

/// Parcours récursif de l'IE tree ; les IE dont le nom est dans
/// `PSEUDONYM_IE_NAMES` contribuent leur valeur string (pseudonyme
/// `psn-...`) au set.
fn collect_pseudonyms(ies: &Value, out: &mut BTreeSet<String>) {
    match ies {
        Value::Array(items) => {
            for item in items {
                collect_pseudonyms(item, out);
            }
        }
        Value::Object(map) => {
            let name = map.get("name").and_then(Value::as_str).unwrap_or("");
            if PSEUDONYM_IE_NAMES.contains(&name) {
                if let Some(value) = map.get("value").and_then(Value::as_str) {
                    if !value.is_empty() {
                        out.insert(value.to_owned());
                    }
                }
            }
            if let Some(children) = map.get("children") {
                collect_pseudonyms(children, out);
            }
        }
        _ => {}
    }
}

/// Extrait des IE décodés les causes typées. Les causes sont
/// catégorisées par `domain` selon le protocole porteur :
/// `NGAP` / `S1AP` / `5GMM` / `EMM` / `5GSM` / `ESM` / `GTPV2` / `PFCP` / `SBI`.
/// La valeur est normalisée en `"<value>"` (string brut du décodeur,
/// ex. `"radio_network:12"` ou `"cause=64"`). `is_failure` vrai quand
/// la valeur n'est pas la « non-failure » canonique (`cause=1`,
/// HTTP 2xx pour SBI).
fn extract_causes(
    interface: &str,
    protocol: &str,
    ies: &Value,
    semantic_status: &str,
) -> Vec<(String, String, bool)> {
    let Some(items) = ies.as_array() else {
        return Vec::new();
    };
    let base_domain = domain_for(interface, protocol);
    let mut out = Vec::new();
    for ie in items {
        let Some(name) = ie.get("name").and_then(Value::as_str) else {
            continue;
        };
        let value = ie.get("value").and_then(Value::as_str).unwrap_or("");
        let lower = name.to_ascii_lowercase();
        let (domain, raw_value) = if lower.contains("5gmm-cause") || lower.contains("5gmm_cause") {
            ("5GMM".to_string(), value.to_string())
        } else if lower.contains("5gsm-cause") || lower.contains("5gsm_cause") {
            ("5GSM".to_string(), value.to_string())
        } else if lower.contains("emm-cause") || lower.contains("emm_cause") {
            ("EMM".to_string(), value.to_string())
        } else if lower.contains("esm-cause") || lower.contains("esm_cause") {
            ("ESM".to_string(), value.to_string())
        } else if lower.contains("http") && lower.contains("status") {
            ("SBI".to_string(), value.to_string())
        } else if lower.ends_with("cause") || lower == "cause" {
            (base_domain.to_string(), value.to_string())
        } else {
            continue;
        };
        if raw_value.is_empty() {
            continue;
        }
        let is_failure = classify_failure(&domain, &raw_value, semantic_status);
        out.push((domain, raw_value, is_failure));
    }
    out
}

fn domain_for(interface: &str, protocol: &str) -> &'static str {
    match (interface, protocol) {
        (_, "NGAP") | ("N2", _) => "NGAP",
        (_, "S1AP") | ("S1-MME", _) => "S1AP",
        (_, "GTPv2-C") | ("S11", _) => "GTPV2",
        (_, "PFCP") | ("N4", _) => "PFCP",
        (_, "SBI") | ("SBI", _) => "SBI",
        _ => "UNKNOWN",
    }
}

fn classify_failure(domain: &str, value: &str, semantic_status: &str) -> bool {
    if semantic_status == "FAILURE" {
        return true;
    }
    match domain {
        "SBI" => value.parse::<u16>().map_or(false, |code| code >= 400),
        _ => {
            if let Some(stripped) = value.strip_prefix("cause=") {
                stripped != "1" && stripped != "0"
            } else {
                !matches!(value, "1" | "0" | "normal_release" | "cause=1" | "cause=0")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use callflow_schema::{CallFlow, CallFlowEvent, EventAccounting, Participant};
    use session_engine::{Association, PacketRef};

    fn event(
        id: &str,
        interface: &str,
        protocol: &str,
        name: &str,
        ies: Value,
        semantic_status: &str,
    ) -> CallFlowEvent {
        event_at(id, interface, protocol, name, ies, semantic_status, "cap-a", 1)
    }

    fn event_at(
        id: &str,
        interface: &str,
        protocol: &str,
        name: &str,
        ies: Value,
        semantic_status: &str,
        capture_id: &str,
        packet_number: u64,
    ) -> CallFlowEvent {
        CallFlowEvent {
            event_id: id.into(),
            timestamp: "2026-11-10T00:00:00.000000000Z".into(),
            timestamp_ns: "0".into(),
            interface: interface.into(),
            protocol: protocol.into(),
            message_name: name.into(),
            source_participant: "gNB".into(),
            destination_participant: "AMF".into(),
            direction: "RAN_TO_CORE".into(),
            decoded_ie_tree: ies,
            decoding_status: "DECODED".into(),
            semantic_status: semantic_status.into(),
            association: Association::Session,
            procedure_group: "test".into(),
            packet_references: vec![PacketRef {
                source_file: "x".into(),
                packet_number,
                byte_offset: 0,
                interface_id: 0,
                captured_length: 64,
                original_length: 64,
            }],
            capture_id: capture_id.into(),
            decoder_name: "test".into(),
            decoder_version: "test".into(),
            raw_payload_reference: "sha256:x".into(),
            errors: vec![],
        }
    }

    fn flow(session_id: &str, events: Vec<CallFlowEvent>, interfaces: Vec<&str>) -> CallFlow {
        CallFlow {
            callflow_id: format!("cf-{session_id}"),
            session_id: session_id.into(),
            technology: "5G SA".into(),
            start_timestamp: "2026-11-10T00:00:00.000000000Z".into(),
            end_timestamp: "2026-11-10T00:00:00.000000000Z".into(),
            participants: vec![Participant {
                id: "gNB".into(),
                role: "gNB".into(),
                addresses: vec!["10.0.0.1".into()],
            }],
            interfaces: interfaces.into_iter().map(str::to_owned).collect(),
            procedures: vec![],
            events,
            correlation_edges: vec![],
            correlation_status: Default::default(),
            decoder_versions: Default::default(),
            schema_version: "1.5.0".into(),
            capture_references: vec![],
            accounting: EventAccounting {
                source_events: 0,
                session_events: 0,
                background_events: 0,
                unmatched_events: 0,
                duplicate_events: 0,
                extra_events: 0,
            },
            unresolved_fields: 0,
        }
    }

    #[test]
    fn message_filter_matches_by_name_and_optional_interface() {
        let flows = vec![flow(
            "s1",
            vec![event(
                "e1",
                "N2",
                "NGAP",
                "PDUSessionResourceSetupRequest",
                serde_json::json!([]),
                "NORMAL",
            )],
            vec!["N2"],
        )];
        let index = SessionFilterIndex::from_flows(&flows);
        let matches = index.filter(
            &[(Some("N2".into()), "PDUSessionResourceSetupRequest".into())],
            &[],
            false,
            None,
        );
        assert_eq!(matches, vec!["s1"]);
        assert!(index
            .filter(&[(None, "AbsentMessage".into())], &[], false, None)
            .is_empty());
    }

    #[test]
    fn cause_filter_is_scoped_to_domain_when_provided() {
        let flows = vec![flow(
            "s1",
            vec![event(
                "e1",
                "N2",
                "NGAP",
                "PDUSessionResourceSetupFailure",
                serde_json::json!([{"name":"Cause","value":"cause=64"}]),
                "FAILURE",
            )],
            vec!["N2"],
        )];
        let index = SessionFilterIndex::from_flows(&flows);
        let matches = index.filter(
            &[],
            &[(Some("NGAP".into()), "cause=64".into())],
            true,
            None,
        );
        assert_eq!(matches, vec!["s1"]);
        assert!(index
            .filter(
                &[],
                &[(Some("PFCP".into()), "cause=64".into())],
                false,
                None,
            )
            .is_empty());
    }

    #[test]
    fn failures_only_filters_out_normal_sessions() {
        let flows = vec![
            flow(
                "normal",
                vec![event(
                    "e1",
                    "N2",
                    "NGAP",
                    "Setup",
                    serde_json::json!([]),
                    "NORMAL",
                )],
                vec!["N2"],
            ),
            flow(
                "failed",
                vec![event(
                    "e2",
                    "N2",
                    "NGAP",
                    "Reject",
                    serde_json::json!([{"name":"Cause","value":"cause=42"}]),
                    "FAILURE",
                )],
                vec!["N2"],
            ),
        ];
        let index = SessionFilterIndex::from_flows(&flows);
        let matches = index.filter(&[], &[], true, None);
        assert_eq!(matches, vec!["failed"]);
    }

    #[test]
    fn pseudonym_match_is_exact_string_from_ie_name() {
        let flows = vec![flow(
            "s1",
            vec![event(
                "e1",
                "N2",
                "NGAP",
                "Setup",
                serde_json::json!([{"name":"subscriber_pseudonym","value":"psn-cafe-123"}]),
                "NORMAL",
            )],
            vec!["N2"],
        )];
        let index = SessionFilterIndex::from_flows(&flows);
        assert_eq!(
            index.filter(&[], &[], false, Some("psn-cafe-123")),
            vec!["s1"]
        );
        assert!(index
            .filter(&[], &[], false, Some("psn-unknown"))
            .is_empty());
    }

    #[test]
    fn available_causes_counts_unique_causes_per_session() {
        let flows = vec![
            flow(
                "s1",
                vec![event(
                    "e1",
                    "N2",
                    "NGAP",
                    "Reject",
                    serde_json::json!([{"name":"Cause","value":"cause=64"}]),
                    "FAILURE",
                )],
                vec!["N2"],
            ),
            flow(
                "s2",
                vec![event(
                    "e2",
                    "N2",
                    "NGAP",
                    "Reject",
                    serde_json::json!([{"name":"Cause","value":"cause=64"}]),
                    "FAILURE",
                )],
                vec!["N2"],
            ),
        ];
        let index = SessionFilterIndex::from_flows(&flows);
        let causes = index.available_causes();
        assert_eq!(causes.len(), 1);
        assert_eq!(causes[0]["domain"], "NGAP");
        assert_eq!(causes[0]["value"], "cause=64");
        assert_eq!(causes[0]["session_count"], 2);
        assert_eq!(causes[0]["is_failure"], true);
    }

    #[test]
    fn pagination_key_is_capture_then_packet_then_session_never_ts() {
        // 2.10.1 (review devmat) : vérifie que la clé canonique
        // est `(anchor_capture_id, first_packet_number, session_id)`
        // et JAMAIS un timestamp. Les `timestamp` des events
        // sont identiques dans ce test (volontairement) ; seule
        // la combinaison capture+packet+session_id doit trier.
        let flows = vec![
            flow(
                "zeta",
                vec![
                    event_at("ez1", "N2", "NGAP", "A", serde_json::json!([]), "NORMAL", "cap-a", 42),
                    event_at("ez2", "N2", "NGAP", "B", serde_json::json!([]), "NORMAL", "cap-a", 7),
                ],
                vec!["N2"],
            ),
            flow(
                "alpha",
                vec![event_at("ea1", "N2", "NGAP", "A", serde_json::json!([]), "NORMAL", "cap-a", 100)],
                vec!["N2"],
            ),
            flow(
                "mid",
                vec![event_at("em1", "N2", "NGAP", "A", serde_json::json!([]), "NORMAL", "cap-b", 1)],
                vec!["N2"],
            ),
        ];
        let index = SessionFilterIndex::from_flows(&flows);
        // zeta : (cap-a, 7, zeta)
        // alpha : (cap-a, 100, alpha)
        // mid : (cap-b, 1, mid)
        // Ordre attendu : zeta, alpha, mid.
        assert_eq!(index.ids_sorted(), vec!["zeta", "alpha", "mid"]);
        // Clé publique cohérente.
        assert_eq!(index.pagination_key("zeta"), Some(("cap-a", 7u64, "zeta")));
        assert_eq!(index.pagination_key("alpha"), Some(("cap-a", 100u64, "alpha")));
        assert_eq!(index.pagination_key("mid"), Some(("cap-b", 1u64, "mid")));
    }

    #[test]
    fn combined_filters_use_and() {
        let flows = vec![
            flow(
                "pass",
                vec![event(
                    "e1",
                    "N2",
                    "NGAP",
                    "PDUSessionResourceSetupFailure",
                    serde_json::json!([
                        {"name":"Cause","value":"cause=64"},
                        {"name":"subscriber_pseudonym","value":"psn-abc"}
                    ]),
                    "FAILURE",
                )],
                vec!["N2"],
            ),
            flow(
                "missing-cause",
                vec![event(
                    "e2",
                    "N2",
                    "NGAP",
                    "PDUSessionResourceSetupRequest",
                    serde_json::json!([{"name":"subscriber_pseudonym","value":"psn-abc"}]),
                    "NORMAL",
                )],
                vec!["N2"],
            ),
        ];
        let index = SessionFilterIndex::from_flows(&flows);
        let matches = index.filter(
            &[(Some("N2".into()), "PDUSessionResourceSetupFailure".into())],
            &[(Some("NGAP".into()), "cause=64".into())],
            true,
            Some("psn-abc"),
        );
        assert_eq!(matches, vec!["pass"]);
    }
}
