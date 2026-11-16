//! 2.19.0 / 2.19.1 — catalog de filtres/colonnes + projection colonnes.
//!
//! But fonctionnel (ANR1 attend catalog + columns + protocol_tree) :
//! * `GET /sessions/catalog` expose en une requête ce qui est
//!   filtrable (interfaces, technologies, dataset_kinds, states,
//!   correlation_statuses, messages, causes) ET la liste des
//!   colonnes publiables par la liste `/sessions` + `/sessions/filter`.
//! * 2.19.1 : `GET /sessions/catalog` renvoie en plus `protocol_tree`
//!   (interface → protocole → message → paramètres observés avec
//!   type / valeurs ≤ 50 / compte / min-max / preuve DECODED) et
//!   `network_elements` (AMF/SMF/UPF/MME/SGW/PGW/gNB/eNB observés
//!   via `participants`). Construit **depuis les events réels**, pas
//!   une liste figée.
//! * `POST /sessions/filter` accepte un champ optionnel `columns` qui
//!   restreint la projection serveur — moins de bytes sur le fil.
//! * 2.19.1 : `POST /sessions/filter` accepte `criteria[]` + `combinator`
//!   + `network_elements` + `time_window` | `run_id` + `search` +
//!   `limit=0` (meta.total seul, pas de data).
//! * `POST /sessions/columns` prévisualise un sous-ensemble de
//!   colonnes pour une liste de `session_ids` donnée : requête
//!   « donne-moi ces colonnes pour ces N sessions » sans refiltrer.
//! * 2.19.1 : `POST /sessions/columns` accepte `fields[]` (colonnes
//!   PROTOCOLAIRES : interface/protocole/message/param_path + mode
//!   `last|first|all|count`) avec preuve `{event_id, capture_id, seq}`.
//!
//! Contrat vie privée identique à 2.18 : la projection ne crée pas
//! de clé, elle en supprime. `sanitize_all`/`sanitize_value` reste la
//! barrière finale sur les IE qui pourraient porter une identité.
//! Aucun nom de colonne catalog n'est une identité en clair (règle
//! Sadok 2026-11-14 : `identities` reste lisible dans l'UI p900 sans
//! rôles mais jamais dans logs/GitHub). Les wrappers pseudonymisés
//! (`ue_pseudonym`, `subscriber_pseudonym`, `identities`) sont permis.

use std::collections::{BTreeMap, BTreeSet};

use callflow_schema::CallFlowEvent;
use serde::Deserialize;
use serde_json::{json, Value};

/// Colonnes **toujours présentes** dans un summary de session, quelle
/// que soit la projection client. Elles identifient et routent la
/// ligne dans l'UI : sans elles, la ligne devient inexploitable.
pub const ALWAYS_PRESENT_COLUMNS: &[&str] = &[
    "session_id",
    "dataset_id",
    "dataset_kind",
    "technology",
];

/// Catalogue exhaustif des colonnes exposables. `applies_to` est
/// défini en fonction des 3 producteurs : `session_summary`
/// (HISTORICAL 5G), `live_session_summary` (CAPTURED_LIVE/HISTORICAL
/// continuous), `lte_session_summary` (EVIDENCE LTE). Un champ non
/// publié par un producteur donné est simplement absent de la ligne
/// — la projection n'ajoute jamais de clé.
pub fn columns_catalog() -> Vec<Value> {
    fn col(
        name: &str,
        kind: &str,
        applies_to: &[&str],
        always: bool,
        description: &str,
    ) -> Value {
        json!({
            "name": name,
            "type": kind,
            "applies_to": applies_to,
            "always_present": always,
            "description": description,
        })
    }
    let historical_live = &["HISTORICAL_5G", "CAPTURED_LIVE", "HISTORICAL_CONTINUOUS"];
    let historical_live_lte = &[
        "HISTORICAL_5G",
        "CAPTURED_LIVE",
        "HISTORICAL_CONTINUOUS",
        "EVIDENCE_LTE",
    ];
    let lte_only = &["EVIDENCE_LTE"];
    let live_only = &["CAPTURED_LIVE", "HISTORICAL_CONTINUOUS"];
    vec![
        col(
            "session_id",
            "string",
            historical_live_lte,
            true,
            "Canonical session identifier",
        ),
        col(
            "dataset_id",
            "string",
            historical_live_lte,
            true,
            "Dataset that owns the session",
        ),
        col(
            "dataset_kind",
            "string",
            historical_live_lte,
            true,
            "HISTORICAL | CAPTURED_LIVE | EVIDENCE | DERIVED | RECOVERED",
        ),
        col(
            "technology",
            "string",
            historical_live_lte,
            true,
            "5G SA | LTE",
        ),
        col(
            "ue_pseudonym",
            "string",
            historical_live_lte,
            false,
            "Pseudonymized UE handle",
        ),
        col(
            "subscriber_pseudonym",
            "string",
            historical_live_lte,
            false,
            "Pseudonymized subscriber across sessions",
        ),
        col(
            "ue_context_id",
            "string",
            historical_live,
            false,
            "UE context id (5G)",
        ),
        col(
            "pdu_session_id",
            "string",
            historical_live_lte,
            false,
            "PDU session id (5G) or EPS bearer id (LTE)",
        ),
        col(
            "serving_node",
            "string",
            historical_live_lte,
            false,
            "RAN node summary (kept for compat; equals serving_ran_node)",
        ),
        col(
            "serving_ran_node",
            "string",
            historical_live_lte,
            false,
            "RAN node summary (gNB/eNB)",
        ),
        col(
            "core_node",
            "string",
            historical_live_lte,
            false,
            "Core node summary (AMF/MME)",
        ),
        col(
            "procedure",
            "string",
            historical_live_lte,
            false,
            "Concatenated procedure names",
        ),
        col(
            "start_timestamp",
            "string",
            historical_live_lte,
            false,
            "ISO8601 start",
        ),
        col(
            "end_timestamp",
            "string",
            historical_live_lte,
            false,
            "ISO8601 end",
        ),
        col(
            "interfaces",
            "array",
            historical_live_lte,
            false,
            "Observed interfaces (N2, N3, N4, SBI, S1-MME, S1-U, S11, …)",
        ),
        col(
            "message_count",
            "integer",
            historical_live_lte,
            false,
            "Number of session-scoped events",
        ),
        col(
            "source_event_count",
            "integer",
            historical_live_lte,
            false,
            "Raw events seen before association",
        ),
        col(
            "background_event_count",
            "integer",
            historical_live_lte,
            false,
            "Background events (lifecycle)",
        ),
        col(
            "duration_ns",
            "string",
            &["HISTORICAL_5G", "EVIDENCE_LTE"],
            false,
            "Duration in nanoseconds",
        ),
        col(
            "correlation_status",
            "string",
            historical_live_lte,
            false,
            "E2E correlation result",
        ),
        col(
            "decode_completeness",
            "object",
            historical_live_lte,
            false,
            "{decoded, partial, unresolved_fields}",
        ),
        col(
            "state",
            "string",
            historical_live_lte,
            false,
            "ACTIVE_WITH_USER_PLANE | RELEASED | INCOMPLETE | HISTORICAL_CONTEXT | UNKNOWN",
        ),
        col(
            "runtime_evidence",
            "object",
            live_only,
            false,
            "Live runtime context (observed_epoch_ms, provenance, ue_ip, teids, directions)",
        ),
        col(
            "identities",
            "object",
            historical_live_lte,
            false,
            "Pseudonymized identity summary (SUPI / GUTI / TMSI / IMEI pseudonyms)",
        ),
        col(
            "subscriber_session_count",
            "integer",
            historical_live,
            false,
            "Count of sessions for the same subscriber",
        ),
        col(
            "previous_session_id",
            "string",
            historical_live,
            false,
            "Previous session_id for the same subscriber",
        ),
        col(
            "next_session_id",
            "string",
            historical_live,
            false,
            "Next session_id for the same subscriber",
        ),
        col(
            "user_plane_packets",
            "integer",
            lte_only,
            false,
            "LTE user plane packet count",
        ),
        col(
            "limitations",
            "array",
            lte_only,
            false,
            "LTE evidence limitations list",
        ),
    ]
}

/// Set des noms de colonne connus — utilisé pour valider une
/// requête client. Un nom hors catalogue déclenche 400.
pub fn known_column_names() -> BTreeSet<String> {
    columns_catalog()
        .into_iter()
        .filter_map(|column| {
            column
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect()
}

/// Projection : garde uniquement les colonnes demandées **plus** les
/// `ALWAYS_PRESENT_COLUMNS`. Jamais d'ajout — jamais de valeur
/// fabriquée : si une colonne n'est pas publiée par le producteur
/// pour cette ligne, elle reste absente.
pub fn project_columns(summary: &mut Value, requested: &BTreeSet<String>) {
    let Some(object) = summary.as_object_mut() else {
        return;
    };
    let keep: BTreeSet<String> = ALWAYS_PRESENT_COLUMNS
        .iter()
        .map(|name| (*name).to_owned())
        .chain(requested.iter().cloned())
        .collect();
    let to_remove: Vec<String> = object
        .keys()
        .filter(|key| !keep.contains(key.as_str()))
        .cloned()
        .collect();
    for key in to_remove {
        object.remove(&key);
    }
}

/// Valide un vecteur de noms de colonne. Retourne `Err(name)` au
/// premier inconnu — le handler convertit en 400.
pub fn validate_columns(requested: &[String]) -> Result<BTreeSet<String>, String> {
    let known = known_column_names();
    let mut out = BTreeSet::new();
    for name in requested {
        if !known.contains(name) {
            return Err(name.clone());
        }
        out.insert(name.clone());
    }
    Ok(out)
}

/// Agrégation distincte des valeurs de `interface` observées dans
/// l'index filtres. Trie canonique pour stabilité snapshot.
pub fn distinct_interfaces(index: &crate::session_filters::SessionFilterIndex) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for session_id in index.ids_sorted() {
        if let Some(entry) = index.entry(session_id) {
            for iface in &entry.interfaces {
                set.insert(iface.clone());
            }
        }
    }
    set.into_iter().collect()
}

/// Liste `(interface, message_name)` connue dans l'index filtres,
/// agrégée en ordre canonique BTree.
pub fn distinct_messages(index: &crate::session_filters::SessionFilterIndex) -> Vec<Value> {
    let mut set: BTreeMap<(String, String), usize> = BTreeMap::new();
    for session_id in index.ids_sorted() {
        if let Some(entry) = index.entry(session_id) {
            for (iface, name) in &entry.messages {
                *set.entry((iface.clone(), name.clone())).or_insert(0) += 1;
            }
        }
    }
    set.into_iter()
        .map(|((interface, name), session_count)| {
            json!({
                "interface": interface,
                "name": name,
                "session_count": session_count,
            })
        })
        .collect()
}

/// Shape d'une requête `POST /sessions/columns`. 2.19.1 : `fields`
/// permet aussi de demander des colonnes PROTOCOLAIRES (interface,
/// protocole, message, param_path, mode).
#[derive(Deserialize, Default)]
pub struct SessionsColumnsRequest {
    #[serde(default)]
    pub session_ids: Vec<String>,
    #[serde(default)]
    pub columns: Vec<String>,
    #[serde(default)]
    pub fields: Vec<ColumnField>,
}

// =====================================================================
// 2.19.1 — PROTOCOL TREE
// =====================================================================

/// Un nœud feuille (paramètre) agrégé sur un périmètre d'events. Le
/// path depuis la racine (`information_elements` / `decoded_ie_tree`)
/// vit dans la clé de la map parent. Jamais de valeur en clair pour
/// une IE identité (filtrée via `is_identity_label` au moment
/// de l'insertion).
#[derive(Default, Debug, Clone)]
pub struct ParamObservations {
    pub type_kind: String,
    pub occurrences: usize,
    /// ≤ 50 valeurs distinctes avec compte. BTreeMap = tri canonique.
    pub observed_values: BTreeMap<String, usize>,
    pub min_i64: Option<i64>,
    pub max_i64: Option<i64>,
    pub decoded_from_octets: bool,
}

/// Limite stricte sur le nombre de valeurs distinctes publiées. Au-delà
/// la publication expose `truncated: true` + le compte observé total.
const MAX_DISTINCT_VALUES_PER_PARAM: usize = 50;

impl ParamObservations {
    fn observe(&mut self, value: &Value, decoded: bool) {
        self.occurrences += 1;
        self.decoded_from_octets |= decoded;
        let (type_kind, canonical) = classify_value(value);
        if self.type_kind.is_empty() {
            self.type_kind = type_kind.to_owned();
        } else if self.type_kind != type_kind {
            // Promotion de type si mélange : string surclasse tout.
            self.type_kind = "string".to_owned();
        }
        if let Some(as_i64) = parse_i64_from(value) {
            self.min_i64 = Some(self.min_i64.map(|m| m.min(as_i64)).unwrap_or(as_i64));
            self.max_i64 = Some(self.max_i64.map(|m| m.max(as_i64)).unwrap_or(as_i64));
        }
        // Cap sur distincts : on ne grandit plus la map une fois à
        // la borne. On incrémente les valeurs déjà présentes.
        let seen = self.observed_values.contains_key(&canonical);
        if seen {
            *self.observed_values.get_mut(&canonical).unwrap() += 1;
        } else if self.observed_values.len() < MAX_DISTINCT_VALUES_PER_PARAM {
            self.observed_values.insert(canonical, 1);
        }
    }

    fn to_json(&self, truncated_total: usize) -> Value {
        let values: Vec<Value> = self
            .observed_values
            .iter()
            .map(|(value, count)| json!({"value": value, "count": count}))
            .collect();
        let mut body = json!({
            "type": self.type_kind,
            "occurrences": self.occurrences,
            "observed_values": values,
            "decoded_from_octets": self.decoded_from_octets,
        });
        if truncated_total > MAX_DISTINCT_VALUES_PER_PARAM {
            body["truncated"] = Value::Bool(true);
            body["distinct_values_seen"] = Value::from(truncated_total);
        }
        if let (Some(min), Some(max)) = (self.min_i64, self.max_i64) {
            body["min"] = Value::from(min);
            body["max"] = Value::from(max);
        }
        body
    }
}

/// Classification type d'une valeur IE.
fn classify_value(value: &Value) -> (&'static str, String) {
    match value {
        Value::Null => ("string", String::new()),
        Value::Bool(b) => ("string", b.to_string()),
        Value::Number(n) => ("integer", n.to_string()),
        Value::String(s) => {
            let trimmed = s.trim();
            // Valeurs du décodeur type `key=val,key=val` : on garde
            // la chaîne entière comme clé observée — c'est le
            // niveau sémantique publié.
            if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
                return ("octetstring", trimmed.to_owned());
            }
            if !trimmed.is_empty() && trimmed.chars().all(|c| c == '0' || c == '1') {
                return ("bitstring", trimmed.to_owned());
            }
            if trimmed.parse::<i64>().is_ok() {
                return ("integer", trimmed.to_owned());
            }
            ("string", trimmed.to_owned())
        }
        Value::Array(_) | Value::Object(_) => (
            "object",
            serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned()),
        ),
    }
}

fn parse_i64_from(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// `(interface, protocol, message, param_path_joined)` identifie un
/// paramètre dans l'arbre protocolaire. `param_path_joined` est la
/// séquence `.name` depuis la racine IE, jointe par `/` (séparateur
/// stable, impossible dans un `name` de spec 3GPP).
pub type ProtocolTreeKey = (String, String, String, String);

#[derive(Default, Debug)]
pub struct ProtocolTreeBuilder {
    /// Compte d'occurrences par (interface, protocol, message).
    message_counts: BTreeMap<(String, String, String), usize>,
    params: BTreeMap<ProtocolTreeKey, ParamObservations>,
    /// Compteurs de valeurs distinctes vues (avant cap) pour
    /// `truncated=true` dans la publication.
    distinct_seen: BTreeMap<ProtocolTreeKey, usize>,
    /// 2.19.1 — network_elements = (role, address pseudonymisée).
    network_elements: BTreeMap<(String, String), usize>,
}

impl ProtocolTreeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingère un event. `decoded_ie_tree` (CallFlowEvent) est utilisé
    /// comme source primaire ; chaque IE est parcourue avec son
    /// chemin `.name/.name/...`. Les valeurs portant un nom
    /// d'identité (via `is_identity_label`) ne contribuent pas au
    /// bag de valeurs — l'arbre reste utilisable pour le filtre
    /// sémantique sans jamais exposer d'IMSI/IMEI brute.
    pub fn observe_event(&mut self, event: &CallFlowEvent) {
        if event.message_name.is_empty() {
            return;
        }
        let key_msg = (
            event.interface.clone(),
            event.protocol.clone(),
            event.message_name.clone(),
        );
        *self.message_counts.entry(key_msg.clone()).or_insert(0) += 1;
        walk_ie_tree(&event.decoded_ie_tree, Vec::new(), &mut |path, ie_obj| {
            let name = ie_obj.get("name").and_then(Value::as_str).unwrap_or("");
            if crate::is_identity_label_pub(name) {
                return; // jamais d'identité en clair dans l'arbre
            }
            let value = ie_obj.get("value").cloned().unwrap_or(Value::Null);
            let decoded = ie_obj
                .get("status")
                .and_then(Value::as_str)
                .map(|s| s == "DECODED")
                .unwrap_or(false);
            let path_joined = path.join("/");
            let key = (
                event.interface.clone(),
                event.protocol.clone(),
                event.message_name.clone(),
                path_joined,
            );
            let entry = self.params.entry(key.clone()).or_default();
            let seen_before = entry.observed_values.contains_key(
                &classify_value(&value).1,
            );
            entry.observe(&value, decoded);
            let distinct = self.distinct_seen.entry(key).or_insert(0);
            if !seen_before {
                *distinct += 1;
            }
        });
    }

    /// Ingère un participant (pour `network_elements`). Les rôles
    /// non-réseau (ex: `UNKNOWN`) sont ignorés.
    pub fn observe_participant(&mut self, role: &str, address: &str) {
        const NETWORK_ROLES: &[&str] = &[
            "AMF", "SMF", "UPF", "MME", "SGW", "PGW", "gNB", "eNB", "UDM", "AUSF", "PCF", "NRF",
            "SMS-F",
        ];
        if !NETWORK_ROLES.iter().any(|r| r.eq_ignore_ascii_case(role)) {
            return;
        }
        if address.is_empty() {
            return;
        }
        *self
            .network_elements
            .entry((role.to_owned(), address.to_owned()))
            .or_insert(0) += 1;
    }

    pub fn to_protocol_tree_json(&self) -> Value {
        // (interface, protocol, message) → message node
        // message node has `occurrences` et `params`.
        // Regroupement hiérarchique interface → protocol → messages.
        let mut by_interface: BTreeMap<String, BTreeMap<String, BTreeMap<String, Value>>> =
            BTreeMap::new();
        for ((interface, protocol, message), occurrences) in &self.message_counts {
            let mut params: Vec<Value> = Vec::new();
            for ((p_interface, p_protocol, p_message, path), observations) in &self.params {
                if p_interface == interface && p_protocol == protocol && p_message == message {
                    let truncated_total = self
                        .distinct_seen
                        .get(&(
                            p_interface.clone(),
                            p_protocol.clone(),
                            p_message.clone(),
                            path.clone(),
                        ))
                        .copied()
                        .unwrap_or_else(|| observations.observed_values.len());
                    let mut param_json = observations.to_json(truncated_total);
                    if let Some(object) = param_json.as_object_mut() {
                        object.insert("param_path".into(), Value::String(path.clone()));
                    }
                    params.push(param_json);
                }
            }
            by_interface
                .entry(interface.clone())
                .or_default()
                .entry(protocol.clone())
                .or_default()
                .insert(
                    message.clone(),
                    json!({
                        "occurrences": occurrences,
                        "params": params,
                    }),
                );
        }
        // Serialize hierarchy.
        let interfaces: Vec<Value> = by_interface
            .into_iter()
            .map(|(interface, protocols)| {
                let protocol_vec: Vec<Value> = protocols
                    .into_iter()
                    .map(|(protocol, messages)| {
                        let message_vec: Vec<Value> = messages
                            .into_iter()
                            .map(|(message, body)| json!({"message": message, "detail": body}))
                            .collect();
                        json!({"protocol": protocol, "messages": message_vec})
                    })
                    .collect();
                json!({"interface": interface, "protocols": protocol_vec})
            })
            .collect();
        Value::Array(interfaces)
    }

    pub fn to_network_elements_json(&self) -> Value {
        let items: Vec<Value> = self
            .network_elements
            .iter()
            .map(|((role, address), count)| {
                json!({
                    "role": role,
                    "address": address,
                    "occurrences": count,
                })
            })
            .collect();
        Value::Array(items)
    }
}

/// Parcours récursif des IEs : `path` = suite des `.name` depuis la
/// racine. Pour chaque IE qui est un **objet** (dict), on invoque
/// `visitor(path_courant, ie_object)` puis on descend dans
/// `.children` si présent. Les items qui ne sont pas des objets
/// sont ignorés (la spec garantit un array d'objets, mais on reste
/// défensif).
fn walk_ie_tree<F>(tree: &Value, path: Vec<String>, visitor: &mut F)
where
    F: FnMut(&[String], &serde_json::Map<String, Value>),
{
    match tree {
        Value::Array(items) => {
            for item in items {
                walk_ie_tree(item, path.clone(), visitor);
            }
        }
        Value::Object(map) => {
            let name = map
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let mut sub_path = path.clone();
            if !name.is_empty() {
                sub_path.push(name);
            }
            visitor(&sub_path, map);
            if let Some(children) = map.get("children") {
                walk_ie_tree(children, sub_path, visitor);
            }
        }
        _ => {}
    }
}

// =====================================================================
// 2.19.1 — CRITERIA (POST /sessions/filter)
// =====================================================================

#[derive(Deserialize, Debug, Clone)]
pub struct FilterCriterion {
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    pub message: String,
    #[serde(default)]
    pub param_path: Option<String>,
    pub op: String,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub values: Option<Vec<Value>>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub enum FilterCombinator {
    #[default]
    And,
    Or,
}

/// Résultat d'un match : sur quelle criterion_index + quel event
/// (preuve) l'event a validé le prédicat. Garde l'ordre canonique
/// (sorted by (capture_id, packet_number, event_id)) à la
/// consommation.
#[derive(Debug, Clone)]
pub struct CriterionHit {
    pub criterion_index: usize,
    pub event_id: String,
    pub capture_id: String,
    pub seq: u64,
}

/// Évalue un unique critère contre un event. Retourne vrai + le
/// `seq` (packet_number) du premier packet_reference pour la
/// preuve de match.
pub fn evaluate_criterion(event: &CallFlowEvent, criterion: &FilterCriterion) -> Option<u64> {
    if !criterion.message.is_empty() && criterion.message != event.message_name {
        return None;
    }
    if let Some(iface) = &criterion.interface {
        if iface != &event.interface {
            return None;
        }
    }
    if let Some(protocol) = &criterion.protocol {
        if protocol != &event.protocol {
            return None;
        }
    }
    let matches = match &criterion.param_path {
        Some(path) => {
            let path_segments: Vec<String> =
                path.split('/').map(str::to_owned).filter(|s| !s.is_empty()).collect();
            let mut found = false;
            walk_ie_tree(&event.decoded_ie_tree, Vec::new(), &mut |ie_path, map| {
                if ie_path == path_segments.as_slice() {
                    let value = map.get("value").cloned().unwrap_or(Value::Null);
                    if apply_op(&criterion.op, &value, criterion.value.as_ref(), criterion.values.as_deref()) {
                        found = true;
                    }
                }
            });
            found
        }
        None => {
            // Pas de chemin : critère sur le message seul.
            true
        }
    };
    if matches {
        let seq = event
            .packet_references
            .first()
            .map(|pr| pr.packet_number)
            .unwrap_or(0);
        Some(seq)
    } else {
        None
    }
}

fn apply_op(op: &str, left: &Value, right: Option<&Value>, rights: Option<&[Value]>) -> bool {
    let left_str = classify_value(left).1;
    match op {
        "eq" => right.map(|r| classify_value(r).1 == left_str).unwrap_or(false),
        "ne" => right.map(|r| classify_value(r).1 != left_str).unwrap_or(false),
        "gt" | "lt" => {
            let left_num = parse_i64_from(left);
            let right_num = right.and_then(parse_i64_from);
            match (left_num, right_num) {
                (Some(l), Some(r)) if op == "gt" => l > r,
                (Some(l), Some(r)) if op == "lt" => l < r,
                _ => false,
            }
        }
        "contains" => {
            let needle = right.map(|r| classify_value(r).1).unwrap_or_default();
            !needle.is_empty() && left_str.contains(&needle)
        }
        "in" => rights
            .map(|rs| {
                rs.iter()
                    .any(|candidate| classify_value(candidate).1 == left_str)
            })
            .unwrap_or(false),
        _ => false,
    }
}

/// Évalue TOUS les criteria contre un event. Retourne les
/// `criterion_index` validés — vide si aucun.
pub fn evaluate_event_against_criteria(
    event: &CallFlowEvent,
    criteria: &[FilterCriterion],
) -> Vec<(usize, u64)> {
    criteria
        .iter()
        .enumerate()
        .filter_map(|(idx, criterion)| {
            evaluate_criterion(event, criterion).map(|seq| (idx, seq))
        })
        .collect()
}

/// Combine les hits de tous les events d'une session selon
/// AND/OR. Retourne les hits à publier dans `matched_criteria` ET
/// un booléen « cette session passe le filtre ».
pub fn aggregate_session_hits(
    events: &[CallFlowEvent],
    criteria: &[FilterCriterion],
    combinator: &FilterCombinator,
) -> (Vec<CriterionHit>, bool) {
    if criteria.is_empty() {
        return (Vec::new(), true);
    }
    let mut hits: Vec<CriterionHit> = Vec::new();
    let mut criterion_covered: BTreeSet<usize> = BTreeSet::new();
    for event in events {
        let event_hits = evaluate_event_against_criteria(event, criteria);
        for (idx, seq) in event_hits {
            criterion_covered.insert(idx);
            hits.push(CriterionHit {
                criterion_index: idx,
                event_id: event.event_id.clone(),
                capture_id: event.capture_id.clone(),
                seq,
            });
        }
    }
    let passes = match combinator {
        FilterCombinator::And => criterion_covered.len() == criteria.len(),
        FilterCombinator::Or => !criterion_covered.is_empty(),
    };
    (hits, passes)
}

// =====================================================================
// 2.19.1 — PROTOCOL COLUMNS (POST /sessions/columns.fields[])
// =====================================================================

#[derive(Deserialize, Debug, Clone)]
pub struct ColumnField {
    pub interface: String,
    pub protocol: String,
    #[serde(default)]
    pub message: Option<String>,
    pub param_path: String,
    pub mode: String,
}

/// Résultat d'une colonne protocolaire pour une session. Respecte
/// le mode demandé. `proof` reflète les events qui ont contribué.
#[derive(Debug, Clone)]
pub struct ColumnFieldResult {
    pub value: Value,
    pub proof: Vec<CriterionHit>,
}

pub fn evaluate_field_on_session(
    events: &[CallFlowEvent],
    field: &ColumnField,
) -> Option<ColumnFieldResult> {
    let path_segments: Vec<String> = field
        .param_path
        .split('/')
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
        .collect();
    let mut hits: Vec<(String, u64, String, Value)> = Vec::new();
    for event in events {
        if event.interface != field.interface || event.protocol != field.protocol {
            continue;
        }
        if let Some(message) = &field.message {
            if event.message_name != *message {
                continue;
            }
        }
        walk_ie_tree(&event.decoded_ie_tree, Vec::new(), &mut |ie_path, map| {
            if ie_path == path_segments.as_slice() {
                let value = map.get("value").cloned().unwrap_or(Value::Null);
                let seq = event
                    .packet_references
                    .first()
                    .map(|pr| pr.packet_number)
                    .unwrap_or(0);
                hits.push((
                    event.capture_id.clone(),
                    seq,
                    event.event_id.clone(),
                    value,
                ));
            }
        });
    }
    if hits.is_empty() {
        return Some(ColumnFieldResult {
            value: Value::Null,
            proof: Vec::new(),
        });
    }
    // Ordre canonique : (capture_id, seq, event_id).
    hits.sort_by(|a, b| {
        a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2))
    });
    let pick_proof = |i: usize| CriterionHit {
        criterion_index: 0,
        event_id: hits[i].2.clone(),
        capture_id: hits[i].0.clone(),
        seq: hits[i].1,
    };
    let result = match field.mode.as_str() {
        "last" => ColumnFieldResult {
            value: hits.last().map(|h| h.3.clone()).unwrap_or(Value::Null),
            proof: vec![pick_proof(hits.len() - 1)],
        },
        "first" => ColumnFieldResult {
            value: hits.first().map(|h| h.3.clone()).unwrap_or(Value::Null),
            proof: vec![pick_proof(0)],
        },
        "all" => {
            let values: Vec<Value> = hits.iter().map(|h| h.3.clone()).collect();
            let proofs: Vec<CriterionHit> = (0..hits.len()).map(pick_proof).collect();
            ColumnFieldResult {
                value: Value::Array(values),
                proof: proofs,
            }
        }
        "count" => ColumnFieldResult {
            value: Value::from(hits.len()),
            proof: (0..hits.len()).map(pick_proof).collect(),
        },
        _ => ColumnFieldResult {
            value: Value::Null,
            proof: Vec::new(),
        },
    };
    Some(result)
}

pub fn validate_fields(fields: &[ColumnField]) -> Result<(), String> {
    for (i, f) in fields.iter().enumerate() {
        if f.interface.is_empty() {
            return Err(format!("fields[{i}].interface is required"));
        }
        if f.protocol.is_empty() {
            return Err(format!("fields[{i}].protocol is required"));
        }
        if f.param_path.is_empty() {
            return Err(format!("fields[{i}].param_path is required"));
        }
        if !matches!(f.mode.as_str(), "last" | "first" | "all" | "count") {
            return Err(format!(
                "fields[{i}].mode must be one of last|first|all|count"
            ));
        }
    }
    Ok(())
}

pub fn criterion_hit_to_json(hit: &CriterionHit) -> Value {
    json!({
        "criterion_index": hit.criterion_index,
        "event_id": hit.event_id,
        "capture_id": hit.capture_id,
        "seq": hit.seq,
    })
}

// =====================================================================
// 2.19.1 — PROTOCOL CATALOG SEARCH + PARAM
// =====================================================================

/// Classe un match sur le nom (message ou paramètre). Pertinence
/// décroissante : exact (1000), préfixe (500), contient (100). Comparaison
/// insensible à la casse ; la casse d'origine est préservée pour l'affichage.
fn relevance_score(haystack: &str, needle: &str) -> i32 {
    let hay = haystack.to_ascii_lowercase();
    let n = needle.to_ascii_lowercase();
    if hay == n {
        1000
    } else if hay.starts_with(&n) {
        500
    } else if hay.contains(&n) {
        100
    } else {
        0
    }
}

/// Résultat d'un `/sessions/catalog/search`. Matches sur message
/// ET sur paramètre fusionnés, triés par pertinence décroissante
/// puis par (interface, protocol, message, param_path) stable.
pub fn search_protocol_tree(
    builder: &ProtocolTreeBuilder,
    needle: &str,
    interfaces_scope: &BTreeSet<String>,
    limit: usize,
) -> Vec<Value> {
    if needle.trim().is_empty() {
        return Vec::new();
    }
    let needle_trimmed = needle.trim();
    let mut rows: Vec<(i32, Value, String, String, String, String)> = Vec::new();
    // 1) Match sur message_name.
    for ((interface, protocol, message), occurrences) in &builder.message_counts {
        if !interfaces_scope.is_empty() && !interfaces_scope.contains(interface) {
            continue;
        }
        let score = relevance_score(message, needle_trimmed);
        if score == 0 {
            continue;
        }
        rows.push((
            score,
            json!({
                "interface": interface,
                "protocol": protocol,
                "message": message,
                "param_path": Value::Null,
                "type": "message",
                "occurrences": occurrences,
            }),
            interface.clone(),
            protocol.clone(),
            message.clone(),
            String::new(),
        ));
    }
    // 2) Match sur param_path (dernier segment ou segment contenant).
    for ((interface, protocol, message, path), observations) in &builder.params {
        if !interfaces_scope.is_empty() && !interfaces_scope.contains(interface) {
            continue;
        }
        let last_segment = path.rsplit('/').next().unwrap_or(path);
        let score = relevance_score(last_segment, needle_trimmed)
            .max(relevance_score(path, needle_trimmed));
        if score == 0 {
            continue;
        }
        rows.push((
            score,
            json!({
                "interface": interface,
                "protocol": protocol,
                "message": message,
                "param_path": path,
                "type": observations.type_kind,
                "occurrences": observations.occurrences,
            }),
            interface.clone(),
            protocol.clone(),
            message.clone(),
            path.clone(),
        ));
    }
    rows.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then(a.2.cmp(&b.2))
            .then(a.3.cmp(&b.3))
            .then(a.4.cmp(&b.4))
            .then(a.5.cmp(&b.5))
    });
    rows.into_iter()
        .take(limit)
        .map(|(_, body, ..)| body)
        .collect()
}

/// Lookup d'un paramètre précis dans l'arbre. Retourne la fiche
/// détaillée (type, observed_values ≤50, min/max, occurrences, flag
/// `decoded_from_octets`, `truncated`+`distinct_values_seen` si
/// dépassement). Les `example_sessions` sont ajoutés par le
/// handler qui a l'accès aux events.
pub fn lookup_param(
    builder: &ProtocolTreeBuilder,
    interface: &str,
    protocol: &str,
    message: &str,
    param_path: &str,
) -> Option<Value> {
    let key = (
        interface.to_owned(),
        protocol.to_owned(),
        message.to_owned(),
        param_path.to_owned(),
    );
    let obs = builder.params.get(&key)?;
    let truncated_total = builder
        .distinct_seen
        .get(&key)
        .copied()
        .unwrap_or_else(|| obs.observed_values.len());
    let mut body = obs.to_json(truncated_total);
    if let Some(object) = body.as_object_mut() {
        object.insert("interface".into(), Value::String(interface.to_owned()));
        object.insert("protocol".into(), Value::String(protocol.to_owned()));
        object.insert("message".into(), Value::String(message.to_owned()));
        object.insert("param_path".into(), Value::String(param_path.to_owned()));
    }
    Some(body)
}

/// Rend `message_counts` + `params` accessibles au handler pour
/// collecter des exemples sans ré-ingester les events.
impl ProtocolTreeBuilder {
    pub fn knows_message(&self, interface: &str, protocol: &str, message: &str) -> bool {
        self.message_counts
            .contains_key(&(interface.to_owned(), protocol.to_owned(), message.to_owned()))
    }

    pub fn knows_param(
        &self,
        interface: &str,
        protocol: &str,
        message: &str,
        param_path: &str,
    ) -> bool {
        self.params.contains_key(&(
            interface.to_owned(),
            protocol.to_owned(),
            message.to_owned(),
            param_path.to_owned(),
        ))
    }
}

/// Scanne les events d'un flow pour collecter les ≤ N tuples
/// `(session_id, event_id, capture_id, seq)` qui portent le
/// paramètre `(interface, protocol, message, param_path)`.
/// Ordre canonique (capture_id, seq, event_id).
pub fn collect_param_example_sessions<'a, F>(
    flows: F,
    interface: &str,
    protocol: &str,
    message: &str,
    param_path: &str,
    max: usize,
) -> Vec<Value>
where
    F: IntoIterator<Item = (&'a str, &'a [CallFlowEvent])>,
{
    let path_segments: Vec<String> = param_path
        .split('/')
        .map(str::to_owned)
        .filter(|s| !s.is_empty())
        .collect();
    let mut hits: Vec<(String, u64, String, String)> = Vec::new();
    for (session_id, events) in flows {
        for event in events {
            if event.interface != interface
                || event.protocol != protocol
                || event.message_name != message
            {
                continue;
            }
            let mut found = false;
            walk_ie_tree(&event.decoded_ie_tree, Vec::new(), &mut |ie_path, _map| {
                if ie_path == path_segments.as_slice() {
                    found = true;
                }
            });
            if !found {
                continue;
            }
            let seq = event
                .packet_references
                .first()
                .map(|pr| pr.packet_number)
                .unwrap_or(0);
            hits.push((
                event.capture_id.clone(),
                seq,
                event.event_id.clone(),
                session_id.to_owned(),
            ));
        }
    }
    hits.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    hits.into_iter()
        .take(max)
        .map(|(capture_id, seq, event_id, session_id)| {
            json!({
                "session_id": session_id,
                "event_id": event_id,
                "capture_id": capture_id,
                "seq": seq,
            })
        })
        .collect()
}

pub fn field_result_to_json(field: &ColumnField, result: &ColumnFieldResult) -> Value {
    let proof: Vec<Value> = result
        .proof
        .iter()
        .map(|p| {
            json!({
                "event_id": p.event_id,
                "capture_id": p.capture_id,
                "seq": p.seq,
            })
        })
        .collect();
    json!({
        "interface": field.interface,
        "protocol": field.protocol,
        "message": field.message,
        "param_path": field.param_path,
        "mode": field.mode,
        "value": result.value,
        "proof": proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_present_columns_remain_after_projection() {
        let mut summary = json!({
            "session_id": "s1",
            "dataset_id": "d1",
            "dataset_kind": "HISTORICAL",
            "technology": "5G SA",
            "ue_pseudonym": "psn-aaa",
            "state": "ACTIVE_WITH_USER_PLANE",
            "procedure": "PDUSessionEstablishment",
            "message_count": 42,
        });
        let requested: BTreeSet<String> = ["state"].into_iter().map(String::from).collect();
        project_columns(&mut summary, &requested);
        let object = summary.as_object().unwrap();
        assert!(object.contains_key("session_id"));
        assert!(object.contains_key("dataset_id"));
        assert!(object.contains_key("dataset_kind"));
        assert!(object.contains_key("technology"));
        assert!(object.contains_key("state"));
        assert!(!object.contains_key("procedure"));
        assert!(!object.contains_key("message_count"));
        assert!(!object.contains_key("ue_pseudonym"));
    }

    #[test]
    fn projection_does_not_invent_missing_columns() {
        let mut summary = json!({
            "session_id": "s1",
            "dataset_id": "d1",
            "dataset_kind": "HISTORICAL",
            "technology": "5G SA",
        });
        let requested: BTreeSet<String> = ["user_plane_packets"]
            .into_iter()
            .map(String::from)
            .collect();
        project_columns(&mut summary, &requested);
        let object = summary.as_object().unwrap();
        assert!(!object.contains_key("user_plane_packets"));
        assert_eq!(object.len(), 4, "only always-present survive");
    }

    #[test]
    fn validate_columns_rejects_unknown_name() {
        let error = validate_columns(&["state".into(), "not_a_real_column".into()]).unwrap_err();
        assert_eq!(error, "not_a_real_column");
    }

    #[test]
    fn validate_columns_accepts_all_catalog_names() {
        let names: Vec<String> = known_column_names().into_iter().collect();
        let accepted = validate_columns(&names).unwrap();
        assert_eq!(accepted.len(), known_column_names().len());
    }

    #[test]
    fn catalog_never_lists_clear_identity_columns() {
        // Règle Sadok 2026-11-14 : aucune colonne nommée imsi/supi/
        // msisdn/imei/guti/tmsi/suci en clair dans le catalog.
        let forbidden = [
            "imsi", "supi", "suci", "msisdn", "imei", "imeisv", "guti", "tmsi", "pei",
        ];
        for column in columns_catalog() {
            let name = column
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            for banned in &forbidden {
                assert!(
                    !name.contains(banned)
                        || name.contains("pseudonym")
                        || name.contains("identities"),
                    "forbidden clear identity column name: {name}"
                );
            }
        }
    }

    // 2.19.1 tests — protocol tree, criteria, fields, search, param.

    use callflow_schema::{CallFlow, CallFlowEvent, EventAccounting, Participant};
    use session_engine::{Association, PacketRef};

    fn mk_event(
        id: &str,
        interface: &str,
        protocol: &str,
        message_name: &str,
        decoded_ie_tree: Value,
        capture_id: &str,
        packet_number: u64,
    ) -> CallFlowEvent {
        CallFlowEvent {
            event_id: id.into(),
            timestamp: "2026-11-16T00:00:00.000000000Z".into(),
            timestamp_ns: "0".into(),
            interface: interface.into(),
            protocol: protocol.into(),
            message_name: message_name.into(),
            source_participant: "gNB".into(),
            destination_participant: "AMF".into(),
            direction: "RAN_TO_CORE".into(),
            decoded_ie_tree,
            decoding_status: "DECODED".into(),
            semantic_status: "NORMAL".into(),
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

    fn mk_flow(session_id: &str, events: Vec<CallFlowEvent>) -> CallFlow {
        CallFlow {
            callflow_id: format!("cf-{session_id}"),
            session_id: session_id.into(),
            technology: "5G SA".into(),
            start_timestamp: "2026-11-16T00:00:00.000000000Z".into(),
            end_timestamp: "2026-11-16T00:00:00.000000000Z".into(),
            participants: vec![
                Participant {
                    id: "gNB".into(),
                    role: "gNB".into(),
                    addresses: vec!["10.0.0.1".into()],
                },
                Participant {
                    id: "AMF".into(),
                    role: "AMF".into(),
                    addresses: vec!["172.22.0.10".into()],
                },
            ],
            interfaces: vec!["N2".into()],
            procedures: vec![],
            events,
            correlation_edges: vec![],
            correlation_status: Default::default(),
            decoder_versions: Default::default(),
            schema_version: "1.5.0".into(),
            capture_references: vec!["run-001".into()],
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

    /// 2.19.1 — `ProtocolTreeBuilder` publie les valeurs réellement
    /// observées (≤ 50, comptées), min/max numériques, et le flag
    /// `decoded_from_octets=true` pour une IE marquée DECODED.
    #[test]
    fn protocol_tree_publishes_observed_values_and_min_max() {
        let event_a = mk_event(
            "e1",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            json!([
                {"name": "RAN-UE-NGAP-ID", "value": "4", "status": "DECODED"},
                {"name": "Cause", "value": "cause=1", "status": "DECODED"},
            ]),
            "cap-a",
            7,
        );
        let event_b = mk_event(
            "e2",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            json!([
                {"name": "RAN-UE-NGAP-ID", "value": "9", "status": "DECODED"},
                {"name": "Cause", "value": "cause=42", "status": "DECODED"},
            ]),
            "cap-a",
            12,
        );
        let mut builder = ProtocolTreeBuilder::new();
        for e in [&event_a, &event_b] {
            builder.observe_event(e);
        }
        let tree = builder.to_protocol_tree_json();
        // Shape : array of interfaces → protocols → messages.
        let n2 = tree
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["interface"] == "N2")
            .unwrap();
        let ngap = n2["protocols"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["protocol"] == "NGAP")
            .unwrap();
        let message = &ngap["messages"][0];
        assert_eq!(message["message"], "PDUSessionResourceSetupResponse");
        assert_eq!(message["detail"]["occurrences"], 2);
        let params = message["detail"]["params"].as_array().unwrap();
        let ran_ue = params
            .iter()
            .find(|p| p["param_path"] == "RAN-UE-NGAP-ID")
            .unwrap();
        assert_eq!(ran_ue["occurrences"], 2);
        assert_eq!(ran_ue["decoded_from_octets"], true);
        assert_eq!(ran_ue["min"], 4);
        assert_eq!(ran_ue["max"], 9);
        // 2 valeurs distinctes {"4","9"} chacune comptée 1.
        let values = ran_ue["observed_values"].as_array().unwrap();
        assert_eq!(values.len(), 2);
    }

    /// 2.19.1 — tous les opérateurs (eq, ne, gt, lt, contains, in).
    #[test]
    fn criteria_operators_match_expected_events() {
        let event = mk_event(
            "e1",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            json!([{"name": "Cause", "value": "42", "status": "DECODED"}]),
            "cap-a",
            1,
        );
        let eq_crit = FilterCriterion {
            interface: Some("N2".into()),
            protocol: Some("NGAP".into()),
            message: "PDUSessionResourceSetupResponse".into(),
            param_path: Some("Cause".into()),
            op: "eq".into(),
            value: Some(json!("42")),
            values: None,
        };
        assert!(evaluate_criterion(&event, &eq_crit).is_some());
        let ne_crit = FilterCriterion { op: "ne".into(), value: Some(json!("99")), ..eq_crit.clone() };
        assert!(evaluate_criterion(&event, &ne_crit).is_some());
        let gt_crit = FilterCriterion { op: "gt".into(), value: Some(json!("40")), ..eq_crit.clone() };
        assert!(evaluate_criterion(&event, &gt_crit).is_some());
        let lt_crit = FilterCriterion { op: "lt".into(), value: Some(json!("100")), ..eq_crit.clone() };
        assert!(evaluate_criterion(&event, &lt_crit).is_some());
        let contains_crit = FilterCriterion {
            op: "contains".into(),
            value: Some(json!("4")),
            ..eq_crit.clone()
        };
        assert!(evaluate_criterion(&event, &contains_crit).is_some());
        let in_crit = FilterCriterion {
            op: "in".into(),
            value: None,
            values: Some(vec![json!("1"), json!("42"), json!("99")]),
            ..eq_crit.clone()
        };
        assert!(evaluate_criterion(&event, &in_crit).is_some());
        // Non-match : cause doit être 99.
        let no_match = FilterCriterion {
            op: "eq".into(),
            value: Some(json!("99")),
            ..eq_crit
        };
        assert!(evaluate_criterion(&event, &no_match).is_none());
    }

    /// 2.19.1 — AND / OR combinator + matched_criteria pointe le
    /// bon event.
    #[test]
    fn criteria_combinator_and_or_and_matched_hits_point_events() {
        let event_a = mk_event(
            "ea",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            json!([{"name": "Cause", "value": "42", "status": "DECODED"}]),
            "cap-a",
            10,
        );
        let event_b = mk_event(
            "eb",
            "N2",
            "NGAP",
            "InitialContextSetupResponse",
            json!([{"name": "Cause", "value": "1", "status": "DECODED"}]),
            "cap-a",
            20,
        );
        let events = vec![event_a.clone(), event_b.clone()];
        let crit1 = FilterCriterion {
            interface: None,
            protocol: None,
            message: "PDUSessionResourceSetupResponse".into(),
            param_path: Some("Cause".into()),
            op: "eq".into(),
            value: Some(json!("42")),
            values: None,
        };
        let crit2 = FilterCriterion {
            interface: None,
            protocol: None,
            message: "InitialContextSetupResponse".into(),
            param_path: Some("Cause".into()),
            op: "eq".into(),
            value: Some(json!("1")),
            values: None,
        };
        // AND : les 2 crit doivent chacun matcher ≥ 1 event.
        let (hits_and, passes_and) =
            aggregate_session_hits(&events, &[crit1.clone(), crit2.clone()], &FilterCombinator::And);
        assert!(passes_and);
        assert_eq!(hits_and.len(), 2);
        // matched_hits pointent les bons events.
        assert!(hits_and
            .iter()
            .any(|h| h.event_id == "ea" && h.criterion_index == 0 && h.seq == 10));
        assert!(hits_and
            .iter()
            .any(|h| h.event_id == "eb" && h.criterion_index == 1 && h.seq == 20));

        // OR : un seul critère suffit.
        let crit_absent = FilterCriterion {
            interface: None,
            protocol: None,
            message: "DoesNotExist".into(),
            param_path: None,
            op: "eq".into(),
            value: None,
            values: None,
        };
        let (_hits_or, passes_or) = aggregate_session_hits(
            &events,
            &[crit_absent, crit1.clone()],
            &FilterCombinator::Or,
        );
        assert!(passes_or);

        // AND avec un critère absent → passes=false.
        let (_hits, passes) = aggregate_session_hits(
            &events,
            &[crit1, FilterCriterion {
                interface: None,
                protocol: None,
                message: "DoesNotExist".into(),
                param_path: None,
                op: "eq".into(),
                value: None,
                values: None,
            }],
            &FilterCombinator::And,
        );
        assert!(!passes);
    }

    /// 2.19.1 — les 4 modes de `ColumnField` et la preuve
    /// `{event_id, capture_id, seq}` en ordre canonique.
    #[test]
    fn column_field_modes_last_first_all_count_with_proof() {
        let e1 = mk_event(
            "e1",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            json!([{"name": "Cause", "value": "1", "status": "DECODED"}]),
            "cap-a",
            10,
        );
        let e2 = mk_event(
            "e2",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            json!([{"name": "Cause", "value": "42", "status": "DECODED"}]),
            "cap-a",
            30,
        );
        let events = vec![e1, e2];
        let base = ColumnField {
            interface: "N2".into(),
            protocol: "NGAP".into(),
            message: Some("PDUSessionResourceSetupResponse".into()),
            param_path: "Cause".into(),
            mode: "last".into(),
        };
        let last = evaluate_field_on_session(&events, &base).unwrap();
        assert_eq!(last.value, json!("42"));
        assert_eq!(last.proof[0].event_id, "e2");
        assert_eq!(last.proof[0].seq, 30);

        let first = evaluate_field_on_session(
            &events,
            &ColumnField { mode: "first".into(), ..base.clone() },
        )
        .unwrap();
        assert_eq!(first.value, json!("1"));
        assert_eq!(first.proof[0].event_id, "e1");

        let all = evaluate_field_on_session(
            &events,
            &ColumnField { mode: "all".into(), ..base.clone() },
        )
        .unwrap();
        assert_eq!(all.value, json!(["1", "42"]));
        assert_eq!(all.proof.len(), 2);

        let count = evaluate_field_on_session(
            &events,
            &ColumnField { mode: "count".into(), ..base.clone() },
        )
        .unwrap();
        assert_eq!(count.value, json!(2));

        // Absent → value Null.
        let absent = evaluate_field_on_session(
            &events,
            &ColumnField {
                param_path: "MissingParam".into(),
                ..base
            },
        )
        .unwrap();
        assert_eq!(absent.value, Value::Null);
        assert!(absent.proof.is_empty());
    }

    /// 2.19.1 — recherche : exact > préfixe > contient, insensible
    /// à la casse. Scope `interfaces` applique.
    #[test]
    fn search_protocol_tree_orders_by_relevance_and_scopes_by_interface() {
        let events = vec![
            mk_event(
                "e1",
                "N2",
                "NGAP",
                "PDUSessionResourceSetupResponse",
                json!([{"name": "Cause", "value": "1", "status": "DECODED"}]),
                "cap-a",
                1,
            ),
            mk_event(
                "e2",
                "N4",
                "PFCP",
                "PFCP Session Establishment Response",
                json!([{"name": "Cause", "value": "1", "status": "DECODED"}]),
                "cap-b",
                2,
            ),
        ];
        let mut builder = ProtocolTreeBuilder::new();
        for e in &events {
            builder.observe_event(e);
        }
        let results = search_protocol_tree(&builder, "Cause", &BTreeSet::new(), 50);
        // "Cause" matche exactement le param path → score max.
        assert!(!results.is_empty());
        assert_eq!(results[0]["param_path"], "Cause");
        // Scope N2 uniquement : exclut PFCP.
        let n2_only: BTreeSet<String> = ["N2".into()].into_iter().collect();
        let scoped = search_protocol_tree(&builder, "Cause", &n2_only, 50);
        for row in scoped {
            assert_eq!(row["interface"], "N2");
        }
    }

    /// 2.19.1 — fiche param : type, observed_values ≤ 50, min/max.
    #[test]
    fn lookup_param_returns_type_and_observed_values_bag() {
        let event = mk_event(
            "e1",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            json!([{"name": "Cause", "value": "42", "status": "DECODED"}]),
            "cap-a",
            1,
        );
        let mut builder = ProtocolTreeBuilder::new();
        builder.observe_event(&event);
        let body = lookup_param(
            &builder,
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            "Cause",
        )
        .unwrap();
        assert_eq!(body["type"], "integer");
        assert_eq!(body["occurrences"], 1);
        assert_eq!(body["min"], 42);
        assert_eq!(body["max"], 42);
        let values = body["observed_values"].as_array().unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["value"], "42");
        assert_eq!(values[0]["count"], 1);
    }

    /// 2.19.1 — `collect_param_example_sessions` renvoie ≤ N
    /// exemples triés (capture_id, seq, event_id).
    #[test]
    fn param_example_sessions_are_bounded_and_canonically_ordered() {
        let e_late = mk_event(
            "e-late",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            json!([{"name": "Cause", "value": "42", "status": "DECODED"}]),
            "cap-a",
            100,
        );
        let e_early = mk_event(
            "e-early",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            json!([{"name": "Cause", "value": "1", "status": "DECODED"}]),
            "cap-a",
            10,
        );
        let flow_a = mk_flow("s1", vec![e_late]);
        let flow_b = mk_flow("s2", vec![e_early]);
        let examples = collect_param_example_sessions(
            [
                (flow_a.session_id.as_str(), flow_a.events.as_slice()),
                (flow_b.session_id.as_str(), flow_b.events.as_slice()),
            ],
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            "Cause",
            5,
        );
        assert_eq!(examples.len(), 2);
        // Ordre canonique : seq=10 avant seq=100.
        assert_eq!(examples[0]["seq"], 10);
        assert_eq!(examples[0]["session_id"], "s2");
        assert_eq!(examples[1]["seq"], 100);
    }

    /// 2.19.1 — les IEs identité (imsi/supi/imei/…) ne contribuent
    /// PAS aux observed_values de l'arbre.
    #[test]
    fn protocol_tree_excludes_clear_identity_ies_from_value_bag() {
        let event = mk_event(
            "e1",
            "N2",
            "NAS-5GMM",
            "Registration Request",
            json!([
                {"name": "imsi", "value": "001011234567890", "status": "DECODED"},
                {"name": "Cause", "value": "42", "status": "DECODED"},
            ]),
            "cap-a",
            1,
        );
        let mut builder = ProtocolTreeBuilder::new();
        builder.observe_event(&event);
        let body = lookup_param(&builder, "N2", "NAS-5GMM", "Registration Request", "imsi");
        assert!(
            body.is_none(),
            "imsi path must never be ingested into the tree"
        );
        // Mais Cause est bien là.
        assert!(lookup_param(&builder, "N2", "NAS-5GMM", "Registration Request", "Cause").is_some());
    }

    /// 2.19.1 — observed_values est plafonné à `MAX_DISTINCT_VALUES_PER_PARAM` et
    /// `truncated=true` + `distinct_values_seen` signalés.
    #[test]
    fn protocol_tree_caps_distinct_values_and_signals_truncation() {
        let mut builder = ProtocolTreeBuilder::new();
        for i in 0..120 {
            let event = mk_event(
                "eX",
                "N2",
                "NGAP",
                "PDUSessionResourceSetupResponse",
                json!([{"name": "Cause", "value": format!("{i}"), "status": "DECODED"}]),
                "cap-a",
                i as u64,
            );
            builder.observe_event(&event);
        }
        let body = lookup_param(
            &builder,
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            "Cause",
        )
        .unwrap();
        let values = body["observed_values"].as_array().unwrap();
        assert_eq!(values.len(), MAX_DISTINCT_VALUES_PER_PARAM);
        assert_eq!(body["truncated"], true);
        assert_eq!(body["distinct_values_seen"], 120);
    }
}
