//! 2.19.0 — catalog de filtres/colonnes + projection colonnes.
//!
//! But fonctionnel (ANR1 attend catalog + columns pour p900 2.7.0) :
//! * `GET /sessions/catalog` expose en une requête ce qui est
//!   filtrable (interfaces, technologies, dataset_kinds, states,
//!   correlation_statuses, messages, causes) ET la liste des
//!   colonnes publiables par la liste `/sessions` + `/sessions/filter`.
//! * `POST /sessions/filter` accepte un champ optionnel `columns` qui
//!   restreint la projection serveur — moins de bytes sur le fil.
//! * `POST /sessions/columns` prévisualise un sous-ensemble de
//!   colonnes pour une liste de `session_ids` donnée : requête
//!   « donne-moi ces colonnes pour ces N sessions » sans refiltrer.
//!
//! Contrat vie privée identique à 2.18 : la projection ne crée pas
//! de clé, elle en supprime. `sanitize_all`/`sanitize_value` reste la
//! barrière finale sur les IE qui pourraient porter une identité.
//! Aucune des colonnes exposées ne contient d'identité en clair
//! (règle Sadok 2026-11-14 : null-scheme IMSI/SUPI uniquement dans
//! l'UI Auth). Les colonnes catalog NE listent QUE les champs
//! pseudonymisés — `ue_pseudonym`, `subscriber_pseudonym` — jamais
//! `imsi`, `supi`, `msisdn`, `imei`, `guti` ou `tmsi` en clair.

use std::collections::{BTreeMap, BTreeSet};

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

/// Shape d'une requête `POST /sessions/columns`.
#[derive(Deserialize, Default)]
pub struct SessionsColumnsRequest {
    #[serde(default)]
    pub session_ids: Vec<String>,
    #[serde(default)]
    pub columns: Vec<String>,
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
}
