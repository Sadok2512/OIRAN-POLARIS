//! 2.22.2 — table de corrélation `TEID ↔ SEID ↔ subscriber_pseudonym` (lot P2.2).
//!
//! Alimentée en lecture par les events normalisés du pipeline multi-capture
//! (`N2`, `N3`, `N4`, `SBI`). Lookup O(1) depuis `N3FlowAggregator` au moment
//! d'attacher l'identité pseudonymisée à un `UserPlaneSummary` (lot 2.22.3).
//!
//! # Sources
//!
//! Chaîne SUPI **multi-source** (correction C3 #9 6927882355) — ne pas
//! dépendre uniquement du NAS en clair qui n'est utilisable qu'en lab NEA0 :
//!
//! | Source                                    | Fiabilité | Message typique |
//! |-------------------------------------------|-----------|-----------------|
//! | `SourceKind::Sbi` (primaire)              | HAUTE     | `Nsmf_PDUSession CreateSMContext` (vTAP TLS) |
//! | `SourceKind::Pfcp` (primaire)             | HAUTE     | PFCP Session Establishment Request / Response |
//! | `SourceKind::Ngap` (primaire)             | HAUTE     | NGAP PDUSessionResourceSetupRequest / Response |
//! | `SourceKind::NasCleartext` (secondaire)   | FAIBLE    | NAS Registration Request/Complete — **uniquement si NAS en clair** |
//!
//! En production sous NEA2+, `NasCleartext` ne fournit rien ; les trois sources
//! primaires suffisent. Quand `NasCleartext` est observée en prod, un event
//! structuré `USERPLANE_NAS_CLEARTEXT_SEEN` est émis (dédupé par
//! `subscriber_pseudonym`).
//!
//! # Invariants
//!
//! - **Aucune identité en clair** : `subscriber_pseudonym` est un hash
//!   SHA-256 déjà calculé par `decoder-sbi::uri_subscriber_pseudonym` /
//!   `decoder-ngap`. La table ne stocke jamais de SUPI/IMSI/MSISDN brut.
//! - **Ordre canonique** : lookup indifférent au `ts`. Seul le dernier
//!   événement du tri canonique `(capture_id, packet_number)` ayant
//!   renseigné un champ fait foi (merge non-écrasant si la nouvelle source
//!   est plus faible ; les sources primaires ne sont pas écrasées par
//!   `NasCleartext`).
//! - **Dédup miss** : `record_miss(teid, direction)` renvoie `true` la
//!   première fois qu'un `(teid, direction)` manque, puis `false` ensuite.
//!   L'appelant n'émet l'event `USERPLANE_INDEX_MISS` que sur `true`.

use std::collections::{BTreeMap, BTreeSet};

use event_schema::{NamedValue, NormalizedEvent, Protocol};

/// Origine de l'information attachée à une entrée.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    /// Primaire : `Nsmf_PDUSession CreateSMContext` (SBI).
    Sbi,
    /// Primaire : PFCP Session Establishment Req/Resp (N4).
    Pfcp,
    /// Primaire : NGAP PDU Session Resource Setup (N2).
    Ngap,
    /// Secondaire : NAS Registration — utilisable uniquement en clair (NEA0).
    NasCleartext,
}

impl SourceKind {
    pub fn is_primary(self) -> bool {
        !matches!(self, SourceKind::NasCleartext)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Sbi => "sbi",
            SourceKind::Pfcp => "pfcp",
            SourceKind::Ngap => "ngap",
            SourceKind::NasCleartext => "nas_cleartext",
        }
    }
}

/// Entrée agrégée pour une session PDU, keyée (dans la table) par TEID
/// (UL et/ou DL). Les champs non encore renseignés sont `None`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserplaneIndexEntry {
    pub subscriber_pseudonym: Option<String>,
    pub subscriber_pseudonym_source: Option<SourceKind>,
    pub pdu_session_id: Option<u8>,
    pub seid_smf: Option<u64>,
    pub seid_upf: Option<u64>,
    pub teid_ul: Option<u32>,
    pub teid_dl: Option<u32>,
    pub five_qi: Option<u16>,
    pub qfi: Option<u8>,
    pub ue_ipv4: Option<String>,
    pub ue_ipv6: Option<String>,
    pub ran_ue_ngap_id: Option<u64>,
    pub amf_ue_ngap_id: Option<u64>,
}

impl UserplaneIndexEntry {
    /// Fusionne non-destructivement une mise à jour dans l'entrée. Les
    /// sources primaires (SBI/PFCP/NGAP) ne sont jamais écrasées par une
    /// source secondaire (NasCleartext).
    pub fn merge(&mut self, patch: UserplaneIndexEntry, patch_source: SourceKind) {
        let allow_overwrite = |existing_source: Option<SourceKind>| -> bool {
            match existing_source {
                None => true,
                Some(existing) => patch_source.is_primary() || !existing.is_primary(),
            }
        };
        if patch.subscriber_pseudonym.is_some()
            && (self.subscriber_pseudonym.is_none()
                || allow_overwrite(self.subscriber_pseudonym_source))
        {
            self.subscriber_pseudonym = patch.subscriber_pseudonym;
            self.subscriber_pseudonym_source = Some(patch_source);
        }
        if self.pdu_session_id.is_none() {
            self.pdu_session_id = patch.pdu_session_id;
        }
        if self.seid_smf.is_none() {
            self.seid_smf = patch.seid_smf;
        }
        if self.seid_upf.is_none() {
            self.seid_upf = patch.seid_upf;
        }
        if self.teid_ul.is_none() {
            self.teid_ul = patch.teid_ul;
        }
        if self.teid_dl.is_none() {
            self.teid_dl = patch.teid_dl;
        }
        if self.five_qi.is_none() {
            self.five_qi = patch.five_qi;
        }
        if self.qfi.is_none() {
            self.qfi = patch.qfi;
        }
        if self.ue_ipv4.is_none() {
            self.ue_ipv4 = patch.ue_ipv4;
        }
        if self.ue_ipv6.is_none() {
            self.ue_ipv6 = patch.ue_ipv6;
        }
        if self.ran_ue_ngap_id.is_none() {
            self.ran_ue_ngap_id = patch.ran_ue_ngap_id;
        }
        if self.amf_ue_ngap_id.is_none() {
            self.amf_ue_ngap_id = patch.amf_ue_ngap_id;
        }
    }
}

/// Table de corrélation partagée sur l'ensemble des captures N2/N3/N4/SBI.
///
/// Indexée **par TEID** (UL et DL pointent vers la même entrée logique via
/// `canonical_by_teid`). Une seconde table `by_subscriber` facilite le
/// recoupement avec le NAS en clair pour émettre `USERPLANE_NAS_CLEARTEXT_SEEN`
/// quand un subscriber_pseudonym vient du NAS secondaire sur un réseau qui
/// devrait l'avoir chiffré.
#[derive(Default, Debug)]
pub struct UserplaneIndex {
    /// Clé = `teid` en représentation hexadécimale `0x12345678` (format
    /// émis par `decoder-gtpu`, `decoder-pfcp`, `decoder-ngap`).
    by_teid: BTreeMap<String, UserplaneIndexEntry>,
    by_subscriber: BTreeMap<String, Vec<String>>, // pseudonym → [teids]
    miss_seen: BTreeSet<(String, String)>,         // (teid, direction)
    nas_cleartext_seen: BTreeSet<String>,          // pseudonyms déjà loggés
}

impl UserplaneIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe un event normalisé et extrait les signaux pertinents selon
    /// son `protocol` + `message_name` + `session_identifiers`.
    ///
    /// Renvoie la liste des sources déclenchées (vide si l'event n'apporte
    /// aucun signal pour la table).
    pub fn observe(&mut self, event: &NormalizedEvent) -> Vec<SourceKind> {
        let mut triggered = Vec::new();
        for source in classify_sources(event) {
            if let Some((teid_keys, patch)) = extract_patch(event, source) {
                for teid in teid_keys {
                    self.upsert(&teid, patch.clone(), source);
                }
                if let Some(pseudo) = &patch.subscriber_pseudonym {
                    if matches!(source, SourceKind::NasCleartext)
                        && self.nas_cleartext_seen.insert(pseudo.clone())
                    {
                        // L'appelant inspecte ce retour et émet
                        // `USERPLANE_NAS_CLEARTEXT_SEEN` une seule fois
                        // par pseudonym.
                        triggered.push(SourceKind::NasCleartext);
                        continue;
                    }
                }
                triggered.push(source);
            }
        }
        triggered
    }

    /// Lookup par TEID. Retourne `None` si le TEID n'a jamais été vu. L'appelant
    /// doit utiliser `record_miss` pour éviter les events miss en rafale.
    pub fn lookup(&self, teid_hex: &str) -> Option<&UserplaneIndexEntry> {
        self.by_teid.get(teid_hex)
    }

    /// Mémorise un couple `(teid, direction)` manquant. Renvoie `true` la
    /// première fois (l'appelant émet `USERPLANE_INDEX_MISS`) puis `false`.
    pub fn record_miss(&mut self, teid_hex: &str, direction: &str) -> bool {
        self.miss_seen
            .insert((teid_hex.into(), direction.into()))
    }

    /// Taille mémoire logique (nombre de TEIDs indexés). Pour la pression
    /// mémoire du lot 2.22.3.
    pub fn len(&self) -> usize {
        self.by_teid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_teid.is_empty()
    }

    fn upsert(&mut self, teid_hex: &str, patch: UserplaneIndexEntry, source: SourceKind) {
        let pseudo = patch.subscriber_pseudonym.clone();
        let entry = self.by_teid.entry(teid_hex.into()).or_default();
        entry.merge(patch, source);
        if let Some(pseudo) = pseudo {
            let teids = self.by_subscriber.entry(pseudo).or_default();
            if !teids.iter().any(|t| t == teid_hex) {
                teids.push(teid_hex.into());
            }
        }
    }
}

/// Classifie un event en zéro, une ou plusieurs sources potentielles selon
/// son protocole et son nom de message.
fn classify_sources(event: &NormalizedEvent) -> Vec<SourceKind> {
    let name = event.message_name.as_str();
    match event.protocol {
        Protocol::SbiHttp2 => {
            // `decoder-sbi` publie des events typiquement nommés
            // "Nsmf_PDUSession CreateSMContext" ou l'operation en IE. On
            // s'intéresse à tous les events SBI qui portent déjà
            // `subscriber_pseudonym` + `pdu_session_id`, pas seulement
            // CreateSMContext (UpdateSMContext fournit aussi la mise à jour
            // de TEID dans certains flux).
            vec![SourceKind::Sbi]
        }
        Protocol::Pfcp => {
            if name.contains("Session Establishment")
                || name.contains("Session Modification")
                || name.contains("Session Deletion")
            {
                vec![SourceKind::Pfcp]
            } else {
                Vec::new()
            }
        }
        Protocol::Ngap => {
            if name.contains("PDUSessionResourceSetup")
                || name.contains("PDU Session Resource Setup")
                || name.contains("PDUSessionResourceModify")
                || name.contains("PDUSessionResourceRelease")
                || name.contains("InitialContextSetup")
            {
                vec![SourceKind::Ngap]
            } else {
                Vec::new()
            }
        }
        Protocol::Nas5gmm => {
            // NAS Registration en clair (NEA0, lab) : secondaire.
            if name.contains("Registration") || name.contains("Service") {
                vec![SourceKind::NasCleartext]
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// Extrait les champs utiles d'un event selon la source. Retourne `None`
/// s'il n'y a pas de TEID exploitable (clé d'indexation primaire).
fn extract_patch(
    event: &NormalizedEvent,
    source: SourceKind,
) -> Option<(Vec<String>, UserplaneIndexEntry)> {
    let pick = |name: &str| -> Option<String> {
        event
            .session_identifiers
            .iter()
            .find(|identifier| identifier.name == name)
            .map(|identifier| identifier.value.clone())
    };
    let pick_u64 = |name: &str| -> Option<u64> {
        pick(name).and_then(|value| parse_hex_or_dec_u64(&value))
    };
    let pick_u32 = |name: &str| -> Option<u32> {
        pick(name).and_then(|value| parse_hex_or_dec_u64(&value).and_then(|n| u32::try_from(n).ok()))
    };
    let pick_u16 = |name: &str| -> Option<u16> {
        pick(name).and_then(|value| parse_hex_or_dec_u64(&value).and_then(|n| u16::try_from(n).ok()))
    };
    let pick_u8 = |name: &str| -> Option<u8> {
        pick(name).and_then(|value| parse_hex_or_dec_u64(&value).and_then(|n| u8::try_from(n).ok()))
    };

    let mut teid_keys: Vec<String> = Vec::new();
    for key in ["teid", "gtp_teid", "gtp_teid_ul", "gtp_teid_dl"] {
        if let Some(value) = pick(key) {
            let normalized = normalize_teid_key(&value);
            if !teid_keys.contains(&normalized) {
                teid_keys.push(normalized);
            }
        }
    }
    // NAS Registration n'a pas de TEID ; on indexe alors par pseudonym si
    // la table contient déjà une entrée avec ce pseudonym (merge enrichit
    // seulement la source=NasCleartext).
    if teid_keys.is_empty() {
        return None;
    }

    let teid_ul = pick_u32("gtp_teid_ul").or_else(|| pick_u32("teid").filter(|_| source_is_ul(event)));
    let teid_dl = pick_u32("gtp_teid_dl").or_else(|| pick_u32("teid").filter(|_| source_is_dl(event)));

    let five_qi = event
        .session_identifiers
        .iter()
        .filter(|identifier| identifier.name.starts_with("five_qi_"))
        .find_map(|identifier| identifier.value.parse().ok());
    let qfi = pick_u8("qfi").or_else(|| {
        event
            .session_identifiers
            .iter()
            .filter(|identifier| identifier.name.starts_with("qfi_"))
            .find_map(|identifier| identifier.value.parse().ok())
    });

    let (ue_ipv4, ue_ipv6) = match pick("ue_ip") {
        Some(value) if value.contains(':') => (None, Some(value)),
        Some(value) => (Some(value), None),
        None => (None, None),
    };

    let entry = UserplaneIndexEntry {
        subscriber_pseudonym: pick("subscriber_pseudonym"),
        subscriber_pseudonym_source: None, // positionné par merge
        pdu_session_id: pick_u8("pdu_session_id"),
        seid_smf: pick_u64("f_seid").or_else(|| pick_u64("seid")),
        seid_upf: pick_u64("seid_upf"),
        teid_ul,
        teid_dl,
        five_qi,
        qfi,
        ue_ipv4,
        ue_ipv6,
        ran_ue_ngap_id: pick_u64("ran_ue_ngap_id"),
        amf_ue_ngap_id: pick_u64("amf_ue_ngap_id"),
    };
    let _ = source; // la source est passée à `merge` par le caller.
    Some((teid_keys, entry))
}

/// Normalise une valeur de TEID en représentation `0x{:08x}` indifférente
/// à la casse d'entrée. `decoder-gtpu` émet déjà cette forme, mais
/// `decoder-pfcp` et `decoder-ngap` peuvent émettre `0x1234` sans padding.
fn normalize_teid_key(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(stripped) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        if let Ok(n) = u64::from_str_radix(stripped, 16) {
            return format!("0x{:08x}", n & 0xffff_ffff);
        }
    }
    if let Ok(n) = trimmed.parse::<u64>() {
        return format!("0x{:08x}", n & 0xffff_ffff);
    }
    trimmed.to_ascii_lowercase()
}

fn parse_hex_or_dec_u64(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(stripped) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        return u64::from_str_radix(stripped, 16).ok();
    }
    trimmed.parse().ok()
}

fn source_is_ul(event: &NormalizedEvent) -> bool {
    matches!(
        event.direction,
        event_schema::Direction::Uplink | event_schema::Direction::RanToCore
    )
}

fn source_is_dl(event: &NormalizedEvent) -> bool {
    matches!(
        event.direction,
        event_schema::Direction::Downlink | event_schema::Direction::CoreToRan
    )
}

/// Attache les champs de l'entrée (si présents) sur un `NormalizedEvent`
/// produit par un agrégateur N3. Utilisé par le lot 2.22.3 ; exposé ici
/// pour que les tests 2.22.2 puissent valider l'enrichissement.
pub fn attach_entry_to_event(event: &mut NormalizedEvent, entry: &UserplaneIndexEntry) {
    let mut push = |name: &str, value: String, pseudonymized: bool| {
        // N'ajoute pas un doublon si l'event porte déjà cette clé
        // (preserve l'identifier émis par le décodeur, ex. `qfi` gtpu).
        if event
            .session_identifiers
            .iter()
            .any(|identifier| identifier.name == name)
        {
            return;
        }
        event.session_identifiers.push(NamedValue {
            name: name.into(),
            value,
            pseudonymized,
        });
    };
    if let Some(pseudo) = &entry.subscriber_pseudonym {
        push("subscriber_pseudonym", pseudo.clone(), true);
    }
    if let Some(source) = entry.subscriber_pseudonym_source {
        push(
            "subscriber_pseudonym_source",
            source.as_str().into(),
            false,
        );
    }
    if let Some(pdu_session_id) = entry.pdu_session_id {
        push("pdu_session_id", pdu_session_id.to_string(), false);
    }
    if let Some(seid) = entry.seid_smf {
        push("seid_smf", format!("0x{seid:016x}"), false);
    }
    if let Some(seid) = entry.seid_upf {
        push("seid_upf", format!("0x{seid:016x}"), false);
    }
    if let Some(five_qi) = entry.five_qi {
        push("five_qi", five_qi.to_string(), false);
    }
    if let Some(qfi) = entry.qfi {
        push("qfi", qfi.to_string(), false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_schema::{
        DecodeStatus, Direction, Endpoint, ExactTimestamp, InformationElement, NormalizedEvent,
        Protocol,
    };

    fn make_event(
        protocol: Protocol,
        interface: &str,
        message_name: &str,
        identifiers: Vec<(&str, &str, bool)>,
    ) -> NormalizedEvent {
        NormalizedEvent {
            event_id: "evt".into(),
            parent_event_id: None,
            probe_id: "oiran-vprobe-local-01".into(),
            capture_point_id: interface.into(),
            capture_id: "sha256:synthetic".into(),
            packet_references: vec![],
            timestamp: ExactTimestamp {
                seconds: 1,
                nanoseconds: 0,
                raw_ticks: 1,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: interface.into(),
            protocol,
            message_name: message_name.into(),
            message_type: 0,
            procedure_code: None,
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: Endpoint {
                address: "10.0.0.1".into(),
                port: None,
                network_function: None,
            },
            destination_endpoint: Endpoint {
                address: "10.0.0.2".into(),
                port: None,
                network_function: None,
            },
            direction: Direction::Unknown,
            session_identifiers: identifiers
                .into_iter()
                .map(|(name, value, pseudonymized)| NamedValue {
                    name: name.into(),
                    value: value.into(),
                    pseudonymized,
                })
                .collect(),
            information_elements: Vec::<InformationElement>::new(),
            decoder_name: "test".into(),
            decoder_version: "0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:x".into(),
            evidence_references: vec![],
            sbi: None,
        }
    }

    #[test]
    fn sbi_create_smcontext_seeds_subscriber_pseudonym_and_pdu_session_id() {
        let event = make_event(
            Protocol::SbiHttp2,
            "SBI",
            "Nsmf_PDUSession CreateSMContext",
            vec![
                ("teid", "0x000096a8", false),
                ("subscriber_pseudonym", "sha256:pseudo-ue201", true),
                ("pdu_session_id", "1", false),
            ],
        );
        let mut index = UserplaneIndex::new();
        let triggered = index.observe(&event);
        assert_eq!(triggered, vec![SourceKind::Sbi]);
        let entry = index.lookup("0x000096a8").expect("indexed");
        assert_eq!(entry.subscriber_pseudonym.as_deref(), Some("sha256:pseudo-ue201"));
        assert_eq!(entry.subscriber_pseudonym_source, Some(SourceKind::Sbi));
        assert_eq!(entry.pdu_session_id, Some(1));
    }

    #[test]
    fn pfcp_session_establishment_seeds_seid_and_ue_ip() {
        let event = make_event(
            Protocol::Pfcp,
            "N4",
            "Session Establishment Request",
            vec![
                ("teid", "0x96a8", false),
                ("f_seid", "0x0123456789abcdef", false),
                ("ue_ip", "10.45.0.4", true),
            ],
        );
        let mut index = UserplaneIndex::new();
        index.observe(&event);
        // TEID 0x96a8 (sans padding) et 0x000096a8 (format décodeur-gtpu)
        // doivent indexer la même entrée.
        let entry = index.lookup("0x000096a8").expect("normalized teid");
        assert_eq!(entry.seid_smf, Some(0x0123_4567_89ab_cdef));
        assert_eq!(entry.ue_ipv4.as_deref(), Some("10.45.0.4"));
    }

    #[test]
    fn ngap_pdu_session_resource_setup_seeds_five_qi_and_teid_ul() {
        let event = make_event(
            Protocol::Ngap,
            "N2",
            "PDUSessionResourceSetupRequest",
            vec![
                ("gtp_teid", "0x000096a8", false),
                ("pdu_session_id", "1", false),
                ("subscriber_pseudonym", "sha256:pseudo-ue201", true),
                ("five_qi_0", "9", false),
                ("ran_ue_ngap_id", "4", false),
                ("amf_ue_ngap_id", "73", false),
            ],
        );
        let mut index = UserplaneIndex::new();
        index.observe(&event);
        let entry = index.lookup("0x000096a8").expect("indexed");
        assert_eq!(entry.five_qi, Some(9));
        assert_eq!(entry.pdu_session_id, Some(1));
        assert_eq!(entry.ran_ue_ngap_id, Some(4));
        assert_eq!(entry.amf_ue_ngap_id, Some(73));
    }

    #[test]
    fn nas_cleartext_is_secondary_and_does_not_overwrite_sbi_primary_pseudonym() {
        let mut index = UserplaneIndex::new();
        // Étape 1 : SBI pose un pseudonym primaire.
        let sbi = make_event(
            Protocol::SbiHttp2,
            "SBI",
            "Nsmf_PDUSession CreateSMContext",
            vec![
                ("teid", "0x000096a8", false),
                ("subscriber_pseudonym", "sha256:sbi-primary", true),
                ("pdu_session_id", "1", false),
            ],
        );
        index.observe(&sbi);
        // Étape 2 : NAS en clair prétend fournir le pseudonym.
        let nas = make_event(
            Protocol::Nas5gmm,
            "N2",
            "Registration Request",
            vec![
                ("teid", "0x000096a8", false),
                ("subscriber_pseudonym", "sha256:nas-cleartext", true),
            ],
        );
        index.observe(&nas);
        let entry = index.lookup("0x000096a8").expect("indexed");
        assert_eq!(
            entry.subscriber_pseudonym.as_deref(),
            Some("sha256:sbi-primary"),
            "SBI primary ne doit JAMAIS être écrasé par NAS en clair"
        );
        assert_eq!(entry.subscriber_pseudonym_source, Some(SourceKind::Sbi));
    }

    #[test]
    fn multi_source_scenario_fills_all_fields() {
        let mut index = UserplaneIndex::new();
        index.observe(&make_event(
            Protocol::SbiHttp2,
            "SBI",
            "Nsmf_PDUSession CreateSMContext",
            vec![
                ("teid", "0x000096a8", false),
                ("subscriber_pseudonym", "sha256:ue201", true),
                ("pdu_session_id", "1", false),
            ],
        ));
        index.observe(&make_event(
            Protocol::Pfcp,
            "N4",
            "Session Establishment Request",
            vec![
                ("teid", "0x000096a8", false),
                ("f_seid", "0x0123456789abcdef", false),
                ("ue_ip", "10.45.0.4", true),
            ],
        ));
        index.observe(&make_event(
            Protocol::Ngap,
            "N2",
            "PDUSessionResourceSetupRequest",
            vec![
                ("gtp_teid", "0x000096a8", false),
                ("five_qi_0", "9", false),
                ("ran_ue_ngap_id", "4", false),
            ],
        ));
        let entry = index.lookup("0x000096a8").expect("indexed");
        assert_eq!(entry.subscriber_pseudonym.as_deref(), Some("sha256:ue201"));
        assert_eq!(entry.pdu_session_id, Some(1));
        assert_eq!(entry.seid_smf, Some(0x0123_4567_89ab_cdef));
        assert_eq!(entry.five_qi, Some(9));
        assert_eq!(entry.ue_ipv4.as_deref(), Some("10.45.0.4"));
        assert_eq!(entry.ran_ue_ngap_id, Some(4));
    }

    #[test]
    fn miss_is_deduped_per_teid_and_direction() {
        let mut index = UserplaneIndex::new();
        assert!(index.record_miss("0x000096a8", "UPLINK"), "1ère miss");
        assert!(!index.record_miss("0x000096a8", "UPLINK"), "doublon UPLINK");
        assert!(index.record_miss("0x000096a8", "DOWNLINK"), "direction nouvelle");
        assert!(!index.record_miss("0x000096a8", "DOWNLINK"), "doublon DOWNLINK");
        assert!(index.record_miss("0x00000003", "UPLINK"), "teid nouveau");
    }

    #[test]
    fn nas_cleartext_sans_pseudonym_existant_ouvre_entry_mais_marque_source_nas() {
        let mut index = UserplaneIndex::new();
        index.observe(&make_event(
            Protocol::Nas5gmm,
            "N2",
            "Registration Request",
            vec![
                ("teid", "0x00000003", false),
                ("subscriber_pseudonym", "sha256:nas-only", true),
            ],
        ));
        let entry = index.lookup("0x00000003").expect("indexed");
        assert_eq!(entry.subscriber_pseudonym.as_deref(), Some("sha256:nas-only"));
        assert_eq!(
            entry.subscriber_pseudonym_source,
            Some(SourceKind::NasCleartext)
        );
    }

    #[test]
    fn attach_entry_to_event_fills_aggregate_identifiers() {
        let mut index = UserplaneIndex::new();
        index.observe(&make_event(
            Protocol::SbiHttp2,
            "SBI",
            "Nsmf_PDUSession CreateSMContext",
            vec![
                ("teid", "0x000096a8", false),
                ("subscriber_pseudonym", "sha256:ue201", true),
                ("pdu_session_id", "1", false),
            ],
        ));
        let mut aggregate = make_event(
            Protocol::Gtpu,
            "N3",
            "G-PDU",
            vec![("teid", "0x000096a8", false)],
        );
        let entry = index.lookup("0x000096a8").cloned().expect("indexed");
        attach_entry_to_event(&mut aggregate, &entry);
        let pick = |name: &str| {
            aggregate
                .session_identifiers
                .iter()
                .find(|identifier| identifier.name == name)
                .map(|identifier| identifier.value.clone())
        };
        assert_eq!(pick("subscriber_pseudonym").as_deref(), Some("sha256:ue201"));
        assert_eq!(pick("pdu_session_id").as_deref(), Some("1"));
        assert_eq!(pick("subscriber_pseudonym_source").as_deref(), Some("sbi"));
    }

    #[test]
    fn teid_key_normalization_canonical_format_regardless_of_input() {
        assert_eq!(normalize_teid_key("0x96a8"), "0x000096a8");
        assert_eq!(normalize_teid_key("0X96A8"), "0x000096a8");
        assert_eq!(normalize_teid_key("0x000096a8"), "0x000096a8");
        assert_eq!(normalize_teid_key("38568"), "0x000096a8"); // décimal
    }
}
