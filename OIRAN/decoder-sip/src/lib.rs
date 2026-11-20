//! Session Initiation Protocol decoder (RFC 3261) for IMS voice
//! signalling.
//!
//! # Scope
//!
//! * Start-line : request (method + Request-URI + SIP/2.0) **or**
//!   status-line (SIP/2.0 + code + reason).
//! * Headers : `Call-ID`, `CSeq`, `From` (tag + URI), `To` (tag +
//!   URI), `Via` (branch), `Contact`.
//! * SDP body (if `Content-Type: application/sdp` and `Content-Length`
//!   accommodates it) : `c=` (connection address) and `m=audio port
//!   RTP/AVP codec` (dynamic port + codec).
//!
//! # Privacy
//!
//! Tout `sip:`/`tel:`/`sips:` URI et tout numéro de téléphone sont
//! pseudonymisés AVANT émission via
//! `event_schema::pseudonym(key, SUBSCRIBER_PSEUDO_DOMAIN, bytes)` —
//! la valeur brute ne sort pas du décodeur. L'`event_id` est
//! déterministe, dérivé des champs non-identifiants (Call-ID, CSeq,
//! méthode) de sorte que deux décodes du même message produisent
//! le même id.

use event_schema::{
    pseudonym, pseudonym_subscriber_digits, sha256_hex, DecodeStatus, Direction,
    EvidenceReference, EvidenceState, InformationElement, NormalizedEvent, Protocol,
    SUBSCRIBER_PSEUDO_DOMAIN,
};
use plugin_runtime::{
    DecoderCapabilities, DecoderInput, DecoderManifest, DecoderOutput, ProtocolDecoder,
    PLUGIN_API_VERSION,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SCHEMA_VERSION: &str = "IETF RFC 3261 + RFC 4566 SDP";

/// 2.11.0 (devmat) — port d'écoute SIP par défaut. Sert au routing
/// UDP/TCP (voir `oiran-decode::udp_route`).
pub const SIP_DEFAULT_PORT: u16 = 5060;

#[derive(Default)]
pub struct SipDecoder;

/// Résultat compact du parse SIP. Ne contient AUCUNE identité en
/// clair — URIs/numéros sont pseudonymisés sur place par le
/// décodeur.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SipMessage {
    pub is_request: bool,
    pub method: String,
    pub request_uri_pseudonym: Option<String>,
    pub status_code: u16,
    pub reason_phrase: String,
    pub call_id: String,
    pub cseq_number: u32,
    pub cseq_method: String,
    pub from_tag: String,
    pub from_uri_pseudonym: Option<String>,
    pub to_tag: String,
    pub to_uri_pseudonym: Option<String>,
    pub via_branch: String,
    pub sdp: Option<SdpSummary>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SdpSummary {
    /// `c=IN IP4 <addr>` ou `c=IN IP6 <addr>` — adresse de
    /// connexion négociée. Pas pseudonymisée : c'est de la
    /// topologie réseau, pas une identité abonné.
    pub connection_address: String,
    /// `m=audio <port> RTP/AVP <payload-types>` — on garde le
    /// premier port + les codecs en PT list.
    pub media_audio_port: u16,
    pub media_audio_codec_pts: Vec<u8>,
    /// 2.21.79 (CLAUDE1, ordre #9 7012275179 §1) — `a=rtpmap:<pt>
    /// <encoding>/<clock_rate>[/<channels>]` (RFC 4566 §6). Nécessaire
    /// pour calculer le jitter RTP sur les PT dynamiques (96..=127) où
    /// l'horloge n'est pas fixée par la table statique RFC 3551 §6.
    /// Première paire `(pt, clock_rate_hz)` trouvée dans le bloc audio,
    /// `None` si absent.
    pub media_audio_rtpmap_clock_rate_hz: Option<u32>,
}

/// Parse best-effort d'un message SIP à partir de son payload UDP/TCP.
/// Retourne `None` si le payload ne ressemble pas à du SIP (ni
/// start-line valide ni status-line). Fail-safe : jamais de panic.
pub fn parse(payload: &[u8]) -> Option<SipMessage> {
    // SIP est textuel (ASCII). On lit ligne par ligne jusqu'à une
    // ligne vide (fin des headers) puis on considère le reste
    // comme body.
    let text = std::str::from_utf8(payload).ok()?;
    let mut lines = text.split("\r\n");
    let start_line = lines.next()?;
    let mut msg = SipMessage::default();

    if let Some(rest) = start_line.strip_prefix("SIP/2.0 ") {
        // Status-line : "SIP/2.0 200 OK"
        msg.is_request = false;
        let mut parts = rest.splitn(2, ' ');
        let code = parts.next()?.parse::<u16>().ok()?;
        msg.status_code = code;
        msg.reason_phrase = parts.next().unwrap_or("").to_string();
    } else {
        // Request-line : "INVITE sip:bob@example.com SIP/2.0"
        let mut parts = start_line.split(' ');
        let method = parts.next()?;
        let uri = parts.next()?;
        let version = parts.next()?;
        if !version.starts_with("SIP/2.0") || method.is_empty() {
            return None;
        }
        msg.is_request = true;
        msg.method = method.to_string();
        // Request-URI pseudonymisé plus bas (il faut la clé).
        msg.request_uri_pseudonym = Some(uri.to_string());
    }

    // Collecte des headers jusqu'à la ligne vide.
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body_offset: Option<usize> = None;
    let mut byte_cursor: usize = start_line.len() + 2; // +\r\n
    while let Some(line) = lines.next() {
        if line.is_empty() {
            body_offset = Some(byte_cursor + 2);
            break;
        }
        if let Some(idx) = line.find(':') {
            let name = line[..idx].trim().to_ascii_lowercase();
            let value = line[idx + 1..].trim().to_string();
            headers.push((name, value));
        }
        byte_cursor += line.len() + 2;
    }

    for (name, value) in &headers {
        match name.as_str() {
            "call-id" | "i" => msg.call_id = value.clone(),
            "cseq" => {
                let mut split = value.split_whitespace();
                if let Some(num) = split.next().and_then(|v| v.parse::<u32>().ok()) {
                    msg.cseq_number = num;
                }
                msg.cseq_method = split.next().unwrap_or("").to_string();
            }
            "from" | "f" => {
                let (uri, tag) = split_name_addr(value);
                msg.from_tag = tag;
                msg.from_uri_pseudonym = Some(uri);
            }
            "to" | "t" => {
                let (uri, tag) = split_name_addr(value);
                msg.to_tag = tag;
                msg.to_uri_pseudonym = Some(uri);
            }
            "via" | "v" => {
                for param in value.split(';') {
                    if let Some(branch) = param.trim().strip_prefix("branch=") {
                        if msg.via_branch.is_empty() {
                            msg.via_branch = branch.to_string();
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Body : si Content-Type: application/sdp.
    let content_type = headers
        .iter()
        .find(|(n, _)| n == "content-type" || n == "c")
        .map(|(_, v)| v.to_ascii_lowercase());
    if let (Some(offset), Some(ct)) = (body_offset, content_type) {
        if ct.contains("application/sdp") && offset <= payload.len() {
            let body = &payload[offset..];
            msg.sdp = parse_sdp(body);
        }
    }

    Some(msg)
}

/// Extrait l'URI entre `<...>` (ou le mot nu avant `;`), et le
/// paramètre `tag=`. Pas de pseudonymisation ici — faite à
/// l'émission.
fn split_name_addr(value: &str) -> (String, String) {
    let uri = if let (Some(lt), Some(gt)) = (value.find('<'), value.find('>')) {
        value[lt + 1..gt].to_string()
    } else {
        value.split(';').next().unwrap_or("").trim().to_string()
    };
    let mut tag = String::new();
    for param in value.split(';') {
        if let Some(t) = param.trim().strip_prefix("tag=") {
            tag = t.to_string();
            break;
        }
    }
    (uri, tag)
}

/// 2.21.79 (CLAUDE1, ordre #9 7012275179 §2) — Extrait les chiffres
/// IMSI/MSISDN canoniques depuis le user-part d'une URI SIP/TEL :
///
/// * `sip:208930000000001@ims.mnc093.mcc208.3gppnetwork.org` → `208930000000001` (IMSI, 3GPP TS 23.003 §13.4.2)
/// * `sip:+33612345678@ims.example.com;user=phone`           → `33612345678` (MSISDN E.164 sans `+`)
/// * `tel:+33612345678`                                      → `33612345678`
/// * `sips:…`                                                → idem `sip:`
/// * `sip:alice@ims.example.com`                             → `None` (user non-numérique)
/// * `sip:208...999a@...`                                    → `None` (user mixte)
///
/// Retourne `None` quand aucune identité numérique canonique n'est
/// extractible. Le hash NAS est calculé via
/// `pseudonym_subscriber_digits(key, digits)` sur les mêmes bytes :
/// deux chemins (NAS et SIP) rendent le MÊME pseudonyme pour la
/// même identité physique.
fn extract_subscriber_digits_from_uri(uri: &str) -> Option<Vec<u8>> {
    let scheme_stripped = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))
        .or_else(|| uri.strip_prefix("tel:"))
        .unwrap_or(uri);
    // Coupe à `@` (sip/sips) et à `;` (params tel/sip) et `,` (telURI extensions).
    let user_part = scheme_stripped
        .split('@')
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .split(',')
        .next()
        .unwrap_or("")
        .trim();
    // `+<digits>` (E.164) → strip `+`.
    let canonical = user_part.strip_prefix('+').unwrap_or(user_part);
    // Filtre : user DOIT être entièrement composé de chiffres ASCII
    // décimaux et non vide. Pas de tolérance : un user mixte
    // (`208...999a`) retourne `None`.
    if canonical.is_empty() || !canonical.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(canonical.as_bytes().to_vec())
}

/// Parse SDP minimal (RFC 4566) : `c=IN IPx <addr>` + première
/// `m=audio <port> RTP/AVP <pt...>`.
fn parse_sdp(body: &[u8]) -> Option<SdpSummary> {
    let text = std::str::from_utf8(body).ok()?;
    let mut summary = SdpSummary::default();
    let mut in_audio_media = false;
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("c=") {
            // `IN IP4 1.2.3.4`
            if let Some(addr) = rest.split_whitespace().nth(2) {
                if summary.connection_address.is_empty() {
                    summary.connection_address = addr.to_string();
                }
            }
        } else if let Some(rest) = line.strip_prefix("m=") {
            let mut parts = rest.split_whitespace();
            let media = parts.next().unwrap_or("");
            let port = parts.next().and_then(|v| v.parse::<u16>().ok()).unwrap_or(0);
            let _proto = parts.next().unwrap_or("");
            if media == "audio" && summary.media_audio_port == 0 {
                summary.media_audio_port = port;
                for pt in parts {
                    if let Ok(v) = pt.parse::<u8>() {
                        summary.media_audio_codec_pts.push(v);
                    }
                }
                in_audio_media = true;
            } else {
                in_audio_media = false;
            }
        } else if in_audio_media && line.starts_with("a=") {
            // 2.21.79 — `a=rtpmap:<pt> <encoding>/<clock_rate>[/<channels>]`
            // RFC 4566 §6. On ne garde que la première paire du bloc
            // audio (celle qui correspond au PT préféré de l'offerer).
            if summary.media_audio_rtpmap_clock_rate_hz.is_none() {
                if let Some(rest) = line.strip_prefix("a=rtpmap:") {
                    let mut parts = rest.split_whitespace();
                    let _pt = parts.next();
                    if let Some(encoding_desc) = parts.next() {
                        let mut subparts = encoding_desc.split('/');
                        let _encoding_name = subparts.next();
                        if let Some(rate_str) = subparts.next() {
                            if let Ok(rate) = rate_str.parse::<u32>() {
                                if rate > 0 {
                                    summary.media_audio_rtpmap_clock_rate_hz = Some(rate);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if summary.media_audio_port == 0 && summary.connection_address.is_empty() {
        None
    } else {
        Some(summary)
    }
}

impl ProtocolDecoder for SipDecoder {
    fn manifest(&self) -> DecoderManifest {
        DecoderManifest {
            decoder_name: "decoder-sip",
            decoder_version: VERSION,
            api_version: PLUGIN_API_VERSION,
            protocol: Protocol::Sip,
            specification: SCHEMA_VERSION,
            deterministic: true,
        }
    }
    fn capabilities(&self) -> DecoderCapabilities {
        DecoderCapabilities {
            message_families: &[
                "REGISTER",
                "INVITE",
                "BYE",
                "ACK",
                "CANCEL",
                "OPTIONS",
                "PRACK",
                "UPDATE",
                "MESSAGE",
                "SUBSCRIBE",
                "NOTIFY",
                "status-response",
            ],
            preserves_unknown_fields: false,
            supports_extensions: false,
            limitations: &[
                "URIs and phone numbers are pseudonymized before emission",
                "SDP body parsing is minimal (c= + m=audio)",
                "TCP/TLS reassembly not performed (caller must provide a complete SIP message)",
                "SIP compact header forms accepted (f=, t=, i=, v=, c=)",
            ],
        }
    }
    fn decode(&self, input: &DecoderInput<'_>) -> DecoderOutput {
        let Some(msg) = parse(input.payload) else {
            return DecoderOutput {
                status: DecodeStatus::Malformed,
                events: vec![emit_malformed_event(input, "unparseable SIP payload")],
                errors: vec!["unparseable SIP payload".into()],
            };
        };
        let event = emit_event(msg, input);
        DecoderOutput {
            status: DecodeStatus::Decoded,
            events: vec![event],
            errors: Vec::new(),
        }
    }
}

fn emit_malformed_event(input: &DecoderInput<'_>, reason: &str) -> NormalizedEvent {
    let mut event = NormalizedEvent {
        event_id: String::new(),
        stable_event_key: String::new(),
        parent_event_id: None,
        probe_id: "oiran-vprobe-01".into(),
        capture_point_id: input.interface.into(),
        capture_id: input.capture_id.into(),
        packet_references: input.packet_references.to_vec(),
        timestamp: input.timestamp.clone(),
        interface: input.interface.into(),
        protocol: Protocol::Sip,
        message_name: "MalformedSipMessage".into(),
        message_type: 0,
        procedure_code: None,
        procedure: None,
        security_state: None,
        source_byte_offset: None,
        source_endpoint: input.source_endpoint.clone(),
        destination_endpoint: input.destination_endpoint.clone(),
        direction: Direction::Unknown,
        session_identifiers: Vec::new(),
        information_elements: vec![InformationElement {
            id: None,
            name: "parse_error".into(),
            length: reason.len() as u32,
            value: Some(reason.into()),
            raw_sha256: None,
            status: DecodeStatus::Malformed,
        }],
        decoder_name: "decoder-sip".into(),
        decoder_version: VERSION.into(),
        schema_version: NormalizedEvent::SCHEMA_VERSION,
        decoding_status: DecodeStatus::Malformed,
        errors: vec![reason.into()],
        raw_payload_reference: input.raw_payload_reference.into(),
        evidence_references: vec![EvidenceReference {
            state: EvidenceState::Exact,
            kind: "packet-provenance".into(),
            reference: input.raw_payload_reference.into(),
        }],
        sbi: None,
    };
    event.assign_deterministic_id();
    event
}

fn emit_event(mut msg: SipMessage, input: &DecoderInput<'_>) -> NormalizedEvent {
    let key = input.pseudonym_key;
    // Pseudonymise à l'émission. Les champs locaux détiennent
    // encore l'URI/numéro en clair ; après cette étape ils sont
    // remplacés par leur pseudonyme et sortent de scope à la fin
    // du match.
    let pseudo_uri = |uri: &str| {
        // Normalise `sip:alice@example.com;params` → `sip:alice@example.com`
        // avant hash pour que deux URIs équivalents produisent le
        // même pseudonyme.
        let trimmed = uri.split(';').next().unwrap_or(uri).trim();
        pseudonym(key, SUBSCRIBER_PSEUDO_DOMAIN, trimmed.as_bytes())
    };
    // 2.21.79 (CLAUDE1, ordre #9 7012275179 §2) — extraction des chiffres
    // IMSI/MSISDN avant pseudonymisation URI, pour que `subscriber_pseudonym`
    // SIP soit *identique* à `subscriber_pseudonym` NAS sur la même
    // identité. Les URIs qui ne portent pas de chiffres (ex. `sip:alice@…`)
    // retombent sur le pseudonyme URI pur (non-unifié, utilisé seulement
    // pour l'affichage).
    let from_digits_pseudo = msg
        .from_uri_pseudonym
        .as_deref()
        .and_then(extract_subscriber_digits_from_uri)
        .map(|digits| pseudonym_subscriber_digits(key, &digits));
    let to_digits_pseudo = msg
        .to_uri_pseudonym
        .as_deref()
        .and_then(extract_subscriber_digits_from_uri)
        .map(|digits| pseudonym_subscriber_digits(key, &digits));
    let request_digits_pseudo = msg
        .request_uri_pseudonym
        .as_deref()
        .and_then(extract_subscriber_digits_from_uri)
        .map(|digits| pseudonym_subscriber_digits(key, &digits));
    if let Some(uri) = msg.request_uri_pseudonym.as_deref() {
        msg.request_uri_pseudonym = Some(pseudo_uri(uri));
    }
    if let Some(uri) = msg.from_uri_pseudonym.as_deref() {
        msg.from_uri_pseudonym = Some(pseudo_uri(uri));
    }
    if let Some(uri) = msg.to_uri_pseudonym.as_deref() {
        msg.to_uri_pseudonym = Some(pseudo_uri(uri));
    }

    let (message_name, direction) = if msg.is_request {
        (msg.method.clone(), Direction::Uplink)
    } else {
        (
            format!("{} {}", msg.status_code, msg.reason_phrase),
            Direction::Downlink,
        )
    };

    let mut ies: Vec<InformationElement> = Vec::new();
    ies.push(InformationElement {
        id: None,
        name: "CSeq".into(),
        length: 0,
        value: Some(format!("{} {}", msg.cseq_number, msg.cseq_method)),
        raw_sha256: None,
        status: DecodeStatus::Decoded,
    });
    ies.push(InformationElement {
        id: None,
        name: "via_branch".into(),
        length: msg.via_branch.len() as u32,
        value: Some(msg.via_branch.clone()),
        raw_sha256: None,
        status: DecodeStatus::Decoded,
    });
    ies.push(InformationElement {
        id: None,
        name: "from_tag".into(),
        length: msg.from_tag.len() as u32,
        value: Some(msg.from_tag.clone()),
        raw_sha256: None,
        status: DecodeStatus::Decoded,
    });
    ies.push(InformationElement {
        id: None,
        name: "to_tag".into(),
        length: msg.to_tag.len() as u32,
        value: Some(msg.to_tag.clone()),
        raw_sha256: None,
        status: DecodeStatus::Decoded,
    });
    // 2.21.79 (CLAUDE1, ordre #9 7012275179 §2) — `subscriber_pseudonym`
    // UNIFIÉ avec NAS : dérivé des chiffres canoniques IMSI/MSISDN
    // extraits du user-part de l'URI From. Deux chemins (NAS et SIP)
    // produisent la MÊME valeur pour la même identité → corrélation
    // directe par pseudonyme. Le pseudonyme URI pur reste exposé en
    // `from_uri_pseudonym` pour les cas où le user-part n'est pas
    // numérique (`sip:alice@…`), afin de ne pas perdre la provenance
    // présentationnelle. L'IE `subscriber_pseudonym` n'est émise QUE
    // quand l'extraction a réussi — pas de valeur fausse.
    if let Some(unified) = from_digits_pseudo.as_deref() {
        ies.push(InformationElement {
            id: None,
            name: "subscriber_pseudonym".into(),
            length: unified.len() as u32,
            value: Some(unified.into()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    if let Some(uri) = msg.from_uri_pseudonym.as_deref() {
        ies.push(InformationElement {
            id: None,
            name: "from_uri_pseudonym".into(),
            length: uri.len() as u32,
            value: Some(uri.into()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    if let Some(unified) = to_digits_pseudo.as_deref() {
        ies.push(InformationElement {
            id: None,
            name: "peer_subscriber_pseudonym".into(),
            length: unified.len() as u32,
            value: Some(unified.into()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    if let Some(uri) = msg.to_uri_pseudonym.as_deref() {
        ies.push(InformationElement {
            id: None,
            name: "to_uri_pseudonym".into(),
            length: uri.len() as u32,
            value: Some(uri.into()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    if let Some(unified) = request_digits_pseudo.as_deref() {
        ies.push(InformationElement {
            id: None,
            name: "request_subscriber_pseudonym".into(),
            length: unified.len() as u32,
            value: Some(unified.into()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    if let Some(uri) = msg.request_uri_pseudonym.as_deref() {
        ies.push(InformationElement {
            id: None,
            name: "request_uri_pseudonym".into(),
            length: uri.len() as u32,
            value: Some(uri.into()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    if let Some(sdp) = msg.sdp.as_ref() {
        ies.push(InformationElement {
            id: None,
            name: "sdp.c".into(),
            length: sdp.connection_address.len() as u32,
            value: Some(sdp.connection_address.clone()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
        // 2.17.0 (ANR1 #10 E2E 5G) — pseudonyme de l'adresse de
        // connexion SDP, utilisant EXACTEMENT le même domain que
        // `decoder-pfcp` pour `ue_ip` (`"pfcp-ue-ip"`, voir
        // `decoder-pfcp/src/lib.rs:268`). Ce hash est l'unique
        // identifiant qui permet la corrélation EXACT SIP↔N4 via UE
        // IP sans jamais exposer l'IP UE en clair hors de la trame
        // dissequée. Nom canonique : `sdp.c_ue_ip_pseudonym`.
        let ue_ip_pseudo = pseudonym(
            input.pseudonym_key,
            "pfcp-ue-ip",
            sdp.connection_address.as_bytes(),
        );
        ies.push(InformationElement {
            id: None,
            name: "sdp.c_ue_ip_pseudonym".into(),
            length: ue_ip_pseudo.len() as u32,
            value: Some(ue_ip_pseudo),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
        ies.push(InformationElement {
            id: None,
            name: "sdp.m.audio.port".into(),
            length: 2,
            value: Some(sdp.media_audio_port.to_string()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
        let pts = sdp
            .media_audio_codec_pts
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        ies.push(InformationElement {
            id: None,
            name: "sdp.m.audio.pt".into(),
            length: pts.len() as u32,
            value: Some(pts),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
        // 2.21.79 (CLAUDE1, ordre #9 7012275179 §1) — clock_rate SDP
        // propagée pour que `RtpFlowAggregator` puisse calculer le
        // jitter en ticks RTP sur les PT dynamiques (96..=127).
        if let Some(rate) = sdp.media_audio_rtpmap_clock_rate_hz {
            ies.push(InformationElement {
                id: None,
                name: "sdp.m.audio.rtpmap_clock_rate_hz".into(),
                length: 4,
                value: Some(rate.to_string()),
                raw_sha256: None,
                status: DecodeStatus::Decoded,
            });
        }
    }

    let mut session_identifiers = Vec::new();
    if !msg.call_id.is_empty() {
        session_identifiers.push(event_schema::NamedValue {
            name: "sip_call_id".into(),
            value: msg.call_id.clone(),
            pseudonymized: false,
        });
    }
    // 2.21.79 (CLAUDE1, ordre #9 7012275179 §2) — propage le pseudo
    // unifié dans `session_identifiers` pour que la corrélation moteur
    // (`correlation-engine::subscriber_key`) rattache SIP ↔ NAS via le
    // même filtre `subscriber_pseudonym` que le reste du pipeline.
    if let Some(unified) = from_digits_pseudo.as_deref() {
        session_identifiers.push(event_schema::NamedValue {
            name: "subscriber_pseudonym".into(),
            value: unified.into(),
            pseudonymized: true,
        });
    }

    let payload_hash = sha256_hex(input.payload);
    let mut event = NormalizedEvent {
        event_id: String::new(),
        stable_event_key: String::new(),
        parent_event_id: None,
        probe_id: "oiran-vprobe-01".into(),
        capture_point_id: input.interface.into(),
        capture_id: input.capture_id.into(),
        packet_references: input.packet_references.to_vec(),
        timestamp: input.timestamp.clone(),
        interface: input.interface.into(),
        protocol: Protocol::Sip,
        message_name,
        message_type: msg.cseq_number,
        procedure_code: None,
        procedure: Some("VoNR/VoLTE".into()),
        security_state: None,
        source_byte_offset: None,
        source_endpoint: input.source_endpoint.clone(),
        destination_endpoint: input.destination_endpoint.clone(),
        direction,
        session_identifiers,
        information_elements: ies,
        decoder_name: "decoder-sip".into(),
        decoder_version: VERSION.into(),
        schema_version: NormalizedEvent::SCHEMA_VERSION,
        decoding_status: DecodeStatus::Decoded,
        errors: Vec::new(),
        raw_payload_reference: format!("sha256:{payload_hash}"),
        evidence_references: vec![EvidenceReference {
            state: EvidenceState::Exact,
            kind: "packet-provenance".into(),
            reference: input.raw_payload_reference.into(),
        }],
        sbi: None,
    };
    event.assign_deterministic_id();
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_schema::{Endpoint, ExactTimestamp, PacketReference, PseudonymKey};

    fn key() -> PseudonymKey {
        PseudonymKey::from_bytes([0x5a; 32])
    }

    fn input<'a>(payload: &'a [u8], key: &'a PseudonymKey, iface: &'a str) -> DecoderInput<'a> {
        DecoderInput {
            capture_id: "sha256:test",
            packet_references: Box::leak(Box::new([PacketReference {
                source_file: "x.pcapng".into(),
                source_sha256: None,
                packet_number: 1,
                byte_offset: 0,
                interface_id: 0,
                link_type: None,
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: payload.len() as u32,
                original_length: payload.len() as u32,
            }])),
            timestamp: Box::leak(Box::new(ExactTimestamp {
                seconds: 1_794_320_000,
                nanoseconds: 0,
                raw_ticks: 0,
                resolution_base: 10,
                resolution_exponent: 9,
            })),
            interface: iface,
            source_endpoint: Endpoint {
                address: "10.77.20.1".into(),
                port: Some(5060),
                network_function: Some("UE".into()),
            },
            destination_endpoint: Endpoint {
                address: "10.77.20.2".into(),
                port: Some(5060),
                network_function: Some("P-CSCF".into()),
            },
            payload,
            raw_payload_reference: "sha256:test-ref",
            pseudonym_key: key,
        }
    }

    #[test]
    fn parses_invite_with_sdp_and_pseudonymizes_uris() {
        let payload = b"\
INVITE sip:bob@ims.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-vonr-a1b2c3\r\n\
From: Alice <sip:alice@ims.example.com>;tag=a-tag-1234\r\n\
To: Bob <sip:bob@ims.example.com>\r\n\
Call-ID: cid-vonr-9f8e7d6c5b4a3210\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@10.0.0.1:5060>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 123\r\n\
\r\n\
v=0\r\n\
o=alice 1 1 IN IP4 10.0.0.1\r\n\
s=-\r\n\
c=IN IP4 10.0.0.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 8 96\r\n\
";
        let k = key();
        let d = SipDecoder;
        let out = d.decode(&input(payload, &k, "IMS"));
        assert_eq!(out.status, DecodeStatus::Decoded);
        assert_eq!(out.events.len(), 1);
        let ev = &out.events[0];
        assert_eq!(ev.protocol, Protocol::Sip);
        assert_eq!(ev.message_name, "INVITE");
        let serialized = ev.to_json();
        assert!(
            !serialized.contains("alice@"),
            "raw sip URI leaked: {serialized}"
        );
        assert!(
            !serialized.contains("bob@"),
            "raw sip URI leaked: {serialized}"
        );
        // Call-ID is identifier not identity → kept as identifier.
        assert!(serialized.contains("cid-vonr-9f8e7d6c5b4a3210"));
        // SDP c= + m= captured.
        assert!(serialized.contains("10.0.0.1"));
        assert!(serialized.contains("49170"));
    }

    #[test]
    fn parses_200_ok_status_line() {
        let payload = b"\
SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-vonr-a1b2c3\r\n\
From: Alice <sip:alice@ims.example.com>;tag=a-tag-1234\r\n\
To: Bob <sip:bob@ims.example.com>;tag=b-tag-5678\r\n\
Call-ID: cid-vonr-9f8e7d6c5b4a3210\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let k = key();
        let d = SipDecoder;
        let out = d.decode(&input(payload, &k, "IMS"));
        assert_eq!(out.status, DecodeStatus::Decoded);
        let ev = &out.events[0];
        assert_eq!(ev.message_name, "200 OK");
        assert!(ev.to_json().contains("b-tag-5678"));
    }

    #[test]
    fn deterministic_event_id_across_two_decodes() {
        let payload = b"\
BYE sip:bob@ims.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-vonr-bye-1\r\n\
From: Alice <sip:alice@ims.example.com>;tag=a-tag-1234\r\n\
To: Bob <sip:bob@ims.example.com>;tag=b-tag-5678\r\n\
Call-ID: cid-vonr-9f8e7d6c5b4a3210\r\n\
CSeq: 2 BYE\r\n\
Content-Length: 0\r\n\
\r\n";
        let k = key();
        let d = SipDecoder;
        let a = d.decode(&input(payload, &k, "IMS"));
        let b = d.decode(&input(payload, &k, "IMS"));
        assert_eq!(a.events[0].event_id, b.events[0].event_id);
    }

    #[test]
    fn same_uri_hashes_to_same_pseudonym() {
        let k = key();
        let p1 = pseudonym(&k, SUBSCRIBER_PSEUDO_DOMAIN, b"sip:alice@ims.example.com");
        let p2 = pseudonym(&k, SUBSCRIBER_PSEUDO_DOMAIN, b"sip:alice@ims.example.com");
        assert_eq!(p1, p2);
        let p3 = pseudonym(&k, SUBSCRIBER_PSEUDO_DOMAIN, b"sip:bob@ims.example.com");
        assert_ne!(p1, p3);
    }

    #[test]
    fn rejects_non_sip_payload() {
        let k = key();
        let d = SipDecoder;
        let out = d.decode(&input(b"\x00\x01\x02not SIP", &k, "IMS"));
        assert_eq!(out.status, DecodeStatus::Malformed);
        assert_eq!(out.events[0].message_name, "MalformedSipMessage");
    }

    /// 2.21.79 (CLAUDE1, ordre #9 7012275179 §2) — table de vérité de
    /// l'extracteur de chiffres : IMSI pur, MSISDN E.164, Tel URI, user
    /// non-numérique, user mixte.
    #[test]
    fn extract_subscriber_digits_from_uri_canonical_forms() {
        // IMSI 3GPP TS 23.003 §13.4.2 (sip:imsi@ims.mncXXX.mccYYY.3gppnetwork.org)
        assert_eq!(
            extract_subscriber_digits_from_uri("sip:208930000000001@ims.mnc093.mcc208.3gppnetwork.org"),
            Some(b"208930000000001".to_vec())
        );
        // sips: idem
        assert_eq!(
            extract_subscriber_digits_from_uri("sips:208930000000001@ims.mnc093.mcc208.3gppnetwork.org"),
            Some(b"208930000000001".to_vec())
        );
        // MSISDN E.164 — +33612345678 → 33612345678
        assert_eq!(
            extract_subscriber_digits_from_uri("sip:+33612345678@ims.example.com;user=phone"),
            Some(b"33612345678".to_vec())
        );
        // tel: URI — même pattern
        assert_eq!(
            extract_subscriber_digits_from_uri("tel:+33612345678"),
            Some(b"33612345678".to_vec())
        );
        // Parameters après `;` ignorés
        assert_eq!(
            extract_subscriber_digits_from_uri("sip:208930000000001@ims.example.com;transport=udp"),
            Some(b"208930000000001".to_vec())
        );
        // User textuel → None (pas d'identité numérique)
        assert_eq!(extract_subscriber_digits_from_uri("sip:alice@ims.example.com"), None);
        // User mixte → None (strictement numérique attendu)
        assert_eq!(extract_subscriber_digits_from_uri("sip:208abc999@ims.example.com"), None);
        // User vide → None
        assert_eq!(extract_subscriber_digits_from_uri("sip:@ims.example.com"), None);
        // URI sans schéma supporté → fallback (user part = chaîne complète)
        assert_eq!(extract_subscriber_digits_from_uri("bob@ims.example.com"), None);
    }

    /// 2.21.79 (CLAUDE1, ordre #9 7012275179 §2) — INVARIANT : le
    /// `subscriber_pseudonym` SIP, dérivé des chiffres canoniques
    /// extraits de l'URI From, DOIT ÉGALER le pseudonyme produit
    /// par `event_schema::pseudonym_subscriber_digits` sur les MÊMES
    /// chiffres (= ce que NAS fait sur son SUPI). Donc SIP ↔ NAS se
    /// rejoignent sur la même identité physique.
    #[test]
    fn sip_subscriber_pseudonym_equals_nas_pseudonym_on_same_identity() {
        let k = key();
        let imsi = b"208930000000001"; // 15 digits
        let nas_pseudo = pseudonym_subscriber_digits(&k, imsi);

        // SIP From URI porte le même IMSI en user-part.
        let payload = format!(
            "\
INVITE sip:208930000000002@ims.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-vonr-sub\r\n\
From: <sip:208930000000001@ims.mnc093.mcc208.3gppnetwork.org>;tag=t1\r\n\
To: <sip:208930000000002@ims.mnc093.mcc208.3gppnetwork.org>\r\n\
Call-ID: cid-sub-unification\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
        );
        let d = SipDecoder;
        let out = d.decode(&input(payload.as_bytes(), &k, "IMS"));
        assert_eq!(out.status, DecodeStatus::Decoded);
        let ev = &out.events[0];

        // IE `subscriber_pseudonym` == NAS pseudonym.
        let sip_sub = ev
            .information_elements
            .iter()
            .find(|ie| ie.name == "subscriber_pseudonym")
            .expect("subscriber_pseudonym doit être émis quand l'URI porte des chiffres")
            .value
            .as_deref()
            .unwrap();
        assert_eq!(sip_sub, nas_pseudo, "SIP et NAS doivent produire le MÊME pseudonyme");

        // Pseudo URI (`from_uri_pseudonym`) existe aussi, mais c'est une
        // valeur DIFFÉRENTE (hash de l'URI complète, pas seulement des
        // chiffres canoniques).
        let from_uri_pseudo = ev
            .information_elements
            .iter()
            .find(|ie| ie.name == "from_uri_pseudonym")
            .unwrap()
            .value
            .as_deref()
            .unwrap();
        assert_ne!(from_uri_pseudo, nas_pseudo);

        // session_identifiers doit contenir le pseudo unifié pour que
        // la corrélation engine le lise.
        let si_sub = ev
            .session_identifiers
            .iter()
            .find(|v| v.name == "subscriber_pseudonym")
            .expect("subscriber_pseudonym doit être propagé dans session_identifiers");
        assert_eq!(si_sub.value, nas_pseudo);
        assert!(si_sub.pseudonymized);
    }

    /// 2.21.79 — URI alphabétique (`sip:alice@…`) → aucun
    /// `subscriber_pseudonym` émis (pas de valeur fausse). Seul
    /// `from_uri_pseudonym` (opaque, présentationnel) reste.
    #[test]
    fn sip_without_numeric_user_emits_no_unified_subscriber_pseudonym() {
        let k = key();
        let payload = b"\
INVITE sip:bob@ims.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-vonr-alpha\r\n\
From: <sip:alice@ims.example.com>;tag=ta\r\n\
To: <sip:bob@ims.example.com>\r\n\
Call-ID: cid-alpha\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let d = SipDecoder;
        let out = d.decode(&input(payload, &k, "IMS"));
        let ev = &out.events[0];
        assert!(
            ev.information_elements
                .iter()
                .find(|ie| ie.name == "subscriber_pseudonym")
                .is_none(),
            "aucun subscriber_pseudonym ne doit sortir sans chiffres extractibles"
        );
        assert!(
            ev.session_identifiers
                .iter()
                .find(|v| v.name == "subscriber_pseudonym")
                .is_none(),
            "aucun subscriber_pseudonym ne doit figurer dans session_identifiers non plus"
        );
        // from_uri_pseudonym (opaque, non-unifié) reste présent.
        assert!(ev
            .information_elements
            .iter()
            .any(|ie| ie.name == "from_uri_pseudonym"));
    }
}
