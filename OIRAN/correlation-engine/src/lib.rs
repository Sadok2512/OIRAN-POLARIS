//! Evidence-based N2/N4/N3 correlation without timestamp-only joins.

use callflow_schema::CorrelationEdge;
use serde::Deserialize;
use session_engine::{
    component, discover_lte_sessions, Association, DiscoveryResult, EventRecord, Reconstruction,
};
use std::collections::BTreeMap;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const RULE_VERSION: &str = "1.0.0";
pub const DISCOVERY_RULE_VERSION: &str = "1.1.0";
pub const SBI_RULE_VERSION: &str = "1.0.0";
pub const E2E_EVIDENCE_RULE_VERSION: &str = "2.0.0";
/// 2.7.16 — N4↔N3 edge rule publishes the PFCP F-TEID / outer-header-creation
/// evidence that was previously hidden inside session-engine's gtpu_tunnels
/// discovery. See DSN-ENGINE-002 in AUDIT_E2E_CERT_001.
pub const N4_N3_RULE_VERSION: &str = "1.0.0";
pub const LTE_RULE_VERSION: &str = "1.1.0-offline.1";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TunnelCorrelationKey {
    endpoint_ip: String,
    teid: String,
    capture_id: String,
}

fn capture_scope(event: &EventRecord) -> String {
    // 2.7.16 (DSN-SCOPE-001): when `source_file` carries the live-probe
    // convention `/captures/<scope>/<pcapng>`, extract <scope>. Fall back
    // to the parent-directory segment of the source file (works for
    // dataset fixtures rooted under `datasets/<scope>/<pcapng>`), and
    // finally to the per-file capture_id — which only unifies within a
    // single plane and is therefore a last resort. Prior to this fix a
    // continuous or fixture dataset whose planes each carried their own
    // pcapng SHA-256 would never match across N2/N4/N3 because the
    // fallback keyed on the sha. See AUDIT_E2E_CERT_001.
    event
        .packet_references
        .first()
        .and_then(|packet| {
            if let Some(start) = packet.source_file.find("/captures/") {
                let rest = &packet.source_file[start + "/captures/".len()..];
                return rest.split('/').next().map(str::to_owned);
            }
            let path = std::path::Path::new(&packet.source_file);
            path.parent()
                .and_then(|parent| parent.file_name())
                .and_then(|name| name.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| event.capture_id.clone())
}

/// Correlates independently decoded N2, SBI and N4 observations without
/// turning a tunnel match into an identity assertion. The capture scope and
/// uniqueness checks are mandatory; timestamps are retained as provenance but
/// are never the matching key.
pub fn correlate_cross_interface_evidence(events: &[EventRecord]) -> Vec<CorrelationEdge> {
    let mut edges = Vec::new();
    let ngap = events
        .iter()
        .filter_map(|event| {
            if event.interface != "N2" || event.protocol != "NGAP" {
                return None;
            }
            tunnel_key(event).map(|key| (event, key))
        })
        .collect::<Vec<_>>();
    let pfcp = events
        .iter()
        .flat_map(|event| {
            if event.interface != "N4" || event.protocol != "PFCP" {
                return Vec::new();
            }
            tunnel_keys(event)
                .into_iter()
                .map(|key| (event, key))
                .collect()
        })
        .collect::<Vec<_>>();
    for (n2, key) in &ngap {
        let matches = pfcp
            .iter()
            .filter(|(_, candidate)| candidate == key)
            .collect::<Vec<_>>();
        let n2_duplicates = ngap
            .iter()
            .filter(|(_, candidate)| candidate == key)
            .count();
        if matches.len() == 1 && n2_duplicates == 1 {
            let mut found = edge(n2, matches[0].0,
                vec![format!("endpoint_ip={}", key.endpoint_ip), format!("teid={}", key.teid), format!("capture_scope={}", key.capture_id)],
                "ngap-pfcp-exact-tunnel", "EXACT",
                "A unique NGAP UP transport endpoint/TEID equals a unique PFCP Created-PDR F-TEID in the same capture scope");
            found.rule_version = E2E_EVIDENCE_RULE_VERSION.into();
            found.evidence_type = "EXACT_TUNNEL_MATCH".into();
            found.scope = "tunnel-only".into();
            found.limitations = vec![
                "The tunnel match does not by itself prove UE or full session identity".into(),
            ];
            edges.push(found);
        }
    }

    let n2_contexts = events
        .iter()
        .filter(|e| {
            e.interface == "N2"
                && e.protocol == "NGAP"
                && e.message_name == "PDUSessionResourceSetupRequest"
                && e.first_identifier("pdu_session_id").is_some()
        })
        .collect::<Vec<_>>();
    let sbi_contexts = events
        .iter()
        .filter(|e| {
            e.interface == "SBI"
                && e.protocol == "SBI-HTTP2"
                && matches!(
                    e.message_name.as_str(),
                    "CreateSMContext" | "N1N2MessageTransfer" | "UpdateSMContext"
                )
        })
        .collect::<Vec<_>>();
    if let [n2] = n2_contexts.as_slice() {
        let pdu = n2.first_identifier("pdu_session_id");
        let candidates = sbi_contexts
            .iter()
            .filter(|sbi| {
                sbi.message_name == "CreateSMContext"
                    && pdu.is_some()
                    && sbi.first_identifier("pdu_session_id") == pdu
                    && capture_scope(sbi) == capture_scope(n2)
            })
            .collect::<Vec<_>>();
        if let [sbi] = candidates.as_slice() {
            let mut found = edge(n2, sbi, vec![format!("pdu_session_id={}", pdu.unwrap_or("unknown"))], "ngap-sbi-context-association", "STRONG", "The uniquely scoped NGAP context and SBI operation share the observed PDU Session ID");
            found.rule_version = E2E_EVIDENCE_RULE_VERSION.into();
            found.evidence_type = "STRONG_CONTEXT_ASSOCIATION".into();
            found.scope = "capture+pdu-session".into();
            found.limitations = vec!["No explicit verified NGAP UE identifier to SBI subscriber identity bridge is present".into()];
            edges.push(found);
        }
    }

    // Multiple independent properties may justify STRONG association, but no
    // direct SM Context-to-SEID mapping is asserted.
    let creates = sbi_contexts
        .iter()
        .filter(|event| event.message_name == "CreateSMContext")
        .copied()
        .collect::<Vec<_>>();
    let establishments = events
        .iter()
        .filter(|event| {
            event.interface == "N4"
                && event.protocol == "PFCP"
                && event.message_name == "PFCP Session Establishment Request"
        })
        .collect::<Vec<_>>();
    if let ([sbi], [pfcp]) = (creates.as_slice(), establishments.as_slice()) {
        let sbi_dnn = ie_value(sbi, "dnn");
        let pfcp_dnn =
            ie_component(pfcp, "network_instance").or_else(|| ie_component(pfcp, "apn_dnn"));
        if sbi_dnn.is_some()
            && sbi_dnn == pfcp_dnn.as_deref()
            && capture_scope(sbi) == capture_scope(pfcp)
        {
            let sm_context = sbi_contexts
                .iter()
                .find_map(|event| event.first_identifier("sm_context_reference"));
            let seids = [
                pfcp.first_identifier("seid"),
                pfcp.first_identifier("f_seid"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            let mut identifiers = vec![format!("dnn={}", sbi_dnn.unwrap_or("unknown"))];
            if let Some(reference) = sm_context {
                identifiers.push(format!("sm_context_reference={reference}"));
            }
            identifiers.extend(
                seids
                    .into_iter()
                    .map(|seid| format!("pfcp_session_identifier={seid}")),
            );
            let mut found = edge(sbi, pfcp, identifiers, "sbi-pfcp-context-association", "STRONG", "A unique CreateSMContext and PFCP Session Establishment in the same capture scope share DNN and observed SMF procedure context");
            found.rule_version = E2E_EVIDENCE_RULE_VERSION.into();
            found.evidence_type = "STRONG_CONTEXT_ASSOCIATION".into();
            found.scope = "capture+smf-procedure+dnn".into();
            found.limitations = vec!["SM Context reference and PFCP SEIDs are preserved but no direct mapping between them is claimed".into()];
            edges.push(found);
        }
    }

    // 2.7.16 (DSN-ENGINE-002): publish the N4↔N3 edge that session-engine
    // already knew about via gtpu_tunnels but never emitted as a
    // CorrelationEdge. For every N4 PFCP event that exposes a (ipv4, teid)
    // F-TEID pair, find the N3 GTP-U events whose destination endpoint IP
    // and teid session identifier match byte-perfectly within the same
    // capture scope. The N3 side is anchored on `destination_address`
    // (where the tunnel terminates — the owner of the F-TEID), not on any
    // timestamp. Multi-match → fail-closed, no edge.
    let n4_tunnels = events
        .iter()
        .filter(|event| event.interface == "N4" && event.protocol == "PFCP")
        .flat_map(|event| {
            tunnel_keys(event)
                .into_iter()
                .map(move |key| (event, key))
        })
        .collect::<Vec<_>>();
    let n3_tunnels = events
        .iter()
        .filter(|event| event.interface == "N3" && event.protocol == "GTP-U")
        .filter_map(|event| {
            let teid = event.first_identifier("teid").and_then(normalize_teid)?;
            Some((
                event,
                TunnelCorrelationKey {
                    endpoint_ip: event.destination_address.clone(),
                    teid,
                    capture_id: capture_scope(event),
                },
            ))
        })
        .collect::<Vec<_>>();
    // Deduplicate N3 keys so a 10-packet uplink flow does not look like
    // 10 ambiguous candidates against the single N4 F-TEID.
    let mut n3_by_key = BTreeMap::<TunnelCorrelationKey, Vec<&EventRecord>>::new();
    for (event, key) in &n3_tunnels {
        n3_by_key.entry(key.clone()).or_default().push(*event);
    }
    for (n4, key) in &n4_tunnels {
        let Some(n3_group) = n3_by_key.get(key) else {
            continue;
        };
        let n4_duplicates = n4_tunnels
            .iter()
            .filter(|(_, candidate)| candidate == key)
            .count();
        if n4_duplicates != 1 {
            continue;
        }
        // The deterministic representative is the first N3 event ordered
        // by (capture_id, packet_number, event_id) — canonical sort key.
        let mut representative = n3_group.clone();
        representative.sort_by(|a, b| {
            (
                a.capture_id.as_str(),
                a.packet_number(),
                a.event_id.as_str(),
            )
                .cmp(&(
                    b.capture_id.as_str(),
                    b.packet_number(),
                    b.event_id.as_str(),
                ))
        });
        let n3 = representative[0];
        let mut found = edge(
            n4,
            n3,
            vec![
                format!("endpoint_ip={}", key.endpoint_ip),
                format!("teid={}", key.teid),
                format!("capture_scope={}", key.capture_id),
                format!("gtpu_frame_count={}", n3_group.len()),
            ],
            "pfcp-outer-header-matches-gtpu-tunnel",
            "EXACT",
            "A unique PFCP F-TEID or Update-FAR outer-header-creation (endpoint_ip, teid) equals the N3 GTP-U tunnel terminus in the same capture scope",
        );
        found.rule_version = N4_N3_RULE_VERSION.into();
        found.evidence_type = "EXACT_TUNNEL_MATCH".into();
        found.scope = "tunnel-only".into();
        found.limitations = vec![
            "The tunnel match confirms the user-plane carrier but does not by itself prove UE identity".into(),
        ];
        edges.push(found);
    }

    // 2.8.0 (issue #9): SBI N1N2MessageTransfer (SMF→AMF) carries the
    // n2SmInfo multipart part = NGAP PDUSessionResourceSetupRequest-
    // Transfer, whose UL NG-U UP TNL Information is the SAME F-TEID
    // the matching N2 PDUSessionResourceSetupRequest and the matching
    // N4 PFCP Session Establishment see. The decoder-sbi 0.4.0
    // multipart dispatcher surfaces that (ipv4, teid) as a tunnel_key
    // IE on the SBI event; here we match it byte-perfectly against
    // the N2 and N4 sides. No key → no edge (open link, never
    // inferred by ts); multi-match → fail-closed; one match on each
    // side → EXACT. The 2.7.26 fold handles overlap with
    // `ngap-sbi-context-association` on the same pair.
    let sbi_tunnels = events
        .iter()
        .filter(|event| {
            event.interface == "SBI"
                && event.protocol == "SBI-HTTP2"
                && event.message_name == "N1N2MessageTransfer"
        })
        .flat_map(|event| {
            tunnel_keys(event)
                .into_iter()
                .map(move |key| (event, key))
        })
        .collect::<Vec<_>>();
    for (sbi, key) in &sbi_tunnels {
        let sbi_duplicates = sbi_tunnels
            .iter()
            .filter(|(_, candidate)| candidate == key)
            .count();
        if sbi_duplicates != 1 {
            continue;
        }
        let n2_matches = ngap
            .iter()
            .filter(|(_, candidate)| candidate == key)
            .collect::<Vec<_>>();
        if n2_matches.len() == 1 {
            let mut found = edge(
                sbi,
                n2_matches[0].0,
                vec![
                    format!("endpoint_ip={}", key.endpoint_ip),
                    format!("teid={}", key.teid),
                    format!("capture_scope={}", key.capture_id),
                ],
                "sbi-n2-tunnel-match",
                "EXACT",
                "The SBI N1N2MessageTransfer carries an n2SmInfo PDUSessionResourceSetupRequestTransfer whose UL NG-U UP TNL Information equals the N2 PDUSessionResourceSetupRequest tunnel in the same capture scope",
            );
            found.rule_version = E2E_EVIDENCE_RULE_VERSION.into();
            found.evidence_type = "EXACT_TUNNEL_MATCH".into();
            found.scope = "tunnel-only".into();
            found.limitations = vec![
                "The tunnel match binds the SBI operation to the N2 setup it triggered; it does not by itself prove UE identity".into(),
            ];
            edges.push(found);
        }
        let n4_matches = pfcp
            .iter()
            .filter(|(_, candidate)| candidate == key)
            .collect::<Vec<_>>();
        if n4_matches.len() == 1 {
            let mut found = edge(
                sbi,
                n4_matches[0].0,
                vec![
                    format!("endpoint_ip={}", key.endpoint_ip),
                    format!("teid={}", key.teid),
                    format!("capture_scope={}", key.capture_id),
                ],
                "sbi-n4-tunnel-match",
                "EXACT",
                "The SBI N1N2MessageTransfer carries an n2SmInfo PDUSessionResourceSetupRequestTransfer whose UL NG-U UP TNL Information equals the PFCP Created-PDR F-TEID in the same capture scope",
            );
            found.rule_version = E2E_EVIDENCE_RULE_VERSION.into();
            found.evidence_type = "EXACT_TUNNEL_MATCH".into();
            found.scope = "tunnel-only".into();
            found.limitations = vec![
                "The tunnel match binds the SBI operation to the PFCP session the SMF created; it does not by itself prove UE identity".into(),
            ];
            edges.push(found);
        }
    }

    edges.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));
    edges
}

/// Prepares explicit LTE bearer edges from the uniquely partitioned LTE
/// sessions. Per-file capture IDs remain provenance and are never an identity
/// key. Real-world certification remains gated on an ANR1 fixture.
pub fn correlate_lte_evidence(events: &[EventRecord]) -> Vec<CorrelationEdge> {
    let mut edges = Vec::new();
    let by_id = events
        .iter()
        .map(|event| (event.event_id.as_str(), event))
        .collect::<BTreeMap<_, _>>();
    for session in discover_lte_sessions(events) {
        let session_events = session
            .event_ids
            .iter()
            .filter_map(|id| by_id.get(id.as_str()).copied())
            .collect::<Vec<_>>();
        let radios = session_events
            .iter()
            .copied()
            .filter(|event| event.interface == "S1-MME" && event.protocol == "S1AP")
            .collect::<Vec<_>>();
        let controls = session_events
            .iter()
            .copied()
            .filter(|event| event.interface == "S11" && event.protocol == "GTPv2-C")
            .collect::<Vec<_>>();
        let users = session_events
            .iter()
            .copied()
            .filter(|event| event.interface == "S1-U" && event.protocol == "GTP-U")
            .collect::<Vec<_>>();

        for control in &controls {
            let control_teids = ["bearer_f_teid", "f_teid"]
                .into_iter()
                .flat_map(|name| control.identifier_values(name))
                .filter_map(normalize_teid)
                .collect::<std::collections::BTreeSet<_>>();
            let candidates = users
                .iter()
                .copied()
                .filter_map(|user| {
                    let teid = user.first_identifier("teid").and_then(normalize_teid)?;
                    control_teids.contains(&teid).then_some((user, teid))
                })
                .collect::<Vec<_>>();
            if let Some((user, teid)) = candidates.first() {
                let mut found = edge(
                    control,
                    user,
                    vec![
                        format!("teid={teid}"),
                        format!("session_id={}", session.session_id),
                    ],
                    "gtpv2c-s1u-session-owned-teid",
                    "EXACT",
                    "A uniquely partitioned S1/S11 session owns the F-TEID observed on S1-U",
                );
                found.rule_version = LTE_RULE_VERSION.into();
                found.evidence_type = "EXACT_TUNNEL_MATCH".into();
                found.scope = "lte-bearer-tunnel-only".into();
                found.limitations = vec![
                "Synthetic preparation rule; real LTE evidence is not ANR1-certified".into(),
                    "The tunnel edge depends on the explicit S1 context, opaque pseudonym and bearer chain".into(),
            ];
                edges.push(found);
            }
        }
        for radio in &radios {
            let radio_teids = radio
                .identifier_values("erab_teid")
                .into_iter()
                .filter_map(normalize_teid)
                .collect::<std::collections::BTreeSet<_>>();
            for control in &controls {
                let common = ["bearer_f_teid", "f_teid"]
                    .into_iter()
                    .flat_map(|name| control.identifier_values(name))
                    .filter_map(normalize_teid)
                    .find(|teid| radio_teids.contains(teid));
                let Some(teid) = common else { continue };
                let mut found = edge(
                radio,
                    control,
                    vec![format!("erab_teid={teid}"), format!("session_id={}", session.session_id)],
                "s1ap-gtpv2c-context-pseudonym-bearer",
                "STRONG",
                    "A unique S1 context and opaque pseudonym bridge the matching E-RAB/F-TEID across capture files",
            );
                found.rule_version = LTE_RULE_VERSION.into();
                found.evidence_type = "STRONG_BEARER_ASSOCIATION".into();
                found.scope = "lte-bearer-control-plane".into();
                found.limitations = vec![
                    "Requires certified nested E-RAB TEID extraction before production use".into(),
                ];
                edges.push(found);
            }
        }
    }
    edges.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));
    edges
}

fn normalize_teid(value: &str) -> Option<String> {
    let raw = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches('0');
    let raw = if raw.is_empty() { "0" } else { raw };
    u32::from_str_radix(raw, 16)
        .ok()
        .map(|value| format!("0x{value:x}"))
}

fn tunnel_key(event: &EventRecord) -> Option<TunnelCorrelationKey> {
    tunnel_keys(event).into_iter().next()
}

fn directional_tunnel_components(value: &str) -> Vec<(String, String)> {
    let components = value
        .split(',')
        .filter_map(|part| {
            let (key, value) = part.split_once('=')?;
            Some((key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect::<BTreeMap<_, _>>();
    let mut pairs = Vec::new();
    for direction in ["ul", "dl"] {
        let endpoint_suffix = format!("tunnel_ip_{direction}");
        let teid_suffix = format!("gtp_teid_{direction}");
        for (endpoint_key, endpoint) in components.iter().filter(|(key, _)| {
            key.as_str() == endpoint_suffix || key.ends_with(&format!("_{endpoint_suffix}"))
        }) {
            let prefix = endpoint_key
                .strip_suffix(&endpoint_suffix)
                .unwrap_or_default();
            let teid_key = format!("{prefix}{teid_suffix}");
            if let Some(teid) = components
                .get(&teid_key)
                .and_then(|value| normalize_teid(value))
            {
                pairs.push((endpoint.clone(), teid));
            }
        }
    }
    pairs
}

fn tunnel_keys(event: &EventRecord) -> Vec<TunnelCorrelationKey> {
    let mut keys = event
        .information_elements
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|ie| {
            let Some(value) = ie.get("value").and_then(serde_json::Value::as_str) else {
                return Vec::new();
            };
            let mut components = [("tunnel_endpoint_ip", "gtp_teid"), ("ipv4", "teid")]
                .into_iter()
                .filter_map(|(endpoint_name, teid_name)| {
                    let endpoint_ip = component(value, endpoint_name)?;
                    let teid =
                        component(value, teid_name).and_then(|value| normalize_teid(&value))?;
                    Some((endpoint_ip, teid))
                })
                .collect::<Vec<_>>();
            components.extend(directional_tunnel_components(value));
            components
                .into_iter()
                .map(|(endpoint_ip, teid)| TunnelCorrelationKey {
                    endpoint_ip,
                    teid,
                    capture_id: capture_scope(event),
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

fn ie_value<'a>(event: &'a EventRecord, name: &str) -> Option<&'a str> {
    event
        .information_elements
        .as_array()?
        .iter()
        .find_map(|ie| {
            (ie.get("name")?.as_str()? == name)
                .then(|| ie.get("value")?.as_str())
                .flatten()
        })
}

fn ie_component(event: &EventRecord, name: &str) -> Option<String> {
    event
        .information_elements
        .as_array()?
        .iter()
        .find_map(|ie| component(ie.get("value")?.as_str()?, name))
}

/// Correlates two independently observed HTTP/2 hops through an SCP.  This
/// intentionally does not bridge N2 to N4: a shared PDU Session ID or close
/// timestamp is not a globally scoped identity and therefore produces no edge.
pub fn correlate_sbi_routing(events: &[EventRecord]) -> Vec<CorrelationEdge> {
    let mut edges = Vec::new();
    let sbi = events
        .iter()
        .filter(|event| event.protocol == "SBI-HTTP2")
        .collect::<Vec<_>>();
    for first in &sbi {
        let Some(first_meta) = first.source_json.get("sbi") else {
            continue;
        };
        let Some(uri) = first_meta
            .get("request_uri")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let method = first_meta
            .get("http_method")
            .and_then(serde_json::Value::as_str);
        let operation = first_meta
            .get("operation")
            .and_then(serde_json::Value::as_str);
        if first.destination_participant != "SCP" {
            continue;
        }
        let candidates = sbi
            .iter()
            .copied()
            .filter(|second| {
                let Some(meta) = second.source_json.get("sbi") else {
                    return false;
                };
                second.source_participant == "SCP"
                    && meta.get("request_uri").and_then(serde_json::Value::as_str) == Some(uri)
                    && meta.get("http_method").and_then(serde_json::Value::as_str) == method
                    && meta.get("operation").and_then(serde_json::Value::as_str) == operation
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            continue;
        }
        let mut correlation = edge(first, candidates[0], vec![format!("http_method={}", method.unwrap_or("unknown")), format!("sanitized_uri={uri}")], "sbi-scp-forwarded-request", "EXACT", "The same sanitized method/URI operation is independently observed on the consumer-to-SCP and SCP-to-producer HTTP/2 hops");
        correlation.rule_version = SBI_RULE_VERSION.into();
        edges.push(correlation);
    }
    edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    edges
}

#[derive(Clone, Debug, Deserialize)]
pub struct CertifiedIdentifiers {
    pub pdu_session_id: u64,
    pub uplink_teid: String,
    pub downlink_teid: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScenarioManifest {
    pub scenario_id: String,
    pub test_ue: String,
    pub identifiers: CertifiedIdentifiers,
    pub network_functions: NetworkFunctions,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NetworkFunctions {
    pub gnb_n3: String,
    pub upf_n3: String,
}

pub fn correlate(r: &Reconstruction, manifest: &ScenarioManifest) -> Vec<CorrelationEdge> {
    let mut edges = Vec::new();
    let n2_request = find(r, "N2", "PDUSessionResourceSetupRequest");
    let n2_response = find(r, "N2", "PDUSessionResourceSetupResponse");
    let n4_uplink = unique_pfcp_teid(
        r,
        &manifest.identifiers.uplink_teid,
        &manifest.network_functions.upf_n3,
    );
    let n4_downlink = unique_pfcp_teid(
        r,
        &manifest.identifiers.downlink_teid,
        &manifest.network_functions.gnb_n3,
    );
    if let (Some(n2), Match::Unique(n4)) = (n2_request, n4_uplink) {
        edges.push(edge(
            n2,
            n4,
            vec![
                format!("pdu_session_id={}", manifest.identifiers.pdu_session_id),
                format!("certified_uplink_teid={}", manifest.identifiers.uplink_teid),
            ],
            "n2-n4-certified-tunnel-bridge",
            "STRONG",
            "N2 nested transfer is partial in OIRAN; certified TShark/manifest TEID equals the PFCP F-TEID",
        ));
    }
    if let (Some(n2), Match::Unique(n4)) = (n2_response, n4_downlink) {
        edges.push(edge(
            n2,
            n4,
            vec![
                format!("pdu_session_id={}", manifest.identifiers.pdu_session_id),
                format!(
                    "certified_downlink_teid={}",
                    manifest.identifiers.downlink_teid
                ),
            ],
            "n2-n4-certified-tunnel-bridge",
            "STRONG",
            "Certified N2 response tunnel equals PFCP Outer Header Creation TEID and gNB endpoint",
        ));
    }
    for (teid, candidate) in [
        (
            &manifest.identifiers.uplink_teid,
            unique_pfcp_teid(
                r,
                &manifest.identifiers.uplink_teid,
                &manifest.network_functions.upf_n3,
            ),
        ),
        (
            &manifest.identifiers.downlink_teid,
            unique_pfcp_teid(
                r,
                &manifest.identifiers.downlink_teid,
                &manifest.network_functions.gnb_n3,
            ),
        ),
    ] {
        let Match::Unique(n4) = candidate else {
            continue;
        };
        let endpoint = pfcp_teid_endpoint(n4, teid);
        let matching: Vec<_> = r
            .events
            .iter()
            .filter(|e| {
                r.association.get(&e.event_id) == Some(&Association::Session)
                    && e.protocol == "GTP-U"
                    && e.first_identifier("teid") == Some(teid)
                    && endpoint
                        .as_ref()
                        .map(|x| x == &e.source_address || x == &e.destination_address)
                        .unwrap_or(false)
            })
            .collect();
        for n3 in matching {
            edges.push(edge(
                n4,
                n3,
                vec![
                    format!("teid={teid}"),
                    format!(
                        "tunnel_endpoint={}",
                        endpoint.as_deref().unwrap_or("unknown")
                    ),
                ],
                "n4-n3-teid-endpoint",
                "EXACT",
                "PFCP tunnel TEID and endpoint equal the observed directional GTP-U header",
            ));
        }
    }
    edges.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));
    edges
}

/// Builds only correlation edges that are demonstrable from discovered state.
/// Ambiguous TEID reuse deliberately produces no edge; callers can retain the
/// affected observations as unmatched instead of forcing a visually complete flow.
pub fn correlate_discovered_tunnels(
    events: &[EventRecord],
    discovery: &DiscoveryResult,
) -> Vec<CorrelationEdge> {
    let by_id = events
        .iter()
        .map(|event| (event.event_id.as_str(), event))
        .collect::<BTreeMap<_, _>>();
    let mut edges = Vec::new();
    for tunnel in discovery
        .gtpu_tunnels
        .iter()
        .filter(|tunnel| tunnel.related_pfcp_session.is_some())
    {
        let Some(pfcp) = discovery.pfcp_sessions.iter().find(|session| {
            Some(session.pfcp_session_id.as_str()) == tunnel.related_pfcp_session.as_deref()
        }) else {
            continue;
        };
        let candidates = pfcp
            .event_ids
            .iter()
            .filter_map(|id| by_id.get(id.as_str()).copied())
            .filter(|event| {
                pfcp_teid_endpoint(event, &tunnel.teid)
                    .map(|endpoint| {
                        endpoint == tunnel.source_endpoint
                            || endpoint == tunnel.destination_endpoint
                    })
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            continue;
        }
        // 2.7.26: emit ONE edge per tunnel (not one per G-PDU). The
        // rule's claim is "this PFCP TEID matches this tunnel", which
        // is a tunnel-level statement — not a per-packet one. A
        // tunnel with N G-PDUs previously produced N identical edges
        // and made `fold_overlapping_edges` unable to collapse them
        // with `pfcp-outer-header-matches-gtpu-tunnel` (which already
        // picked a canonical representative). We pick the same
        // deterministic representative here: the G-PDU with the
        // smallest canonical key `(capture_id, packet_number,
        // event_id)` — never a timestamp.
        let mut tunnel_gtpu_events: Vec<&EventRecord> = tunnel
            .event_ids
            .iter()
            .filter_map(|id| by_id.get(id.as_str()).copied())
            .collect();
        tunnel_gtpu_events.sort_by(|a, b| {
            (
                a.capture_id.as_str(),
                a.packet_number(),
                a.event_id.as_str(),
            )
                .cmp(&(
                    b.capture_id.as_str(),
                    b.packet_number(),
                    b.event_id.as_str(),
                ))
        });
        let Some(&representative) = tunnel_gtpu_events.first() else {
            continue;
        };
        let mut correlation = edge(
            candidates[0],
            representative,
            vec![
                format!("teid={}", tunnel.teid),
                format!(
                    "endpoints={}<->{}",
                    tunnel.source_endpoint, tunnel.destination_endpoint
                ),
                format!("gtpu_frame_count={}", tunnel_gtpu_events.len()),
            ],
            "n4-n3-discovered-teid-endpoint",
            "EXACT",
            "A unique PFCP F-TEID endpoint matches the directional GTP-U tunnel",
        );
        correlation.rule_version = DISCOVERY_RULE_VERSION.into();
        edges.push(correlation);
    }
    edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    edges
}

enum Match<'a> {
    None,
    Unique(&'a EventRecord),
    Ambiguous,
}

fn unique_pfcp_teid<'a>(r: &'a Reconstruction, teid: &str, endpoint: &str) -> Match<'a> {
    let found: Vec<_> = r
        .events
        .iter()
        .filter(|e| {
            r.association.get(&e.event_id) == Some(&Association::Session)
                && e.protocol == "PFCP"
                && pfcp_teid_endpoint(e, teid).as_deref() == Some(endpoint)
        })
        .collect();
    match found.as_slice() {
        [] => Match::None,
        [one] => Match::Unique(one),
        _ => Match::Ambiguous,
    }
}

fn pfcp_teid_endpoint(event: &EventRecord, teid: &str) -> Option<String> {
    event
        .information_elements
        .as_array()?
        .iter()
        .find_map(|ie| {
            let value = ie.get("value")?.as_str()?;
            (component(value, "teid").as_deref() == Some(teid))
                .then(|| component(value, "ipv4"))
                .flatten()
        })
}

fn find<'a>(r: &'a Reconstruction, interface: &str, name: &str) -> Option<&'a EventRecord> {
    r.events.iter().find(|e| {
        r.association.get(&e.event_id) == Some(&Association::Session)
            && e.interface == interface
            && e.message_name == name
    })
}

fn edge(
    source: &EventRecord,
    target: &EventRecord,
    identifiers: Vec<String>,
    rule: &str,
    confidence: &str,
    description: &str,
) -> CorrelationEdge {
    let mut packets = source.packet_references.clone();
    packets.extend(target.packet_references.clone());
    CorrelationEdge {
        edge_id: format!("edge-{}-{}-{}", rule, source.event_id, target.event_id),
        source_event_id: source.event_id.clone(),
        target_event_id: target.event_id.clone(),
        source_interface: source.interface.clone(),
        target_interface: target.interface.clone(),
        matching_identifiers: identifiers,
        rule_id: rule.into(),
        rule_version: RULE_VERSION.into(),
        evidence_description: description.into(),
        packet_references: packets,
        confidence: confidence.into(),
        evidence_type: match confidence {
            "EXACT" => "EXACT_CONTEXT_MATCH",
            "STRONG" => "STRONG_CONTEXT_ASSOCIATION",
            "POSSIBLE" => "POSSIBLE_ASSOCIATION",
            _ => "UNKNOWN",
        }
        .into(),
        matched_rules: Vec::new(),
        scope: String::new(),
        limitations: Vec::new(),
    }
}

pub fn edge_counts(edges: &[CorrelationEdge]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for e in edges {
        *counts
            .entry(format!(
                "{}_{}_{}",
                e.source_interface, e.target_interface, e.confidence
            ))
            .or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use session_engine::{discover_sessions, reconstruct, EventRecord, ReconstructionHints};

    fn e(
        id: &str,
        iface: &str,
        protocol: &str,
        name: &str,
        packet: u64,
        ids: &[(&str, &str)],
        ie: serde_json::Value,
    ) -> EventRecord {
        EventRecord {
            event_id: id.into(),
            parent_event_id: None,
            capture_id: "c".into(),
            capture_point_id: iface.into(),
            timestamp: format!("1.{packet:09}Z"),
            timestamp_ns: packet as i128,
            raw_ticks: packet,
            interface: iface.into(),
            protocol: protocol.into(),
            message_name: name.into(),
            source_address: "10.0.0.1".into(),
            destination_address: "10.0.0.2".into(),
            source_participant: "a".into(),
            destination_participant: "b".into(),
            direction: "UNKNOWN".into(),
            identifiers: ids
                .iter()
                .map(|(a, b)| ((*a).into(), (*b).into()))
                .collect(),
            information_elements: ie,
            decoding_status: "DECODED".into(),
            decoder_name: "d".into(),
            decoder_version: "1".into(),
            raw_payload_reference: "sha256:x".into(),
            packet_references: vec![session_engine::PacketRef {
                source_file: "x".into(),
                packet_number: packet,
                byte_offset: 0,
                interface_id: 0,
                captured_length: 1,
                original_length: 1,
            }],
            errors: vec![],
            source_json: json!({}),
        }
    }
    fn manifest() -> ScenarioManifest {
        ScenarioManifest {
            scenario_id: "x".into(),
            test_ue: "UE-A".into(),
            identifiers: CertifiedIdentifiers {
                pdu_session_id: 1,
                uplink_teid: "0x1".into(),
                downlink_teid: "0x2".into(),
            },
            network_functions: NetworkFunctions {
                gnb_n3: "10.0.0.2".into(),
                upf_n3: "10.0.0.2".into(),
            },
        }
    }

    #[test]
    fn n2_n4_bridge_is_strong() {
        let events = vec![
            e(
                "n",
                "N2",
                "NGAP",
                "PDUSessionResourceSetupRequest",
                1,
                &[("ran_ue_ngap_id", "4"), ("pdu_session_id", "1")],
                json!([]),
            ),
            e(
                "p",
                "N4",
                "PFCP",
                "PFCP Session Establishment Response",
                2,
                &[("pfcp_sequence", "1")],
                json!([{"value":"teid=0x1,ipv4=10.0.0.2"}]),
            ),
        ];
        let r = reconstruct(
            events,
            ReconstructionHints {
                ue_pseudonym: Some("UE-A".into()),
                ..Default::default()
            },
        );
        assert!(correlate(&r, &manifest())
            .iter()
            .any(|x| x.confidence == "STRONG"));
    }
    #[test]
    fn n4_n3_requires_teid_and_endpoint() {
        let events = vec![
            e(
                "n",
                "N2",
                "NGAP",
                "PDUSessionResourceSetupRequest",
                1,
                &[("ran_ue_ngap_id", "4"), ("pdu_session_id", "1")],
                json!([]),
            ),
            e(
                "p",
                "N4",
                "PFCP",
                "PFCP Session Establishment Response",
                2,
                &[("pfcp_sequence", "1")],
                json!([{"value":"teid=0x1,ipv4=10.0.0.2"}]),
            ),
            e(
                "g",
                "N3",
                "GTP-U",
                "G-PDU",
                3,
                &[("teid", "0x1")],
                json!([]),
            ),
        ];
        let r = reconstruct(
            events,
            ReconstructionHints {
                ue_pseudonym: Some("UE-A".into()),
                ..Default::default()
            },
        );
        assert!(correlate(&r, &manifest())
            .iter()
            .any(|x| x.target_event_id == "g" && x.confidence == "EXACT"));
    }
    #[test]
    fn ambiguous_pfcp_match_does_not_force_edge() {
        let ie = json!([{"value":"teid=0x1,ipv4=10.0.0.2"}]);
        let events = vec![
            e(
                "n",
                "N2",
                "NGAP",
                "PDUSessionResourceSetupRequest",
                1,
                &[("ran_ue_ngap_id", "4"), ("pdu_session_id", "1")],
                json!([]),
            ),
            e(
                "p1",
                "N4",
                "PFCP",
                "PFCP Session Establishment Response",
                2,
                &[("pfcp_sequence", "1")],
                ie.clone(),
            ),
            e(
                "p2",
                "N4",
                "PFCP",
                "PFCP Session Modification Request",
                3,
                &[("pfcp_sequence", "2")],
                ie,
            ),
        ];
        let r = reconstruct(events, Default::default());
        assert!(!correlate(&r, &manifest())
            .iter()
            .any(|x| x.matching_identifiers.iter().any(|i| i == "teid=0x1")));
    }
    #[test]
    fn missing_messages_produce_no_fabricated_edges() {
        let r = reconstruct(vec![], Default::default());
        assert!(correlate(&r, &manifest()).is_empty());
    }
    #[test]
    fn every_edge_preserves_both_packet_references() {
        let events = vec![
            e(
                "n",
                "N2",
                "NGAP",
                "PDUSessionResourceSetupRequest",
                1,
                &[("ran_ue_ngap_id", "4"), ("pdu_session_id", "1")],
                json!([]),
            ),
            e(
                "p",
                "N4",
                "PFCP",
                "PFCP Session Establishment Response",
                2,
                &[("pfcp_sequence", "1")],
                json!([{"value":"teid=0x1,ipv4=10.0.0.2"}]),
            ),
        ];
        let r = reconstruct(events, Default::default());
        let edges = correlate(&r, &manifest());
        assert!(edges.iter().all(|x| x.packet_references.len() >= 2));
    }

    #[test]
    fn discovered_tunnel_uses_unique_composite_evidence() {
        let events = vec![
            e(
                "p",
                "N4",
                "PFCP",
                "PFCP Session Establishment Response",
                1,
                &[("pfcp_sequence", "7"), ("f_seid", "0x7")],
                json!([{"value":"teid=0x1,ipv4=10.0.0.2"}]),
            ),
            e(
                "g",
                "N3",
                "GTP-U",
                "G-PDU",
                2,
                &[("teid", "0x1")],
                json!([]),
            ),
        ];
        let discovery = discover_sessions(&mut events.clone());
        let edges = correlate_discovered_tunnels(&events, &discovery);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].confidence, "EXACT");
        assert_eq!(edges[0].rule_version, DISCOVERY_RULE_VERSION);
        assert_eq!(edges[0].packet_references.len(), 2);
    }

    #[test]
    fn discovered_tunnel_does_not_link_reused_ambiguous_teid() {
        let ie = json!([{"value":"teid=0x1,ipv4=10.0.0.2"}]);
        let events = vec![
            e(
                "p1",
                "N4",
                "PFCP",
                "PFCP Session Establishment Response",
                1,
                &[("pfcp_sequence", "7"), ("f_seid", "0x7")],
                ie.clone(),
            ),
            e(
                "p2",
                "N4",
                "PFCP",
                "PFCP Session Establishment Response",
                2,
                &[("pfcp_sequence", "8"), ("f_seid", "0x8")],
                ie,
            ),
            e(
                "g",
                "N3",
                "GTP-U",
                "G-PDU",
                3,
                &[("teid", "0x1")],
                json!([]),
            ),
        ];
        let discovery = discover_sessions(&mut events.clone());
        assert!(discovery.gtpu_tunnels[0].related_pfcp_session.is_none());
        assert!(correlate_discovered_tunnels(&events, &discovery).is_empty());
    }

    #[test]
    fn sbi_scp_hops_require_unique_method_uri_evidence() {
        let mut incoming = e(
            "s1",
            "SBI",
            "SBI-HTTP2",
            "UpdateSMContext",
            1,
            &[],
            json!([]),
        );
        incoming.destination_participant = "SCP".into();
        incoming.source_json = json!({"sbi":{"request_uri":"/nsmf-pdusession/v1/sm-contexts/4/modify","http_method":"POST","operation":"UpdateSMContext"}});
        let mut forwarded = e(
            "s2",
            "SBI",
            "SBI-HTTP2",
            "UpdateSMContext",
            2,
            &[],
            json!([]),
        );
        forwarded.source_participant = "SCP".into();
        forwarded.destination_participant = "SMF".into();
        forwarded.source_json = incoming.source_json.clone();
        let edges = correlate_sbi_routing(&[incoming, forwarded]);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].confidence, "EXACT");
        assert_eq!(edges[0].rule_version, SBI_RULE_VERSION);
    }

    #[test]
    fn reused_pdu_session_id_does_not_create_cross_interface_edge() {
        let n2 = e(
            "n",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[("pdu_session_id", "1")],
            json!([]),
        );
        let sbi = e(
            "s",
            "SBI",
            "SBI-HTTP2",
            "CreateSMContext",
            2,
            &[("pdu_session_id", "1")],
            json!([]),
        );
        assert!(correlate_sbi_routing(&[n2, sbi]).is_empty());
    }

    #[test]
    fn exact_tunnel_match_does_not_claim_exact_identity() {
        let mut n2 = e(
            "n2",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            39,
            &[
                ("amf_ue_ngap_id", "8"),
                ("ran_ue_ngap_id", "8"),
                ("pdu_session_id", "1"),
            ],
            json!([{"value":"pdu_session_id=1,tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5"}]),
        );
        n2.capture_id = "n2-hash".into();
        n2.packet_references[0].source_file = "/var/lib/oiran/captures/job-1/pcap/N2.pcap0".into();
        let mut n4 = e(
            "n4",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            30,
            &[],
            json!([{"value":"teid=0x0000b3b5,v4=true,ipv4=10.77.22.13"}]),
        );
        n4.capture_id = "n4-hash".into();
        n4.packet_references[0].source_file = "/var/lib/oiran/captures/job-1/pcap/N4.pcap0".into();
        let edges = correlate_cross_interface_evidence(&[n2, n4]);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].evidence_type, "EXACT_TUNNEL_MATCH");
        assert_eq!(edges[0].scope, "tunnel-only");
        assert!(!edges[0].limitations.is_empty());
    }

    #[test]
    fn exact_tunnel_match_normalizes_directional_ngap_transfer_fields() {
        let mut n2 = e(
            "n2",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            801,
            &[("pdu_session_id", "1")],
            json!([{"value":"item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0xf68d"}]),
        );
        n2.packet_references[0].source_file =
            "/var/lib/oiran/captures/continuous-lab-import/pcap/N2.pcap0".into();
        let mut n4 = e(
            "n4",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            803,
            &[],
            json!([{"value":"teid=0x0000f68d,v4=true,ipv4=10.77.22.13"}]),
        );
        n4.packet_references[0].source_file =
            "/var/lib/oiran/captures/continuous-lab-import/pcap/N4.pcap0".into();

        let edges = correlate_cross_interface_evidence(&[n2, n4]);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].evidence_type, "EXACT_TUNNEL_MATCH");
        assert!(edges[0]
            .matching_identifiers
            .iter()
            .any(|identifier| identifier == "teid=0xf68d"));
    }

    #[test]
    fn reused_tunnel_tuple_is_rejected_as_ambiguous() {
        let mut events = Vec::new();
        for (id, packet) in [("n2-a", 1), ("n2-b", 2)] {
            let mut event = e(
                id,
                "N2",
                "NGAP",
                "PDUSessionResourceSetupRequest",
                packet,
                &[],
                json!([{"value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5"}]),
            );
            event.packet_references[0].source_file =
                "/var/lib/oiran/captures/job-1/pcap/N2.pcap0".into();
            events.push(event);
        }
        let mut pfcp = e(
            "n4",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            3,
            &[],
            json!([{"value":"teid=0xb3b5,ipv4=10.77.22.13"}]),
        );
        pfcp.packet_references[0].source_file =
            "/var/lib/oiran/captures/job-1/pcap/N4.pcap0".into();
        events.push(pfcp);
        assert!(correlate_cross_interface_evidence(&events).is_empty());
    }

    #[test]
    fn lte_unique_s11_s1u_teid_builds_exact_edge() {
        let mut radio = e(
            "radio",
            "S1-MME",
            "S1AP",
            "E-RABSetupResponse",
            1,
            &[
                ("enb_ue_s1ap_id", "41"),
                ("mme_ue_s1ap_id", "7"),
                ("imsi_pseudonym", "subscriber-opaque-a"),
                ("erab_teid", "0x01020304"),
            ],
            json!([]),
        );
        radio.capture_id = "capture-s1".into();
        let mut s11 = e(
            "s11",
            "S11",
            "GTPv2-C",
            "CreateSessionResponse",
            2,
            &[
                ("imsi_pseudonym", "subscriber-opaque-a"),
                ("bearer_f_teid", "0x01020304"),
            ],
            json!([]),
        );
        s11.capture_id = "capture-s11".into();
        let mut s1u = e(
            "s1u",
            "S1-U",
            "GTP-U",
            "G-PDU",
            3,
            &[("teid", "0x01020304")],
            json!([]),
        );
        s1u.capture_id = "capture-s1u".into();
        let mut s1u_second_packet = s1u.clone();
        s1u_second_packet.event_id = "s1u-second-packet".into();
        s1u_second_packet.packet_references[0].packet_number = 3;
        let edges = correlate_lte_evidence(&[radio, s11, s1u, s1u_second_packet]);
        assert_eq!(edges.len(), 2);
        let tunnel = edges
            .iter()
            .find(|edge| edge.target_interface == "S1-U")
            .unwrap();
        assert_eq!(tunnel.confidence, "EXACT");
        assert_eq!(tunnel.rule_version, LTE_RULE_VERSION);
        assert_eq!(tunnel.source_interface, "S11");
    }

    #[test]
    fn lte_reused_teid_does_not_force_edge() {
        let s11a = e(
            "s11-a",
            "S11",
            "GTPv2-C",
            "CreateSessionResponse",
            1,
            &[("bearer_f_teid", "0x01020304")],
            json!([]),
        );
        let mut s11b = s11a.clone();
        s11b.event_id = "s11-b".into();
        s11b.packet_references[0].packet_number = 2;
        let s1u = e(
            "s1u",
            "S1-U",
            "GTP-U",
            "G-PDU",
            3,
            &[("teid", "0x01020304")],
            json!([]),
        );
        assert!(correlate_lte_evidence(&[s11a, s11b, s1u]).is_empty());
    }

    #[test]
    fn lte_two_ue_bearers_do_not_cross_correlate() {
        let mut events = Vec::new();
        for (ordinal, teid) in [(1u64, "0x01020304"), (2u64, "0x05060708")] {
            let pseudonym = format!("subscriber-opaque-{ordinal}");
            let enb = format!("enb-{ordinal}");
            let mme = format!("mme-{ordinal}");
            events.push(e(
                &format!("s1ap-{ordinal}"),
                "S1-MME",
                "S1AP",
                "E-RABSetupResponse",
                ordinal * 10,
                &[
                    ("enb_ue_s1ap_id", &enb),
                    ("mme_ue_s1ap_id", &mme),
                    ("imsi_pseudonym", &pseudonym),
                    ("erab_teid", teid),
                ],
                json!([]),
            ));
            events.push(e(
                &format!("s11-{ordinal}"),
                "S11",
                "GTPv2-C",
                "CreateSessionResponse",
                ordinal * 10 + 1,
                &[("imsi_pseudonym", &pseudonym), ("bearer_f_teid", teid)],
                json!([]),
            ));
            events.push(e(
                &format!("s1u-{ordinal}"),
                "S1-U",
                "GTP-U",
                "G-PDU",
                ordinal * 10 + 2,
                &[("teid", teid)],
                json!([]),
            ));
        }
        let edges = correlate_lte_evidence(&events);
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/lte-offline-certification-synthetic-manifest.json"
        ))
        .unwrap();
        assert_eq!(
            edges.len() as u64,
            manifest["expected"]["correlation_edges"].as_u64().unwrap()
        );
        for teid in ["0x1020304", "0x5060708"] {
            assert_eq!(
                edges
                    .iter()
                    .filter(|edge| edge.matching_identifiers.iter().any(|id| id.contains(teid)))
                    .count(),
                2
            );
        }
    }

    // --- 2.7.16: DSN-ENGINE-002 and DSN-SCOPE-001 regression coverage ---

    /// Builds an EventRecord whose packet_references[0].source_file is rooted
    /// under `datasets/<scope>/` so capture_scope() falls back to the
    /// parent-directory segment and unifies N2, N3 and N4 under one scope.
    fn scoped(
        id: &str,
        iface: &str,
        protocol: &str,
        name: &str,
        packet: u64,
        ids: &[(&str, &str)],
        ie: serde_json::Value,
        destination: &str,
        scope: &str,
    ) -> EventRecord {
        let mut event = e(id, iface, protocol, name, packet, ids, ie);
        event.destination_address = destination.into();
        event.packet_references[0].source_file = format!("datasets/{scope}/{iface}.pcapng");
        event.capture_id = format!("sha256:{iface}-per-plane-{scope}");
        event
    }

    #[test]
    fn n4_n3_rule_publishes_one_exact_edge_per_matching_tunnel() {
        // One UPF F-TEID on N4 → 3 G-PDUs on N3 at the same (endpoint, TEID).
        let n4 = scoped(
            "n4-up",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            10,
            &[("pfcp_sequence", "93"), ("f_seid", "0x1a8")],
            json!([
                {"value":"f_seid=0x35e,v4=true,v6=false,ipv4=10.77.23.13"},
                {"value":"teid=0x000096a8,v4=true,v6=false,ipv4=10.77.22.13"}
            ]),
            "10.77.23.12",
            "AUDIT",
        );
        let n3a = scoped(
            "n3-1", "N3", "GTP-U", "G-PDU", 1, &[("teid", "0x000096a8")],
            json!([]), "10.77.22.13", "AUDIT",
        );
        let n3b = scoped(
            "n3-2", "N3", "GTP-U", "G-PDU", 2, &[("teid", "0x000096a8")],
            json!([]), "10.77.22.13", "AUDIT",
        );
        let n3c = scoped(
            "n3-3", "N3", "GTP-U", "G-PDU", 3, &[("teid", "0x000096a8")],
            json!([]), "10.77.22.13", "AUDIT",
        );
        let edges = correlate_cross_interface_evidence(&[n4, n3a, n3b, n3c]);
        let n4_n3 = edges
            .iter()
            .filter(|e| e.rule_id == "pfcp-outer-header-matches-gtpu-tunnel")
            .collect::<Vec<_>>();
        assert_eq!(n4_n3.len(), 1, "exactly one N4↔N3 edge");
        assert_eq!(n4_n3[0].confidence, "EXACT");
        assert_eq!(n4_n3[0].rule_version, N4_N3_RULE_VERSION);
        assert!(n4_n3[0]
            .matching_identifiers
            .iter()
            .any(|id| id == "capture_scope=AUDIT"));
        assert!(n4_n3[0]
            .matching_identifiers
            .iter()
            .any(|id| id == "gtpu_frame_count=3"));
        assert_eq!(n4_n3[0].source_event_id, "n4-up");
        // First representative by canonical (capture_id, packet_number, event_id).
        assert_eq!(n4_n3[0].target_event_id, "n3-1");
    }

    #[test]
    fn n4_n3_rule_is_fail_closed_when_the_pfcp_teid_is_reused() {
        let n4_a = scoped(
            "n4-a",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            1,
            &[("pfcp_sequence", "1")],
            json!([{"value":"teid=0x000096a8,v4=true,v6=false,ipv4=10.77.22.13"}]),
            "10.77.23.12",
            "DUP",
        );
        let n4_b = scoped(
            "n4-b",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            2,
            &[("pfcp_sequence", "2")],
            json!([{"value":"teid=0x000096a8,v4=true,v6=false,ipv4=10.77.22.13"}]),
            "10.77.23.12",
            "DUP",
        );
        let n3 = scoped(
            "n3-1", "N3", "GTP-U", "G-PDU", 3, &[("teid", "0x000096a8")],
            json!([]), "10.77.22.13", "DUP",
        );
        let edges = correlate_cross_interface_evidence(&[n4_a, n4_b, n3]);
        assert!(
            edges
                .iter()
                .all(|e| e.rule_id != "pfcp-outer-header-matches-gtpu-tunnel"),
            "ambiguous N4 F-TEID must not produce an edge",
        );
    }

    // --- 2.8.0 SBI↔N2 / SBI↔N4 tunnel-match rules -----------------

    /// Positive fixture: SBI N1N2MessageTransfer with the SAME tunnel
    /// (ipv4, teid) as the N2 PDUSessionResourceSetupRequest and the
    /// N4 PFCP Session Establishment. Expect EXACT edges on both
    /// pairs. The pre-existing N2↔N4 EXACT is preserved.
    #[test]
    fn sbi_n2_and_sbi_n4_tunnel_matches_are_exact() {
        let tunnel_ie = json!([
            {
                "name": "N2 UL NG-U UP TNL Information",
                "value": "tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5",
            }
        ]);
        let ngap = e(
            "ngap",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[("ran_ue_ngap_id", "4"), ("pdu_session_id", "1")],
            json!([{"value":"pdu_session_id=1,tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5"}]),
        );
        let pfcp = e(
            "pfcp",
            "N4",
            "PFCP",
            "PFCP Session Establishment Request",
            2,
            &[("f_seid", "1")],
            json!([{"value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5"}]),
        );
        let sbi = e(
            "sbi",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            3,
            &[("pdu_session_id", "1")],
            tunnel_ie,
        );
        let edges = correlate_cross_interface_evidence(&[ngap, pfcp, sbi]);
        let rules: Vec<_> = edges.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(
            rules.contains(&"sbi-n2-tunnel-match"),
            "SBI↔N2 tunnel match must emit an edge; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n4-tunnel-match"),
            "SBI↔N4 tunnel match must emit an edge; rules={rules:?}"
        );
        assert!(
            rules.contains(&"ngap-pfcp-exact-tunnel"),
            "pre-existing N2↔N4 EXACT must be preserved; rules={rules:?}"
        );
        let sbi_n2 = edges
            .iter()
            .find(|e| e.rule_id == "sbi-n2-tunnel-match")
            .unwrap();
        assert_eq!(sbi_n2.confidence, "EXACT");
        assert_eq!(sbi_n2.evidence_type, "EXACT_TUNNEL_MATCH");
        let sbi_n4 = edges
            .iter()
            .find(|e| e.rule_id == "sbi-n4-tunnel-match")
            .unwrap();
        assert_eq!(sbi_n4.confidence, "EXACT");
        assert_eq!(sbi_n4.evidence_type, "EXACT_TUNNEL_MATCH");
    }

    /// Negative fixture: SBI carries a DIFFERENT TEID than the N2 /
    /// N4 pair. No tunnel match → no SBI edge is emitted. The link
    /// stays "open" as the user asked — never inferred by timestamps
    /// or by partial fields.
    #[test]
    fn sbi_tunnel_match_stays_open_when_teid_differs() {
        let ngap = e(
            "ngap",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[],
            json!([{"value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5"}]),
        );
        let pfcp = e(
            "pfcp",
            "N4",
            "PFCP",
            "PFCP Session Establishment Request",
            2,
            &[],
            json!([{"value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5"}]),
        );
        let sbi = e(
            "sbi",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            3,
            &[],
            json!([{"name":"N2 UL NG-U UP TNL Information","value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xdeadbeef"}]),
        );
        let edges = correlate_cross_interface_evidence(&[ngap, pfcp, sbi]);
        assert!(
            edges
                .iter()
                .all(|e| e.rule_id != "sbi-n2-tunnel-match"
                    && e.rule_id != "sbi-n4-tunnel-match"),
            "SBI with a non-matching TEID must not produce any tunnel-match edge"
        );
    }

    /// If two SBI N1N2MessageTransfer events share the same (ipv4,
    /// teid), neither is uniquely bound to the N2/N4 pair and no edge
    /// is emitted. Fail-closed mirrors the ngap-pfcp-exact-tunnel
    /// policy.
    #[test]
    fn sbi_tunnel_match_fails_closed_on_duplicate_sbi_tunnel_keys() {
        let ngap = e(
            "ngap",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[],
            json!([{"value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5"}]),
        );
        let pfcp = e(
            "pfcp",
            "N4",
            "PFCP",
            "PFCP Session Establishment Request",
            2,
            &[],
            json!([{"value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5"}]),
        );
        let sbi_a = e(
            "sbi-a",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            3,
            &[],
            json!([{"name":"N2 UL NG-U UP TNL Information","value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5"}]),
        );
        let sbi_b = e(
            "sbi-b",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            4,
            &[],
            json!([{"name":"N2 UL NG-U UP TNL Information","value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xb3b5"}]),
        );
        let edges = correlate_cross_interface_evidence(&[ngap, pfcp, sbi_a, sbi_b]);
        assert!(
            edges
                .iter()
                .all(|e| e.rule_id != "sbi-n2-tunnel-match"
                    && e.rule_id != "sbi-n4-tunnel-match"),
            "duplicate SBI tunnel keys must fail-closed"
        );
    }

    /// 2.9.2 — ANR2 #9 comment 6712678520. Real production shape:
    ///   * N2 NGAP emits `tunnel_endpoint_ip=10.77.22.13,gtp_teid=0x12a6`.
    ///   * N4 PFCP emits `teid=0x000012a6,v4=true,v6=false,ipv4=10.77.22.13`
    ///     — PADDING 8 hex digits + `ipv4=`/`teid=` naming (decoder-pfcp).
    ///   * SBI N1N2MessageTransfer emits
    ///     `tunnel_endpoint_ip=10.77.22.13,gtp_teid=0x12a6` as the
    ///     composed `N2 UL NG-U UP TNL Information` IE (decoder-sbi).
    ///   * Same `(ip, teid)` as a u32: 0x12a6. The shared
    ///     `normalize_teid` MUST collapse them.
    /// ANR2 observed EXACT on N2↔N4 but UNKNOWN on SBI↔N2 and SBI↔N4;
    /// this test fails BEFORE the 2.9.2 fix and passes AFTER.
    #[test]
    fn sbi_tunnel_match_links_production_event_shapes_from_anr2_6712678520() {
        let n2 = e(
            "evt-a608157cbcd0940b",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[],
            json!([
                {"name":"UL NG-U UP TNL Information",
                 "value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0x12a6"}
            ]),
        );
        let n4 = e(
            "evt-ee7c9b46059e58e6",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            2,
            &[],
            json!([
                {"name":"F-TEID",
                 "value":"teid=0x000012a6,v4=true,v6=false,ipv4=10.77.22.13"}
            ]),
        );
        let sbi = e(
            "evt-0555068f3e89d755",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            3,
            &[
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0x12a6"),
            ],
            json!([
                {"name":"N2 UL NG-U UP TNL Information",
                 "value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0x12a6"},
                {"name":"n2SmInfo sha256",
                 "value":"2aebc25884ad9dd4e43995cc7f1075dc1be24459c5f0a2c04d23624f45d5f389"}
            ]),
        );
        let edges = correlate_cross_interface_evidence(&[n2, n4, sbi]);
        let rules: Vec<&str> = edges.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(
            rules.contains(&"ngap-pfcp-exact-tunnel"),
            "N2↔N4 EXACT must hold with real N4 padding format; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n2-tunnel-match"),
            "SBI↔N2 must emit EXACT on real ANR2 shapes; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n4-tunnel-match"),
            "SBI↔N4 must emit EXACT on real ANR2 shapes; rules={rules:?}"
        );
    }

    #[test]
    fn capture_scope_fallback_unifies_planes_under_dataset_directory() {
        // Each plane has its own per-file capture_id; only the parent dir is
        // shared. Prior to 2.7.16 this disjoint SHA fallback prevented any
        // cross-interface match. The fix: fall back to the parent-dir name.
        let event = scoped(
            "p", "N3", "GTP-U", "G-PDU", 1, &[("teid", "0x1")],
            json!([]), "10.0.0.1", "OIRAN_5G_PDU_SESSION_DATA_V1",
        );
        assert_eq!(capture_scope(&event), "OIRAN_5G_PDU_SESSION_DATA_V1");
        // Backwards-compat: the `/captures/<scope>/` convention still wins.
        let mut live = event.clone();
        live.packet_references[0].source_file =
            "/var/lib/oiran/captures/continuous-lab-import/N3.pcapng".into();
        assert_eq!(capture_scope(&live), "continuous-lab-import");
    }
}
