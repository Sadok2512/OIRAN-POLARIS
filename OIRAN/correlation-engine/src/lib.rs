//! Evidence-based N2/N4/N3 correlation without timestamp-only joins.

use callflow_schema::CorrelationEdge;
use serde::Deserialize;
use session_engine::{component, Association, DiscoveryResult, EventRecord, Reconstruction};
use std::collections::BTreeMap;

pub const VERSION: &str = "0.4.0";
pub const RULE_VERSION: &str = "1.0.0";
pub const DISCOVERY_RULE_VERSION: &str = "1.1.0";
pub const SBI_RULE_VERSION: &str = "1.0.0";
pub const E2E_EVIDENCE_RULE_VERSION: &str = "2.0.0";
pub const LTE_RULE_VERSION: &str = "0.1.0-pre-certification";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TunnelCorrelationKey {
    endpoint_ip: String,
    teid: String,
    capture_id: String,
}

fn capture_scope(event: &EventRecord) -> String {
    event
        .packet_references
        .first()
        .and_then(|packet| {
            let marker = "/captures/";
            let start = packet.source_file.find(marker)? + marker.len();
            let rest = &packet.source_file[start..];
            Some(rest.split('/').next()?.to_owned())
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
    edges.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));
    edges
}

/// Prepares explicit LTE bearer edges without using timestamp proximity or
/// subscriber identity. Real-world certification remains gated on an ANR1
/// fixture; these rules only accept unique, same-capture TEID evidence.
pub fn correlate_lte_evidence(events: &[EventRecord]) -> Vec<CorrelationEdge> {
    let s1ap = events
        .iter()
        .filter(|event| event.interface == "S1-MME" && event.protocol == "S1AP")
        .flat_map(|event| {
            event
                .identifier_values("erab_teid")
                .into_iter()
                .filter_map(normalize_teid)
                .map(|teid| (event, teid))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let s11 = events
        .iter()
        .filter(|event| event.interface == "S11" && event.protocol == "GTPv2-C")
        .flat_map(|event| {
            ["bearer_f_teid", "f_teid"]
                .into_iter()
                .flat_map(|name| event.identifier_values(name))
                .filter_map(normalize_teid)
                .map(|teid| (event, teid))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let s1u = events
        .iter()
        .filter(|event| event.interface == "S1-U" && event.protocol == "GTP-U")
        .filter_map(|event| {
            normalize_teid(event.first_identifier("teid")?).map(|teid| (event, teid))
        })
        .collect::<Vec<_>>();
    let mut edges = Vec::new();
    for (control, teid) in &s11 {
        let candidates = s1u
            .iter()
            .filter(|(user, candidate)| {
                candidate == teid && capture_scope(user) == capture_scope(control)
            })
            .collect::<Vec<_>>();
        let endpoint_pairs = candidates
            .iter()
            .map(|(event, _)| {
                let mut endpoints = [
                    event.source_address.as_str(),
                    event.destination_address.as_str(),
                ];
                endpoints.sort();
                format!("{}|{}", endpoints[0], endpoints[1])
            })
            .collect::<std::collections::BTreeSet<_>>();
        let controls = s11
            .iter()
            .filter(|(other, candidate)| {
                candidate == teid && capture_scope(other) == capture_scope(control)
            })
            .count();
        if controls == 1 && !candidates.is_empty() && endpoint_pairs.len() == 1 {
            let mut found = edge(
                control,
                candidates[0].0,
                vec![
                    format!("teid={teid}"),
                    format!("capture_scope={}", capture_scope(control)),
                ],
                "gtpv2c-s1u-unique-teid",
                "EXACT",
                "A unique S11 bearer F-TEID equals a unique S1-U GTP-U TEID in the same capture scope",
            );
            found.rule_version = LTE_RULE_VERSION.into();
            found.evidence_type = "EXACT_TUNNEL_MATCH".into();
            found.scope = "lte-bearer-tunnel-only".into();
            found.limitations = vec![
                "Synthetic preparation rule; real LTE evidence is not ANR1-certified".into(),
                "The tunnel match does not independently prove subscriber identity".into(),
            ];
            edges.push(found);
        }
    }
    for (radio, teid) in &s1ap {
        let candidates = s11
            .iter()
            .filter(|(control, candidate)| {
                candidate == teid && capture_scope(control) == capture_scope(radio)
            })
            .collect::<Vec<_>>();
        if candidates.len() == 1 {
            let mut found = edge(
                radio,
                candidates[0].0,
                vec![format!("erab_teid={teid}")],
                "s1ap-gtpv2c-explicit-bearer-teid",
                "STRONG",
                "An explicit S1AP E-RAB TEID equals a unique S11 bearer F-TEID in the same capture scope",
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
            if let Some(teid) = components.get(&teid_key).and_then(|value| normalize_teid(value)) {
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
            let mut components = [
                ("tunnel_endpoint_ip", "gtp_teid"),
                ("ipv4", "teid"),
            ]
            .into_iter()
            .filter_map(|(endpoint_name, teid_name)| {
                let endpoint_ip = component(value, endpoint_name)?;
                let teid = component(value, teid_name)
                    .and_then(|value| normalize_teid(&value))?;
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
        for event_id in &tunnel.event_ids {
            let Some(gtpu) = by_id.get(event_id.as_str()).copied() else {
                continue;
            };
            let mut correlation = edge(
                candidates[0],
                gtpu,
                vec![
                    format!("teid={}", tunnel.teid),
                    format!(
                        "endpoints={}<->{}",
                        tunnel.source_endpoint, tunnel.destination_endpoint
                    ),
                ],
                "n4-n3-discovered-teid-endpoint",
                "EXACT",
                "A unique PFCP F-TEID endpoint matches the directional GTP-U tunnel",
            );
            correlation.rule_version = DISCOVERY_RULE_VERSION.into();
            edges.push(correlation);
        }
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
        let s11 = e(
            "s11",
            "S11",
            "GTPv2-C",
            "CreateSessionResponse",
            1,
            &[("bearer_f_teid", "0x01020304")],
            json!([]),
        );
        let s1u = e(
            "s1u",
            "S1-U",
            "GTP-U",
            "G-PDU",
            2,
            &[("teid", "0x01020304")],
            json!([]),
        );
        let mut s1u_second_packet = s1u.clone();
        s1u_second_packet.event_id = "s1u-second-packet".into();
        s1u_second_packet.packet_references[0].packet_number = 3;
        let edges = correlate_lte_evidence(&[s11, s1u, s1u_second_packet]);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].confidence, "EXACT");
        assert_eq!(edges[0].rule_version, LTE_RULE_VERSION);
        assert_eq!(edges[0].source_interface, "S11");
        assert_eq!(edges[0].target_interface, "S1-U");
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
}
