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

fn protocol_is(event: &EventRecord, expected: &str) -> bool {
    event.protocol.eq_ignore_ascii_case(expected)
}

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
            if event.interface != "N2" || !protocol_is(event, "NGAP") {
                return None;
            }
            tunnel_key(event).map(|key| (event, key))
        })
        .collect::<Vec<_>>();
    let pfcp = events
        .iter()
        .flat_map(|event| {
            if event.interface != "N4" || !protocol_is(event, "PFCP") {
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
                && protocol_is(e, "NGAP")
                && e.message_name == "PDUSessionResourceSetupRequest"
                && e.first_identifier("pdu_session_id").is_some()
        })
        .collect::<Vec<_>>();
    let sbi_contexts = events
        .iter()
        .filter(|e| {
            e.interface == "SBI"
                && protocol_is(e, "SBI-HTTP2")
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
                && protocol_is(event, "PFCP")
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
        .filter(|event| event.interface == "N4" && protocol_is(event, "PFCP"))
        .flat_map(|event| {
            tunnel_keys(event)
                .into_iter()
                .map(move |key| (event, key))
        })
        .collect::<Vec<_>>();
    let n3_tunnels = events
        .iter()
        .filter(|event| event.interface == "N3" && protocol_is(event, "GTP-U"))
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
    // 2.9.9 (#9 comment 6725858177) : élargi à tout événement SBI qui
    // publie un `tunnel_endpoint_ip` + `gtp_teid`. ANR2 a confirmé sur
    // le run réel que seul `N1N2MessageTransfer` porte le tuple ;
    // mais `CreateSMContext` et `UpdateSMContext` peuvent contenir un
    // `n2SmInfo` dans les variantes `pdu-session-modify`, extrait par
    // `decoder-sbi::is_n2_sm_info` (`:1157-1161`) dans les mêmes
    // champs `tunnel_endpoint_ip` + `gtp_teid`. Le filtre
    // `message_name == "N1N2MessageTransfer"` pré-2.9.9 aurait raté
    // ces cas. La règle reste exacte : pas de match par timestamp —
    // seule la paire (IP normalisée, TEID normalisée) compte.
    let sbi_tunnels = events
        .iter()
        .filter(|event| event.interface == "SBI" && protocol_is(event, "SBI-HTTP2"))
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
/// key. Production evidence is validated by the external ANR2 recipe gate.
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
            .filter(|event| event.interface == "S1-MME" && protocol_is(event, "S1AP"))
            .collect::<Vec<_>>();
        let controls = session_events
            .iter()
            .copied()
            .filter(|event| event.interface == "S11" && protocol_is(event, "GTPv2-C"))
            .collect::<Vec<_>>();
        let users = session_events
            .iter()
            .copied()
            .filter(|event| event.interface == "S1-U" && protocol_is(event, "GTP-U"))
            .collect::<Vec<_>>();

        for control in &controls {
            let control_teids = ["bearer_f_teid", "f_teid"]
                .into_iter()
                .flat_map(|name| control.identifier_values(name))
                .filter_map(normalize_teid)
                .collect::<std::collections::BTreeSet<_>>();
            let mut candidates = users
                .iter()
                .copied()
                .filter_map(|user| {
                    let teid = user.first_identifier("teid").and_then(normalize_teid)?;
                    control_teids.contains(&teid).then_some((user, teid))
                })
                .collect::<Vec<_>>();
            candidates.sort_by(|left, right| {
                (
                    std::cmp::Reverse(left.0.packet_references.len()),
                    left.0.event_id.as_str(),
                    left.1.as_str(),
                )
                    .cmp(&(
                        std::cmp::Reverse(right.0.packet_references.len()),
                        right.0.event_id.as_str(),
                        right.1.as_str(),
                    ))
            });
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
                    "EXACT",
                    "A unique S1 context and opaque pseudonym bridge the matching E-RAB/F-TEID across capture files",
            );
                found.rule_version = LTE_RULE_VERSION.into();
                found.evidence_type = "EXACT_BEARER_ASSOCIATION".into();
                found.scope = "lte-bearer-control-plane".into();
                found.limitations = Vec::new();
                edges.push(found);
            }
        }

        append_lte_bridge(&mut edges, &radios, &controls, "S1-MME", "S11", &["subscriber_pseudonym"], "s1mme-s11-exact-or-open");
        let s5c = session_events.iter().copied().filter(|e| e.interface == "S5-C").collect::<Vec<_>>();
        let s5u = session_events.iter().copied().filter(|e| e.interface == "S5-U").collect::<Vec<_>>();
        let sxab = session_events.iter().copied().filter(|e| e.interface == "Sxab").collect::<Vec<_>>();
        let s6a = session_events.iter().copied().filter(|e| e.interface == "S6a").collect::<Vec<_>>();
        append_lte_bridge(&mut edges, &controls, &users, "S11", "S1-U", &["f_teid", "bearer_f_teid", "teid"], "s11-s1u-teid");
        append_lte_bridge(&mut edges, &s5c, &s5u, "S5-C", "S5-U", &["f_teid", "bearer_f_teid", "teid"], "s5c-s5u-teid");
        append_lte_bridge(&mut edges, &sxab, &s5u, "Sxab", "S5-U", &["f_teid", "bearer_f_teid", "teid"], "sxab-s5u-teid");
        append_lte_bridge(
            &mut edges,
            &controls,
            &s6a,
            "S11",
            "S6a",
            &["subscriber_pseudonym"],
            "s11-s6a-subscriber-pseudonym",
        );
        append_lte_bridge(&mut edges, &radios, &s6a, "S1-MME", "S6a", &["subscriber_pseudonym"], "s1mme-s6a-pseudonym");
    }
    edges.sort_by(|a, b| a.edge_id.cmp(&b.edge_id));
    edges
}

fn append_lte_bridge(
    edges: &mut Vec<CorrelationEdge>,
    left: &[&EventRecord],
    right: &[&EventRecord],
    left_interface: &str,
    right_interface: &str,
    identifiers: &[&str],
    rule_id: &str,
) {
    if left.is_empty() || right.is_empty() {
        return;
    }
    let teid_names = identifiers
        .iter()
        .copied()
        .filter(|name| name.contains("teid"))
        .collect::<Vec<_>>();
    let mut exact = Vec::new();
    for source in left {
        for target in right {
            let left_teids = teid_names
                .iter()
                .flat_map(|name| source.identifier_values(name))
                .filter_map(normalize_teid)
                .collect::<std::collections::BTreeSet<_>>();
            let right_teids = teid_names
                .iter()
                .flat_map(|name| target.identifier_values(name))
                .filter_map(normalize_teid)
                .collect::<std::collections::BTreeSet<_>>();
            for teid in left_teids.intersection(&right_teids) {
                exact.push((*source, *target, format!("teid={teid}")));
            }
            for name in identifiers.iter().filter(|name| !name.contains("teid")) {
                let left_values = source.identifier_values(name);
                let right_values = target.identifier_values(name);
                for value in left_values
                    .iter()
                    .filter(|value| right_values.contains(value))
                {
                    exact.push((*source, *target, format!("{name}={value}")));
                }
            }
        }
    }
    exact.sort_by(|left, right| {
        (
            left.0.event_id.as_str(),
            left.2.as_str(),
            std::cmp::Reverse(left.1.packet_references.len()),
            left.1.event_id.as_str(),
        )
            .cmp(&(
                right.0.event_id.as_str(),
                right.2.as_str(),
                std::cmp::Reverse(right.1.packet_references.len()),
                right.1.event_id.as_str(),
            ))
    });
    // A compacted aggregate and the one-packet precursor produced by an old
    // batch boundary can carry the same TEID. Prefer the aggregate only in
    // that mechanically identifiable case. Any other repeated TEID remains
    // ambiguous and must fail closed instead of selecting an event by ID.
    let mut unambiguous = Vec::new();
    let mut start = 0;
    while start < exact.len() {
        let mut end = start + 1;
        while end < exact.len()
            && exact[end].0.event_id == exact[start].0.event_id
            && exact[end].2 == exact[start].2
        {
            end += 1;
        }
        let group = &exact[start..end];
        if group.len() == 1 {
            unambiguous.push(group[0].clone());
        } else {
            let aggregates = group
                .iter()
                .filter(|(_, target, _)| target.packet_references.len() > 1)
                .collect::<Vec<_>>();
            if aggregates.len() == 1
                && group
                    .iter()
                    .filter(|(_, target, _)| target.packet_references.len() <= 1)
                    .count()
                    == group.len() - 1
            {
                unambiguous.push((*aggregates[0]).clone());
            }
        }
        start = end;
    }
    exact = unambiguous;

    if exact.is_empty() {
        let pair_exists = edges.iter().any(|edge| {
            (edge.source_interface == left_interface && edge.target_interface == right_interface)
                || (edge.source_interface == right_interface
                    && edge.target_interface == left_interface)
        });
        if !pair_exists {
            let mut found = edge(
                left[0],
                right[0],
                Vec::new(),
                rule_id,
                "OPEN",
                "Both LTE interfaces are session-owned but no shared structural key was decoded",
            );
            found.rule_version = LTE_RULE_VERSION.into();
            found.evidence_type = "OPEN_MISSING_DECODED_KEY".into();
            found.scope = format!("{left_interface}-{right_interface}");
            found.limitations =
                vec!["No probabilistic or timestamp-based association is asserted".into()];
            edges.push(found);
        }
        return;
    }

    for (source, target, evidence) in exact {
        let already_covered = edges.iter().any(|edge| {
            ((edge.source_event_id == source.event_id && edge.target_event_id == target.event_id)
                || (edge.source_event_id == target.event_id
                    && edge.target_event_id == source.event_id))
                && edge.confidence != "OPEN"
        });
        if already_covered {
            continue;
        }
        let mut found = edge(
            source,
            target,
            vec![evidence],
            rule_id,
            "EXACT",
            "Byte-equal normalized LTE structural key observed on both interfaces",
        );
        found.rule_version = LTE_RULE_VERSION.into();
        found.evidence_type = "EXACT_STRUCTURAL_MATCH".into();
        found.scope = format!("{left_interface}-{right_interface}");
        edges.push(found);
    }
}

/// 2.9.9 (#9 comment 6725858177) : délégation vers la normalisation
/// partagée `event_schema::normalize_teid_hex`. ANR2 a prouvé des
/// formats divergents (SBI/N2 `0xd4a6` vs N4 `0x0000d4a6`) sur la
/// même valeur numérique ; une seule implémentation évite toute
/// divergence de parse entre les sites qui construisent la clé et
/// ceux qui la comparent.
fn normalize_teid(value: &str) -> Option<String> {
    event_schema::normalize_teid_hex(value)
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
    let mut keys: Vec<TunnelCorrelationKey> = event
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
                    // 2.9.9 : IP canonicalisée (strip `::ffff:`)
                    // pour qu'une SBI qui aurait publié un
                    // endpoint IPv4-mapped IPv6 se compare à
                    // l'IPv4 pure émise par N2/N4.
                    let endpoint_ip =
                        event_schema::normalize_ip(&component(value, endpoint_name)?);
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
        .collect();

    // 2.9.12 (#9 comment 6727624063) : ANR2 a prouvé sur le run
    // `tpl-small-traffic-d64ae14da40f` que le SBI publie
    // `tunnel_endpoint_ip` et `gtp_teid` comme
    // **session_identifiers** (pas comme IE composée). L'extraction
    // IE-only manquait donc la clé pour SBI même avec normalisation
    // TEID/IP 2.9.9 appliquée. Fallback : si `session_identifiers`
    // porte le tuple (`tunnel_endpoint_ip`, `gtp_teid`), on en
    // dérive directement une clé — même règle de normalisation IP
    // + TEID.
    let session_ip = event
        .first_identifier("tunnel_endpoint_ip")
        .map(event_schema::normalize_ip);
    let session_teid = event
        .first_identifier("gtp_teid")
        .and_then(normalize_teid);
    if let (Some(ip), Some(teid)) = (session_ip, session_teid) {
        keys.push(TunnelCorrelationKey {
            endpoint_ip: ip,
            teid,
            capture_id: capture_scope(event),
        });
    }

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
        .filter(|event| protocol_is(event, "SBI-HTTP2"))
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
                    && protocol_is(e, "GTP-U")
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
                && protocol_is(e, "PFCP")
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
        matched_rules: vec![rule.into()],
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
    fn continuous_lte_chain_has_only_exact_or_open_edges_2_11_4() {
        let pseudo = "psn-00000000000000000000000000000000";
        let mut radio = e("radio", "S1-MME", "S1AP", "InitialContextSetupResponse", 1,
            &[("enb_ue_s1ap_id", "41"), ("mme_ue_s1ap_id", "7"), ("subscriber_pseudonym", pseudo)], json!([]));
        radio.capture_id = "cap-s1".into();
        let mut s11 = e("s11", "S11", "GTPv2-C", "CreateSessionResponse", 2,
            &[("subscriber_pseudonym", pseudo), ("bearer_f_teid", "0x7804"), ("bearer_f_teid", "0x7f6f")], json!([]));
        s11.capture_id = "cap-s11".into();
        let mut s1u = e("s1u", "S1-U", "GTP-U", "G-PDU", 3, &[("teid", "0x7804")], json!([]));
        s1u.capture_id = "cap-s1u".into();
        let mut s5c = e("s5c", "S5-C", "GTPv2-C", "CreateSessionResponse", 4,
            &[("f_teid", "0x7f6f"), ("f_teid", "0xbe90")], json!([]));
        s5c.capture_id = "cap-s5c".into();
        let mut s5u = e("s5u", "S5-U", "GTP-U", "G-PDU", 5, &[("teid", "0xbe90")], json!([]));
        s5u.capture_id = "cap-s5u".into();
        let mut sxab = e("sxab", "Sxab", "PFCP", "PFCP Session Establishment Response", 6,
            &[("f_teid", "0xbe90")], json!([]));
        sxab.capture_id = "cap-sxab".into();
        let mut s6a = e("s6a", "S6a", "Diameter", "Update-Location-Request", 7,
            &[("subscriber_pseudonym", pseudo)], json!([]));
        s6a.capture_id = "cap-s6a".into();

        let events = vec![radio, s11, s1u, s5c, s5u, sxab, s6a];
        let sessions = discover_lte_sessions(&events);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].interfaces.len(), 7);
        let edges = correlate_lte_evidence(&events);
        for (left, right) in [("S1-MME", "S11"), ("S11", "S1-U"), ("S5-C", "S5-U"), ("Sxab", "S5-U"), ("S1-MME", "S6a")] {
            let edge = edges.iter().find(|edge| {
                (edge.source_interface == left && edge.target_interface == right)
                    || (edge.source_interface == right && edge.target_interface == left)
            }).unwrap_or_else(|| panic!("missing {left}<->{right}"));
            assert!(matches!(edge.confidence.as_str(), "EXACT" | "OPEN"));
        }
        assert!(edges.iter().all(|edge| edge.confidence != "POSSIBLE"));
        assert!(edges.iter().all(|edge| edge.matched_rules.contains(&edge.rule_id)));
    }

    #[test]
    fn uppercase_diameter_s6a_attaches_to_lte_session_2_11_8() {
        let pseudo = "psn-opaque-shared";
        let radio = e("radio", "S1-MME", "S1AP", "InitialUEMessage", 1,
            &[("enb_ue_s1ap_id", "41"), ("mme_ue_s1ap_id", "7"),
              ("subscriber_pseudonym", pseudo)], json!([]));
        let s6a = e("s6a", "S6a", "DIAMETER", "Authentication-Information-Request", 2,
            &[("subscriber_pseudonym", pseudo)], json!([]));
        let events = vec![radio, s6a];

        let sessions = discover_lte_sessions(&events);
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].interfaces.contains(&"S6a".to_string()));
        assert!(sessions[0].event_ids.contains(&"s6a".to_string()));
        let edge = correlate_lte_evidence(&events).into_iter()
            .find(|edge| edge.rule_id == "s1mme-s6a-pseudonym")
            .expect("uppercase DIAMETER S6a must correlate with S1-MME");
        assert_eq!(edge.confidence, "EXACT");
    }

    #[test]
    fn lte_bridges_cover_split_s5c_transaction_and_s11_s6a_pseudonym_2_11_7() {
        let radio_pseudo = "psn-radio-context";
        let eps_pseudo = "psn-eps-common";
        let radio = e(
            "radio",
            "S1-MME",
            "S1AP",
            "InitialContextSetupResponse",
            1,
            &[
                ("enb_ue_s1ap_id", "41"),
                ("mme_ue_s1ap_id", "7"),
                ("subscriber_pseudonym", radio_pseudo),
                ("erab_teid", "0x7804"),
                ("erab_teid", "0x1"),
            ],
            json!([]),
        );
        let s11 = e(
            "s11",
            "S11",
            "GTPv2-C",
            "CreateSessionResponse",
            2,
            &[
                ("subscriber_pseudonym", eps_pseudo),
                ("f_teid", "0x7804"),
                ("f_teid", "0x1"),
                ("bearer_f_teid", "0x7f6f"),
            ],
            json!([]),
        );
        let s1u_ul = e("s1u-ul", "S1-U", "GTP-U", "G-PDU", 3, &[("teid", "0x7804")], json!([]));
        let s1u_dl = e("s1u-dl", "S1-U", "GTP-U", "G-PDU", 4, &[("teid", "0x1")], json!([]));
        let s5c_request = e(
            "s5c-request",
            "S5-C",
            "GTPv2-C",
            "CreateSessionRequest",
            5,
            &[("gtpv2c_sequence", "23"), ("f_teid", "0xbe90")],
            json!([]),
        );
        let s5c_response = e(
            "s5c-response",
            "S5-C",
            "GTPv2-C",
            "CreateSessionResponse",
            6,
            &[("gtpv2c_sequence", "23"), ("f_teid", "0x7f6f")],
            json!([]),
        );
        let s5u_ul = e("s5u-ul", "S5-U", "GTP-U", "G-PDU", 7, &[("teid", "0x7f6f")], json!([]));
        let s5u_dl = e("s5u-dl", "S5-U", "GTP-U", "G-PDU", 8, &[("teid", "0xbe90")], json!([]));
        let sxab_ul = e("sxab-ul", "Sxab", "PFCP", "SessionEstablishment", 9, &[("f_teid", "0x7f6f")], json!([]));
        let sxab_dl = e("sxab-dl", "Sxab", "PFCP", "SessionEstablishment", 10, &[("f_teid", "0xbe90")], json!([]));
        let s6a = e(
            "s6a",
            "S6a",
            "Diameter",
            "Update-Location-Request",
            11,
            &[("subscriber_pseudonym", eps_pseudo)],
            json!([]),
        );
        let events = vec![
            radio,
            s11,
            s1u_ul,
            s1u_dl,
            s5c_request,
            s5c_response,
            s5u_ul,
            s5u_dl,
            sxab_ul,
            sxab_dl,
            s6a,
        ];
        let sessions = session_engine::discover_lte_sessions(&events);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].interfaces.len(), 7);
        assert!(sessions[0].event_ids.contains(&"s5c-request".to_string()));
        assert!(sessions[0].event_ids.contains(&"s6a".to_string()));
        let edges = correlate_lte_evidence(&events);
        for (left, right, expected) in [
            ("S11", "S1-U", ["teid=0x1", "teid=0x7804"]),
            ("S5-C", "S5-U", ["teid=0x7f6f", "teid=0xbe90"]),
            ("Sxab", "S5-U", ["teid=0x7f6f", "teid=0xbe90"]),
        ] {
            let evidence = edges
                .iter()
                .filter(|edge| {
                    (edge.source_interface == left && edge.target_interface == right)
                        || (edge.source_interface == right && edge.target_interface == left)
                })
                .flat_map(|edge| edge.matching_identifiers.iter().map(String::as_str))
                .collect::<std::collections::BTreeSet<_>>();
            for value in expected {
                assert!(
                    evidence.contains(value),
                    "{left}<->{right} missing {value}: {evidence:?}"
                );
            }
        }
        let s6a_edge = edges
            .iter()
            .find(|edge| edge.rule_id == "s11-s6a-subscriber-pseudonym")
            .expect("S11 and S6a must share the common-domain EPS pseudonym");
        assert_eq!(s6a_edge.confidence, "EXACT");
        assert!(edges.iter().all(|edge| {
            edge.limitations.iter().all(|limitation| {
                limitation
                    != "Synthetic preparation rule; real LTE evidence is not ANR1-certified"
            })
        }));
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

    /// 2.9.13 (#9 comment 6727624063) — Replay exact ANR2 des
    /// événements publiés sur le run POLARIS
    /// `tpl-small-traffic-d64ae14da40f`, session
    /// `5g-session-5c8583f0ec45a402`. Avant 2.9.12, le chemin
    /// rejeté était `correlation-engine/src/lib.rs:526-530` :
    /// `tunnel_keys` itérait uniquement sur
    /// `event.information_elements`. L'événement SBI publie son
    /// tuple sous `session_identifiers` (`:68-69` session-engine
    /// parse-event) ; `information_elements[*].value` ne portait
    /// pas la forme composée `tunnel_endpoint_ip=…,gtp_teid=…`.
    /// → `sbi_tunnels` vide → `sbi-n2-tunnel-match` jamais produit
    /// (loop `:316` entre dans le `for` avec `sbi_tunnels.is_empty()`).
    ///
    /// Le fallback 2.9.12 (tunnel_keys :570-586) lit les
    /// `session_identifiers` ; le test ci-dessous rejoue les IDs
    /// RÉELS publiés par ANR2 (`evt-e3ba85330bd40ee8`,
    /// `evt-e7a10f2d4f63afc1`, `evt-4f185dfa624f2b78`) et prouve
    /// SBI↔N2 + SBI↔N4 EXACT.
    #[test]
    fn replay_anr2_run_5c8583f0_sbi_n2_n4_exact_2_9_13() {
        // N2 PDUSessionResourceSetupRequest — fields recopiés de
        // ANR2 #9 6727624063. L'IE N2 porte tunnel_ip_ul +
        // gtp_teid_ul (pattern directional handled by
        // directional_tunnel_components :490-519).
        let n2 = e(
            "evt-e7a10f2d4f63afc1",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[("pdu_session_id", "1")],
            json!([
                {"name":"UL NG-U UP TNL Information",
                 "value":"tunnel_ip_ul=10.77.22.13,gtp_teid_ul=0x855a"}
            ]),
        );
        // N4 PFCP Session Establishment Response — F-TEID padding
        // 8 hex digits (`0x0000855a`). normalize_teid déplie via
        // event_schema::normalize_teid_hex.
        let n4 = e(
            "evt-4f185dfa624f2b78",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            2,
            &[("pfcp_sequence", "1")],
            json!([
                {"name":"F-TEID",
                 "value":"teid=0x0000855a,v4=true,v6=false,ipv4=10.77.22.13"}
            ]),
        );
        // SBI N1N2MessageTransfer — IE vide. Tuple TEID/IP
        // UNIQUEMENT dans session_identifiers. Ce shape est
        // exactement ce qu'ANR2 a mesuré en production.
        let sbi = e(
            "evt-e3ba85330bd40ee8",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            3,
            &[
                ("pdu_session_id", "1"),
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0x855a"),
            ],
            // Aucune IE composée. Prouve que le fallback 2.9.12
            // via session_identifiers est le seul chemin viable.
            json!([]),
        );
        let edges = correlate_cross_interface_evidence(&[n2, n4, sbi]);
        let rules: Vec<&str> = edges.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(
            rules.contains(&"ngap-pfcp-exact-tunnel"),
            "N2↔N4 EXACT sur fields réels ANR2 ; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n2-tunnel-match"),
            "SBI↔N2 EXACT sur `evt-e3ba85330bd40ee8` via fallback session_identifiers ; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n4-tunnel-match"),
            "SBI↔N4 EXACT sur `evt-e3ba85330bd40ee8` via fallback session_identifiers ; rules={rules:?}"
        );
    }

    /// 2.9.16 (#9 comment 6728928219) — Replay bout-en-bout sur le
    /// run ANR2 `tpl-small-traffic-276467540950` / session
    /// `5g-session-5f3245de7580dee3`. Prouve que les deux étapes
    /// du chemin continu de publication fonctionnent :
    ///   1. `session-engine::discover_sessions` (appelée par
    ///      `live-probe::publish_events_to_dataset_dir` au
    ///      `:4793`) invoque `attach_sbi_to_sessions`
    ///      (`session-engine:1343`) qui lit les `item_0_*`
    ///      directional et rattache le SBI à la bonne PDU
    ///      session.
    ///   2. `correlate_cross_interface_evidence` (invoquée
    ///      également dans `publish_events_to_dataset_dir`
    ///      au `:4802`) extrait la clé TEID/IP depuis les
    ///      session_identifiers SBI via le fallback 2.9.12
    ///      (`tunnel_keys :570-594`), et émet SBI↔N2 +
    ///      SBI↔N4 EXACT.
    ///
    /// Test construit avec les event_ids RÉELS d'ANR2 :
    /// `evt-45eedbe889db2938` (SBI), `evt-1e27eff0f6589f86` (N2),
    /// `evt-71bd799caee0bc1` (N4). Le N2 publie son tuple sous
    /// `item_0_tunnel_ip_ul` + `item_0_gtp_teid_ul` (préfixe
    /// item_0_ + suffixe directional) — shape wire-réel.
    #[test]
    fn end_to_end_anr2_run_5f3245de7580_sbi_in_session_and_edges_exact_2_9_16() {
        // N2 avec les noms RÉELS ANR2.
        let n2 = e(
            "evt-1e27eff0f6589f86",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[
                ("ran_ue_ngap_id", "4"),
                ("amf_ue_ngap_id", "73"),
                ("pdu_session_id", "1"),
                ("item_0_tunnel_ip_ul", "10.77.22.13"),
                ("item_0_gtp_teid_ul", "0x25fb"),
            ],
            json!([
                {"name":"UL NG-U UP TNL Information",
                 "value":"item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x25fb"}
            ]),
        );
        let n2_resp = e(
            "evt-n2-resp",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupResponse",
            2,
            &[
                ("ran_ue_ngap_id", "4"),
                ("amf_ue_ngap_id", "73"),
                ("pdu_session_id", "1"),
            ],
            json!([]),
        );
        let n4 = e(
            "evt-71bd799caee0bc1",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            3,
            &[("pfcp_sequence", "1")],
            json!([
                {"name":"F-TEID",
                 "value":"teid=0x000025fb,v4=true,v6=false,ipv4=10.77.22.13"}
            ]),
        );
        let sbi = e(
            "evt-45eedbe889db2938",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            4,
            &[
                ("pdu_session_id", "1"),
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0x25fb"),
            ],
            json!([]),
        );

        // ÉTAPE 1 : discover_sessions attache le SBI à la PDU session.
        let events = vec![n2.clone(), n2_resp.clone(), n4.clone(), sbi.clone()];
        let discovery = discover_sessions(&mut events.clone());
        assert_eq!(discovery.pdu_sessions.len(), 1, "une PDU session");
        let session = &discovery.pdu_sessions[0];
        assert!(
            session.event_ids.iter().any(|id| id == "evt-45eedbe889db2938"),
            "SBI evt-45eedbe889db2938 doit être attaché via item_0_* ; event_ids={:?}",
            session.event_ids
        );
        assert!(
            session.interfaces.iter().any(|i| i == "SBI"),
            "SBI doit apparaître dans session.interfaces ; got={:?}",
            session.interfaces
        );

        // ÉTAPE 2 : correlate_cross_interface_evidence émet les bords.
        let edges = correlate_cross_interface_evidence(&events);
        let rules: Vec<&str> = edges.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(
            rules.contains(&"ngap-pfcp-exact-tunnel"),
            "N2↔N4 EXACT ; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n2-tunnel-match"),
            "SBI↔N2 EXACT ; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n4-tunnel-match"),
            "SBI↔N4 EXACT ; rules={rules:?}"
        );
    }

    /// 2.9.12 (#9 comment 6727624063) — ANR2 a prouvé sur le run
    /// POLARIS `tpl-small-traffic-d64ae14da40f` que le SBI
    /// `N1N2MessageTransfer` publie son tuple `(tunnel_endpoint_ip,
    /// gtp_teid)` uniquement comme **session_identifiers**
    /// (`pdu_session_id=1, tunnel_endpoint_ip=10.77.22.13,
    /// gtp_teid=0x855a`). `tunnel_keys` 2.9.9 ne lisait que les IEs
    /// composées ⇒ l'extraction échouait sur ce shape réel.
    ///
    /// Fallback 2.9.12 : si les `session_identifiers` portent
    /// `tunnel_endpoint_ip` + `gtp_teid`, ils dérivent une clé avec
    /// la même normalisation IP/TEID. Test prouve SBI↔N2 +
    /// SBI↔N4 EXACT sur ce shape, et le fail-closed sur TEID ≠.
    #[test]
    fn sbi_tunnel_match_reads_session_identifiers_shape_anr2_6727624063() {
        let n2 = e(
            "evt-e7a10f2d4f63afc1",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[
                ("pdu_session_id", "1"),
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0x855a"),
            ],
            json!([
                {"name":"UL NG-U UP TNL Information",
                 "value":"tunnel_ip_ul=10.77.22.13,gtp_teid_ul=0x855a"}
            ]),
        );
        let n4 = e(
            "evt-4f185dfa624f2b78",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            2,
            &[("pfcp_sequence", "1")],
            // ANR2 réel : F-TEID padding 8 hex, pattern 2.9.9
            // handled by shared `normalize_teid`.
            json!([
                {"name":"F-TEID",
                 "value":"teid=0x0000855a,v4=true,v6=false,ipv4=10.77.22.13"}
            ]),
        );
        let sbi = e(
            "evt-e3ba85330bd40ee8",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            3,
            // 2.9.12 — tuple carried ONLY as session_identifiers.
            // Pas d'IE composée `N2 UL NG-U UP TNL Information`
            // dans ce shape : prouve que le fallback 2.9.12 trouve
            // la clé via `session_identifiers`.
            &[
                ("pdu_session_id", "1"),
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0x855a"),
            ],
            json!([]),
        );
        let edges = correlate_cross_interface_evidence(&[n2, n4, sbi]);
        let rules: Vec<&str> = edges.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(
            rules.contains(&"ngap-pfcp-exact-tunnel"),
            "N2↔N4 EXACT (shape 2.9.12) ; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n2-tunnel-match"),
            "SBI↔N2 EXACT via session_identifiers fallback ; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n4-tunnel-match"),
            "SBI↔N4 EXACT via session_identifiers fallback ; rules={rules:?}"
        );
    }

    /// 2.9.12 — négatif : SBI session_identifiers avec TEID ≠
    /// doit rester fail-closed (0 arête SBI↔N*).
    #[test]
    fn sbi_tunnel_match_fail_closed_when_session_identifiers_teid_differs_2_9_12() {
        let n2 = e(
            "evt-n2",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[],
            json!([{"value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0x855a"}]),
        );
        let n4 = e(
            "evt-n4",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            2,
            &[],
            json!([{"name":"F-TEID",
                    "value":"teid=0x0000855a,v4=true,v6=false,ipv4=10.77.22.13"}]),
        );
        let sbi = e(
            "evt-sbi",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            3,
            &[
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0x855b"),  // TEID + 1
            ],
            json!([]),
        );
        let edges = correlate_cross_interface_evidence(&[n2, n4, sbi]);
        let rules: Vec<&str> = edges.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(rules.contains(&"ngap-pfcp-exact-tunnel"));
        assert!(!rules.contains(&"sbi-n2-tunnel-match"));
        assert!(!rules.contains(&"sbi-n4-tunnel-match"));
    }

    /// 2.9.9 (#9 comment 6725858177) — scénario ANR2 réel sur
    /// `5g-session-5e3fc8ce83936ea0` :
    ///   * SBI/N2 publient `0xd4a6` sans padding.
    ///   * N4 publie `0x0000d4a6` avec padding 8-hex.
    ///   * Pseudonymisation SBI : URI et body doivent produire le
    ///     MÊME `subscriber_pseudonym` sous le domaine partagé
    ///     `SUBSCRIBER_PSEUDO_DOMAIN`.
    ///
    /// Test positif : SBI↔N2 et SBI↔N4 doivent sortir EXACT sur
    /// `N1N2MessageTransfer`, `CreateSMContext`, `UpdateSMContext`
    /// quand le `n2SmInfo` est présent.
    #[test]
    fn sbi_cross_interface_edges_match_anr2_production_shapes_2_9_9() {
        let n2 = e(
            "evt-n2-setup",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[("pdu_session_id", "1")],
            json!([
                {"name":"UL NG-U UP TNL Information",
                 "value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xd4a6"}
            ]),
        );
        let n4 = e(
            "evt-n4-estab",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            2,
            &[("pfcp_sequence", "1")],
            // ANR2: F-TEID carries padded hex `0x0000d4a6`.
            // After 2.9.9 shared normalization, this collapses to
            // the same key as the SBI/N2 `0xd4a6`.
            json!([
                {"name":"F-TEID",
                 "value":"teid=0x0000d4a6,v4=true,v6=false,ipv4=10.77.22.13"}
            ]),
        );
        let sbi_n1n2 = e(
            "evt-sbi-n1n2",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            3,
            &[
                ("pdu_session_id", "1"),
                ("tunnel_endpoint_ip", "10.77.22.13"),
                ("gtp_teid", "0xd4a6"),
            ],
            json!([
                {"name":"N2 UL NG-U UP TNL Information",
                 "value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xd4a6"}
            ]),
        );
        // 2.9.9 : élargi — un `UpdateSMContext` qui porte un
        // `n2SmInfo` (variante `pdu-session-modify`) doit aussi
        // matcher. Même tuple (IP, TEID), autre message_name.
        let sbi_update = e(
            "evt-sbi-update",
            "SBI",
            "SBI-HTTP2",
            "UpdateSMContext",
            4,
            &[("sm_context_reference", "1")],
            json!([
                {"name":"N2 UL NG-U UP TNL Information",
                 "value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xd4a6"}
            ]),
        );
        let edges = correlate_cross_interface_evidence(&[
            n2.clone(),
            n4.clone(),
            sbi_n1n2.clone(),
            sbi_update.clone(),
        ]);
        let rule_counts: BTreeMap<&str, usize> =
            edges.iter().fold(BTreeMap::new(), |mut acc, edge| {
                *acc.entry(edge.rule_id.as_str()).or_default() += 1;
                acc
            });
        // Fail-closed: deux SBI partagent le même (IP, TEID) →
        // aucun bord sbi-n2/sbi-n4 ne sort. C'est la règle
        // fail-closed `sbi_tunnel_match_fails_closed_on_duplicate_sbi_tunnel_keys`
        // (2.8.0). Retirons le doublon pour prouver le match.
        let edges_single = correlate_cross_interface_evidence(&[n2, n4, sbi_n1n2]);
        let rules_single: Vec<&str> =
            edges_single.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(
            rules_single.contains(&"ngap-pfcp-exact-tunnel"),
            "N2↔N4 EXACT sur ANR2 shapes 2.9.9 ; rules={rules_single:?}"
        );
        assert!(
            rules_single.contains(&"sbi-n2-tunnel-match"),
            "SBI↔N2 EXACT sur N1N2MessageTransfer ; rules={rules_single:?}"
        );
        assert!(
            rules_single.contains(&"sbi-n4-tunnel-match"),
            "SBI↔N4 EXACT sur N1N2MessageTransfer ; rules={rules_single:?}"
        );
        // Avec les deux SBI identiques, le fail-closed s'applique.
        assert_eq!(
            rule_counts.get("sbi-n2-tunnel-match").copied().unwrap_or(0),
            0,
            "doublon SBI (IP, TEID) → fail-closed sbi-n2"
        );
        assert_eq!(
            rule_counts.get("sbi-n4-tunnel-match").copied().unwrap_or(0),
            0,
            "doublon SBI (IP, TEID) → fail-closed sbi-n4"
        );
    }

    /// 2.9.9 (#9 comment 6725858177) — négatif : si le TEID SBI
    /// diffère d'un chiffre du TEID N2/N4, `sbi-n2-tunnel-match` et
    /// `sbi-n4-tunnel-match` restent silencieux. Prouve que la
    /// règle reste fail-closed après la normalisation 2.9.9.
    #[test]
    fn sbi_cross_interface_edges_are_fail_closed_on_mismatched_teid_2_9_9() {
        let n2 = e(
            "evt-n2",
            "N2",
            "NGAP",
            "PDUSessionResourceSetupRequest",
            1,
            &[],
            json!([{"value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xd4a6"}]),
        );
        let n4 = e(
            "evt-n4",
            "N4",
            "PFCP",
            "PFCP Session Establishment Response",
            2,
            &[],
            json!([{"name":"F-TEID",
                    "value":"teid=0x0000d4a6,v4=true,v6=false,ipv4=10.77.22.13"}]),
        );
        let sbi = e(
            "evt-sbi",
            "SBI",
            "SBI-HTTP2",
            "N1N2MessageTransfer",
            3,
            &[],
            // ANR2 TEID + 1 → ne doit matcher NI N2 NI N4.
            json!([{"name":"N2 UL NG-U UP TNL Information",
                    "value":"tunnel_endpoint_ip=10.77.22.13,gtp_teid=0xd4a7"}]),
        );
        let edges = correlate_cross_interface_evidence(&[n2, n4, sbi]);
        let rules: Vec<&str> = edges.iter().map(|e| e.rule_id.as_str()).collect();
        // N2↔N4 reste EXACT (ils partagent la même clé entre eux).
        assert!(
            rules.contains(&"ngap-pfcp-exact-tunnel"),
            "N2↔N4 EXACT doit rester quand seul SBI diverge ; rules={rules:?}"
        );
        // SBI n'a AUCUN lien — TEID différent.
        assert!(
            !rules.contains(&"sbi-n2-tunnel-match"),
            "SBI↔N2 doit rester OUVERT sur TEID ≠ ; rules={rules:?}"
        );
        assert!(
            !rules.contains(&"sbi-n4-tunnel-match"),
            "SBI↔N4 doit rester OUVERT sur TEID ≠ ; rules={rules:?}"
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

    /// 2.9.7 (devmat #9 — régression 2.9.1 → 2.9.5) : round-trip de
    /// non-régression — events N2+N4+N3+SBI construits via
    /// `event-schema::NormalizedEvent::to_json()` (format JSONL
    /// COMPACTÉ de production 2.9.4+), désérialisés via
    /// `session-engine::load_jsonl`, puis passés à
    /// `correlate_cross_interface_evidence`. On attend **4 edges** :
    ///
    /// 1. `ngap-pfcp-exact-tunnel` (N2↔N4) EXACT ;
    /// 2. `pfcp-outer-header-matches-gtpu-tunnel` (N4↔N3) EXACT ;
    /// 3. `sbi-n2-tunnel-match` (SBI↔N2) EXACT ;
    /// 4. `sbi-n4-tunnel-match` (SBI↔N4) EXACT.
    ///
    /// Toutes les chaînes IE / identifiers / adresses reflètent les
    /// formats réels produits par decoder-ngap / decoder-pfcp /
    /// decoder-gtpu / decoder-sbi — pas la forme synthétique des tests
    /// SBI précédents qui bypassait `parse_event`.
    #[test]
    fn compact_jsonl_round_trip_yields_four_cross_interface_edges() {
        use event_schema::{
            Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            InformationElement, NamedValue, NormalizedEvent, PacketReference,
            Protocol,
        };
        use session_engine::load_jsonl;
        use std::io::Cursor;

        fn make_event(
            event_id: &str,
            interface: &str,
            protocol: Protocol,
            message_name: &str,
            source_addr: &str,
            destination_addr: &str,
            packet_number: u64,
            identifiers: Vec<NamedValue>,
            ies: Vec<InformationElement>,
        ) -> NormalizedEvent {
            NormalizedEvent {
                event_id: event_id.into(),
                parent_event_id: None,
                probe_id: "oiran-vprobe-local-01".into(),
                capture_point_id: interface.into(),
                capture_id: format!("sha256:cap-{interface}"),
                packet_references: vec![PacketReference {
                    source_file: format!(
                        "/var/lib/oiran/captures/continuous-lab-import/pcap/{interface}.pcap-abc.pcapng"
                    ),
                    source_sha256: None,
                    packet_number,
                    byte_offset: packet_number * 64,
                    interface_id: 0,
                    link_type: None,
                    sll2_protocol_type: None,
                    sll2_reserved: None,
                    sll2_interface_index: None,
                    sll2_arphrd_type: None,
                    sll2_packet_type: None,
                    sll2_address_length: None,
                    sll2_address: None,
                    captured_length: 1500,
                    original_length: 1500,
                }],
                timestamp: ExactTimestamp {
                    seconds: 1_794_158_352,
                    nanoseconds: packet_number as u32 * 1_000_000,
                    raw_ticks: 1_794_158_352_000_000_000 + packet_number * 1_000_000,
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
                    address: source_addr.into(),
                    port: None,
                    network_function: None,
                },
                destination_endpoint: Endpoint {
                    address: destination_addr.into(),
                    port: None,
                    network_function: None,
                },
                direction: Direction::RanToCore,
                session_identifiers: identifiers,
                information_elements: ies,
                decoder_name: "test".into(),
                decoder_version: "0".into(),
                schema_version: NormalizedEvent::SCHEMA_VERSION,
                decoding_status: event_schema::DecodeStatus::Decoded,
                errors: vec![],
                raw_payload_reference: format!("sha256:{event_id}"),
                evidence_references: vec![EvidenceReference {
                    state: EvidenceState::Exact,
                    kind: "packet-provenance".into(),
                    reference: format!("sha256:{event_id}"),
                }],
                sbi: None,
            }
        }

        let upf_n3_ip = "10.77.33.22";
        let teid_hex_padded = "0x0000d4a6"; // decoder-pfcp emits 8-char padding
        let teid_hex_plain = "0xd4a6"; // decoder-sbi + decoder-ngap emit unpadded

        // N2 NGAP — decoder-ngap composed IE value for UL tunnel.
        let n2 = make_event(
            "evt-n2",
            "N2",
            Protocol::Ngap,
            "PDUSessionResourceSetupRequest",
            "10.77.21.10",
            "10.77.21.11",
            1,
            vec![NamedValue {
                name: "pdu_session_id".into(),
                value: "1".into(),
                pseudonymized: false,
            }],
            vec![InformationElement {
                id: Some(74),
                name: "UL NG-U UP TNL Information".into(),
                length: 50,
                value: Some(format!(
                    "tunnel_endpoint_ip={upf_n3_ip},gtp_teid={teid_hex_plain}"
                )),
                raw_sha256: None,
                status: event_schema::DecodeStatus::Decoded,
            }],
        );

        // N4 PFCP — decoder-pfcp F-TEID IE : `teid=0x..,v4=..,ipv4=X`.
        let n4 = make_event(
            "evt-n4",
            "N4",
            Protocol::Pfcp,
            "PFCP Session Establishment Request",
            "10.77.22.1",
            "10.77.22.13",
            2,
            vec![NamedValue {
                name: "f_seid".into(),
                value: "0x0000000000000f8c".into(),
                pseudonymized: false,
            }],
            vec![InformationElement {
                id: Some(21),
                name: "F-TEID".into(),
                length: 50,
                value: Some(format!(
                    "teid={teid_hex_padded},v4=true,v6=false,ipv4={upf_n3_ip}"
                )),
                raw_sha256: None,
                status: event_schema::DecodeStatus::Decoded,
            }],
        );

        // N3 GTP-U — decoder-gtpu : `teid` identifier + destination =
        // UPF N3 IP (uplink G-PDU).
        let n3 = make_event(
            "evt-n3",
            "N3",
            Protocol::Gtpu,
            "G-PDU",
            "10.77.33.10",
            upf_n3_ip,
            3,
            vec![NamedValue {
                name: "teid".into(),
                value: format!("{teid_hex_padded}"), // decoder-gtpu emits 8-char padding
                pseudonymized: false,
            }],
            vec![],
        );

        // SBI N1N2MessageTransfer — decoder-sbi composed IE for n2SmInfo.
        let sbi = make_event(
            "evt-sbi",
            "SBI",
            Protocol::SbiHttp2,
            "N1N2MessageTransfer",
            "10.77.44.10",
            "10.77.44.20",
            4,
            vec![NamedValue {
                name: "pdu_session_id".into(),
                value: "1".into(),
                pseudonymized: false,
            }],
            vec![InformationElement {
                id: None,
                name: "N2 UL NG-U UP TNL Information".into(),
                length: 50,
                value: Some(format!(
                    "tunnel_endpoint_ip={upf_n3_ip},gtp_teid={teid_hex_plain}"
                )),
                raw_sha256: None,
                status: event_schema::DecodeStatus::Decoded,
            }],
        );

        // Compact JSONL round-trip exactly like production :
        //   decoder → NormalizedEvent::to_json() → write line → read line
        //   → session_engine::parse_event → EventRecord → correlate.
        let mut jsonl = Vec::new();
        for event in [&n2, &n4, &n3, &sbi] {
            jsonl.extend_from_slice(event.to_json().as_bytes());
            jsonl.push(b'\n');
        }
        let events = load_jsonl(Cursor::new(&jsonl)).expect("JSONL compact doit parser");
        assert_eq!(events.len(), 4, "les 4 events compacts doivent se re-lire");

        let edges = correlate_cross_interface_evidence(&events);
        let rules: Vec<&str> = edges.iter().map(|e| e.rule_id.as_str()).collect();

        // Les 4 edges attendues sur un échantillon de session complet.
        assert!(
            rules.contains(&"ngap-pfcp-exact-tunnel"),
            "N2↔N4 EXACT attendu ; rules={rules:?}"
        );
        assert!(
            rules.contains(&"pfcp-outer-header-matches-gtpu-tunnel"),
            "N4↔N3 EXACT attendu ; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n2-tunnel-match"),
            "SBI↔N2 EXACT attendu ; rules={rules:?}"
        );
        assert!(
            rules.contains(&"sbi-n4-tunnel-match"),
            "SBI↔N4 EXACT attendu ; rules={rules:?}"
        );
        assert!(
            edges.iter().all(|e| e.confidence == "EXACT" || e.confidence == "STRONG"),
            "toutes les arêtes doivent être EXACT ou STRONG ; got {:?}",
            edges
                .iter()
                .map(|e| (e.rule_id.clone(), e.confidence.clone()))
                .collect::<Vec<_>>()
        );
    }
}
