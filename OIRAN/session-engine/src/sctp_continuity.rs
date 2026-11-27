//! Additive continuity evidence between already-discovered N2 PDU sessions.
use super::{DiscoveredPduSession, EventRecord};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SctpContinuityLink {
    pub predecessor_session_id: String,
    pub successor_session_id: String,
    pub setup_event_id: String,
    pub release_event_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct WireKey<'a> {
    capture_point: &'a str,
    probe: Option<&'a str>,
    source: (IpAddr, u16),
    destination: (IpAddr, u16),
    verification_tag: u32,
    ran_ue_id: &'a str,
    amf_ue_id: &'a str,
    pdu_id: &'a str,
    stream: &'a str,
}

fn rotation(source_file: &str) -> Option<(&str, u64)> {
    let name = Path::new(source_file)
        .file_name()?
        .to_str()?
        .strip_suffix(".pcapng")?;
    let (prefix, file_start) = name.rsplit_once('_')?;
    let (stream, sequence) = prefix.rsplit_once('_')?;
    if !stream.starts_with("n2_")
        || file_start.len() != 14
        || !file_start.bytes().all(|byte| byte.is_ascii_digit())
        || sequence.len() != 5
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((stream, sequence.parse().ok()?))
}

fn wire_key(event: &EventRecord) -> Option<(WireKey<'_>, u64)> {
    let reference = event.packet_references.first()?;
    let association = reference.sctp_association.as_ref()?;
    let original_name = association.original_segment_name.as_deref()?;
    let (stream, parsed_index) = rotation(original_name)?;
    let rotation = association.rotation_index.filter(|&index| index == parsed_index)?;
    let port = |index: usize| {
        let port =
            u16::try_from(event.source_json.get("sctp_ports")?.get(index)?.as_u64()?).ok()?;
        (port != 0).then_some(port)
    };
    if event.protocol != "NGAP" || event.interface != "N2" || association.verification_tag == 0 {
        return None;
    }
    let key = WireKey {
        capture_point: &event.capture_point_id,
        probe: event.probe_id.as_deref(),
        source: (event.source_address.parse().ok()?, port(0)?),
        destination: (event.destination_address.parse().ok()?, port(1)?),
        verification_tag: association.verification_tag,
        ran_ue_id: event.first_identifier("ran_ue_ngap_id")?,
        amf_ue_id: event.first_identifier("amf_ue_ngap_id")?,
        pdu_id: event.first_identifier("pdu_session_id")?,
        stream,
    };
    Some((key, rotation))
}

pub(super) fn links(
    sessions: &[DiscoveredPduSession],
    events: &BTreeMap<String, &EventRecord>,
) -> Vec<SctpContinuityLink> {
    let mut generations = BTreeMap::<_, BTreeSet<_>>::new();
    for &event in events.values().filter(|event| event.interface == "N2") {
        if let Some(provenance) = event
            .packet_references
            .first()
            .and_then(|reference| reference.sctp_association.as_ref())
        {
            generations
                .entry((
                    event.capture_id.as_str(),
                    provenance.association_id.as_str(),
                ))
                .or_default()
                .insert(provenance.association_generation);
        }
    }

    let mut setups = BTreeMap::<_, Vec<_>>::new();
    let mut releases = Vec::new();
    for session in sessions {
        let members: Vec<_> = session
            .event_ids
            .iter()
            .filter_map(|id| events.get(id).copied())
            .filter(|event| event.protocol == "NGAP" && event.interface == "N2")
            .collect();
        for &event in &members {
            let is_setup = event.message_name == "PDUSessionResourceSetupRequest";
            if !is_setup && event.message_name != "PDUSessionResourceReleaseCommand" {
                continue;
            }
            let Some((key, rotation)) = wire_key(event) else {
                continue;
            };
            let provenance = event.packet_references[0]
                .sctp_association
                .as_ref()
                .unwrap();
            let (Some(first_tsn), Some(last_tsn)) = (provenance.first_tsn, provenance.last_tsn)
            else {
                continue;
            };
            // Generations are comparable within one capture/reassembler scope.
            if generations[&(
                event.capture_id.as_str(),
                provenance.association_id.as_str(),
            )]
                .len()
                != 1
            {
                continue;
            }
            let prior_opposite = members.iter().any(|other| {
                other.capture_id == event.capture_id
                    && if is_setup {
                        other.packet_number() > event.packet_number()
                            && other.message_name == "PDUSessionResourceReleaseCommand"
                    } else {
                        other.packet_number() <= event.packet_number()
                            && other.message_name == "PDUSessionResourceSetupRequest"
                    }
            });
            if prior_opposite {
                continue;
            }
            if is_setup {
                if let Some(next_rotation) = rotation.checked_add(1) {
                    setups
                        .entry((key, next_rotation, last_tsn.wrapping_add(1)))
                        .or_default()
                        .push((session, event));
                }
            } else {
                releases.push(((key, rotation, first_tsn), session, event));
            }
        }
    }

    let mut candidates = BTreeSet::new();
    for (wire, successor, release) in releases {
        let Some([(predecessor, setup)]) = setups.get(&wire).map(Vec::as_slice) else {
            continue;
        };
        if predecessor.session_id != successor.session_id && setup.capture_id != release.capture_id
        {
            candidates.insert(SctpContinuityLink {
                predecessor_session_id: predecessor.session_id.clone(),
                successor_session_id: successor.session_id.clone(),
                setup_event_id: setup.event_id.clone(),
                release_event_id: release.event_id.clone(),
            });
        }
    }
    let mut outgoing = BTreeMap::new();
    let mut incoming = BTreeMap::new();
    for link in &candidates {
        *outgoing.entry(&link.predecessor_session_id).or_insert(0) += 1;
        *incoming.entry(&link.successor_session_id).or_insert(0) += 1;
    }
    candidates
        .iter()
        .filter(|link| {
            outgoing[&link.predecessor_session_id] == 1 && incoming[&link.successor_session_id] == 1
        })
        .cloned()
        .collect()
}
