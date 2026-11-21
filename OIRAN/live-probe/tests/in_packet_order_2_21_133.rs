//! POLARIS 2.21.133 (ordre #9 7060289296) — ordre et clé des events d'un
//! même paquet, sur captures Open5GS réelles du dépôt.
//!
//! Un paquet NGAP / S1AP qui porte un message NAS produit deux events : le
//! parent, puis l'enfant (`parent_event_id`). Jusqu'en 2.21.132 :
//!   * l'ordre publié départageait les deux par `event_id`, un hachage :
//!     l'enfant passait avant son parent une fois sur deux ;
//!   * la clé `stable_event_key` dérivée à la lecture pour un event stocké
//!     sans clé numérotait dans l'ordre du fichier : sur un stockage trié,
//!     elle n'égalait pas la clé du décodeur.
//!
//! Gate : sur `multi-imsi.pcap` (cinq abonnés, 522 events N2 + N4 + SBI),
//! clé dérivée = clé du décodeur pour 522 / 522 dans trois ordres de
//! stockage et pour trois `capture_id`, et 0 couple enfant avant parent sur
//! 58 ; découverte des sessions indépendante du `capture_id` sur toutes les
//! captures 5G du dépôt.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use event_schema::NormalizedEvent;
use serde_json::Value;
use session_engine::EventRecord;

fn repo_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(relative)
}

fn multi_imsi() -> PathBuf {
    repo_file("benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus/LAB_TESTBED/multi-imsi.pcap")
}

fn capture_id(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

/// Décode un fichier sur les plans donnés, comme l'import continu :
/// `stable_source_file` = nom du fichier, donc le décodeur pose la clé.
fn decode(path: &Path, planes: &[&str], capture: &str) -> Vec<NormalizedEvent> {
    let key = event_schema::PseudonymKey::from_bytes([7; 32]);
    let mut events = Vec::new();
    for plane in planes {
        let config = oiran_decode::DecodeConfig {
            input: path.to_path_buf(),
            capture_id: capture.to_owned(),
            interface: (*plane).to_owned(),
            endpoints: Default::default(),
            stable_source_file: path.file_name().unwrap().to_string_lossy().into_owned(),
        };
        oiran_decode::decode_capture_streaming(&config, &key, |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
    }
    events
}

/// L'event tel qu'un dataset d'avant 2.21.91 le stocke : sans clé.
fn stored_without_key(event: &NormalizedEvent) -> Value {
    let mut value: Value = serde_json::from_str(&event.to_json()).unwrap();
    value.as_object_mut().unwrap().remove("stable_event_key");
    value
}

fn load(values: &[Value]) -> Vec<EventRecord> {
    let jsonl = values.iter().map(Value::to_string).collect::<Vec<_>>().join("\n");
    session_engine::load_jsonl(std::io::Cursor::new(jsonl.into_bytes())).unwrap()
}

fn packet_of(event: &NormalizedEvent) -> u64 {
    event.packet_references.first().map(|p| p.packet_number).unwrap_or(0)
}

/// Trois ordres de stockage : celui du décodeur, l'ordre canonique d'avant
/// 2.21.133 (`capture_id`, paquet, `event_id`), l'ordre du ladder d'avant
/// 2.21.133 (horodatage, paquet, `event_id`).
fn storage_orders(events: &[NormalizedEvent]) -> Vec<(&'static str, Vec<NormalizedEvent>)> {
    let mut canonical = events.to_vec();
    canonical.sort_by(|a, b| {
        (a.capture_id.as_str(), packet_of(a), a.event_id.as_str())
            .cmp(&(b.capture_id.as_str(), packet_of(b), b.event_id.as_str()))
    });
    let mut ladder = events.to_vec();
    ladder.sort_by(|a, b| {
        (a.timestamp.seconds, a.timestamp.nanoseconds, packet_of(a), a.event_id.as_str())
            .cmp(&(b.timestamp.seconds, b.timestamp.nanoseconds, packet_of(b), b.event_id.as_str()))
    });
    vec![
        ("ordre du décodeur", events.to_vec()),
        ("ancien ordre canonique", canonical),
        ("ancien ordre du ladder", ladder),
    ]
}

fn parents(events: &[NormalizedEvent]) -> BTreeMap<String, String> {
    events
        .iter()
        .filter_map(|e| e.parent_event_id.clone().map(|p| (e.event_id.clone(), p)))
        .collect()
}

/// Nombre de couples (enfant, parent) où l'enfant précède son parent dans
/// `order`, et nombre de couples présents.
fn inversions(order: &[&str], parents: &BTreeMap<String, String>) -> (usize, usize) {
    let position: BTreeMap<&str, usize> = order.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    let mut pairs = 0;
    let mut inverted = 0;
    for (child, parent) in parents {
        if let (Some(c), Some(p)) = (position.get(child.as_str()), position.get(parent.as_str())) {
            pairs += 1;
            if c < p {
                inverted += 1;
            }
        }
    }
    (inverted, pairs)
}

#[test]
fn read_time_key_equals_the_decoder_key_whatever_the_storage_order_2_21_133() {
    for fill in ['a', 'b', 'c'] {
        let events = decode(&multi_imsi(), &["N2", "N4", "SBI"], &capture_id(fill));
        assert_eq!(events.len(), 522, "capture réelle : 522 events N2 + N4 + SBI");
        let decoder_key: BTreeMap<&str, &str> = events
            .iter()
            .map(|e| (e.event_id.as_str(), e.stable_event_key.as_str()))
            .collect();
        assert!(decoder_key.values().all(|k| !k.is_empty()), "le décodeur pose toutes les clés");

        // Paquets SCTP qui groupent plusieurs NGAP, chacun avec son NAS :
        // rien dans un event stocké ne dit dans quel ordre le décodeur les
        // a émis (pas de décalage d'octets sur le NGAP, la référence de
        // payload est un hachage). Leur numérotation ne peut être exacte
        // que si le stockage a gardé l'ordre du décodeur. OUVERT, compté.
        let mut roots_per_packet: BTreeMap<String, usize> = BTreeMap::new();
        let packet_key = |e: &NormalizedEvent| {
            let r = e.packet_references.first().unwrap();
            event_schema::packet_lookup_key(&r.source_file, r.interface_id, r.packet_number, r.byte_offset)
        };
        for event in events.iter().filter(|e| e.parent_event_id.is_none()) {
            *roots_per_packet.entry(packet_key(event)).or_default() += 1;
        }
        let bundled: BTreeSet<&str> = events
            .iter()
            .filter(|e| roots_per_packet.get(&packet_key(e)).is_some_and(|n| *n > 1))
            .map(|e| e.event_id.as_str())
            .collect();
        let bundled_packets = roots_per_packet.values().filter(|n| **n > 1).count();
        assert_eq!((bundled_packets, bundled.len()), (5, 20), "5 paquets SCTP à deux NGAP + NAS");

        for (label, stored) in storage_orders(&events) {
            let records = load(&stored.iter().map(stored_without_key).collect::<Vec<_>>());
            let equal = |r: &&EventRecord| decoder_key[r.event_id.as_str()] == r.stable_event_key;
            let outside = records.iter().filter(|r| !bundled.contains(r.event_id.as_str()));
            let inside = records.iter().filter(|r| bundled.contains(r.event_id.as_str()));
            let (outside_total, outside_equal) = (outside.clone().count(), outside.filter(equal).count());
            let inside_equal = inside.filter(equal).count();
            println!(
                "capture {fill}, {label} : clé dérivée = clé du décodeur {} / 522 \
                 (hors paquets groupés {outside_equal} / {outside_total}, dans les paquets groupés {inside_equal} / 20)",
                outside_equal + inside_equal
            );
            assert_eq!(outside_equal, outside_total, "capture {fill}, {label} : hors paquets groupés");
            if label == "ordre du décodeur" {
                assert_eq!(inside_equal, 20, "capture {fill} : ordre du décodeur gardé");
            }
            // Dans un paquet groupé, chaque NAS reste numéroté après son NGAP.
            for record in records.iter().filter(|r| bundled.contains(r.event_id.as_str())) {
                if let Some(parent) = &record.parent_event_id {
                    let parent = records.iter().find(|r| &r.event_id == parent).unwrap();
                    assert!(
                        session_engine::emission_ordinal(&parent.stable_event_key)
                            < session_engine::emission_ordinal(&record.stable_event_key),
                        "capture {fill}, {label} : NAS numéroté après son NGAP"
                    );
                }
            }
        }

        // Callflow stocké dans l'ordre d'affichage d'avant 2.21.133.
        let (_, ladder) = storage_orders(&events).remove(2);
        let mut callflow = serde_json::json!({
            "events": ladder.iter().map(stored_without_key).collect::<Vec<_>>()
        });
        let (patched, skipped) = event_schema::backfill_stable_event_keys_in_callflow(&mut callflow);
        assert_eq!((patched, skipped), (522, 0));
        let mut outside_equal = 0;
        let mut inside_equal = 0;
        for v in callflow["events"].as_array().unwrap() {
            let id = v["event_id"].as_str().unwrap();
            if decoder_key[id] == v["stable_event_key"].as_str().unwrap() {
                if bundled.contains(id) {
                    inside_equal += 1;
                } else {
                    outside_equal += 1;
                }
            }
        }
        println!(
            "capture {fill}, callflow dans l'ordre du ladder : {} / 522 (hors paquets groupés {outside_equal} / 502)",
            outside_equal + inside_equal
        );
        assert_eq!(outside_equal, 502, "capture {fill}, callflow : hors paquets groupés");
    }
}

#[test]
fn no_child_before_its_parent_in_published_order_2_21_133() {
    for fill in ['a', 'b', 'c'] {
        let events = decode(&multi_imsi(), &["N2", "N4", "SBI"], &capture_id(fill));
        let parents = parents(&events);
        assert_eq!(parents.len(), 58, "58 couples parent / enfant dans la capture");
        for (label, stored) in storage_orders(&events) {
            // Event stocké avec sa clé (2.21.91 et après) et sans (avant).
            for with_key in [true, false] {
                let values: Vec<Value> = stored
                    .iter()
                    .map(|e| {
                        if with_key {
                            serde_json::from_str(&e.to_json()).unwrap()
                        } else {
                            stored_without_key(e)
                        }
                    })
                    .collect();
                // `load_jsonl` rend l'ordre canonique (`deterministic_sort`).
                let records = load(&values);
                let order: Vec<&str> = records.iter().map(|r| r.event_id.as_str()).collect();
                assert_eq!(
                    inversions(&order, &parents),
                    (0, 58),
                    "capture {fill}, {label}, clé stockée {with_key} : ordre canonique"
                );
                // Callflow 5G : `reconstruct` puis `build_callflow`.
                let reconstruction =
                    session_engine::reconstruct(records.clone(), Default::default());
                let flow = callflow_schema::build_callflow(&reconstruction, vec![]);
                let order: Vec<&str> = flow.events.iter().map(|e| e.event_id.as_str()).collect();
                let (inverted, pairs) = inversions(&order, &parents);
                assert_eq!(inverted, 0, "capture {fill}, {label} : callflow ({pairs} couples)");
            }
        }
    }
}

/// Résumé de la découverte des sessions, indépendant des `event_id` (qui
/// dépendent du `capture_id`) : chaque event est désigné par plan, paquet,
/// protocole et message.
fn discovery_digest(records: &[EventRecord]) -> String {
    let ident: BTreeMap<&str, String> = records
        .iter()
        .map(|r| {
            (
                r.event_id.as_str(),
                format!("{}#{}#{}#{}", r.interface, r.packet_number(), r.protocol, r.message_name),
            )
        })
        .collect();
    let members = |ids: &[String]| {
        let mut v: Vec<&str> = ids.iter().filter_map(|id| ident.get(id.as_str()).map(String::as_str)).collect();
        v.sort_unstable();
        v.join(";")
    };
    let mut owned = records.to_vec();
    let discovery = session_engine::discover_sessions(&mut owned);
    let mut lines: Vec<String> = Vec::new();
    for c in &discovery.ue_contexts {
        lines.push(format!(
            "ctx {:?} {:?} {} {} [{}]",
            c.amf_ue_ngap_id, c.ran_ue_ngap_id, c.state, c.lifecycle_generation, members(&c.event_ids)
        ));
    }
    for s in &discovery.pdu_sessions {
        lines.push(format!(
            "pdu {} {} {} [{}] [{}]",
            s.pdu_session_id,
            s.state,
            s.correlation_status,
            members(&s.event_ids),
            members(&s.sbi_time_window_event_ids)
        ));
    }
    for p in &discovery.pfcp_sessions {
        lines.push(format!("pfcp {:?} {} {}", p.seids, p.upf_endpoint, p.state));
    }
    for p in &discovery.procedures {
        lines.push(format!(
            "proc {} {} {:?} [{}]",
            p.procedure_type,
            p.result,
            p.pdu_session_id,
            members(&p.event_ids)
        ));
    }
    lines.push(format!(
        "unmatched {} background {}",
        discovery.unmatched_event_ids.len(),
        discovery.background_event_ids.len()
    ));
    lines.sort_unstable();
    event_schema::sha256_hex(lines.join("\n").as_bytes())
}

fn five_g_captures() -> Vec<(&'static str, Vec<(PathBuf, Vec<&'static str>)>)> {
    let merged = |name: &str| vec![(repo_file(&format!("benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus/LAB_TESTBED/{name}")), vec!["N2", "N4", "SBI"])];
    let per_plane = |dir: &str, ext: &str| {
        ["N2", "N3", "N4"]
            .iter()
            .map(|plane| (repo_file(&format!("{dir}/{plane}.{ext}")), vec![*plane]))
            .collect::<Vec<_>>()
    };
    vec![
        ("multi-imsi", merged("multi-imsi.pcap")),
        ("5gc-e2e", merged("5gc-e2e.pcap")),
        ("5gc-registration", merged("5gc-registration.pcap")),
        ("ki-mismatch", merged("ki-mismatch.pcap")),
        ("supi-not-provisioned", merged("supi-not-provisioned.pcap")),
        ("unknown-dnn", merged("unknown-dnn.pcap")),
        ("userplane", merged("userplane.pcap")),
        ("OIRAN_A", per_plane("benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus/OIRAN_A", "pcapng")),
        ("OIRAN_B", per_plane("benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus/OIRAN_B", "pcap")),
        ("OIRAN_5G_PDU_SESSION_DATA_V1", per_plane("datasets/OIRAN_5G_PDU_SESSION_DATA_V1", "pcapng")),
    ]
}

#[test]
fn session_discovery_does_not_depend_on_the_capture_id_2_21_133() {
    for (name, files) in five_g_captures() {
        let mut digests = BTreeSet::new();
        let mut sizes = BTreeSet::new();
        for fill in ['a', 'b', 'c'] {
            let mut events = Vec::new();
            for (path, planes) in &files {
                // Même `capture_id` pour les plans d'une capture : seul ce
                // qui change d'une passe à l'autre est le `capture_id`.
                events.extend(decode(path, planes, &capture_id(fill)));
            }
            let records = load(&events.iter().map(stored_without_key).collect::<Vec<_>>());
            sizes.insert(records.len());
            digests.insert(discovery_digest(&records));
        }
        println!("découverte {name} : events={sizes:?} empreinte={digests:?}");
        assert_eq!(digests.len(), 1, "{name} : découverte indépendante du capture_id");
    }
}


