# P2 — Plan usager résumé (`UserPlaneSummary` par UE / PDU session)

**Branche** : `feat/oiran-2.22.0-userplane`
**Base** : `940342f` (polaris-vtap 2.21.5 SIGHUP, oiran-api 2.21.8, live-probe 0.6.4, decoder-gtpu 0.2.1)
**Statut** : audit — aucun code dans ce lot 2.22.0.
**Session de référence** : UE-201 (`5g-session-0bfac1e7ae159a77`, dataset de validation `datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl`).

Ce document répond, dans l'ordre, aux quatre sections demandées sur #9 2026-11-16 :
1. Existant (code + chiffres).
2. Manque fonctionnel pour un résumé plan usager par UE / PDU session.
3. Schéma `UserPlaneSummary` proposé + coût mesuré et projeté.
4. Plan de lots 2.22.0 → 2.22.x avec test de recette par lot.

---

## 1. Existant

### 1.1 Décodeur `decoder-gtpu` (0.2.1, `decoder-gtpu/src/lib.rs`)

Référence : 3GPP TS 29.281 (GTPv1-U). Fichier 469 lignes.

**Parser (`parse`, l. 33) :** lit l'entête fixe 8 oct + extensions optionnelles. Champs exposés via `GtpuHeader` (l. 15-32) :

| Champ | Octets TS 29.281 | Exploité aujourd'hui |
|---|---|---|
| `message_type` (`u8`) | §5.1 | oui (clé N3FlowKey, keepalive classifier) |
| `teid` (`u32`) | §5.1 | oui (clé N3FlowKey, session_identifier) |
| `sequence_number` (`Option<u16>`) | §5.1 S bit | oui (session_identifier volatile, retiré dans l'aggregate) |
| `npdu_number` (`Option<u8>`) | §5.1 PN bit | oui (session_identifier) |
| `extensions` (`Vec<GtpuExtension>`) | §5.2.1 | oui, dont `extension_type = 0x85` PDU Session Container → QFI (parsée par `parse_qfi` côté live-probe) |
| `payload_offset` / `payload_length` | — | oui (pour `inner_ipv4_addresses`) |

**Payload applicatif :** opaque (`// user-plane application payload is not decoded`, l. 126). Seule exception : `inner_ipv4_addresses(payload)` (l. 267-277) extrait **src/dst IPv4 uniquement** quand `payload[0] >> 4 == 4`. Pas de parsing IPv6, pas de ports, pas de protocole L4. Résultat émis en IEs (`inner_source_ip`, `inner_destination_ip`, non pseudonymisés, l. 186-200).

**Résolution de direction :** `infer_direction_from_inner_ipv4` (l. 279-289) utilise les pools lab UE (`10.45.*`, `10.46.*`) ; si ambigu, retombe sur `infer_direction` (l. 290-316) basé sur `source_endpoint.network_function` (gnb/upf/enb/sgw/pgw). Sinon `UNKNOWN`.

### 1.2 Agrégateur N3 (`N3FlowAggregator`, `live-probe/src/lib.rs:279-469`)

**Clé :** `N3FlowKey { message_type, teid, direction }` (l. 279-283). Capacité `MAX_N3_FLOW_AGGREGATES = 4096` (l. 61) ; dépassement → erreur `N3_FLOW_AGGREGATE_CARDINALITY_LIMIT` (l. 371-373).

**Entrée (`observe`, l. 302-379) :**
- extrait `teid` depuis `session_identifiers`, `qfi` depuis l'IE `PDU Session Container` ;
- si `direction == "UNKNOWN"`, tente la résolution post-hoc en cherchant **un et un seul** agrégat déjà présent avec même `(message_type, teid)` et `direction ≠ UNKNOWN` (l. 319-332) — s'il existe, l'event migre et `set_tunnel_direction` est appelé ;
- cumule `packet_count = packet_references.len()` et `wire_bytes = sum(original_length)` (l. 338-343) ;
- si un agrégat `UNKNOWN` existe avec même `(msg_type, teid)` et que l'event courant porte une vraie direction, l'agrégat `UNKNOWN` est **fusionné dans** le nouvel agrégat directionnel (l. 355-366).

**Sortie (`finish`, l. 381-468) :**
- un `NormalizedEvent` par clé `(msg_type, teid, direction)` ;
- `packet_references` réduites à (first, last) ;
- IE émises : `aggregate_packet_count`, `aggregate_wire_bytes`, `aggregate_first_seen_ns`, `aggregate_last_seen_ns` (l. 411-425) ;
- identifier émis : `qfi` (l. 404-410) si extension PDU Session Container présente ;
- `raw_payload_reference = "n3-flow-aggregate:{capture_id}:{teid}:{first_pn}-{last_pn}"` (l. 445-448) ;
- `decoder_name = "live-probe-n3-flow-aggregator"`, `decoder_version = VERSION` (l. 462-463) ;
- `assign_deterministic_id()` (l. 464) → event_id stable réémissable.

### 1.3 Agrégateur keepalive (`KeepaliveAggregator`, `live-probe/src/lib.rs:623-783`)

Classifie et agrège **4 kinds** (`KeepaliveKind`, l. 538-563) :
- `PFCP Heartbeat Request/Response` (N4)
- `Device-Watchdog-Request/Answer` (Diameter)
- `GTPv2 Echo Request/Response` (S11/S5)
- `GTP-U Echo Request/Response` (N3/S1-U)

Clé : `(interface, kind, pair_low, pair_high)` — paire d'adresses canonicalisée `(min, max)` pour fusionner les deux sens. Capacité `MAX_KEEPALIVE_AGGREGATES = 4096` (l. 533). IEs émises : `aggregate_keepalive_kind`, `aggregate_node_pair_low/high`, `aggregate_message_count`, `aggregate_failure_count`, `aggregate_first_packet_number`, `aggregate_last_packet_number`.

**Attention** : GTP-U Echo est détourné hors de `N3FlowAggregator` et donc N'ENTRE PAS dans un hypothétique `UserPlaneSummary` (ce qui est voulu : échec plane de contrôle ≠ débit plan usager).

### 1.4 Publication par session aujourd'hui

Le pipeline live-probe émet, par session publiée :
- `N` events N3 bruts décodés → agrégés en `K` events `live-probe-n3-flow-aggregator` (1 par `(msg_type, teid, direction)`) ;
- `M` events keepalive bruts → agrégés en `L` events `live-probe-keepalive-aggregator` ;
- aucun record spécifique « PDU session ». Le résumé par PDU session doit être reconstruit **côté API** en recollant les 2 aggregates N3 (UL + DL) via le mapping TEID↔PDU session, mapping **absent du modèle** aujourd'hui.

### 1.5 Volume mesuré — dataset de référence UE-201

```bash
python3 -c "
import json, collections
by_proto = collections.Counter()
gtpu_bytes = []; teids = set()
for line in open('datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl'):
    try: d = json.loads(line)
    except: continue
    by_proto[d.get('protocol','?')] += 1
    if d.get('protocol') == 'GTP-U':
        for pr in d.get('packet_references', []):
            gtpu_bytes.append(pr.get('captured_length', 0))
        for si in d.get('session_identifiers', []):
            if si.get('name') == 'teid': teids.add(si.get('value'))
print('BY_PROTO', sorted(by_proto.items(), key=lambda x:-x[1]))
print('GTPU events', len(gtpu_bytes), 'sum_bytes', sum(gtpu_bytes),
      'avg', sum(gtpu_bytes)//len(gtpu_bytes), 'max', max(gtpu_bytes))
print('DISTINCT_TEIDS', sorted(teids))
"
```

Résultat 2026-11-16 :
- `BY_PROTO`: PFCP 30, NGAP 14, NAS-5GMM 10, GTP-U 10.
- GTP-U : **10 events**, 5 UL + 5 DL, **1 300 octets** cumulés wire, moyenne **130 oct**, max **144 oct**.
- TEID distincts : 2 (`0x000096a8` UL, `0x00000003` DL).

Attendu après `N3FlowAggregator` (dataset repoussé en live-probe) : **2 aggregates** (UL + DL), chacun `packet_count=5`, `wire_bytes=650`.

**Projection horaire lab :** si UE-201 soutenait ce débit en continu (débit moyen = 130 oct × 1 pps par sens → trivial), les chiffres restent dérisoires. Un run lab typique (cf. PHASE1-2.md §4.5, 2.19.x) atteint **~1 180 events GTP-U** → après aggregation **~2 records** par PDU session = **~24 oct de résumé** par PDU session (ce qui dit : *les records bruts GTP-U sont le coût, pas le résumé*).

---

## 2. Manque fonctionnel pour un résumé plan usager par UE / PDU session

### 2.1 5-tuple interne après GTP-U

**État :** `decoder-gtpu::inner_ipv4_addresses` récupère src/dst **IPv4 uniquement** (l. 267). Pas de ports, pas de protocole L4, pas d'IPv6.

**Requis :** parser, à partir de `payload[payload_offset..payload_offset + payload_length]` :
- version IP (4 ou 6), protocole (IPv4.protocol ou IPv6.next_header, en traversant hop-by-hop / routing / fragment / destination options jusqu'à TCP=6 / UDP=17 / ICMP) ;
- src/dst IP (v4 ou v6) ;
- src/dst port (TCP/UDP seulement — ICMP n'a pas de port).

**Lien P8 (PHASE1-2.md §4.5, l. 275-377) :** la troncature **128 octets après l'entête GTP-U** définie pour P8 couvre largement IPv4/v6 + TCP/UDP + options SACK/Timestamps. P2 réutilise la **même fenêtre de 128 oct** : jamais de payload applicatif, suffisant pour un 5-tuple + flags TCP + fenêtre. Mutualiser la troncature évite d'avoir deux chemins de capture distincts pour P2 (aujourd'hui `N3FlowAggregator`) et P8 (futur `UserPlaneTcpInnerFlow`).

### 2.2 UL / DL bytes et packets par PDU session (vs. par TEID)

**État :** `N3FlowAggregator` produit **un aggregate par TEID, par direction** (clé l. 279-283). Une PDU session 5G a **deux TEID distincts** (côté gNB et côté UPF) ; côté LTE S1-U, **deux autres** (eNB ↔ S-GW) voire quatre avec S5/S8 (S-GW ↔ P-GW).

**Requis :** une entité « PDU session » qui recolle :
- 5G : `teid_dl` (émis par UPF, reçu côté gNB, DL vu N3) + `teid_ul` (émis par gNB, reçu côté UPF) ;
- LTE S1-U : idem avec `ul_teid_s1` / `dl_teid_s1`.

Le mapping `pdu_session_id ↔ (teid_ul, teid_dl)` est **émis par PFCP** côté N4 (FAR → OuterHeaderCreation avec TEID + UE IP ; PDR → F-TEID local) et **par NGAP** (`PDU Session Resource Setup Request` → F-TEID UPF ; `Setup Response` → F-TEID gNB). **Les deux décodeurs émettent déjà** ces IEs (cf. correlation-engine) ; il manque une table d'index côté live-probe.

### 2.3 Throughput par fenêtre temporelle

**État :** aggregate N3 ne porte que `first_seen_ns` / `last_seen_ns` + total. Pas de bucketisation.

**Requis :** vecteur `bytes_per_window[]` à pas configurable (défaut 1s) indexé depuis `first_seen_ns`, pour UL et DL séparément. Même mécanique que PHASE1-2.md §4.5 pour P8 (`useful_bytes_*_per_second: Vec<u64>`).

**Volume** (cf. §3) : pour une session 60s à fenêtre 1s : 60 × 8 oct × 2 sens = 960 oct de buckets.

### 2.4 QFI / 5QI

**QFI :** déjà émis par `N3FlowAggregator` via l'extension PDU Session Container (l. 311-316, 404-410). **OK en l'état**.

**5QI :** **non présent dans le plan de données**. 5QI est un attribut de QoS Flow négocié en plan de contrôle :
- côté NGAP : `PDU Session Resource Setup Request` → `QoS Flow Setup Request Item` → `QoS Flow Level QoS Parameters` → `5QI` ;
- côté PFCP : `QER` ↔ QFI, puis mapping QFI → 5QI côté SMF.

**Requis :** une table `(pdu_session_id, qfi) → 5qi` alimentée par NGAP au `PDU Session Resource Setup` et consultée au moment du `finish()` du résumé.

### 2.5 Durée, first/last packet

**État :** `aggregate_first_seen_ns`, `aggregate_last_seen_ns`, et `packet_references` réduites à (first, last) sont déjà émises (l. 411-425, 385-400). **OK** — `duration_ns = last - first` est trivialement dérivable, mais à poser explicitement dans le schéma pour clarté catalogue.

### 2.6 Rattachement `(capture_id, seq)` ↔ TEID / SEID / SUPI pseudonymisé

| Rattachement | État | Manque |
|---|---|---|
| `(capture_id, packet_number)` | déjà dans `packet_references` | — |
| ↔ TEID | déjà dans `session_identifiers` de l'aggregate | — |
| ↔ SEID (SMF/UPF) | PFCP uniquement — **absent de l'aggregate N3** | besoin table `teid ↔ seid_smf, seid_upf` alimentée par PFCP Session Establishment Request (F-SEID + F-TEID) et Response (F-SEID réponse) |
| ↔ SUPI pseudonymisé | **aucun rattachement côté N3 aujourd'hui** | besoin chaîne NAS Registration (SUPI → GUTI / 5G-S-TMSI) → NGAP Initial Context Setup (`GUTI → RAN UE NGAP ID + AMF UE NGAP ID`) → NGAP PDU Session Resource Setup (`PDU session id → TEID UPF`). Le `subscriber_pseudonym` (SHA-256 clé `subscriber`) existe côté decoder-sbi (l. 1291-1328) ; il faut le **propager** jusqu'à l'aggregate N3 via la table de corrélation. |

L'aggregate N3 actuel n'a **jamais** de `subscriber_pseudonym`. C'est le principal trou fonctionnel du résumé plan usager.

---

## 3. Schéma `UserPlaneSummary` + coût

### 3.1 Schéma proposé (`event-schema` crate, ajout `types/userplane_summary.rs`)

```rust
pub struct UserPlaneSummary {
    // Identité (jamais en clair)
    pub subscriber_pseudonym: Option<String>,   // SHA-256 clé "subscriber"
    pub pdu_session_id: u8,                     // 0..15 côté NAS 5GMM

    // TEID des deux sens (5G N3). Pour S1-U, utiliser les mêmes champs.
    pub teid_ul: Option<u32>,                   // gNB-side F-TEID (vu côté UPF)
    pub teid_dl: Option<u32>,                   // UPF-side F-TEID (vu côté gNB)

    // SEID N4 (SMF ↔ UPF) via cross-correlation PFCP
    pub seid_smf: Option<u64>,
    pub seid_upf: Option<u64>,

    // QoS Flow
    pub qfi: Option<u8>,                        // depuis GTP-U PDU Session Container
    pub five_qi: Option<u16>,                   // depuis NGAP Setup Request

    // IP UE (pseudonymisées si pool UE connu)
    pub ue_ipv4: Option<String>,
    pub ue_ipv6: Option<String>,

    // Volumes
    pub ul_bytes: u64,
    pub ul_packets: u64,
    pub dl_bytes: u64,
    pub dl_packets: u64,

    // Fenêtre temporelle + ordre canonique
    pub first_capture_id: String,
    pub first_packet_number: u64,
    pub last_capture_id: String,
    pub last_packet_number: u64,
    pub first_seen_ns: i128,
    pub last_seen_ns: i128,
    pub duration_ns: i128,                      // dérivé (last - first)

    // Throughput par fenêtre 1s (indexé depuis first_seen_ns)
    pub ul_bytes_per_window: Vec<u64>,
    pub dl_bytes_per_window: Vec<u64>,
    pub window_ns: i128,                        // 1_000_000_000 par défaut
}
```

**Invariants :**
- Aucune identité en clair : `subscriber_pseudonym` est le hash SHA-256 clé `subscriber` déjà utilisé par `decoder-sbi::uri_subscriber_pseudonym` (l. 1291). Jamais de SUPI/IMSI brut dans ce record ni dans les logs.
- Ordre canonique strict `(capture_id, packet_number)` sur les bornes. `duration_ns` est dérivé des `timestamp_ns`, **affichage uniquement**, jamais utilisé comme clé.
- Les buckets `*_bytes_per_window` sont dimensionnés `ceil((last_seen - first_seen) / window_ns)`. Pour une session de 60s à `window_ns = 1_000_000_000` → 60 entrées × 8 oct × 2 sens = **960 oct**.

### 3.2 Coût mesuré et projeté

Base de calcul : mêmes commandes et dataset que PHASE1-2.md §4.5 ; cardinalité session réelle issue de UE-201 et des runs lab antérieurs.

**Taille d'un record `UserPlaneSummary` (session 60s) :**
- Partie fixe : ~240 octets (ids, u64, u32, i128).
- Buckets throughput 60s × 1s × 2 sens × 8 oct = 960 octets.
- `subscriber_pseudonym` + `ue_ipv4` + `ue_ipv6` : ~80 octets.
- **Total ≈ 1.3 KiB par PDU session.**

**Cardinalité :**

| Échelle | PDU sessions actives concurrentes | Hypothèse |
|---|---|---|
| Lab UE-201 (dataset référence) | 1 | run ciblé mono-UE |
| Lab multi-UE (CI charge) | ~50 | rythme NAS registration lab |
| Champ 1 Gbit/s | ~5 000 | 1 session active par 100 kbps moyen |
| **PRO 400 Gbit/s (projection)** | **~20 000** | reprend hypothèse PHASE1-2 §4.5 |

**Coût RAM (par sonde) :**
- Lab : 50 × 1.3 KiB = **65 KiB** — négligeable.
- 400G : 20 000 × 1.3 KiB = **~25 MiB** — acceptable.

**Coût disque (par sonde, par jour) :** hypothèse récompaction en fin de session + rétention `UserPlaneSummary` seule (pas les events N3 bruts, qui sont supprimés après `N3FlowAggregator::finish`).
- Lab : 50 sessions × 24 h / (60s session moyenne) × 1.3 KiB ≈ **90 MiB/jour** si sessions courtes. Si sessions typiquement longues (10 min) : 50 × 144 × 1.3 KiB = **9 MiB/jour**.
- 400G : 20 000 × 144 × 1.3 KiB = **~3.6 GiB/jour** par sonde — rétention explicite requise (ex: 7 jours glissant = ~25 GiB).

**Comparaison P2 / P8 :** `UserPlaneSummary` (P2) est **3× plus petit par flux** que `UserPlaneTcpInnerFlow` (P8, ~1.2 KiB) mais **moins nombreux** : 1 record par PDU session vs. 1 record par 5-tuple interne. L'ordre de grandeur disque reste équivalent (quelques GiB/jour à 400G) ; **mutualiser la troncature 128 oct entre P2 et P8** évite de doubler le coût CPU côté sonde.

---

## 4. Plan de lots proposé

Chaque lot ci-dessous = une version patch, CHANGELOG + audit lock + test de recette. Aucun code dans ce lot 2.22.0 (ce document est le livrable 2.22.0).

| Lot | Version API | Crates touchés | Contenu | Test de recette |
|---|---|---|---|---|
| **2.22.0** (ce livrable) | oiran-api 2.22.0 | — | Audit + design (ce document). CHANGELOG mentionnant le design, pas de code d'agrégation. | Document relu + validation Sadok sur chiffres et schéma. |
| **2.22.1** — inner 5-tuple | oiran-api 2.22.1, decoder-gtpu 0.3.0 | `decoder-gtpu` | Étendre `inner_ipv4_addresses` → `inner_five_tuple` (IPv4 **+ IPv6** + proto + ports TCP/UDP). Troncature stricte 128 oct après entête GTP-U (partagée avec P8). Émettre IEs `inner_src_port`, `inner_dst_port`, `inner_l4_proto`, `inner_ip_version`. | Sur dataset UE-201 : 10 G-PDU → 10 events avec `inner_l4_proto = 17` (UDP ICMP typique en lab) ou `6` (TCP) selon trafic lab. Jamais d'octet au-delà de `payload_offset + 128`. Test unitaire IPv6 + extension headers. |
| **2.22.2** — table corrélation TEID↔SEID↔SUPI | oiran-api 2.22.2, correlation-engine | `correlation-engine`, `live-probe` | Module `userplane_index` : table indexée par TEID (UL + DL), peuplée par PFCP Session Establishment (TEID↔SEID) et NGAP PDU Session Resource Setup (TEID↔pdu_session_id↔RAN/AMF UE NGAP ID↔subscriber_pseudonym via chaîne NAS Initial Registration). Lookup O(1) à `N3FlowAggregator::observe`. | Sur UE-201 : lookup `teid=0x000096a8` → `subscriber_pseudonym` non vide, `pdu_session_id = 1` (ou valeur observée), `seid_smf` / `seid_upf` tous deux non vides. Test échec propre : TEID inconnu → `None` + event structuré `USERPLANE_INDEX_MISS` (dédupé par TEID). |
| **2.22.3** — `UserPlaneSummary` struct + agrégateur | oiran-api 2.22.3, event-schema 1.9.0, live-probe 0.7.0 | `event-schema`, `live-probe` | Ajouter `UserPlaneSummary` au schéma. Nouvel agrégateur `UserPlaneSummaryAggregator` qui consomme les sorties de `N3FlowAggregator` + la table corrélation, recolle UL/DL par `(subscriber_pseudonym, pdu_session_id)`, émet 1 record par PDU session. `N3FlowAggregator` reste en place pour la vue par-TEID (compat). | Sur UE-201 : 10 G-PDU → 1 `UserPlaneSummary` avec `ul_packets=5, ul_bytes=650, dl_packets=5, dl_bytes=650`, `subscriber_pseudonym` non vide, `qfi` extrait de l'extension. Test cardinalité : 4096 PDU sessions simultanées → `USERPLANE_SUMMARY_CARDINALITY_LIMIT` émis, pas de panique. |
| **2.22.4** — buckets throughput | oiran-api 2.22.4, live-probe 0.7.1 | `live-probe` | Calcul `ul_bytes_per_window` / `dl_bytes_per_window` au fil de `observe` (pas de rework complet au `finish`). Fenêtre 1s par défaut, configurable via `polaris.toml` section `[userplane] window_ns`. | Test unitaire : séquence 5 UL + 5 DL espacés de 500ms sur 2s → 2 buckets UL × ~325 oct, 2 buckets DL × ~325 oct. Test live : stream 100 pps × 5s → vecteurs à 5 entrées, somme = total. |
| **2.22.5** — route API + colonnes catalogue | oiran-api 2.22.5 | `oiran-api`, `callflow-schema` | Route `GET /sessions/{session_id}/userplane/summary` → JSON `UserPlaneSummary[]` (une entrée par PDU session dans la session). Colonnes `catalog` ajoutées : `ul_bytes`, `dl_bytes`, `qfi`, `five_qi`, `duration_ms`. Filter engine : critère `pdu_session_id`, `qfi` numérique. | Test intégration UE-201 : `curl .../sessions/5g-session-0bfac1e7ae159a77/userplane/summary` → JSON non vide, `ul_bytes` + `dl_bytes` = 1300. Catalog `/sessions/catalog` expose les 5 nouvelles colonnes. |

**Chemin critique :** 2.22.1 → 2.22.2 → 2.22.3 sont séquentiels (chaque lot consomme le précédent). 2.22.4 et 2.22.5 peuvent se faire en parallèle après 2.22.3.

---

## OUVERTS (à trancher avant implémentation)

- **OP2.1** — Troncature 128 oct partagée avec P8 : décision confirmée (mutualisation). Mais la **position** de la troncature (sonde vs. decoder) impacte le disque PCAP : si on tronque **côté sonde** (BPF filter / tc-bpf) le PCAP sur disque est déjà réduit ; si on tronque **côté decoder**, le PCAP reste full-size mais l'event est tronqué. Préférence Sadok à confirmer — par défaut je propose **côté sonde** (réduit I/O 400G).
- **OP2.2** — Pseudonymisation `ue_ipv4` / `ue_ipv6` : pseudo si IP UE connue (via pool `10.45.*` / `10.46.*` ou via N4 UE IP address), clair sinon (serveur applicatif externe). Règle à valider explicitement.
- **OP2.3** — Fenêtre throughput par défaut 1s : OK pour lab, mais à 400G un bucket 1s × 20 000 sessions = **~160 KiB/s** de buckets à écrire. Alternative : fenêtre 5s par défaut en prod (= **32 KiB/s**). Configurable `polaris.toml`.
- **OP2.4** — Rétention `UserPlaneSummary` : à 400G, ~3.6 GiB/jour par sonde. Rétention 7 j glissante proposée, pas implémentée dans ce plan — à ajouter en 2.22.6 si Sadok confirme.
- **OP2.5** — LTE S1-U : les lots 2.22.1-5 cible 5G N3 d'abord. L'extension LTE (`teid_ul_s1` / `teid_dl_s1`) est triviale car le TEID est 32-bit dans les deux cas, mais le mapping `teid ↔ subscriber_pseudonym` passe par **S11** (SGW ↔ MME) et non N4/NGAP. À faire en 2.22.6 ou 2.23.x selon priorité.
- **OP2.6** — Coexistence avec P8 `UserPlaneTcpInnerFlow` : P2 émet 1 record par PDU session, P8 1 record par 5-tuple interne. L'API doit exposer les deux sans confusion. Nom de champs `tcp_perf` (P8) vs. `summary` (P2) clair.

---

## Références

- `decoder-gtpu/src/lib.rs` (0.2.1, 469 lignes).
- `live-probe/src/lib.rs` (0.6.4) : `N3FlowAggregator` (l. 279-469), `KeepaliveAggregator` (l. 623-783).
- `decoder-sbi/src/lib.rs` : `uri_subscriber_pseudonym` (l. 1291-1328) — modèle de pseudonymisation SHA-256 clé `subscriber` réutilisé ici.
- `docs/architecture/PHASE1-2.md` §4.5 (l. 275-377) : Préparation PHASE P8 — troncature 128 oct partagée.
- Session de référence : UE-201, dataset `datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl`.
- 3GPP TS 29.281 (GTPv1-U), TS 29.244 (PFCP N4), TS 38.413 (NGAP), TS 24.501 (NAS 5GMM/5GSM).

---

**Statut livrable 2.22.0 :** audit terminé. Prochaine action : validation Sadok avant 2.22.1 (code inner 5-tuple).
