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

**Statut** : les chiffres par scénario ci-dessous sont **HYPOTHÈSES** (étiquetés explicitement), pas des mesures. La mesure réelle viendra du bench O1 (section « Validation ») et sera substituée à la projection quand disponible. Correction C1 appliquée (#9 6927882355).

**Taille d'un record `UserPlaneSummary` (session 60s)** — mesurable par `sizeof` dans le lot 2.22.3 :
- Partie fixe : ~240 octets (ids, u64, u32, i128).
- Buckets throughput 60s × 1s × 2 sens × 8 oct = 960 octets.
- `subscriber_pseudonym` + `ue_ipv4` + `ue_ipv6` : ~80 octets.
- **Total ≈ 1.3 KiB par PDU session.**

**Formule de cardinalité :**

```
sessions_actives ≈ débit_total / débit_moyen_par_session
```

**HYPOTHÈSE 1** — débit moyen 100 kbit/s par session (lab, IoT, voix) :

| Échelle | Débit total | Sessions actives (H1) | RAM (× 1.3 KiB) | Disque/jour (compact fin de session, 144 sess./jour) |
|---|---|---|---|---|
| Lab UE-201 (dataset référence) | — | 1 (mesuré) | 1.3 KiB | 0.2 KiB |
| Lab multi-UE (CI charge) | ~10 Mbit/s | ~100 | 130 KiB | ~19 MiB |
| 1 Gbit/s | 1 Gbit/s | ~10 000 | ~12.7 MiB | ~1.9 GiB |
| **400 Gbit/s** | 400 Gbit/s | **~4 000 000** | **~5 GiB** | **~720 GiB** |

**HYPOTHÈSE 2** — débit moyen 1 Mbit/s par session (prod mixte streaming/web) :

| Échelle | Débit total | Sessions actives (H2) | RAM | Disque/jour |
|---|---|---|---|---|
| 1 Gbit/s | 1 Gbit/s | ~1 000 | ~1.3 MiB | ~190 MiB |
| **400 Gbit/s** | 400 Gbit/s | **~400 000** | **~508 MiB** | **~73 GiB** |

**HYPOTHÈSE 3** — débit moyen 10 Mbit/s par session (prod streaming lourd) :

| Échelle | Débit total | Sessions actives (H3) | RAM | Disque/jour |
|---|---|---|---|---|
| 1 Gbit/s | 1 Gbit/s | ~100 | ~130 KiB | ~19 MiB |
| **400 Gbit/s** | 400 Gbit/s | **~40 000** | **~51 MiB** | **~7.3 GiB** |

**Conséquences :**
- RAM : entre 51 MiB (H3) et 5 GiB (H1) à 400G. **H1 est la borne haute** : si le mix réel se révèle proche de H1, la rétention mémoire devient **le dimensionneur critique**, et l'éviction sur événement (cf. C2 §4.3) devient obligatoire — pas optionnelle.
- Disque : entre 7 GiB (H3) et 720 GiB (H1) par jour par sonde. **La rétention 7 j glissante** de l'OP2.4 va de 50 GiB (H3) à **5 TiB** (H1) — à dimensionner avec le mix mesuré.
- **La commande réelle de mesure du mix débit/session** sera le bench O1 : voir §5.

**Disclaimer** : les trois hypothèses ci-dessus sont des **ordres de grandeur**. Aucun chiffre 400G n'est mesuré dans le lot 2.22.0. Toute décision de rétention/mémoire sera prise **après** bench O1 avec le mix réel.

**Comparaison P2 / P8 :** `UserPlaneSummary` (P2) fait ~1.3 KiB par record, `UserPlaneTcpInnerFlow` (P8) ~1.2 KiB par record ; **cardinalités différentes** (1 record par PDU session vs. 1 record par 5-tuple interne, typiquement 10-100 flux par session). P8 sera donc beaucoup plus volumineux. **Mutualiser la troncature 128 oct côté sonde** (OP2.1 tranché) évite de doubler le coût CPU et I/O.

---

## 4. Plan de lots proposé

Chaque lot ci-dessous = une version patch, CHANGELOG + audit du lock + test de recette.

### 4.1 Vue d'ensemble

| Lot | Version API | Crates touchés | Contenu | Test de recette |
|---|---|---|---|---|
| **2.22.0** | oiran-api 2.22.0 | — | Audit + design (ce document). | Document relu + validation Sadok (fait #9 6927882355). |
| **2.22.1** — inner 5-tuple + snaplen sonde | oiran-api 2.22.1, decoder-gtpu 0.3.0 | `decoder-gtpu`, `live-probe` (config polaris.toml) | Étendre `inner_ipv4_addresses` → `parse_inner_five_tuple` : IPv4 **+ IPv6** + proto L4 + ports TCP/UDP, traversée des extension headers IPv6 (hop-by-hop, routing, fragment, destination options). Troncature **côté sonde** via snaplen BPF configuré dans `polaris.toml [userplane] snaplen_n3_bytes` (défaut 128 après entête GTP-U). Émettre IEs `inner_src_port`, `inner_dst_port`, `inner_l4_proto`, `inner_ip_version`. | Sur dataset dépôt (10 G-PDU) ET session lab `5g-session-0bfac1e7ae159a77` (via ANR2 sous LAB_LOCK) : 10 G-PDU → 10 events avec `inner_l4_proto`, `inner_src_port`, `inner_dst_port`, `inner_ip_version` renseignés. Test unitaire IPv4+TCP, IPv4+UDP, IPv6+TCP, IPv6+UDP, IPv6+hop-by-hop. **Test dédié volumes** : un event avec `captured_length=128` mais `original_length=1500` contribue `1500` à `aggregate_wire_bytes` (jamais `128`). |
| **2.22.2** — table corrélation TEID↔SEID↔SUPI (multi-source) | oiran-api 2.22.2, correlation-engine | `correlation-engine`, `live-probe` | Module `userplane_index` : table indexée par TEID (UL + DL). **Sources primaires** : SBI `Nsmf_PDUSession CreateSMContext` (supi + pduSessionId + n2SmInfo, visible via vTAP TLS), PFCP Session Establishment Req/Resp (SEID + F-TEID + UE IP), NGAP PDU Session Resource Setup (F-TEID gNB + 5QI). **Source secondaire marquée** : NAS Registration (SUPI → GUTI). Chaque entrée porte un champ `source_kind` (`sbi` / `pfcp` / `ngap` / `nas_cleartext`). Lookup O(1) à `N3FlowAggregator::observe`. | Sur UE-201 ET session lab : lookup `teid=0x000096a8` doit renvoyer `subscriber_pseudonym` non vide. Montrer les 2 sources : (a) SBI primary (supi extrait du body CreateSMContext) et (b) NAS secondary (compare qu'elles concordent quand le NAS est en clair ; si NEA0 lab). Test miss propre : TEID inconnu → event `USERPLANE_INDEX_MISS` dédupé par `(teid, direction)`. |
| **2.22.3** — `UserPlaneSummary` struct + agrégateur « fermeture sur événement » | oiran-api 2.22.3, event-schema 1.9.0, live-probe 0.7.0 | `event-schema`, `live-probe` | Ajouter `UserPlaneSummary` au schéma. Nouvel agrégateur `UserPlaneSummaryAggregator` consommant `N3FlowAggregator` + table corrélation, clé `(subscriber_pseudonym, pdu_session_id)`. **Fermeture sur événement**, **pas** en fin de fichier : (a) PFCP Session Deletion Request/Response, (b) NGAP PDU Session Resource Release Command/Response, (c) inactivité configurable `polaris.toml [userplane] inactivity_timeout_ns` (défaut 300s). **Cardinalité bornée par mémoire** avec éviction ordonnée LRU et événement structuré `USERPLANE_SUMMARY_EVICTED` (jamais erreur bloquante). `N3FlowAggregator` reste en place pour vue par-TEID. | Sur UE-201 : 10 G-PDU + NGAP Release → 1 `UserPlaneSummary` avec `ul_packets=5, ul_bytes=650, dl_packets=5, dl_bytes=650`, `subscriber_pseudonym` non vide, `qfi` extrait. Test éviction : charger mem limit → N+1-ème session évicte la plus ancienne → event `USERPLANE_SUMMARY_EVICTED` avec `(teid_ul, teid_dl, reason=memory_pressure)`, zéro panique. Test rejoué sur session lab `5g-session-0bfac1e7ae159a77`. |
| **2.22.4** — buckets throughput | oiran-api 2.22.4, live-probe 0.7.1 | `live-probe` | Calcul `ul_bytes_per_window` / `dl_bytes_per_window` au fil de `observe`. Fenêtre 1s par défaut, configurable via `polaris.toml [userplane] window_ns`. Recommandation prod : 5s. | Séquence 5 UL + 5 DL espacés 500ms sur 2s → 2 buckets UL + 2 buckets DL. Live stream 100 pps × 5s → vecteurs à 5 entrées, somme = total. |
| **2.22.5** — route API + colonnes catalogue | oiran-api 2.22.5 | `oiran-api`, `callflow-schema` | Route `GET /sessions/{session_id}/userplane/summary` → JSON `UserPlaneSummary[]`. Colonnes catalogue : `ul_bytes`, `dl_bytes`, `qfi`, `five_qi`, `duration_ms`. Filter : critère `pdu_session_id`, `qfi` numérique. Note P8 : route distincte `GET /sessions/{id}/userplane/tcp_perf` (hors scope 2.22.x). | Intégration UE-201 : `curl .../userplane/summary` → JSON conforme, `ul_bytes + dl_bytes = 1300`. Catalog expose les 5 colonnes. |
| **2.22.6** — rétention 7 j glissante | oiran-api 2.22.6 | `oiran-api`, `live-probe` | Rétention `UserPlaneSummary` : 7 jours glissant par défaut, configurable `polaris.toml [userplane] retention_days`. | Dataset synthétique 10 jours → à T+8j, les records du jour T sont supprimés, record de T+1 préservé. |

**Chemin critique :** 2.22.1 → 2.22.2 → 2.22.3 séquentiels. 2.22.4, 2.22.5 parallèles après 2.22.3. 2.22.6 indépendant, planifiable après 2.22.5.

### 4.2 Correction C1 — chiffres 400G étiquetés HYPOTHÈSE

Le §3.2 ci-dessus a été mis à jour (correction #9 6927882355) : trois scénarios H1/H2/H3 avec formule explicite `sessions = débit / débit_moyen`. Aucun chiffre 400G n'est présenté comme mesuré. La mesure réelle viendra du **bench O1** (section §5).

### 4.3 Correction C2 — fermeture sur événement, pas en fin de fichier

Le plafond `MAX_N3_FLOW_AGGREGATES = 4096` et l'émission au `finish()` ne passent pas à l'échelle en flux continu (correction #9 6927882355). Le lot 2.22.3 doit :
- **Fermer un `UserPlaneSummary`** sur l'un des trois événements :
  1. **PFCP Session Deletion Request/Response** (N4 : SMF → UPF ou inverse) ;
  2. **NGAP PDU Session Resource Release Command/Response** (N2 : AMF → gNB ou inverse) ;
  3. **inactivité** après `inactivity_timeout_ns` sans trafic N3 (défaut 300s, configurable).
- **Cardinalité bornée par la mémoire** (budget configurable `max_memory_mib`, défaut 512 MiB) avec éviction ordonnée **LRU** et event structuré `USERPLANE_SUMMARY_EVICTED { teid_ul, teid_dl, pdu_session_id, reason }`. **Jamais** erreur bloquante type `CARDINALITY_LIMIT` sur ce chemin.
- Le `N3FlowAggregator` existant garde sa sémantique actuelle (émission au `finish()`) pour la vue par-TEID brute, utile pour debug et compat descendante.

### 4.4 Correction C3 — chaîne SUPI multi-source

Le lot 2.22.2 doit démontrer **sur UE-201** (ET sur la session lab, cf. C4) :
- **Source primaire SBI** : `Nsmf_PDUSession CreateSMContext` body porte `supi` + `pduSessionId` + `n2SmInfo` (visible via vTAP quand SBI est TLS). Utiliser `decoder-sbi::uri_subscriber_pseudonym` comme pipeline de pseudonymisation (SHA-256 clé `subscriber`).
- **Source primaire PFCP** : Session Establishment Req porte F-SEID + F-TEID (UPF-side) + UE IP ; Response porte F-SEID (SMF-side).
- **Source primaire NGAP** : PDU Session Resource Setup porte F-TEID (gNB-side) + 5QI.
- **Source secondaire NAS** : Registration porte SUPI uniquement si NAS en clair (NEA0, lab). En prod sous NEA2+, le NAS est chiffré → source inutilisable. Marquer explicitement `source_kind = "nas_cleartext"` et émettre event `USERPLANE_NAS_CLEARTEXT_SEEN { subscriber_pseudonym }` dédupé — signaler à Sadok quand NAS est en clair en prod.

Pour UE-201 (NEA0 lab), on peut comparer SBI primary vs. NAS secondary et montrer qu'ils concordent ; c'est le test d'acceptation 2.22.2.

### 4.5 Correction C4 — session de référence lab

Le dataset du dépôt (`datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl`, 10 G-PDU) sert au test d'acceptation **minimal**. Les tests 2.22.1 / 2.22.2 / 2.22.3 doivent **aussi** être rejoués sur la session lab `5g-session-0bfac1e7ae159a77` (rapport ANR2 #10 6921238261) via **ANR2 sous `LAB_LOCK`**.

Protocole :
- demander `LAB_LOCK` sur #10 ;
- exécuter les 3 tests d'acceptation sur la session lab ;
- publier les compteurs avec la commande exacte (grep + jq sur `oiran_events.jsonl` publié par la session lab) ;
- libérer `LAB_UNLOCK`.

Format compteur :
```bash
jq -r 'select(.decoder_name=="live-probe-n3-flow-aggregator") |
       [.session_identifiers[]|select(.name=="teid")|.value,
        (.information_elements[]|select(.name=="aggregate_wire_bytes")|.value)] | @tsv' \
  /chemin/vers/oiran_events.jsonl
```

### 4.6 Validation (bench O1) — mesurer le mix réel

Le bench O1 (déjà planifié phase 2) doit **mesurer le mix `(débit_total, nombre_sessions_actives, débit_moyen/session)`** sur un run lab réaliste de 1 h. Résultat substitué à l'hypothèse dans §3.2. Sans ce chiffre, aucune décision de rétention / mémoire n'est publiée sur l'UI.

---

## OUVERTS — tranchés par Sadok #9 6927882355

- **OP2.1 TRANCHÉ** — Troncature **côté sonde** (snaplen BPF = en-têtes L2/L3/L4 + 128 oct après entête GTP-U). Les volumes se calculent **TOUJOURS** sur `original_length` (jamais sur `captured_length`) : test dédié en 2.22.1.
- **OP2.2 TRANCHÉ** — IP UE = identité, **même règle que l'IMSI** : en clair seulement dans l'UI, pseudonymisée dans les logs, exports et GitHub. Applique le domaine `subscriber` existant côté decoder-sbi.
- **OP2.3 TRANCHÉ** — Fenêtre 1s par défaut. Clé `polaris.toml [userplane] window_ns`. **Recommandation 5s en production** documentée dans le README et la section `[userplane]`.
- **OP2.4 TRANCHÉ** — Rétention glissante **7 jours**, planifiée en **lot 2.22.6** (voir §4.1).
- **OP2.5 TRANCHÉ** — LTE S1-U planifié **2.23.x**, après la 5G.
- **OP2.6 TRANCHÉ** — Nommage API validé : route P2 = `/userplane/summary`, route P8 (futur) = `/userplane/tcp_perf`.

---

## Références

- `decoder-gtpu/src/lib.rs` (0.2.1, 469 lignes).
- `live-probe/src/lib.rs` (0.6.4) : `N3FlowAggregator` (l. 279-469), `KeepaliveAggregator` (l. 623-783).
- `decoder-sbi/src/lib.rs` : `uri_subscriber_pseudonym` (l. 1291-1328) — modèle de pseudonymisation SHA-256 clé `subscriber` réutilisé ici.
- `docs/architecture/PHASE1-2.md` §4.5 (l. 275-377) : Préparation PHASE P8 — troncature 128 oct partagée.
- Session de référence : UE-201, dataset `datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl`.
- 3GPP TS 29.281 (GTPv1-U), TS 29.244 (PFCP N4), TS 38.413 (NGAP), TS 24.501 (NAS 5GMM/5GSM).

---

**Statut livrable 2.22.0 :** audit validé #9 6927882355 avec 4 corrections intégrées dans ce document (C1 §3.2 hypothèses étiquetées H1/H2/H3, C2 §4.3 fermeture sur événement + éviction LRU, C3 §4.4 chaîne SUPI multi-source avec SBI primary, C4 §4.5 session lab via ANR2 sous LAB_LOCK). OUVERTS OP2.1→OP2.6 tranchés.

**Statut livrable 2.22.1 :** code inner 5-tuple IPv4/IPv6/ports/proto + snaplen sonde + test volumes sur `original_length` — en cours.
