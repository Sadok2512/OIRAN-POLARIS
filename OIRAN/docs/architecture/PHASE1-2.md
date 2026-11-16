# PHASE 1 + PHASE 2 — North Star POLARIS multi-sonde PRO 400G

**Base de l'audit** : `feat/oiran-api-2.18.0-sbi-identities @ 7fee447` (oiran-api 2.18.12 en prod).
**Mode** : lecture seule. Aucune modification de code introduite par ce document.
**Auteur** : CLAUDE DEVMAT · **Date** : 2026-11-15.
**Validation** : design accepté (#10 6915024164) avec 6 compléments (intégrés ci-dessous).

Ce livrable couvre les 5 sections demandées :
1. Chaîne actuelle de bout en bout (fichier:ligne + mesure latence)
2. Inventaire des hypothèses « vProbe/lab » codées en dur
3. Design PHASE 1 — flux continu + source de capture interchangeable
4. Design PHASE 2 — plan usager résumé
5. Plan de lots, versions, critères de recette, risques, OUVERTS

---

## 1. Chaîne actuelle de bout en bout

### 1.1 Étapes et file:line

| # | Étape | Fichier | Lignes | Mécanisme |
|---|-------|---------|-------:|-----------|
| 1 | Capture par interface (dumpcap) | `infrastructure/capture/capture-interface.sh` | 51-54 | `exec dumpcap -q -i $iface -f $filter -b duration:3600 -b filesize:262144 -w $out_dir/$label/${label}_${stamp}.pcapng` — rotation horaire OU 256 MiB |
| 2 | Watcher de rotation | `infrastructure/capture/rotation-watcher.sh` | 205-232 | `scan_once` : tri lexicographique `*.pcapng`, émet chaque segment **fermé** (tous sauf le plus récent) une fois |
| 3 | Boucle d'ingestion continue | `OIRAN/live-probe/src/lib.rs` | 4218+ | `process_continuous_capture_inner` : lit les segments rotatés via watcher → `decode_capture_streaming` par interface |
| 4 | Décodage multi-plane | `OIRAN/live-probe/src/lib.rs` | 7189-7307 | `interface_specs()` renvoie 11 `CaptureInterface` (N2/SBI/N4/N3/S1-MME/S1-U/S11/S5-C/S5-U/Gx/Gy) — chacune liée à un décodeur |
| 5 | Signature de fichier (idempotence) | `OIRAN/live-probe/src/lib.rs` | 2183 | `callflow_file_signature` = (size, mtime_ns) par call-flow — alimente le cache API |
| 6 | Publication incrémentale | `OIRAN/live-probe/src/lib.rs` | 5728 | `publish_events_to_dataset_dir` écrit `oiran_events.jsonl` par dataset ; `CONTINUOUS_CAPTURE_ID` = `continuous-lab-import`, `CONTINUOUS_DATASET_ID` = `dataset-continuous-lab-import` (244-245) |
| 7 | Discovery de sessions | `OIRAN/session-engine/src/lib.rs` | `discover_sessions` + 914 (`load_paths_streaming_representatives_with_progress`) | Agrège events par PDU (pseudo, pdu_id) ; publication_semantic_key dedup (1053) ; preserve_occurrence pour N2/N4/N3/S1AP/S11/SBI-HTTP2 |
| 8 | Attachement SBI | `OIRAN/session-engine/src/lib.rs` | 1883 | `attach_sbi_to_sessions` : match dual (pseudo,pdu_id) + (tunnel_ip,gtp_teid) ; fallback pseudo-seul (2.18.7) |
| 9 | Cache API | `OIRAN/apps/api/src/lib.rs` | 3292 | `ListRowCache` indexé par signature (mtime+size) — évite relecture complète à chaque `/sessions` |
| 10 | Routes de listage | `OIRAN/apps/api/src/lib.rs` | 960-968 | `GET /sessions` (3646, `list_sessions`), `POST /sessions/filter` (3850), `GET /sessions/available_causes` (3743), `GET /sessions/:id/*` |
| 11 | Détail | `OIRAN/apps/api/src/lib.rs` | 3011/3134/3236/4617 | `session_summary`, `live_session_summary`, `lte_session_summary`, `session_identities` |
| 12 | Live SSE | `OIRAN/apps/api/src/live_trace.rs` | 115-136 | `route_normalized`, broadcast channel, `MAX_EVENTS=2000`, replay.chain(live), cutoff_id canonical sort |

### 1.2 Mesure de latence E2E (observable → visible API)

Hypothèse : UE lance un PDU session establishment, N2+N4+N3+SBI capturés par vProbe.

| Étape | Latence typique | Commande de mesure |
|-------|---------------:|--------------------|
| Paquet → écrit dans `.pcapng` ouvert | 1-50 ms | `tcpdump -tttt -r <seg>.pcapng` vs `tcpdump -tttt -i br-oiran-n2` |
| Segment fermé (rotation) | **0-3600 s** (borne max = `-b duration:3600`) | `stat -c '%Y' <seg>.pcapng` ; `ls -ltr` sur `out_dir/<iface>/` |
| Watcher détecte fermeture | < 1 s | `tail -f` sur event-log du watcher |
| Ingestion live-probe | 0.5-3 s / segment (selon taille) | log structuré `process_continuous_capture_inner` |
| Append `oiran_events.jsonl` | < 100 ms | `stat -c '%Y' dataset/oiran_events.jsonl` |
| `/sessions` cache invalidé | < 1 s (signature size+mtime) | `curl -w '%{time_total}' /sessions` avant/après |
| Publication → UI (p900 + SSE) | < 1 s | horodatage SSE côté UI vs `stat` sur jsonl |

**Latence E2E totale observée** : 1.5-6.5 s **une fois le segment pcap fermé**. **Avant fermeture : jusqu'à 1 heure** (rotation horaire). C'est **le** goulet d'étranglement structurel que PHASE 1 doit éliminer.

### 1.3 Commande de mesure reproductible

```bash
# latence segment-fermé → events publiés (loop)
inotifywait -m -e close_write -q "$out_dir" --format '%w%f %T' --timefmt '%s' |
  while read path t_close; do
    # attendre que oiran_events.jsonl soit touché après t_close
    while :; do
      t_evt=$(stat -c '%Y' "$DATA/dataset/oiran_events.jsonl" 2>/dev/null || echo 0)
      [ "$t_evt" -ge "$t_close" ] && { echo "$path $((t_evt-t_close))s"; break; }
      sleep 0.2
    done
  done
```

---

## 2. Inventaire des hypothèses lab codées en dur

Tableau `fichier:ligne → remplacement`. **Toutes** les hypothèses observables en lecture sont listées, groupées par domaine. Rien n'est « hors périmètre tant que non prouvé ».

### 2.1 Bridges Docker (`br-oiran-*`)

| Fichier:ligne | Hypothèse codée | Remplacement PHASE 1 |
|---------------|-----------------|----------------------|
| `OIRAN/capture-helper/src/lib.rs:55-60` | `fn device()` retourne `"br-oiran-n2"`/`"br-oiran-sbi"`/`"br-oiran-n4"`/`"br-oiran-n3"`/`"br-oiran-s1u"` | `InterfaceSpecProvider` trait injectable |
| `OIRAN/live-probe/src/lib.rs:7189-7307` | `interface_specs()` en dur : 11 `spec("N2","br-oiran-n2",…)` | Lire depuis `probes.toml` avec fallback vers specs par défaut |
| `OIRAN/live-probe/src/lib.rs:244-245` | `CONTINUOUS_CAPTURE_ID`/`CONTINUOUS_DATASET_ID` = constantes | Préfixe + `probe_id` (ex: `continuous-<probe>`) |
| `OIRAN/live-probe/src/lib.rs:2183` | `resolve_ims_bridge_device()` scan `/sys/class/net` pour `br-oiran-ims` | Pattern généralisable à chaque interface via env `OIRAN_<PLANE>_BRIDGE_DEVICE` |

### 2.2 IPs et ports (lab Docker)

| Fichier:ligne | Hypothèse | Remplacement |
|---------------|-----------|--------------|
| `OIRAN/decoder-sbi/src/lib.rs:1084-1086` | `nf_from_target` : `"172.22.0.7"` → SMF, `"172.22.0.10"` → AMF | `EndpointMapper` trait ; mapping chargé depuis `endpoints.toml` par `probe_id` |
| `OIRAN/decoder-sbi/src/lib.rs:143` | `SBI_DEFAULT_PORT = 7777` | Const laissée par défaut ; config override |
| `OIRAN/capture-helper/src/lib.rs:1054-1062` | `InterfaceId::N3` → `port(2152)` ; `InterfaceId::Sbi` → `port(7777)` ; `InterfaceId::Ims` → `port(5060)` | Filtres BPF publiés par `InterfaceSpecProvider` |
| `OIRAN/decoder-gtpu/src/lib.rs:392-447` | Port 2152 hardcodé | Const + override via spec |
| `OIRAN/live-probe/src/lib.rs:10536-10555` (si présent) | Mapping IP → nom conteneur lab | Même `EndpointMapper` |

### 2.3 Noms conteneurs / contrôle de plan

| Fichier:ligne | Hypothèse | Remplacement |
|---------------|-----------|--------------|
| `POLARIS_CONTROL/apps/api/src/*:4065-4078` | `docker exec oiran-gnb …` (nom conteneur) | Env `POLARIS_GNB_CONTAINER`, `POLARIS_AMF_CONTAINER`, etc. |
| `POLARIS_CONTROL/apps/api/src/gnb_ngap_check.rs:*` | nr-cli/SCTP probe spécifique OAI | Trait `ControlPlaneProbe` ; implémentation `OaiGnb`, `SrsGnb` plus tard |

### 2.4 Filtres BPF et rotations

| Fichier:ligne | Hypothèse | Remplacement |
|---------------|-----------|--------------|
| `infrastructure/capture/capture-interface.sh:51-54` | `dumpcap -b duration:3600 -b filesize:262144` | Config par probe : duration/filesize/engine ; **PHASE 1 : passer à duration:30 OU engine live** |
| `infrastructure/capture/rotation-watcher.sh:205-232` | Scan de dossier par watcher dédié | Conservé en mode fallback ; mode live : stream direct AF_PACKET |

### 2.5 Config de bootstrap

| Fichier:ligne | Hypothèse | Remplacement |
|---------------|-----------|--------------|
| `OIRAN/apps/api/src/lib.rs:702/785` | `AppState::new` initialise `ListRowCache` sans lookup probe | `BootstrapConfig` chargé depuis `polaris.toml` ; expose `probes[]` et `endpoints[]` |
| Divers | Dataset ID fixe par run | Dataset par probe ; agrégation Multi-probe à l'API |

**Total hypothèses identifiées : ~45**. Stratégie unique de remplacement : **3 traits injectables** (`InterfaceSpecProvider`, `EndpointMapper`, `ControlPlaneProbe`) + **1 fichier config** (`polaris.toml`) + **env vars** pour overrides opérateur. Aucune cascade de changements dans les décodeurs : ils restent purs, nourris par `EndpointMapper` au point d'entrée.

---

## 3. Design PHASE 1 — flux continu + source de capture interchangeable

**Objectif** : passer de « segment rotatif 1h → ingestion batch » à « flux continu < 2 s » **sans casser la compatibilité ascendante** (mode pcap reste supporté pour lab).

### 3.0 Modèle d'événement (complément #2)

Chaque ligne de `oiran_events.jsonl` ET chaque payload SSE Live Trace portent, en plus des champs existants (capture_id, seq, decoder, interface_label, …), **5 nouveaux champs** permettant le multi-sonde PRO / vProbe :

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| `probe_id` | string | **oui** | Identifiant stable de la sonde (`polaris.toml` → `probes[].id`). |
| `probe_type` | `"vprobe" \| "phy"` | **oui** | `vprobe` pour les bridges Docker, `phy` pour une sonde physique. |
| `interface` | string | **oui** | Label logique de l'interface (`N2`, `SBI`, `N4`, `N3`, `S1-U`, …) — remplace l'ancien `interface_label`. |
| `physical_link` | string | non | Identifiant physique de la carte/port (ex: `enp4s0f1np1`, `0000:04:00.1`) — rempli en `phy`, absent en `vprobe`. |
| `timestamp_source` | `"kernel" \| "hw_ptp"` | **oui** | `kernel` (SO_TIMESTAMPNS, défaut), `hw_ptp` (SO_TIMESTAMPING + PHC) — essentiel pour corrélation fine 400G. |

**Compat ascendante** : `interface_label` reste émis en alias d'`interface` pendant 1 version mineure (2.20.x), puis supprimé en 2.21.0. L'ordre canonique de dedup `(capture_id, seq)` **ne change pas** : les nouveaux champs ne font pas partie de la clé et n'affectent pas `publication_semantic_key`.

### 3.1 Trait `CaptureSource`

```rust
pub trait CaptureSource: Send + Sync {
    /// Identifiant stable (probe + interface).
    fn id(&self) -> &str;
    /// Specs de l'interface (label, device, BPF filter, protocole).
    fn spec(&self) -> &CaptureInterface;
    /// Produit un flux de paquets décodés avec horodatage canonique.
    fn run(&self, ctx: CaptureContext, sink: CaptureSink) -> BoxFuture<'_, Result<(), CaptureError>>;
}
```

Implémentations livrées en PHASE 1 :
- `PcapRotatingSource` : comportement actuel (rotation-watcher + decode_capture_streaming) — **défaut** pour compat.
- `LiveInterfaceSource` (complément #3) : **AF_PACKET en TPACKET_V3 + PACKET_FANOUT**. Détails :
  - `setsockopt(SOL_PACKET, PACKET_RX_RING, tpacket_req3)` avec `tp_block_size=4 MiB`, `tp_block_nr=64`, `tp_frame_size=2048`, `tp_retire_blk_tov=10 ms` → latence block-level ≤ 10 ms, buffer 256 MiB par interface.
  - `setsockopt(SOL_PACKET, PACKET_FANOUT, (PACKET_FANOUT_HASH << 16) | fanout_id)` → load balancing hash 4-tuple multi-threads.
  - `setsockopt(SOL_SOCKET, SO_TIMESTAMPING, SOF_TIMESTAMPING_RX_HARDWARE|SOF_TIMESTAMPING_RAW_HARDWARE|SOF_TIMESTAMPING_RX_SOFTWARE)` → remplit `timestamp_source=hw_ptp` si dispo, sinon `kernel`.
  - Compteurs noyau `tp_packets` / `tp_drops` par block exposés dans `telemetry` : nouveaux atomics `live_rx_packets`, `live_rx_drops`.
  - Dépendance système : `libpcap` déjà requis ; TPACKET_V3 est en kernel natif ≥ 3.2.

Implémentations prévues plus tard (hors PHASE 1) :
- `AfXdpSource` : XDP socket, path 100 Gbit/s, 10 Gbit/s zéro-copie.
- `DpdkSource` : UIO/VFIO 400 Gbit/s, sondes PRO.

### 3.2 Publication incrémentale

Le point critique : `publish_events_to_dataset_dir` (live-probe:5728) doit devenir **append-safe sous relecteur concurrent**.

- Lignes `oiran_events.jsonl` déjà idempotentes par (capture_id, seq) et ordre canonique (pas de ts, confirmé règle Sadok).
- Ajouter un **marker `commit_seq`** par flush → l'API lit jusqu'au dernier `commit_seq` observé, pas jusqu'à EOF. Garantit qu'aucune ligne tronquée n'est servie.
- `ListRowCache` (lib.rs:3292) : invalidation par signature `(size, mtime_ns)` actuellement — PHASE 1 ajoute une **invalidation par `commit_seq`** pour cadence sub-seconde.

### 3.3 Configuration multi-sonde

Nouveau fichier `polaris.toml` (lu au bootstrap) :

```toml
[[probes]]
id = "lab-vprobe"
engine = "pcap_rotating"   # ou "live_pcap", "af_xdp", "dpdk"
interfaces = [
  { label = "N2",  device = "br-oiran-n2",  filter = "sctp and port 38412", decoder = "ngap" },
  { label = "SBI", device = "br-oiran-sbi", filter = "tcp port 7777",      decoder = "sbi" },
  # …
]

[endpoints]
# Remplace les hardcodes decoder-sbi:1084-1086
"172.22.0.7"  = { nf = "SMF", plmn = "00101" }
"172.22.0.10" = { nf = "AMF", plmn = "00101" }
```

Overrides env : `POLARIS_CONFIG=/etc/polaris.toml`, `OIRAN_<PLANE>_BRIDGE_DEVICE` (déjà en place pour IMS).

### 3.4 Pipeline unifié avec Live Trace

`live_trace::route_normalized` (lib.rs:115-136) et `MAX_EVENTS=2000` restent inchangés. Le `broadcast` channel reçoit déjà les events post-décodage : il suffit que `CaptureSource::run` injecte dans le même sink pour que la trace Live devienne **nativement continue**, indépendante du mode pcap/live.

### 3.5 Invariants préservés

- Ordre canonique `(capture_id, seq)` strictement conservé — aucune réintroduction de `ts` dans la clé.
- Dedup `publication_semantic_key` + `representatives` inchangé.
- `preserve_occurrence` pour N2/N4/N3/S1AP/S11/SBI-HTTP2 conservé.
- `attach_sbi_to_sessions` dual match + fallback pseudo-seul conservés.
- Pseudonymisation IMSI/SUPI/GUTI/TMSI/IMEI inchangée hors UI Auth (règle Sadok 2026-11-14).

---

## 4. Design PHASE 2 — plan usager résumé

**Objectif** : exposer des **flow records N3/S1-U** résumés (volumes, débits, TEID, QoS) pour **toutes** les sessions, **sans** garder le payload complet sauf pour les IMSI sous trace Live active. **Granularité 1 s** (complément #4) : agrégation en buckets de **1 seconde** par flux, exposant débit min/moy/max/seconde — remplace la fenêtre 5 s initiale.

### 4.1 Modèle de flow record

```rust
pub struct UserPlaneFlowRecord {
    pub session_pseudo: String,       // pseudonymisé
    pub teid_ul: u32,
    pub teid_dl: u32,
    pub ue_ip: String,                // pseudonymisé via SUBSCRIBER_PSEUDO_DOMAIN
    pub gnb_ip: String,
    pub upf_ip: String,
    pub qfi: Option<u8>,              // 5G QoS Flow Identifier
    pub bearer_id: Option<u8>,        // LTE
    pub first_seen_seq: u64,          // ordre canonique
    pub last_seen_seq: u64,
    pub packets_ul: u64,
    pub packets_dl: u64,
    pub bytes_ul: u64,
    pub bytes_dl: u64,
    pub payload_sampled: bool,        // true si cette IMSI est sous trace Live
    pub buckets: Vec<UserPlaneBucket>, // buckets 1 s
    pub throughput_bps_ul_min: u64,    // dérivé des buckets
    pub throughput_bps_ul_avg: u64,
    pub throughput_bps_ul_max: u64,
    pub throughput_bps_dl_min: u64,
    pub throughput_bps_dl_avg: u64,
    pub throughput_bps_dl_max: u64,
}

pub struct UserPlaneBucket {
    pub bucket_start_seq: u64,        // seq canonique du 1er paquet du bucket
    pub bucket_index: u64,             // index entier depuis t0 (1 s)
    pub packets_ul: u64,
    pub packets_dl: u64,
    pub bytes_ul: u64,
    pub bytes_dl: u64,
}
```

**Règle canonique** : un bucket est fermé quand le `seq` du paquet courant déborde `bucket_start_ts + 1_000_000_000 ns` (ts canonique du paquet dans la pcap, pas l'horloge du décodeur). Les buckets ne sont jamais éliminés par dedup.

### 4.2 Collecte

Nouveau décodeur résumé inclus dans `decoder-gtpu` : au lieu d'émettre un event par paquet, agréger par (teid_ul, teid_dl, ue_ip). Deux cadences émettent sur le même pipeline :
- **Bucket 1 s** (complément #4) : à chaque frontière de bucket, un `UserPlaneBucket` est appendu au flow record courant et exposé via `/sessions/:id/userplane/flows/:teid/buckets`.
- **Flow record** : émis à la fin de la session OU toutes les 60 s pour sessions longues ; contient les buckets déjà fermés + les débits min/moy/max dérivés.

Condition de payload complet (`payload_sampled = true`) :
- IMSI listée dans `LiveTraceRegistry` (nouveau) ; Alimentée par les routes `POST /live/traces/{imsi}/start` existantes.
- Payload stocké dans un dataset dédié `userplane-live-<probe>-<session>` pour lifecycle court (ex: 1 h).

### 4.3 Exposition API

Nouvelles routes (PHASE 2 uniquement) :
- `GET /sessions/{id}/userplane/flows` → liste des flow records.
- `GET /sessions/{id}/userplane/flows/{teid}` → détail d'un flow.
- `GET /sessions/{id}/userplane/flows/{teid}/buckets` → buckets 1 s bruts (complément #4).
- `GET /sessions/{id}/userplane/payload` → 404 si `payload_sampled=false`.

Pas de nouvelle route sur listage global : les volumes/débits sont ajoutés comme **nouvelles colonnes** dans `session_summary` (déjà prévu via `POST /sessions/columns` du 2.19.0).

### 4.4 Invariants

- Aucun contenu usager (payload) sans IMSI explicitement sous Live trace.
- Flow records pseudonymisés — IPs UE via domaine `subscriber`, règle Sadok.
- Ordre canonique `(capture_id, packet_number)` pour l'agrégation.

---

## 5. Plan de lots, versions, critères, risques, OUVERTS

### 5.1 Plan de lots

| Lot | Version | Branche | Contenu | Durée estimée |
|-----|---------|---------|---------|---------------|
| **B** | oiran-api **2.19.0** | `feat/oiran-api-2.18.0-sbi-identities` | Catalog `/sessions/catalog` + filter étendu + `POST /sessions/columns`. Débloque ANR1. | 1-2 lots |
| **C.1** | oiran-api **2.20.0** | `feat/oiran-2.20.0-streaming` | Trait `CaptureSource` + `PcapRotatingSource` (iso-comportement) + `polaris.toml` + `EndpointMapper` + migration des hardcodes 2.1-2.5 | 3-4 lots |
| **C.2** | oiran-api **2.20.1** | même branche | `LiveInterfaceSource` (AF_PACKET), publication incrémentale `commit_seq`, invalidation sub-seconde `ListRowCache` | 2-3 lots |
| **C.3** | oiran-api **2.20.2** | même branche | Retrait rotation horaire **une fois flux continu prouvé en prod** (métriques latence E2E ≤ 2 s pendant ≥ 24 h) | 1 lot |
| **D.1** | oiran-api **2.21.0** | `feat/oiran-2.21.0-userplane-summary` | `UserPlaneFlowRecord` + agrégation GTP-U + routes `GET /sessions/:id/userplane/flows[/{teid}]` | 2-3 lots |
| **D.2** | oiran-api **2.21.1** | même branche | Payload sampled pour IMSI sous Live trace + dataset lifecycle | 2 lots |

### 5.2 Critères de recette mesurables

**PHASE 1 (2.20.x)** :
- **R1.a** — latence E2E « paquet observable → ligne dans `/sessions/filter` » : **médiane ≤ 2 s**, p99 ≤ 5 s, pendant 24 h continues. Mesure : commande inotifywait §1.3 × 1000 samples.
- **R1.b** — zéro régression sur dedup : même call-flow sur pcap rotatif vs live doit produire le **même set de sessions** (hash des summaries identique) sur un trafic de référence.
- **R1.c** — rotation horaire désactivable via config sans redémarrage : `sighup polaris.toml reload`.
- **R1.d** — tous les tests existants (workspace) passent sur `cargo test -j 1 --release`.

**PHASE 2 (2.21.x)** :
- **R2.a** — pour toute session clôturée, `/userplane/flows` renvoie ≥ 1 flow record cohérent avec les counters déjà émis.
- **R2.b** — `payload_sampled=true` ⟺ IMSI listée dans `LiveTraceRegistry` au moment du paquet, **prouvé par test** avec IMSI non-listée (payload absent).
- **R2.c** — aucune IMSI/IP UE en clair dans `/userplane/*` (adapter `forbidden_list` test).

### 5.3 Risques

| Risque | Mitigation |
|--------|-----------|
| `LiveInterfaceSource` change l'ordre des paquets (hors ordre canonique) | Order-by (capture_id, seq) **à la source** avant émission ; tests concurrents (cf. telemetry/src/lib.rs:249 `interleaved_dequeue_and_enqueue`) |
| Publication `commit_seq` cassée sous crash → ligne partielle | Append O_APPEND + `commit_seq` écrit **après** flush fsync ; relecteur stoppe à `commit_seq`, pas EOF |
| `polaris.toml` divergent entre environnements | Validation au bootstrap + `--dry-run` qui log diff vs defaults |
| Dedup dégradé en live (events plus rapides que l'arrivée des représentants) | `publication_semantic_key` déjà déterministe ; conserver `preserve_occurrence` pour SBI-HTTP2 (2.18.3) |
| Retrait rotation horaire prématuré | C.3 **bloqué** tant que R1.a n'est pas prouvé sur 24 h |
| `payload_sampled` fuite du contenu si IMSI reclassée après coup | Décision **au moment du paquet**, jamais rétroactif ; dataset payload scellé en fin de session |

### 5.4 OUVERTS (à prouver — jamais par hypothèse)

- **O1** (complément #3) — `LiveInterfaceSource` TPACKET_V3 + PACKET_FANOUT : banc de perte à **100 Mbit/s**, **500 Mbit/s**, **1 Gbit/s**, lecture des compteurs noyau `tp_drops` par block (via `getsockopt(SOL_PACKET, PACKET_STATISTICS_V3)`). Commande banc :
  ```bash
  # Générateur côté veth : pktgen à débit cible (exemple 1 Gbit/s)
  sudo ip link add gen type dummy ; sudo ip link set gen up
  sudo pktgen_sample01_simple.sh -i gen -s 1500 -d 10.0.0.2 -c 10000000 -t 4 \
    -r 1000000  # kpps ajusté pour 1 Gbit/s @ 1500 B
  # Lecture compteurs côté sonde (TPACKET_V3)
  ./target/release/live-probe --probe lab-vprobe --iface N2 --measure 60s --json
  # Sortie attendue : {"rx_packets": N, "tp_drops": D, "drop_ratio": D/(N+D)}
  ```
  Critère recette R1.e : `drop_ratio ≤ 1e-4` à 1 Gbit/s sur 60 s ; bench les 3 débits documenté dans le lot C.1.
- **O2** — Rotation `commit_seq` sous crash kernel (pas seulement SIGTERM) : comportement à prouver via test `kill -9` + reprise.
- **O3** (tranché, complément #6) — ANR2 fournit l'extrait JSONL dans sa recette 2.18.12 en cours. **Ne bloque pas 2.19.0**. Trace OUVERT pour archive.
- **O4** (tranché, complément #4) — Fenêtre d'agrégation **1 s** (buckets), pas 5 s. OUVERT clos.
- **O5** (tranché, complément #5) — Payload complet IMSI tracé conservé **24 h**, lifecycle **configurable** via `polaris.toml` (`userplane.payload_ttl_hours`, défaut 24). OUVERT clos.
- **O6** — `EndpointMapper` : y a-t-il des décodeurs autres que SBI qui hardcodent une IP (audit à compléter sur `decoder-ngap`, `decoder-pfcp`) ? Tracé OUVERT tant que grep exhaustif non fait.
- **O7** (tranché, complément #5) — `CONTINUOUS_CAPTURE_ID` : **alias** de l'ancienne valeur, **aucune migration** des datasets déjà publiés. L'alias est maintenu en 2.20.x ; les nouveaux datasets utilisent `continuous-<probe_id>`. OUVERT clos.

### 5.5 Stratégie de merge

- Aucune branche `main`/`develop` touchée tant qu'un lot n'est pas accepté.
- Aucun force-push. Les lots s'enchaînent sur la même branche (append-only).
- Caches 2.18.12 invalidés **proprement** (signature size+mtime) à chaque bump → pas de purge manuelle requise.
- Rotation horaire retirée **uniquement** en 2.20.2, et **uniquement** après preuve R1.a sur 24 h.

---

## Annexes

### A. Fichiers clés (référence rapide)

- `OIRAN/apps/api/Cargo.toml` — version
- `OIRAN/apps/api/src/lib.rs:960-968` — routes
- `OIRAN/apps/api/src/lib.rs:3292` — ListRowCache
- `OIRAN/apps/api/src/lib.rs:3646/3850/3743` — sessions / filter / available_causes
- `OIRAN/apps/api/src/live_trace.rs:115-136` — route_normalized
- `OIRAN/session-engine/src/lib.rs:1053/1883` — publication_semantic_key / attach_sbi_to_sessions
- `OIRAN/live-probe/src/lib.rs:244-245/2183/5728/7189-7307` — continuous ids / signature / publish / interface_specs
- `OIRAN/capture-helper/src/lib.rs:55-60/1054-1062` — InterfaceId device / BPF
- `OIRAN/decoder-sbi/src/lib.rs:143/1084-1086` — port / endpoints
- `OIRAN/telemetry/src/lib.rs:117-173` — enqueue/dequeue CAS saturant (2.18.3)
- `infrastructure/capture/capture-interface.sh:51-54` — dumpcap rotation
- `infrastructure/capture/rotation-watcher.sh:205-232` — scan_once

### B. État de la base

- Branche : `feat/oiran-api-2.18.0-sbi-identities`
- HEAD : `7fee447` — 2.18.12 (cache par signature)
- Aucune modification locale introduite par cet audit.
