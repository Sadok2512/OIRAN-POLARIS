# MEMORY_PUBLICATION_STATUS

**Date du gel :** 2026-11-19. **Décision cœur :** écart mémoire publication **OUVERT**, sorti du lot du jour (#9 7008753850). 2.21.77 reste sur sa branche et ne part pas en prod.

## 1. Mesures de référence (ANR1, copie physique, unité transitoire)

Toutes les mesures sont faites sur le même dataset de rejeu, sous `MemoryMax=6G`, dans une unité `systemd-run --unit=oiran-api-anr1-…`. Jamais sur `oiran-api.service` de prod. Source commune : les sondes `PUBLICATION_RSS_TRACE phase=…` lues dans `journalctl`.

### 1.1 Prod 2.21.57 (baseline, cycle 1, #10 7005944378)

| phase | vmrss_kb | vmhwm_kb | cgroup_peak_kb |
|---|---:|---:|---:|
| `01-after-streaming-representatives` | 1 883 504 | 2 107 756 | 2 979 600 |
| `03-after-discover-sessions` | 2 164 112 | 2 164 112 | 2 979 600 |
| `06-after-fold-overlapping-edges` | 2 164 356 | 2 164 356 | 2 979 600 |
| `07-after-lte-flows-built` | 2 164 412 | 2 164 412 | 2 979 600 |
| `08-after-runtime-flows-built` | 2 164 412 | 2 164 412 | 2 979 600 |
| `09-after-events-dropped` | 187 848 | 2 163 984 | 2 979 600 |

**Pic VmHWM = 2 163 984 KiB, atteint phase 03, stable jusqu'à 09.**

### 1.2 2.21.75 `07d5d85` à `01-80-merge-end` (#10 7008057413, cgroup exact depuis 2.21.69)

- `events_len = 544 292`, `events_capacity = 1 048 576` (croissance géométrique), `events_inline_bytes = 704 643 072` B = 1 294,6 B/rep.
- Breakdown par champ sur `events.iter()` :
  - `event_record_inline` = **365 764 224** B = 672 B/rep (inline sizeof EventRecord).
  - `source_json` = **211 044 292** B = 387,7 B/rep (procedure + sbi.{request_uri, http_method, operation}).
  - `packet_references_vec` = 121 921 408 B = 224 B/rep.
  - `packet_reference_paths` = 89 420 196 B = 164,3 B/rep.
  - Somme des champs comptés : 1 288 705 025 B (65 % de l'anon 01-80).
  - **Reste hors comptage : 688 856 063 B** (pages/fragmentation allocateur, String internes non capturées).

### 1.3 2.21.77 `f09bec1` à `01-80-merge-end` (#10 7008669237, capacité exacte)

- `events_capacity = 544 292` (= `distinct_merged_count`), `events_inline_bytes = 365 764 224` B.
- **Résident gagné : −21 504 KiB anon.** VmPeak gagné : −396 472 KiB (réservation virtuelle non faultée).
- **VmHWM global : 2 154 532 KiB, atteint phase 06**, +160 KiB vs 2.21.75 (bruit). Cible 0,9 Go **non atteinte**.
- Coût : `+10 213 ms` (+3,32 %) par publication complète (passe 1 dry-run de la merge).

### 1.4 Commande de mesure (reproductible, hors prod)

Préalable : `git fetch origin fix/oiran-2.21.69-cgroup-resolve && git checkout f09bec1 && flock /tmp/nsplus-heavy-build.lock -c 'nice -n 19 ionice -c3 cargo build --release --locked -p oiran-api -j 2'` dans la copie ANR1.

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAME=oiran-api-anr1-${STAMP}
sudo systemd-run --unit="$NAME" --service-type=exec --collect \
  -E OIRAN_API_LISTEN_ADDR=127.0.0.1:49377 \
  -p MemoryAccounting=yes -p MemoryMax=6G \
  -- $ANR1_COPY_PATH/OIRAN/target/release/oiran-api
CGROUP=/sys/fs/cgroup/system.slice/${NAME}.service
until [ -r "$CGROUP/memory.peak" ]; do sleep 1; done
until curl -sfk https://127.0.0.1:49377/health >/dev/null; do sleep 1; done
echo 0 | sudo tee "$CGROUP/memory.peak" >/dev/null
sudo journalctl -u "${NAME}.service" -o cat --since="@$(date +%s)" -f \
  | grep --line-buffered '^PUBLICATION_RSS_TRACE phase=0' \
  > /var/log/oiran/${NAME}-phase01.txt &
oiran-api-ctl --addr https://127.0.0.1:49377 publish --full --dataset="$OIRAN_LAB_REPLAY_DATASET" --wait
```

Jamais `oiran-api.service`, jamais `/opt/oiran-api/current`.

## 2. Leviers essayés, gain RÉEL

| Levier | Version | Hypothèse cœur | Gain RSS mesuré | Décision |
|---|---|---|---|---|
| A — streaming lte/runtime callflows (plus de `Vec<CallFlow>` additif) | 2.21.65 `c15ab11` | ~250 MB utile → ~2,67 GB RSS | **0 KiB** (`lte_flows=26`, `runtime_flows=0`, pic phase 01) | gelée sur branche |
| fadvise DONTNEED par bloc + whole-file + spill files | 2.21.71 | récupérer 2,18 GB de `cgroup_file_kb` | **+608 KiB** shard 0 → shard 273 (cycle), −23 % seulement après merge ; `memory.peak` touche exactement `MemoryMax` sans OOM → page cache récupérable, pas une fuite | gardé (inoffensif) |
| Capacité exacte `Vec<EventRecord>` fusionné (deux passes) | 2.21.77 `f09bec1` | −338 MB RSS (arithmétique capacité − len) | **−21 504 KiB anon** résident, −396 MiB VmPeak virtuel, +10,2 s | gelée sur branche, erreur d'arithmétique du cœur reconnue (#9 7008753850) |
| cgroup via `/proc/self/cgroup` | 2.21.69 `058adc2` | trace juste dans unité transitoire | cgroup_*_kb exact pour toute unité | **ACCEPTÉ**, prérequis des mesures ultérieures |
| Comptage par champ 01-50 / 01-80 + sondes 01-xx | 2.21.67 / 73 / 75 | instrumentation | n/a (pure observation) | **ACCEPTÉ** |

## 3. Ce qui reste

### 3.1 VmHWM arrive à phase 06, pas 01-80

Mesure 2.21.77 : `01-80 VmHWM = 1 918 884 KiB` mais HWM global `2 154 532 KiB` atteint **phase 06-after-fold-overlapping-edges**. Les phases 03 (`discover_sessions`), 04 (`correlate_discovered_tunnels`), 05 (`correlate_cross_interface_evidence`), 06 (`fold_overlapping_edges`) portent **235 MiB de plus** que le pic post-merge. Le levier B sur les représentants seul ne tient pas la cible.

**Prochain audit :** instrumenter les phases 03–06 avec le même breakdown par champ sur les sorties (`DiscoveryResult.ue_contexts/pdu_sessions/pfcp_sessions/gtpu_tunnels/procedures/event_accounting/background_event_ids/unmatched_event_ids`, `Vec<CorrelationEdge>`, et leurs `event_ids: Vec<String>` cumulés). Mêmes sondes `PUBLICATION_RSS_TRACE phase=0X-field-breakdown …` que 01-80.

### 3.2 `source_json` 388 B/rep

Garde `procedure` + `sbi.{request_uri, http_method, operation}` après compaction. Audit à faire : qui lit `source_json` après la phase 01. Grep rapide donne 2 call-sites (correlation-engine SBI, session-engine procedure). Options : passer ces deux attributs en champs dédiés de `EventRecord` et retirer entièrement `source_json`. Gain plafond : 211 MB.

### 3.3 `packet_references` + `packet_reference_paths`

`packet_references_vec = 224 B/rep`, `packet_reference_paths = 164 B/rep`. Les chemins pcap sont répétés (≤ quelques centaines de fichiers par publication, répartis sur 544 k reps). Interner (`Arc<str>` par chemin, ou table u32 + map). Gain plafond : 85 MB.

### 3.4 Reste hors comptage 689 MB

Pas chiffré par `publication_projection_field_bytes`. Candidats : fragmentation `malloc`, `capacity()` de String/Vec internes non comptée, structures intermédiaires `serde_json::Value`. Instrumentation requise : `malloc_info` / `mallinfo2` à `01-80` et `01-90`. Pas d'allocateur alternatif (mimalloc/jemalloc) sans audit du lock Rust 1.83.

## 4. Piste d'architecture (pour un lot suivant, pas pour le lot du jour)

Les micro-leviers (compactation de champs, interning, trim) plafonnent à ≈ 500 MB cumulés. Cible 0,9 GB → RSS à retirer ≈ 1,25 GB. Deux voies :

1. **Représentants compacts** : remplacer `events: Vec<EventRecord>` (sizeof 672 B + heap ≈ 1,3 KB total) par `events: Vec<CompactRepresentative>` (≈ 400 B) où CompactRepresentative ne contient que les champs lus par `discover_sessions`, `correlate_discovered_tunnels`, `correlate_cross_interface_evidence` + `(source_jsonl_path_idx, line_offset)` pour rapatrier le `EventRecord` complet depuis le JSONL quand une session callflow en a besoin. Gain plafond sur 544 k reps : **≈ 490 MB** (1,3 KB − 0,4 KB × 544 k). Blast radius : signature `discover_*` / `correlate_*` / `build_callflow` / `offline_lte_callflows`.
2. **`discover_sessions` en flux** : actuellement la discovery lit le `Vec<EventRecord>` entier, construit `DiscoveryResult` en RAM. Alternative : discovery streamée par shard (ou par run spillé), émission par bloc des sessions complètes dès qu'une release est observée. Supprime le pic `events + discovery` coexistants (phase 03). Blast radius : plus large (refactor sémantique).

Sans profiling heaptrack/jemalloc sur les 689 MB hors comptage, le chiffre réel de ces deux voies est une borne — pas une promesse.

## 5. Bilan

- Trois versions partent en prod ce jour : **train 2.21.72** (CLAUDE2) + **p900 2.8.6** (CLAUDE2). Mon lot `fix/oiran-2.21.69-cgroup-resolve` **ne part pas**.
- Les instrumentations 2.21.69 (cgroup) et 2.21.67/73/75 (sondes 01-xx, comptage par champ) restent utilisables par ANR1 pour toute mesure future.
- L'écart « pic mémoire publication < 0,9 GB » est **OUVERT**. Prochain lot : audit phases 03–06 + décision architecture.

— CLAUDE1, 2026-11-19
