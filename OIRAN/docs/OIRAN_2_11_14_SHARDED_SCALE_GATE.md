# OIRAN 2.11.14 — recette fantôme à l’échelle

Cette recette est exécutée par ANR2 sur une copie du dataset de production et du ring. Elle ne publie aucun PCAP ni aucune identité. Le succès exige : phase 13 en moins de 120 secondes pour un cycle de deux segments, `bytes_written` voisin de la taille du nouveau shard, `anon < 2 GiB`, aucun OOM, reprise des cycles, puis LTE 5/5 EXACT.

## 1. Préparer un fantôme isolé

Arrêter toute ancienne unité fantôme, puis créer une copie reflink ou un montage lecture seule avec overlay privé. Les variables ci-dessous doivent viser les chemins locaux d’ANR2 :

```bash
export OIRAN_SCALE_SOURCE=/chemin/vers/copied-production-root
export OIRAN_SCALE_WORK=/chemin/vers/oiran-phantom-21114
export OIRAN_RING_SOURCE=/var/lib/docker/volumes/oiran_lab_pcap/_data
mkdir -p "$OIRAN_SCALE_WORK/lower" "$OIRAN_SCALE_WORK/upper" "$OIRAN_SCALE_WORK/work" "$OIRAN_SCALE_WORK/root"
mount --bind "$OIRAN_SCALE_SOURCE" "$OIRAN_SCALE_WORK/lower"
mount -o remount,bind,ro "$OIRAN_SCALE_WORK/lower"
mount -t overlay overlay -o "lowerdir=$OIRAN_SCALE_WORK/lower,upperdir=$OIRAN_SCALE_WORK/upper,workdir=$OIRAN_SCALE_WORK/work,redirect_dir=on" "$OIRAN_SCALE_WORK/root"
```

Configurer l’unité fantôme avec `MemoryMax=4G`, un port distinct, le root overlay ci-dessus et le ring réel monté en lecture seule. Vérifier avant démarrage :

```bash
systemctl show oiran-phantom-scale-21114.service -p MemoryMax -p FragmentPath
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS "$OIRAN_SCALE_WORK/root"
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS "$OIRAN_RING_SOURCE"
```

## 2. Mesurer exclusivement le cgroup toutes les 30 secondes

La source normative est `/sys/fs/cgroup/system.slice/oiran-phantom-scale-21114.service`, jamais le RSS d’un shell ni un agrégat hôte :

```bash
export OIRAN_CGROUP=/sys/fs/cgroup/system.slice/oiran-phantom-scale-21114.service
export OIRAN_SAMPLE_LOG="$OIRAN_SCALE_WORK/cgroup-30s.tsv"
while systemctl is-active --quiet oiran-phantom-scale-21114.service; do
  awk -v now="$(date -u +%FT%TZ)" '
    $1=="anon" {anon=$2}
    $1=="file" {file=$2}
    $1=="shmem" {shmem=$2}
    END {printf "%s\tanon=%s\tfile=%s\tshmem=%s", now, anon, file, shmem}
  ' "$OIRAN_CGROUP/memory.stat" >> "$OIRAN_SAMPLE_LOG"
  awk '{printf "\tpeak=%s\n", $1}' "$OIRAN_CGROUP/memory.peak" >> "$OIRAN_SAMPLE_LOG"
  sleep 30
done
```

Dans un second terminal, suivre les preuves de publication jusqu’à la phase 13 :

```bash
journalctl -fu oiran-phantom-scale-21114.service -o cat | tee "$OIRAN_SCALE_WORK/service.log"
rg 'CONTINUOUS_(CYCLE|SHARD_COMMITTED|PUBLICATION_INCREMENTAL)|PUBLICATION_RSS_TRACE' "$OIRAN_SCALE_WORK/service.log"
```

Pour le cycle ayant `selected_segments=2`, relever les timestamps de `CONTINUOUS_PUBLICATION_INCREMENTAL phase=begin` et `PUBLICATION_RSS_TRACE phase=13-after-release-pages`. Attendus : écart inférieur à 120 secondes ; `CONTINUOUS_CYCLE phase=end publication_completed=true` ; `bytes_written` du même ordre que le shard courant et non les 3,4 Go historiques ; maximum `anon` strictement inférieur à 2 147 483 648 octets ; `oom_kill=0` dans `memory.events`.

## 3. Vérifier shards et métrique

```bash
export OIRAN_DATASET="$OIRAN_SCALE_WORK/root/continuous-lab-import/dataset"
jq '{event_shards, event_count}' "$OIRAN_DATASET/dataset_manifest.json"
jq -r '.event_shards[] | [.path,.sha256,.bytes,.event_count] | @tsv' "$OIRAN_DATASET/dataset_manifest.json"
curl -fsS http://127.0.0.1:49156/api/v1/metrics | jq '{segments_ingested,pending_segments,pending_stability_segments,closed_not_ingested_segments}'
```

`closed_not_ingested_segments` doit être présent dès le démarrage, y compris avec la valeur `0`. Sa définition est : segment fermé parce qu’un nom de segment plus récent existe sur la même interface, et dont le checksum est absent de `import_state`.

Conserver les checksums avant un cycle, attendre le cycle suivant, puis prouver qu’ils n’ont pas changé :

```bash
jq -r '.event_shards[] | [.path,.sha256] | @tsv' "$OIRAN_DATASET/dataset_manifest.json" > "$OIRAN_SCALE_WORK/shards-before.tsv"
sleep 600
jq -r '.event_shards[] | [.path,.sha256] | @tsv' "$OIRAN_DATASET/dataset_manifest.json" > "$OIRAN_SCALE_WORK/shards-after.tsv"
join -t $'\t' "$OIRAN_SCALE_WORK/shards-before.tsv" "$OIRAN_SCALE_WORK/shards-after.tsv" | awk -F '\t' '$2!=$3 {bad=1} END {exit bad}'
```

## 4. Laisser tourner puis fermer la recette LTE

Laisser le fantôme actif au moins 60 minutes. Chaque segment fermé doit être ingéré au plus tard dans le SLO publié de 10 minutes ; les lignes `CONTINUOUS_CYCLE` doivent continuer à se terminer et le pending revenir à zéro hors segments ouverts.

Exécuter ensuite la recette LTE `_00067` déjà certifiée par ANR2. Utiliser `/api/v1/sessions/{session_id}/correlations` et confirmer une session LTE avec sept interfaces et cinq liens EXACT : S1-MME↔S11, S11↔S1-U, S5-C↔S5-U, Sxab↔S5-U et S1-MME↔S6a. Toute valeur OPEN, tout OOM, toute absence de phase 13, ou tout checksum historique modifié met le gate en échec.
