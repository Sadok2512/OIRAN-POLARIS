# OIRAN 2.11.16 — recette fantôme sur copie figée

Cette recette est exécutée par ANR2. Elle ne publie ni PCAP ni identité. Le lower d'un overlay ne doit **jamais** pointer vers le dataset de production vivant : la publication fantôme doit voir une image immuable pendant toute la recette.

## 1. Créer l'image figée

Vérifier d'abord l'espace (le disque mesuré par la coordination était à environ 77 %) puis créer un répertoire neuf sous `/var/tmp`. La source doit être un snapshot cohérent ou une copie arrêtée par la coordination, pas le répertoire que le service de production continue de modifier.

```bash
df -B1 /var/tmp
export OIRAN_FROZEN_SOURCE=/chemin/vers/snapshot-coherent-production
export OIRAN_SCALE_WORK="$(mktemp -d /var/tmp/oiran-phantom-21116.XXXXXX)"
export OIRAN_FROZEN="$OIRAN_SCALE_WORK/frozen"
mkdir -p "$OIRAN_FROZEN"
cp -a --reflink=auto "$OIRAN_FROZEN_SOURCE"/. "$OIRAN_FROZEN"/
```

Si reflink n'est pas pris en charge, remplacer uniquement la dernière commande par :

```bash
rsync -aH --numeric-ids "$OIRAN_FROZEN_SOURCE"/ "$OIRAN_FROZEN"/
```

Enregistrer la preuve d'immuabilité avant démarrage :

```bash
export OIRAN_FROZEN_DATASET="$OIRAN_FROZEN/continuous-lab-import/dataset"
sha256sum "$OIRAN_FROZEN_DATASET/dataset_manifest.json" > "$OIRAN_SCALE_WORK/manifest-before.sha256"
find "$OIRAN_FROZEN_DATASET" -type f -name '*.jsonl' -print0 | sort -z | xargs -0 sha256sum > "$OIRAN_SCALE_WORK/shards-before.sha256"
```

Monter cette copie en lecture seule avec un upper privé. Configurer `oiran-phantom-scale-21116.service` avec `MemoryMax=4G`, un port distinct et le ring figé ou monté en lecture seule :

```bash
mkdir -p "$OIRAN_SCALE_WORK/lower" "$OIRAN_SCALE_WORK/upper" "$OIRAN_SCALE_WORK/work" "$OIRAN_SCALE_WORK/root"
mount --bind "$OIRAN_FROZEN" "$OIRAN_SCALE_WORK/lower"
mount -o remount,bind,ro "$OIRAN_SCALE_WORK/lower"
mount -t overlay overlay -o "lowerdir=$OIRAN_SCALE_WORK/lower,upperdir=$OIRAN_SCALE_WORK/upper,workdir=$OIRAN_SCALE_WORK/work,redirect_dir=on" "$OIRAN_SCALE_WORK/root"
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS "$OIRAN_SCALE_WORK/root"
systemctl show oiran-phantom-scale-21116.service -p MemoryMax -p FragmentPath
```

## 2. Mesurer pendant 60 minutes

La source mémoire normative est le cgroup du fantôme, échantillonné toutes les 30 secondes :

```bash
export OIRAN_CGROUP=/sys/fs/cgroup/system.slice/oiran-phantom-scale-21116.service
export OIRAN_SAMPLE_LOG="$OIRAN_SCALE_WORK/cgroup-30s.tsv"
while systemctl is-active --quiet oiran-phantom-scale-21116.service; do
  awk -v now="$(date -u +%FT%TZ)" '$1=="anon"{anon=$2} $1=="file"{file=$2} $1=="shmem"{shmem=$2} END{printf "%s\tanon=%s\tfile=%s\tshmem=%s",now,anon,file,shmem}' "$OIRAN_CGROUP/memory.stat" >> "$OIRAN_SAMPLE_LOG"
  awk '{printf "\tpeak=%s\n",$1}' "$OIRAN_CGROUP/memory.peak" >> "$OIRAN_SAMPLE_LOG"
  sleep 30
done
```

Conserver `CONTINUOUS_PUBLICATION_INCREMENTAL`, toutes les phases `PUBLICATION_RSS_TRACE`, `CONTINUOUS_CYCLE` et `CONTINUOUS_SHARD_COMMITTED`. Chaque cycle doit publier `bytes_written` et `files_created`; `pending_segments` et `closed_not_ingested_segments` doivent revenir à zéro hors rotation ouverte. L'absence de rotation pendant un intervalle n'est pas un échec de progression.

## 3. Fermer le gate

Attendus : aucun OOM, `anon < 2 GiB`, checksums historiques inchangés, upper inférieur à 50 MiB après 60 minutes, et une session LTE globale à sept interfaces avec cinq liens EXACT via `/api/v1/sessions/{session_id}/correlations` : S1-MME↔S11, S11↔S1-U, S5-C↔S5-U, Sxab↔S5-U et S1-MME↔S6a. Vérifier aussi la session 5G de référence : 18 événements, dont les trois occurrences restaurées documentées dans le CHANGELOG.

```bash
sha256sum "$OIRAN_FROZEN_DATASET/dataset_manifest.json" > "$OIRAN_SCALE_WORK/manifest-after.sha256"
find "$OIRAN_FROZEN_DATASET" -type f -name '*.jsonl' -print0 | sort -z | xargs -0 sha256sum > "$OIRAN_SCALE_WORK/shards-after.sha256"
diff -u "$OIRAN_SCALE_WORK/manifest-before.sha256" "$OIRAN_SCALE_WORK/manifest-after.sha256"
diff -u "$OIRAN_SCALE_WORK/shards-before.sha256" "$OIRAN_SCALE_WORK/shards-after.sha256"
upper_bytes=$(du -sb "$OIRAN_SCALE_WORK/upper" | awk '{print $1}')
test "$upper_bytes" -lt 52428800
cat "$OIRAN_CGROUP/memory.events"
```
