# OIRAN 2.11.15 — gate fantôme overlay sans copy-up du shard 0

Reprendre la préparation, la mesure cgroup toutes les 30 secondes et la recette LTE 5/5 de `OIRAN_2_11_14_SHARDED_SCALE_GATE.md`, avec l'unité `oiran-phantom-scale-21115.service`. Aucun PCAP ni aucune identité ne doit être publié.

Avant le démarrage, enregistrer l'état du monolithe historique dans le lower :

```bash
export OIRAN_SCALE_WORK=/chemin/vers/oiran-phantom-21115
export OIRAN_DATASET="$OIRAN_SCALE_WORK/root/continuous-lab-import/dataset"
export OIRAN_SHARD0="$OIRAN_DATASET/oiran_events.jsonl"
stat -c 'inode=%i size=%s mtime=%Y' "$OIRAN_SHARD0" | tee "$OIRAN_SCALE_WORK/shard0-before.stat"
sha256sum "$OIRAN_SHARD0" | tee "$OIRAN_SCALE_WORK/shard0-before.sha256"
du -sb "$OIRAN_SCALE_WORK/upper" | tee "$OIRAN_SCALE_WORK/upper-before.tsv"
```

Laisser tourner 60 minutes. Chaque `CONTINUOUS_CYCLE phase=end` doit contenir `bytes_written` et `files_created`, finir avec `publication_completed=true`, et la phase 13 doit rester sous deux minutes pour un lot de deux segments.

Après 60 minutes :

```bash
stat -c 'inode=%i size=%s mtime=%Y' "$OIRAN_SHARD0" | tee "$OIRAN_SCALE_WORK/shard0-after.stat"
sha256sum "$OIRAN_SHARD0" | tee "$OIRAN_SCALE_WORK/shard0-after.sha256"
diff -u "$OIRAN_SCALE_WORK/shard0-before.stat" "$OIRAN_SCALE_WORK/shard0-after.stat"
diff -u "$OIRAN_SCALE_WORK/shard0-before.sha256" "$OIRAN_SCALE_WORK/shard0-after.sha256"
find "$OIRAN_SCALE_WORK/upper" -type f -size +10M -printf '%s\t%p\n'
upper_bytes=$(du -sb "$OIRAN_SCALE_WORK/upper" | awk '{print $1}')
test "$upper_bytes" -lt 52428800
```

Attendus : inode, taille, mtime et checksum du shard 0 identiques ; aucun nouveau fichier de plus de 10 MiB ; upper strictement inférieur à 50 MiB ; `anon < 2 GiB` et `oom_kill=0`; ingestion continue avec pending revenu à zéro hors segments ouverts ; LTE 7 interfaces et 5/5 liens EXACT via `/api/v1/sessions/{session_id}/correlations`.
