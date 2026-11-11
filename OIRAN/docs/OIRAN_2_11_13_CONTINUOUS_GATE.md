# Recette de reprise continue OIRAN 2.11.13 — 60 minutes

Cette recette est exécutée par ANR2 dans un fantôme isolé contenant le dataset
de production complet et une vue en lecture seule du ring. Elle ne copie aucun
pcap ni aucune identité dans le dépôt. Le service de production reste intact.

## Préparer et démarrer le fantôme

Réutiliser la préparation par copie reflink ou lower lecture seule + overlay de
`OIRAN_2_11_12_SCALE_GATE.md`. Installer le binaire 2.11.13, conserver
`MemoryMax=4G`, puis démarrer l'unité fantôme. Dans les commandes ci-dessous,
adapter uniquement le nom d'unité et le port isolé :

```sh
unit=oiran-phantom-scale-21113.service
port=49156
cg=/sys/fs/cgroup/system.slice/$unit
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
started_epoch_ms=$(( $(date +%s) * 1000 ))
systemctl show "$unit" -p MainPID -p MemoryMax -p ActiveEnterTimestamp
```

## Relever pendant exactement 60 minutes

Le relevé canonique de mémoire est le cgroup. Les compteurs d'ingestion sont
lus via l'API du namespace du fantôme toutes les 30 secondes. Cette boucle ne
modifie ni le ring ni le dataset :

```sh
pid=$(systemctl show "$unit" -p MainPID --value)
deadline=$(( $(date +%s) + 3600 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf 'utc=%s ' "$now"
  awk '$1 == "anon" || $1 == "file" || $1 == "shmem" { printf "%s=%s ", $1, $2 }' "$cg/memory.stat"
  printf 'memory.peak='; cat "$cg/memory.peak"
  nsenter -t "$pid" -n curl -fsS "http://127.0.0.1:$port/api/v1/metrics" |
    jq -c '.data | {segments_ingested,pending_segments,pending_stability_segments,open_segments}'
  sleep 30
done | tee /var/tmp/oiran-2.11.13-continuous-60m.log
```

En parallèle, conserver les cycles, les bornes de publication et le nettoyage
post-swap :

```sh
journalctl -fu "$unit" -o short-iso |
  grep --line-buffered -E 'CONTINUOUS_CYCLE|CONTINUOUS_PUBLICATION_INCREMENTAL|CONTINUOUS_PUBLICATION_PHASE|CONTINUOUS_DATASET_GC|PUBLICATION_RSS_TRACE'
```

Après 60 minutes, extraire l'ensemble probant :

```sh
journalctl -u "$unit" --since "$started" --no-pager -o short-iso |
  grep -E 'CONTINUOUS_|PUBLICATION_RSS_TRACE' \
  > /var/tmp/oiran-2.11.13-continuous-journal.log
grep 'CONTINUOUS_CYCLE' /var/tmp/oiran-2.11.13-continuous-journal.log |
  grep '"phase":"end"' |
  sed 's/^[^{]*//' |
  jq -c 'select(.ingested_this_cycle > 0) |
    {cycle_id,ingested_this_cycle,pending,pending_stability,duration_ms,
     oldest_closed_epoch_ms,
     closed_segment_max_lag_ms,closed_segment_slo_met}'
```

## Résultat requis

- chaque tour produit une paire `CONTINUOUS_CYCLE` begin/end ;
- chaque publication décode uniquement les nouveaux segments et journalise
  `historical_segments_skipped` ;
- toute rotation fermée pendant ou après une publication est ingérée ;
- `segments_ingested` croît au fil des rotations et `pending_segments` revient
  à zéro hors segments ouverts ; `pending_stability_segments` ne reste pas
  figé sur deux cycles consécutifs ;
- après drainage du backlog antérieur au démarrage, chaque cycle dont
  `oldest_closed_epoch_ms >= started_epoch_ms` et qui ingère un segment publie
  `closed_segment_slo_met=true`, soit un délai maximal de 10 minutes depuis le
  dernier mtime du segment fermé jusqu'au commit ;
- une suppression lente de l'ancien dataset apparaît sous
  `CONTINUOUS_DATASET_GC`, mais n'allonge pas le cycle qui suit la permutation ;
- l'unité reste active, sans OOM, et atteint la phase 13 à chaque publication.

Tout `closed_segment_slo_met=false` pour une rotation fermée après le démarrage,
compteur figé, segment fermé encore pending à la fin de la fenêtre ou absence
de tour après la phase 13 fait échouer la recette avant déploiement. Terminer
par la recette LTE 5/5 EXACT de `OIRAN_2_11_12_SCALE_GATE.md`.
