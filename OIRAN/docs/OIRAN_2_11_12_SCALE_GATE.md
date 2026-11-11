# Gate à l'échelle OIRAN 2.11.12

Cette recette est exécutée par ANR2 sur un hôte fantôme isolé, jamais sur le
service de production. Elle n'ajoute aucun pcap ni aucune identité au dépôt.

## 1. Préparer la vue fantôme

Arrêter l'unité fantôme, puis créer une copie reflink/snapshot du répertoire
complet de production et une copie du ring. Une vue lecture seule + overlay est
également valide. Les chemins présentés au processus doivent rester ceux de la
production, car l'API refuse une source de ring hors allowlist.

```sh
sudo systemctl stop oiran-api.service
sudo install -d -m 0750 /var/lib/oiran/captures /var/lib/docker/volumes/oiran_lab_pcap/_data
sudo cp --reflink=auto -a /snapshot/prod-captures/. /var/lib/oiran/captures/
sudo cp --reflink=auto -a /snapshot/prod-ring/. /var/lib/docker/volumes/oiran_lab_pcap/_data/
sudo install -m 0755 ./target/release/oiran-api /opt/oiran/bin/oiran-api
sudo systemctl set-property oiran-api.service MemoryMax=4G
sudo systemctl start oiran-api.service
```

Le snapshot de `prod-captures` doit contenir le dataset continu complet, pas un
échantillon. Le snapshot du ring doit contenir les sept segments LTE `_00067`
(`s1mme`, `s11`, `s1u`, `s5c`, `s5u`, `sxab`, `s6a`) et leurs successeurs fermant
la rotation. L'environnement de l'unité doit contenir :

```ini
OIRAN_CONTINUOUS_IMPORT_ENABLED=1
OIRAN_CONTINUOUS_IMPORT_SOURCE=/var/lib/docker/volumes/oiran_lab_pcap/_data
OIRAN_CAPTURE_ROOT=/var/lib/oiran/captures
```

## 2. Mesurer le memcg toutes les 30 secondes

La seule source admise pour le gate est le cgroup du service. `free`, `top`,
`/proc/<pid>/status` et le RSS applicatif ne remplacent pas cette mesure.

```sh
sudo sh -c '
cg=/sys/fs/cgroup/system.slice/oiran-api.service
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
while :; do
  date -u +%Y-%m-%dT%H:%M:%SZ
  awk '\''$1 == "anon" || $1 == "file" || $1 == "shmem" { print $1 "=" $2 }'\'' "$cg/memory.stat"
  sed "s/^/memory.peak=/" "$cg/memory.peak"
  journalctl -u oiran-api.service --since "$started" --no-pager \
    | grep -q "phase=13-after-release-pages" && break
  sleep 30
done
' | sudo tee /var/tmp/oiran-2.11.12-memory-gate.log
```

Dans un second terminal, conserver les traces de progression :

```sh
sudo journalctl -fu oiran-api.service -o short-iso \
  | grep --line-buffered -E 'PUBLICATION_RSS_TRACE|segments_ingested|13-after-release-pages'
```

Attendre `phase=13-after-release-pages`. Entre les phases 00 et 01, les lignes
`phase=00c-streaming-representatives` doivent faire croître `scanned_events` par
pas de 100 000 : une valeur répétée sans progression est un échec. Le maximum de
`memory.peak` doit être strictement inférieur à `2147483648` octets, même si
`MemoryMax=4G`. L'unité doit rester active et sans OOM. `scanned_events` prouve
la progression de l'ingestion du JSONL pendant la publication ;
`segments_ingested`, qui est un compteur de commit et ne doit pas anticiper la
publication atomique, doit reprendre au premier scan suivant la phase 13.

## 3. Vérifier la session LTE et les cinq liens

```sh
base=http://127.0.0.1:8091/api/v1
curl -fsS "$base/sessions" \
  | jq -er '.data[] | select(.technology == "LTE") | .session_id' \
  | head -n 1 > /var/tmp/oiran-lte-session-id
session_id=$(sed -n '1p' /var/tmp/oiran-lte-session-id)
curl -fsS "$base/sessions/$session_id" \
  | jq -e '.data.interfaces | (index("S1-MME") and index("S11") and index("S1-U") and index("S5-C") and index("S5-U") and index("Sxab") and index("S6a"))'
curl -fsS "$base/sessions/$session_id/correlations" > /var/tmp/oiran-lte-correlations.json
jq -e '
  def exact_pair($a; $b):
    any(.data[];
      .confidence == "EXACT"
      and ((.source_interface == $a and .target_interface == $b)
        or (.source_interface == $b and .target_interface == $a)));
  exact_pair("S1-MME"; "S11")
  and exact_pair("S11"; "S1-U")
  and exact_pair("S5-C"; "S5-U")
  and exact_pair("Sxab"; "S5-U")
  and exact_pair("S1-MME"; "S6a")
' /var/tmp/oiran-lte-correlations.json
```

Résultat requis : une session LTE couvrant les sept interfaces et cinq ponts
sur cinq `EXACT`. Toute arête absente ou `OPEN`, tout pic supérieur ou égal à
2 GiB, toute absence de phase 13 ou toute stagnation d'ingestion fait échouer le
gate avant déploiement.
