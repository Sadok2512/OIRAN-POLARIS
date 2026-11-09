# POLARIS — Déploiement `oiran-lab` (overlay healthcheck)

## Objet

Prescription d'overlay Compose pour fermer la race de démarrage
hôte prouvée par ANR1 sur #10 comment 6737561274 (2026-11-09).

## Preuves ANR1

- Compose base : `/root/POLARIS/compose/docker-compose.oiran-lab.yml`
  (hors repo, serveur `151.242.147.49`).
- Pré-correctif : healthcheck commun `kill -0 1` + `restart:
  unless-stopped`, aucun `depends_on`.
- Au boot 2026-11-07 :
  - gNB tente SCTP à `21:38:51.372Z` → `Connection refused`
    à `21:38:51.435Z`.
  - AMF ouvre la socket NGAP 38412 à `21:38:51.495Z` (60 ms
    après le refus).
  - UERANSIM `src/ueransim/src/gnb/sctp/task.cpp:211-219`
    journalise puis `return` sans replanifier. Le gNB n'a établi
    NGAP qu'après son redémarrage manuel du 2026-11-08
    à `17:18:51Z`.

## Overlay fourni

`docker-compose.healthcheck.override.yml` (ce dossier) :

- `amf.healthcheck` : SCTP readiness `ss -S -H -l -n | grep -qE
  ':38412\b'`.
- `mme.healthcheck` : même règle sur `36412`.
- `gnb.depends_on.amf.condition: service_healthy`.
- `srsenb.depends_on.mme.condition: service_healthy`.

## Déploiement opérateur (NON-APPLIQUÉ par ce commit)

```bash
# 1. Validation du rendu Compose sans redémarrage.
docker compose \
  -f /root/POLARIS/compose/docker-compose.oiran-lab.yml \
  -f /root/POLARIS/deployment/oiran-lab/docker-compose.healthcheck.override.yml \
  config > /tmp/rendered.yml
grep -E 'healthcheck:|depends_on:' /tmp/rendered.yml

# 2. Application contrôlée : AMF+MME d'abord, puis gNB+srsENB.
docker compose \
  -f /root/POLARIS/compose/docker-compose.oiran-lab.yml \
  -f /root/POLARIS/deployment/oiran-lab/docker-compose.healthcheck.override.yml \
  up -d --no-deps --no-recreate amf mme
# attendre que `docker inspect oiran-lab-amf-1 --format='{{.State.Health.Status}}'`
# retourne `healthy` (max 30 × 2 s = 1 min).
docker compose \
  -f /root/POLARIS/compose/docker-compose.oiran-lab.yml \
  -f /root/POLARIS/deployment/oiran-lab/docker-compose.healthcheck.override.yml \
  up -d gnb srsenb
```

## Limite résiduelle

srsENB gère déjà la reconnexion S1AP (`src/srsran4g/srsenb/src/main.cc:287-288`
et `s1ap.cc:299-315`, retries illimités, timer 10 s). UERANSIM ne
replanifie pas ; une **perte ultérieure** de l'AMF après démarrage
re-provoquera le symptôme. Correction UERANSIM distincte et plus
intrusive (`task.cpp:215-219`, non comprise ici).

## Scénario LTE : alignement d'IP SGi

Fichier serveur : `/root/POLARIS/config/scenarios/lte.yaml:4`.

- Pré-correctif ANR1 : cible `10.77.16.100` (aucun occupant).
- Attendue : `10.77.16.30` (`polaris-lte-sgi-dn`, déjà
  running/healthy depuis 2026-11-07 21:38Z).

Edit opérateur (hors repo) :

```bash
# Dry run diff
grep -nE '10\.77\.16\.(100|30)' /root/POLARIS/config/scenarios/lte.yaml
sed -i 's|10\.77\.16\.100|10.77.16.30|g' /root/POLARIS/config/scenarios/lte.yaml
```

Aucune autre adresse en dur à aligner — `srsran_controller.rs` lit
l'IP depuis la variable d'environnement
`POLARIS_LTE_TRAFFIC_PEER_IP` (défaut `10.77.16.30`).

## Statut d'application

Aucun redémarrage, aucune modification du serveur par ce commit.
L'overlay et cette prescription sont réviewables ; l'opérateur
décide du calendrier.
