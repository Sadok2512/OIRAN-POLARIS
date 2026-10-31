# POLARIS UE Manager RAT / Simulator — rapport ANR2

Date UTC : 2026-10-31

Branche : `feat/polaris-ue-manager-rat-simulator-v1`

Base : `9fc72cd05ec8b75aaf5d9f3cc1aa2504c28edd55`

SHA implémentation testée : `16e14f84ef2299bda648cc10180661a3e8baa968`

Version frontend : `0.17.0`

Portée : code et preview DEMO uniquement ; aucune modification ou relance de production.

## Verdict

**FAIL (condition de PASS réel non satisfaite).** Le code, le build, les tests unitaires et
la preview isolée sont PASS. UE-01 et UE-201 ont une association RAT/simulateur démontrée
par le backend déployé. En revanche, le backend de production répond `404` pour
`LTE-SRSUE-TEST-01` et `/lte/status`; il ne peut donc pas prouver ni afficher réellement ce
profil LTE. La preview l'affiche exclusivement comme donnée synthétique marquée DEMO.

Ce verdict ne remet pas en cause l'implémentation offline : il applique littéralement la
règle « PASS uniquement si chaque UE affiche sa technologie et son simulateur correctement,
avec preuve backend » sans inventer une preuve LTE absente.

## État initial et isolation Git

Commandes :

```text
git status --short --branch
git rev-parse HEAD
git worktree list --porcelain
git merge-base --is-ancestor 9fc72cd05ec8b75aaf5d9f3cc1aa2504c28edd55 HEAD
```

Résultats : worktree isolé `/root/OIRAN_POLARIS_UE_RAT_ANR2`, branche dédiée propre avant
travail, HEAD initial `9fc72cd05ec8b75aaf5d9f3cc1aa2504c28edd55`, ascendance de la base : exit `0`.
Les worktrees et modifications des autres agents n'ont pas été modifiés. Les phases de test
ont été retardées lorsque PostgreSQL/Rust d'autres agents faisaient tomber `MemAvailable`
sous 4 GiB ; aucun de leurs processus n'a été interrompu.

## Preuves backend réelles (sanitisées)

Lecture seule sur `https://151.242.147.49:8020/polaris-api/v1`; aucun champ IMSI ou secret
d'abonné n'a été imprimé.

```text
curl -ksS "$base/ues" | jq <projection sans identité>
curl -ksS "$base/nodes" | jq <projection sans identité>
curl -ksS -o /tmp/profile.json -w '%{http_code}' "$base/ue-profiles/$id"
curl -ksS -o /dev/null -w '%{http_code}' "$base/lte/status"
```

| UE | Preuve technology / simulator / RAN / core | État runtime réellement observé |
|---|---|---|
| `UE-01` | `configured_profiles`: `GNB-01`, `UERANSIM`; `/nodes`: `GNB-01`, `5G SA`, N2/N3 présents, donc `gNB` / `Open5GS 5GC` | Aucun item runtime dans `/ues` : Registration, IP et session doivent rester `UNKNOWN` |
| `UE-201` | `/ues.serving_node=GNB-01`; profil configuré `UERANSIM`; `/nodes`: `5G SA`, N2/N3 présents, donc `gNB` / `Open5GS 5GC` | `STOPPED`, `DEREGISTERED`, RRC `UNKNOWN`, PDU `INACTIVE`, IP `null`, aucun dernier événement |
| `LTE-SRSUE-TEST-01` | Contrat source offline : `LTE_UE_ID`, `ENB_ID=ENB-01`, `technology=LTE 4G`, `simulator=srsRAN`; mapping UI du simulateur UE : `srsUE` | Production : profil HTTP `404`, `/lte/status` HTTP `404`; association et runtime réels non démontrés |

Les profils UE-01 et UE-201 répondent HTTP `200`, indiquent `GNB-01`, DNN `internet` et
abonnement `VERIFIED`. Le nœud `ENB-01` existe dans `/nodes` comme LTE/srsRAN, mais il est
`configured=false`, processus/santé `unknown` et sans endpoint core observé : cela ne prouve
pas l'existence du profil LTE demandé.

## Changements

- Ajout des colonnes `Technology` et `Simulator` au tableau UE Manager existant.
- Remplacement du libellé `Serving gNB` par `Serving RAN`, avec type `gNB`, `srsENB` ou
  `UNKNOWN`.
- Jointure fondée uniquement sur `/ues`, `configured_profiles` et `/nodes`. Aucune inférence
  à partir du nom de l'UE ; toute association non démontrée devient `UNKNOWN`.
- Ajout des filtres Technology et Simulator.
- Attach/Registration, session et IP proviennent uniquement du runtime observé ; absence de
  runtime = `UNKNOWN`.
- Actions Start/Stop/Run, RBAC, Grant V2 et masquage IMSI conservés. Les tests existants
  d'IMSI operator et viewer restent PASS.
- Preview DEMO enrichie avec UE-01, UE-201 et LTE-SRSUE-TEST-01, sans secret, avec toutes les
  mutations HTTP verrouillées en `423`.
- SemVer frontend `0.16.0` -> `0.17.0` et CHANGELOG mis à jour.

## Tests manuels réels

```text
npm ci
```

PASS : 265 paquets installés. Avertissements : Node local `18.19.1` alors que
`react-router(-dom) 7.18.5` déclare Node >=20 ; audit npm total : 6 avis (2 moderate,
2 high, 2 critical). Aucun `npm audit fix --force` destructif appliqué.

```text
npm run typecheck
```

PASS, exit `0`.

```text
npm test -- --run src/pages/UeManager.rat.test.tsx
```

PASS : 1 fichier, 6 tests. Couvre UE-01, UE-201, LTE, association inconnue, core non prouvé
et champs runtime absents. Un essai préalable avec `--maxWorkers=1` n'a exécuté aucun test
à cause d'un conflit Vitest `minThreads/maxThreads`; il n'est pas compté comme PASS.

```text
npm test -- --run
```

PASS : 36 fichiers, 221 tests. Les avertissements React `act(...)` sont préexistants et non
bloquants.

```text
POLARIS_DEMO_MODE=1 VITE_POLARIS_DEMO_MODE=1 npm run build
```

PASS : TypeScript + Vite, 1708 modules, bundle `index-DCz1o50H.js` (536140 octets),
SHA-256 `3e984fbe2bbfe56cace06cfceb48b1d534f56b48077a738aa4680f5f79fa8d0b`.

```text
POLARIS_DEMO_MODE=1 POLARIS_SIM_E2E_BASE_URL=http://127.0.0.1:4331/simulator/ \
  npx playwright test e2e/demo-preview.spec.ts e2e/topology-lte-5g.spec.ts
```

PASS : 12/12, Chromium 1280/1440/1920, clair et sombre. Les assertions vérifient les trois
UE, leurs RAT/simulateurs/états, les deux filtres, l'absence de débordement de page, les pages
Scenario Builder, Simulator Control et Traffic Generator, ainsi que les chaînes LTE/5G de la
topologie.

## Preview et captures

URL vérifiée : `http://151.242.147.49:4331/simulator/ues`

- `/simulator/` public : HTTP `200`.
- `/simulator/ues` public : HTTP `200`.
- bundle public : HTTP `200`, SHA-256 identique au build local.
- `POST /polaris-api/v1/ues` sur la preview : HTTP `423`.
- écoute limitée au processus DEMO sur le port distinct `4331`; aucune API production
  d'administration n'est exposée par cette preview.

Captures :

- `apps/simulator-control/docs/preview/chromium-1440-light/ue-manager-lte.png`
- `apps/simulator-control/docs/preview/chromium-1440-dark/ue-manager-lte.png`
- captures complémentaires Scenario Builder, Simulator Control, Traffic Generator et
  Topology dans les mêmes répertoires.

## Gates et anomalies

Commandes finales :

```text
df -P /root
awk '/MemAvailable/ {print $2}' /proc/meminfo
pgrep -x dumpcap | wc -l
```

- disque : 47 %, PASS (<85 %).
- RAM : contrôlée avant chaque phase lourde ; tests différés tant que <4 GiB.
- dumpcap externes : 12, préservés.
- aucun live, grant, trafic, démarrage srsENB/srsUE, déploiement ou redémarrage production.
- anomalie bloquante réelle : backend déployé sans profil/status LTE canonique (HTTP 404).
- dette environnement : Node 18 non conforme à l'engine Node >=20 des versions actuelles de
  React Router ; avis npm à traiter séparément après revue de compatibilité.

## Étape suivante

Revue de branche, puis intégration/déploiement du backend LTE canonique uniquement avec
autorisation distincte. Après cela, refaire la même lecture backend et une recette UI
read-only : le verdict ne pourra devenir PASS que lorsque `LTE-SRSUE-TEST-01` sera réellement
publié et que les champs LTE non observables resteront `UNKNOWN`.

— ANR2
