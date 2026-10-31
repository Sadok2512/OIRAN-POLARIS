# POLARIS real-lab staging V1 — ANR2

Date UTC: 2026-10-31

## Verdict

**BLOCKED** pour une promotion/déploiement. Le staging fonctionnel est validé hors production, mais le contrôle final de RAM est descendu à 3,49 GiB disponibles pendant une charge externe au staging (seuil requis: 4 GiB) et `cargo fmt --all -- --check` expose une dérive de formatage héritée sur plusieurs fichiers Rust. Aucun live ni déploiement n'a été effectué.

## Git et versions

- Branche isolée: `staging/polaris-real-lab-v1-anr2`
- Commit code testé: `65e2da977ce5f5e4153e06b6ec0cdc2f5b0620b7`
- Parents réels du merge normal: `7f84c4963c36b80c582f7572000596a2ab7c57d9` et `5e5c83601bb4f0a13556972765393393f9512485`
- Base commune historique des deux lignées avant merge: `87daa3445e3058352d21efeba21d05fefe3029d4`
- `git merge-base --is-ancestor 7f84c496... 65e2da97...`: code 0
- `git merge-base --is-ancestor 5e5c8360... 65e2da97...`: code 0
- Staging: API `0.25.1`, UI `0.18.1`, Platform `3.2.1`
- Production observée en lecture seule sur `127.0.0.1:49153`: API `0.19.8`, Platform `3.2.1`; service resté actif avec le même PID `3747586`.

Le merge n'utilise pas `-s ours`: le commit possède les deux parents et conserve les contrats ANR1/ANR3 non conflictuels tout en intégrant le candidat ANR2.

## Staging isolé

- UI locale vérifiée: `http://127.0.0.1:4336/simulator/` — HTTP 200
- API locale: `http://127.0.0.1:49325/api/v1/` — proxy UI HTTP 200
- `ss -ltnp '( sport = :49325 or sport = :4336 )'`: les deux sockets écoutent exclusivement sur `127.0.0.1`.
- Tous les fichiers mutables sont redirigés sous `/root/polaris-staging-anr2.y2vSUn/` (mode 0700); aucune mutation ne pointe vers l'état de production.
- `POLARIS_STAGING_READ_ONLY=true`, exécution et live LTE/5G désactivés.
- Un middleware global laisse passer GET/HEAD/OPTIONS et l'authentification locale staging; toute autre mutation retourne `423 STAGING_READ_ONLY` avant le handler.

Preuves HTTP 423 obtenues sur `/live/grant`, `/lte/runs`, `/lte/components/start`, `/lte/components/stop`, `/scenarios/start`, `/traffic/sessions`, `/subscribers` et `/ue-profiles`. Aucun grant, scénario, UE, simulateur ou trafic n'a été créé/démarré.

## Données réelles et routes

| Route | Résultat observé |
|---|---|
| `GET /health` | `ok`, version `0.25.1`, `staging_read_only=true` |
| `GET /version` | API `0.25.1`, Platform `3.2.1`, contrôleur srsRAN `0.2.1` |
| `GET /lab` | source `READ_ONLY_HOST_AUDIT`, Open5GS `running/healthy` |
| `GET /nodes` | 2 nœuds configurés; GNB-01 UERANSIM `running/healthy`; ENB-01 srsRAN `UNKNOWN/unknown` |
| `GET /ues` | 3 profils, 0 actif, 0 enregistré; LTE-SRSUE-TEST-01 `UNKNOWN` |
| `GET /lte/status` | non certifié, aucun grant, srsUE non observé, état `UNKNOWN` |
| `GET /lte/profiles/LTE-SRSUE-TEST-01` | HTTP 200; profil LTE/srsUE, runtime `UNKNOWN` |
| `GET /traffic/sessions` | 0 session, aucun échantillon ni faux compteur |
| `GET /scenario-templates` | exactement 13: 6 LTE + 7 5G SA; 0 occurrence `DEMO` |
| `GET /scenario-definitions` | 31 définitions réelles/copiées, 0 occurrence `DEMO` |
| `GET /plmns`, `GET /dnns` | respectivement 1 et 2 entrées |

Observation Docker en lecture seule: les fonctions EPC/5GC Open5GS et `oiran-lab-ueransim-gnb-1` sont actives; aucun conteneur srsENB/srsUE n'est présent. Les états LTE restent donc `UNKNOWN`, jamais transformés en `RUNNING` ou `ATTACHED`.

## RBAC et confidentialité

- Session anonyme: `authenticated=false`, rôle `viewer`.
- Les trois abonnés retournés au viewer n'exposent ni IMSI/SUPI ni champ K/OP/OPc/secret.
- Session locale staging `staging-operator`: rôle `operator`; trois identités visibles comme prévu, sans secret abonné.
- Le mot de passe, cookie et résultat de login restent dans le répertoire staging privé et ne figurent ni dans Git ni dans ce rapport.
- Recherche récursive des réponses opérationnelles: aucune donnée `DEMO`.

## Corrections staging

- API `0.25.1`: verrou staging global 423, indicateur read-only dans `/health` et `/version`, audit local des refus.
- UI `0.18.1`: cible proxy configurable pour `vite preview`, adaptateur typé du contrat `ScenarioTemplateDescriptor`, suppression de toute dépendance à un fallback navigateur pour le catalogue opérationnel.
- Tests mis à jour pour les contrats réels: nœuds configurés affichés honnêtement comme `PLANNED/UNKNOWN`, templates immuables fournis par l'API.
- SemVer et CHANGELOG mis à jour côté API et UI.

## Tests manuels exécutés

| Commande | Résultat réel |
|---|---|
| `CARGO_BUILD_JOBS=1 cargo check -p polaris-control-api` | PASS; 7 warnings hérités |
| `CARGO_BUILD_JOBS=1 cargo test -p polaris-control-api` | PASS: 229 passés, 0 échec, 3 ignorés (benchmarks manuels) |
| `CARGO_BUILD_JOBS=1 cargo build -p polaris-control-api --bins` | PASS |
| Node isolé `v20.20.2`; `npm ci --no-audit --no-fund` | PASS, 265 paquets |
| `npm run typecheck` | PASS |
| `npm test -- --reporter=json` | PASS: 234/234 tests, 37 fichiers/100 suites Vitest |
| `npm run build` | PASS: 1708 modules, bundle JS 538,87 kB (151,64 kB gzip) |
| Playwright réel `e2e/real-lab-staging.spec.ts` | PASS: 6/6 — 1280/1440/1920, clair/sombre, sans mock ni interception réseau |
| `cargo fmt --all -- --check` | FAIL: dérive héritée dans plusieurs fichiers (`activity.rs`, `lte_orchestrator.rs`, `srsran_controller.rs`, etc.); les deux blocs ANR2 ajoutés dans `lib.rs` ont été remis au format attendu |

Le test Playwright vérifie l'API réelle via le proxy, le verrou 423, les 13 templates, l'absence de `DEMO`, GNB-01/ENB-01, LTE-SRSUE-TEST-01 avec `LTE 4G / srsUE`, Traffic observabilité, l'absence de débordement horizontal, et les six profils d'écran. Capture locale: `/root/polaris-staging-anr2.y2vSUn/evidence/traffic-real-lab-1440.png`.

## Ressources et invariants

- Disque: 52% utilisé, donc inférieur à 85%.
- RAM avant Playwright: 5 169 952 KiB disponibles (PASS); contrôle final: 3 663 368 KiB (BLOCKED sous 4 GiB, neuf processus `mongosh` externes observés; aucun processus tiers interrompu).
- Dumpcap: 12 avant et 12 après; aucun PID dumpcap touché.
- API production: active depuis `2026-10-30 23:41:02 UTC`, PID inchangé.
- Aucun srsENB/srsUE, UE, scénario, grant ou trafic live démarré.

## Plan de déploiement atomique — non exécuté

1. Attendre RAM disponible >=4 GiB et corriger/acter la dérive rustfmt; rejouer toute la matrice.
2. Vérifier `git merge-base --is-ancestor` depuis les SHA production API/UI vers le SHA release signé.
3. Sauvegarder binaire API, bundle UI, fichiers d'environnement, registres et état; calculer SHA-256 et manifeste horodaté.
4. Construire API/UI depuis le même SHA et déposer dans des chemins versionnés temporaires.
5. Basculer atomiquement les liens API/UI, redémarrer uniquement le service POLARIS autorisé, puis tester santé, version, RBAC, lecture et verrou live.
6. Ne pas démarrer LTE/5G ni trafic pendant la recette de déploiement.
7. Au premier FAIL, restaurer les deux liens et fichiers de configuration, redémarrer l'ancienne API, vérifier API `0.19.8`/UI actuelle et consigner le rollback.

## Défauts ouverts

1. Gate RAM final sous 4 GiB: bloque READY tant que la mesure n'est pas revenue au-dessus du seuil.
2. `cargo fmt --check` échoue sur une dette de formatage Rust héritée; aucune réécriture massive n'a été faite pendant ce lot.
3. LTE réel non certifié et srsUE/srsENB absents: `UNKNOWN` est le seul état valable; ce staging ne constitue pas un LTE E2E PASS.
4. Le port public 8020 n'est pas écouté directement sur loopback; la version production a été vérifiée sur son bind interne réel `127.0.0.1:49153`. Aucun proxy production n'a été modifié.

— ANR2
