# ANR3 — Rapport final OIRAN LTE hors production

Date : 2026-10-31 UTC
Mission : `OIRAN_POLARIS_FINAL_INTEGRATION_V1` — volet ANR3
Mode : fixtures synthétiques anonymisées uniquement ; aucun live, déploiement, service ou processus de capture touché.

## Verdict

**OFFLINE_PASS / REAL_CERTIFICATION_BLOCKED**

Le pipeline LTE hors production est implémenté, versionné et poussé. Il couvre S1-MME/S1AP+NAS EPS, S11/GTPv2-C, S1-U/GTP-U, la reconstruction de sessions et bearers EPS, la corrélation prudente par identifiants/TEID, les compteurs UL/DL et le Call Flow LTE. Les régressions 5G N2/N3/N4 restent couvertes. Une certification LTE réelle reste bloquée tant qu'ANR1 n'a pas remis de PCAP anonymisés `SANITIZED_APPROVED`.

## Source et versions

- Branche de livraison distante : `anr3/oiran-lte-pipeline` (alias certifié : `cert/anr3-oiran-lte-offline-v1`)
- Préparation : `c42973e4e48223be8a807299e59ecf8fca4b7331`
- Certification : `2c67fe6b2cbb450fefaa789c76f947678388953c`
- Preuve remote : `git ls-remote origin refs/heads/anr3/oiran-lte-pipeline refs/heads/cert/anr3-oiran-lte-offline-v1` retourne `2c67fe6b…` pour les deux références.
- `decoder-s1ap` 0.2.0 ; `decoder-gtpv2c` 0.1.0 ; `decoder-gtpu` 0.2.0.
- `oiran-decode` 0.6.0 ; `session-engine` 0.5.0 ; `correlation-engine` 0.5.0 ; `callflow-schema` 1.2.0.
- Analyzer `2.6.0-pre.1+lte.offline.1`.
- SemVer et changelogs OIRAN/Analyzer présents dans les deux commits.

## Fonctionnalités livrées

| Domaine | État mesuré | Preuve source |
|---|---|---|
| Routage S1-MME | PPID SCTP 18 vers S1AP + NAS EPS ; séparation stricte de N2 | `OIRAN/oiran-decode/src/lib.rs:34-52` |
| Routage S11 | UDP/2123 vers GTPv2-C | `OIRAN/oiran-decode/src/lib.rs:34-44` |
| Routage S1-U | UDP/2152 vers GTP-U, sans confusion N3 | `OIRAN/oiran-decode/src/lib.rs:34-44` |
| Attach / E-RAB | Procédures S1AP/NAS classées ; contexte parent conservé | tests `decoder-s1ap` et fixture synthétique |
| Create/Modify/Delete Session | EBI et F-TEID GTPv2-C normalisés | tests `decoder-gtpv2c` |
| User plane | TEID, direction eNB↔SGW, paquets/octets UL/DL | tests `decoder-gtpu` |
| Sessions LTE | Partition par contexte S1AP explicite, pseudonyme opaque, EBI/F-TEID | `session-engine/src/lib.rs:254-425` |
| Corrélation | S1AP↔S11 et S11↔S1-U, ambiguïtés rejetées | `correlation-engine/src/lib.rs:184-286` |
| Call Flow | Tri déterministe, participants, procédures, provenance, état de corrélation | `callflow-schema/src/lib.rs:250-392` |
| Pagination mémoire bornée | `limit/cursor`, plafond 256 événements/réponse | `apps/api/src/lib.rs:2075-2192`, tests `:3236-3290` |
| Préservation 5G | NGAP/NAS-5G/PFCP/GTP-U restent présents et testés | suites Rust et Analyzer |

Les limites restent honnêtes : l'extraction imbriquée E-RAB transport/TEID n'est pas certifiée sur APER réel et aucune association temporelle seule n'est autorisée.

## Tests manuels

### Rust LTE et régressions 5G

```bash
CARGO_TARGET_DIR=/dev/shm/anr3-final-verify CARGO_BUILD_JOBS=2 \
cargo test --offline \
  -p decoder-s1ap -p decoder-gtpv2c -p decoder-gtpu \
  -p oiran-decode -p session-engine -p correlation-engine \
  -p callflow-schema
```

Résultat : **66 PASS, 0 FAIL**. Détail : callflow-schema 3, correlation-engine 15, decoder-gtpu 5, decoder-gtpv2c 8, decoder-s1ap 10, oiran-decode 8, fixture LTE pipeline 1, session-engine 16. Les doc-tests passent également. Seul avertissement : trois `unused_mut` non bloquants dans des tests/session-engine ; aucune réécriture cosmétique globale.

### API

```bash
CARGO_TARGET_DIR=/dev/shm/anr3-api-final CARGO_BUILD_JOBS=2 \
cargo test --offline -p oiran-api
```

Résultat : **33 PASS, 0 FAIL, 0 ignoré** en 1.01 s après compilation. Le test `callflow_route_pages_persisted_events_with_a_bounded_cursor_contract` confirme la pagination bornée ; les tests provenance, sessions, corrélations, capture context et confidentialité passent également.

### Analyzer

```bash
npm ci --ignore-scripts
npm rebuild node
./node_modules/node/bin/node --version
npm run typecheck
npm run test
npm run build
```

Résultat : Node `v22.23.4`; TypeScript **PASS** ; Vitest **10 fichiers / 73 tests PASS** ; Vite **1 636 modules**, JS **358.59 kB** (gzip **106.16 kB**) ; `check-dist-leaks` **PASS**, 3 fichiers inspectés.

### Fixtures et confidentialité

```bash
find OIRAN/tests/fixtures -type f -name '*lte*.json' -exec jq empty {} \;
rg -n '\b[0-9]{14,16}\b' OIRAN/tests/fixtures \
  OIRAN/oiran-decode/tests OIRAN/session-engine/tests OIRAN/correlation-engine/tests
git diff --check
```

Résultat : quatre documents JSON valides ; **aucune identité numérique longue trouvée** ; les seules occurrences IMSI/IMEI/GUTI sont les noms de champs explicitement interdits et les assertions de test ; `git diff --check` PASS. Aucun K, OPc, identité abonné ou adresse de production n'est inclus.

## Contrat d'intégration ANR1 → ANR3

Le schéma canonique ANR1 est `infrastructure/lte-certification/lte-evidence-schema.json` au SHA `514359f`.

- `profile_id` : `LTE-SRSUE-TEST-01`.
- `scenario_id` : `lte-e2e-certification-v1`.
- Plans acceptés : `S1_MME`, `S11`, `S1_U`; `S5_C`/`S5_U` sont acceptés par le schéma mais hors pipeline minimal.
- Chaque `capture_ref` fournit SHA-256 source, première/dernière trame et état d'assainissement.
- L'ingestion réelle échoue fermée tant que chaque plan requis n'est pas `SANITIZED_APPROVED`.
- Le brut `RAW_PROTECTED` ne doit jamais être publié dans l'Analyzer ni commité.

Événement normalisé requis : `run_id`, `capture_id`, `seq`, `event_id`, plan/interface, protocole, procédure, référence paquet, IDs parent S1AP pseudonymisés, EBI, F-TEID S11, TEID S1-U, rôles des endpoints, direction, octets, statut/version du décodeur.

Règles de corrélation :

1. S1AP/NAS : mêmes IDs parent explicites dans le même scope.
2. S1AP↔S11 : preuve E-RAB/TEID explicite et unique.
3. S11↔S1-U : TEID unique + scope de capture + paire d'endpoints/rôles.
4. L'égalité de TEID prouve un tunnel, jamais une identité abonné.
5. La proximité temporelle seule ne crée aucune identité ni arête.

## Contrat ANR2 → ANR3

ANR2 confirme les mêmes `profile_id` et `scenario_id`. Le run doit remettre `run_id`, `evidence_schema`, les `evidence_refs` et `capture_refs` conformes au schéma ANR1, sans identité. ANR3 publie ensuite sessions/callflows paginés, provenance paquet, compteurs UL/DL et confiance/limitations des arêtes. Toute valeur inconnue reste `null/UNKNOWN`, jamais zéro inventé.

## Défauts et blocages ouverts

1. Aucun triplet PCAP réel S1-MME/S11/S1-U anonymisé et approuvé par ANR1 : **GATE 6 bloqué**.
2. Extraction E-RAB transport/TEID sur encodage APER réel non prouvée.
3. Continuité multi-UE réelle et absence de contamination croisée non prouvées.
4. Activation live-probe/API LTE en production interdite avant validation des fixtures réelles.
5. Le worktree de développement partagé a reçu des modifications OIRAN 2.6.0/live-probe 0.3.0 non liées pendant la validation ; elles ont été préservées et exclues. Tous les tests ANR3 ont été exécutés depuis le worktree propre `cert/anr3-oiran-lte-offline-v1`.

## État final

- Code hors production : **IMPLEMENTED / TESTED / COMMITTED / PUSHED**.
- Déploiement : **NON EXÉCUTÉ**.
- Live/capture/trafic : **NON EXÉCUTÉ**.
- Open5GS, POLARIS, services, captures externes : **NON MODIFIÉS**.
- Certification offline synthétique : **PASS**.
- Certification LTE réelle : **BLOCKED** par les preuves PCAP approuvées manquantes.

— ANR3
