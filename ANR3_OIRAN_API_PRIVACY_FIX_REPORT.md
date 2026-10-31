# ANR3 — OIRAN API Privacy Fix P0

Date: 2026-10-31  
Verdict: **PASS (offline, non déployé)**  
Base vérifiée: `integ/polaris-real-lab-live-v1` / `7f84c4963c36b80c582f7572000596a2ab7c57d9`  
Branche isolée: `fix/anr3-oiran-api-privacy-p0`  
Commit du correctif: `d02d57f`  
Version: OIRAN API `2.7.1` (Platform inchangée `2.7.0`)

## Route et cause

La fuite reproductible provenait de `GET /api/v1/sessions/:id/callflow`: le champ
`decoded_ie_tree` était sérialisé avec un élément d'identité d'équipement masqué.
Le même modèle pouvait être lu par les routes suivantes:

- `GET /api/v1/sessions/:id/events`
- `GET /api/v1/events/:id`
- `GET /api/v1/packets` et `GET /api/v1/packets/:id`
- `GET /api/v1/exports/callflow/:id?format=json`
- `GET /api/v1/exports/callflow/:id?format=html`

La protection antérieure remplaçait seulement la valeur par un marqueur, laissant
le nom/type de l'identité visible. L'export HTML primaire lisait en outre un fichier
pré-rendu qui ne bénéficiait pas de la sérialisation assainie.

## Correction

- Suppression complète des clés et objets portant une identité abonné ou équipement,
  après normalisation des variantes de casse, espaces, tirets et underscores.
- Application défensive du filtre aux deux sorties JSON communes: réponses simples
  et réponses paginées. Cela couvre datasets, sessions, événements, paquets, Call
  Flow et les futurs handlers qui utilisent ces sorties.
- Régénération de l'export HTML depuis un `CallFlow` assaini; le fichier pré-rendu
  n'est plus renvoyé directement.
- Conservation des données utiles vérifiée: événements/procédures protocole,
  compteurs de source, provenance expurgée et identifiants techniques non privés.
- Confidentialité identique pour une lecture viewer et une lecture operator.
- SemVer `2.7.0` → `2.7.1`, lockfile et `OIRAN/CHANGELOG.md` mis à jour.

## Routes testées sur réponses brutes

| Route | Contrôle | Résultat |
|---|---|---|
| `/api/v1/datasets?page_size=100` | JSON brut, données utiles présentes | PASS |
| `/api/v1/sessions?page_size=100` | JSON brut, données utiles présentes | PASS |
| `/api/v1/sessions/:id` | JSON brut | PASS |
| `/api/v1/sessions/:id/events?page_size=100` | JSON brut | PASS |
| `/api/v1/sessions/:id/callflow?limit=100` | viewer + operator, événements et accounting présents | PASS |
| `/api/v1/events/:id` | événement qui contenait l'IE privé dans la fixture interne | PASS |
| `/api/v1/events/:id/provenance` | provenance expurgée | PASS |
| `/api/v1/packets` et `/api/v1/packets/:id` | liste et détail bruts | PASS |
| `/api/v1/exports/callflow/:id?format=json` | export JSON brut | PASS |
| `/api/v1/exports/callflow/:id?format=html` | export HTML régénéré et scanné | PASS |

La preuve de test est volontairement expurgée: la fixture interne contient bien
l'élément privé avant sérialisation, puis aucune clé, étiquette ou valeur d'identité
n'est présente dans les corps de réponse.

## Tests manuels et preuves

Commandes exécutées depuis `/root/OIRAN_API_PRIVACY_ANR3/OIRAN`:

```text
cargo test -p oiran-api response_sanitizer_removes_identity_fields_and_identity_ies -- --nocapture
PASS — 1 passed, 0 failed

cargo test -p oiran-api raw_read_routes_remove_identity_material_for_viewer_and_operator -- --nocapture
PASS final — 1 passed, 0 failed

cargo test -p oiran-api
PASS — 38 passed, 0 failed, doctests 0 failed

cargo test -p live-probe
PASS — 52 passed, 0 failed, 4 ignored (tests de très gros volumes), doctests 0 failed

git diff --check
PASS — aucune erreur

rg -n -i 'masked.?imeisv|masked_imeisv|identity_withheld' \
  OIRAN/apps/api/src OIRAN/apps/api/Cargo.toml OIRAN/CHANGELOG.md
PASS avec occurrences attendues exclusivement dans les tests de régression
```

Le test de routes a rencontré une erreur de compilation intermédiaire `E0505` dans
le code de test nouvellement ajouté. La fixture est désormais clonée avant transfert
au routeur; le test final puis la suite complète passent.

Le gate RAM a refusé deux tentatives lorsque la mémoire disponible était
respectivement `4212383744` et `4214743040` octets, sous 4 GiB. Les suites n'ont été
lancées qu'après des mesures conformes (`4320337920` octets pour l'API et
`4320768000` avant Live Probe).

`cargo fmt --all -- --check` reste en échec sur un passif de formatage de la base:
1 461 lignes de propositions réparties dans plusieurs crates non modifiées. Aucun
reformatage massif n'a été appliqué afin de préserver le travail partagé. Les
changements présents passent `git diff --check`.

## RBAC et sécurité opérationnelle

- Les tests `lte_evidence_import_requires_operator_and_csrf`,
  `probe_creation_requires_operator_role`, `probe_creation_requires_csrf_proof`
  et les contrôles de capture protégée passent dans les 38 tests API.
- Le rôle operator ne contourne pas l'expurgation des lectures.
- Aucun dataset historique n'a été modifié.
- Aucun service, trafic, UE, capture ou déploiement n'a été démarré ou arrêté.
- Vérification finale: `12` processus `dumpcap`; disque `/root` à `51 %`.

## Limites et suite

Le correctif est certifié hors production uniquement. La production n'a pas été
modifiée et ne doit pas être considérée corrigée avant revue, autorisation de
déploiement distincte, sauvegarde/rollback et recette contrôlée des mêmes routes.

— ANR3
