# POLARIS API — Mode « run de certification » LTE

> Contrat réservé **opérateur**, tracé par run, sans secret dans le
> code ni dans les journaux. Document à appliquer en API 0.30.0
> au-dessus de 0.29.16 (déployée), sur la branche `feat/polaris-api-0.30.0-lte-run-certif`.

## Motivation (ANR1 #10 comment 6737561274, 2026-11-09)

> « L'API 0.29.16 annonce LTE `available:true, certified:false,
> reason:LTE_E2E_CERTIFICATION_REQUIRED`; les pas `lte_attach`,
> `lte_detach`, `lte_traffic_ul`, `lte_traffic_dl` sont refusés HTTP
> 423; les définitions attach/detach sont `CERTIFICATION_REQUIRED`,
> les scénarios de données `BACKEND_REQUIRED`. »

Impasse : **le run produit lui-même la certification**. Sans un
chemin autorisé pour exécuter les pas une première fois, l'API
reste définitivement bloquée. Le mode « run de certification »
ouvre cette fenêtre d'exécution d'une manière contrôlée.

## Contrat

### 1. Autorisation

Mode activable **uniquement** par un rôle `operator` ou
`administrator`. Pattern existant 0.29.16 : `require_operator`
(`POLARIS_CONTROL/apps/api/src/lib.rs:6005-6019`) — rôle +
`csrf_valid`. Pas de duplication : la nouvelle route réutilise la
même garde.

### 2. Endpoint

```
POST /polaris-api/v1/lte/certification-run
Content-Type: application/json

{
  "run_id": "lte-certif-YYYYMMDDTHHMMSS-<short-uuid>",
  "steps": ["lte_attach", "lte_traffic_ul", "lte_traffic_dl", "lte_detach"],
  "profile": "LTE-SRSUE-TEST-01",
  "evidence_sink": "oiran-dataset-dir"
}
```

Réponse (succès) :
```json
{
  "run_id": "lte-certif-...",
  "state": "AUTHORIZED",
  "authorized_steps": ["lte_attach", "lte_detach", "lte_traffic_ul", "lte_traffic_dl"],
  "backend_compose_profile": "lte",
  "containers_bootstrapped": ["oiran-lab-srsenb-1", "oiran-lab-srsue-1"]
}
```

Refus (403) si pas operator/CSRF, (423) si une certification est
déjà active, (409) si `run_id` collision.

### 3. Trace

Chaque demande produit **une ligne d'audit** append-only sous
`/var/lib/polaris/audit/lte-certification-runs.jsonl` :

```json
{
  "event": "LTE_CERTIFICATION_RUN_AUTHORIZED",
  "run_id": "lte-certif-...",
  "authorized_at_epoch_s": 1794163383,
  "operator_username_pseudo": "psn-...",
  "operator_role": "operator",
  "steps": ["lte_attach", "lte_traffic_ul", "lte_traffic_dl", "lte_detach"],
  "target_dn": "10.77.16.30",
  "target_dn_service": "polaris-lte-sgi-dn"
}
```

- `operator_username_pseudo` : pseudonyme HMAC-SHA256 du username
  (clé `PseudonymKey` partagée avec OIRAN event-schema 2.9.9) —
  **jamais** l'IMSI/SUPI/MSISDN ni le username en clair dans le
  journal.
- `target_dn` : lu du scénario, pas du code (`config/scenarios/lte.yaml`
  après le fix 10.77.16.30, cf. `POLARIS_CONTROL/deployment/oiran-lab/README.md`).
- Append-only + fsync par ligne pour la durabilité crash-safe.

Fin du run : seconde ligne `LTE_CERTIFICATION_RUN_COMPLETED` ou
`..._FAILED` avec les compteurs d'étapes passées/failed. L'opérateur
peut ensuite marquer le backend `certified: true` via le pipeline
de certification (hors scope ce document).

### 4. Pas autorisés

Durant la fenêtre `state=AUTHORIZED`, les routes existantes qui
servent `lte_attach`/`lte_detach`/`lte_traffic_ul`/`lte_traffic_dl`
retournent 200 au lieu de 423 **iff** :

1. La requête porte un en-tête `X-Polaris-Certification-Run-Id`
   contenant un `run_id` dont l'état est `AUTHORIZED` et non
   expiré (fenêtre maximum 1 h, configurable).
2. L'identité de la requête matche le pseudo opérateur du run.
3. Le step demandé est dans la liste `authorized_steps`.

Sans ces trois conditions, 423 reste le comportement par défaut.

### 5. Démarrage conteneurs LTE

Le mode orchestre `docker compose --profile lte up -d srsenb srsue`
via `compose_file_args()` déjà en place (`srsran_controller.rs:17`
+ `COMPOSE_FILE_ARGS` 0.29.13). **Pas de secret dans le code** :
tous les paramètres (PLMN, TAC, APN, IMSI, K, OPc) proviennent des
profils stockés en base (`ue_profiles.rs`), lus par le binder
compose existant.

### 6. Arrêt

À la fin du run (succès ou échec), le mode :
1. Arrête `srsenb` + `srsue` (`docker compose down` ciblé).
2. Marque le run `COMPLETED`/`FAILED` dans l'audit.
3. Libère l'état `AUTHORIZED` → retour à 423 par défaut.

## Tests (prescrits pour 0.30.0)

- `lte_certification_run_requires_operator_role` : viewer → 403.
- `lte_certification_run_rejects_conflicting_run_id` : 2 runs
  simultanés → 409.
- `lte_certification_run_authorizes_only_listed_steps` : step
  inconnu → 400.
- `lte_certification_run_audit_line_pseudonymises_operator` :
  la ligne JSONL n'expose PAS le username clair.
- `lte_certification_run_expiry_closes_window` : au-delà de la
  fenêtre configurée, 423 retour par défaut.
- `lte_certification_run_target_dn_comes_from_scenario` : lit
  `10.77.16.30` depuis `config/scenarios/lte.yaml`, jamais en dur.

## Statut

Prescription, non-implémentée sur cette branche sim-0.13.3
(l'infra certification 0.29.x n'existe pas ici). Implémentation
attendue sur la branche de la 0.30.0 au-dessus de 0.29.16.
