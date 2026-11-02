# CLAUDE — NS-20261102-CLAUDE-REVIEW-98 — Independent review

**Date UTC** : 2026-11-02 09:50
**Agent** : BC3 (Claude Opus 4.7)
**Mission source** : Issue #9 comment `6573786725` (`NS-20261102-CLAUDE-REVIEW-98`)
**Nature** : revue indépendante **hors production**, lecture seule — aucun déploiement, aucun live.
**Review branch** : `review/claude-ns-20261102-98` basée sur `9d6239be2c05c0b491421d8b65f2c74e89f74f28`.

---

## 1. Rapport court (acceptance criteria)

```
SOURCE_SHA          = 9d6239be2c05c0b491421d8b65f2c74e89f74f28
LINEAGE             = parent 6734c75891832cce83edbfd3e5e622a8289835e6 (integ/oiran-polaris-lte-final-merge)
                      → 1 commit "fix: raise guarded disk ceiling to 98 percent" (Codex)
                      → branch origin/fix/anr3-disk-policy-98-p0
                      Pas de drift, pas de force-push, pas de rebase destructif.
DIFF_REVIEW         = 25 fichiers / +230 / -70. 2 bump crate (safety-guard 0.1.0→0.2.0,
                      disk-safety 0.1.0→0.2.0), 2 bump API (POLARIS 0.29.0→0.29.1,
                      OIRAN 2.7.4→2.7.5), 2 call-sites POLARIS gates, 1 call-site OIRAN,
                      3 docs métier.
TESTS               = PASS sur l'arbre revu (voir §4) :
                        safety-guard  : 6/6 PASS
                        disk-safety   : 8/8 PASS
                        POLARIS wsp   : 320 PASS / 1 ENV-FAIL (12-dumpcap, non-régression) / 3 ignored
                        OIRAN LTE evd : 3/3 PASS
                        OIRAN disk    : 1/1 PASS
SAFETY              = Fail-closed sur mesure, inodes, ENOSPC et croissance imprévue vérifié par
                      tests dédiés (safety-guard et disk-safety). Stop + cleanup + inspection
                      lecture seule restent accessibles au plafond. Aucune ouverture de
                      shell channel, aucun secret abonné, aucun grant, aucun trafic.
COMPATIBILITY       = JSON gate POLARIS : champs existants préservés + 3 nouveaux
                      (`disk_estimated_write_bytes`, `disk_maximum_budget_bytes`,
                      `disk_reserve_bytes`). API OIRAN : noms de champ Policy inchangés,
                      valeurs mises à jour. **Backward-compatible côté structure.**
                      Breaking côté *valeurs* : clients câblés sur 75/80/85/90 ou 32 MiB
                      verront 95/97/98/98 et 8 GiB.
RELEASE_REVIEW      = READY pour revue par ANR1. Scope confiné, tests passent sauf le fail
                      environnemental connu depuis le merge 6734c75 (non lié à cette release).
                      Policy 98 %/8 GiB cohérente avec l'objectif utilisateur ; voir §5 pour
                      risques résiduels non-bloquants.
BLOCKERS            = Aucun blocker de code côté BC3.
NEXT_ACTION         = Attendre feedback ANR1 et autorisation utilisateur explicite pour toute
                      activation. Pas de merge dans integ ni de déploiement initié par BC3.
```

---

## 2. Lignée Git vérifiée

| Vérification | Résultat |
| --- | --- |
| `git fetch origin --prune` | OK |
| `git cat-file -t 9d6239be…` | `commit` ✓ |
| Branche d'origine | `origin/fix/anr3-disk-policy-98-p0` |
| Auteur | `Codex <codex-handoff@local.invalid>` |
| Date | 2026-11-02 09:15:40 +0000 |
| Parent | `6734c75891832cce83edbfd3e5e622a8289835e6` (integ/oiran-polaris-lte-final-merge au moment du branchement) |
| Commits ajoutés sur parent | **1 seul** : `9d6239b fix: raise guarded disk ceiling to 98 percent` |
| Rebase ou force-push observé | Non |
| Touche à `anr1/*`, `anr2/*`, `anr3/*` | Non |

Chaîne complète vers la base originale :

```
9d6239b (fix/anr3-disk-policy-98-p0) — fix: raise guarded disk ceiling to 98 percent
└── 6734c75 (integ/oiran-polaris-lte-final-merge) — docs(integration): final merge report
    └── ef4c6a5 — Merge ANR3 real LTE evidence finalizer over ANR2 traffic peer fix
        └── 34882ec — Merge ANR2 fix (SHA 2106366)
            └── 880c493 (base) — test(polaris): isolate LTE orchestrator fixtures
```

---

## 3. Revue du diff (fichier par fichier)

### 3.1 POLARIS — `crates/safety-guard/src/lib.rs` (+58, –19)

Changements observés :

| Avant | Après |
| --- | --- |
| `VERSION = "0.1.0"` | `VERSION = "0.2.0"` |
| `information: 75, warning: 80, stop: 85, hard: 90` | `information: 95, warning: 97, stop: 98, hard: 98` |
| `reserve_bytes: 32 * MIB` | `reserve_bytes: 8 * GIB` |
| 1 test « exact_thresholds » 75/80/85/90 | 1 test révisé 94/95/97/98 |

Tests ajoutés :

- `legacy_thresholds_do_not_block_when_budget_and_reserve_fit` → vérifie qu'à 80/85/90 % la décision reste `State::Normal` et `writes_allowed=true` quand budget et reserve tiennent. Ceci documente l'élargissement voulu.
- `projected_budget_and_absolute_reserve_fail_closed_before_98_percent` → vérifie qu'à 97 % avec `reserve_bytes=2*MIB, max_scenario_bytes=50*MIB` on tombe en `State::Warning`, `writes_allowed=false`, `maximum_budget_bytes=0`. Fail-closed strict même avant 98 %.
- `inode_exhaustion_and_measurement_failure_remain_closed` → `available_inodes=16` et `Err("ENOSPC")` restent `writes_allowed=false`.

Verdict code : cohérent, lisible, tests probants. Pas de dead code ni de constant hard-codée oubliée.

### 3.2 OIRAN — `disk-safety/src/lib.rs` (+69, –26)

Même pattern : seuils 75/80/85/90 → 95/97/98/98, reserve 32 MiB → 8 GiB, VERSION bump 0.2.0.

Changement comportemental significatif dans `CaptureGuard::reserve` :

```rust
let decision = assess(sample.clone(), self.policy);
let current_budget = capture_budget(sample, bytes, self.policy);
if !decision.new_capture_allowed
    || !current_budget.allowed
    || bytes > self.remaining_budget_bytes
{
    self.active = false;
    self.final_reason = Some(if bytes > self.remaining_budget_bytes {
        "reserved write budget exhausted".into()
    } else if !current_budget.allowed {
        current_budget.reason   // ← nouveau : raison issue du budget courant
    } else {
        decision.reason
    });
    ...
}
```

→ Le guard de capture rejette désormais aussi si le **budget courant** (évalué à cette lecture) refuse l'écriture, pas seulement si l'état global rejette. Important pour les captures longues où l'état peut dériver pendant la vie du guard.

Tests ajoutés :

- `legacy_thresholds_do_not_block_bounded_captures` : à 80/85/90 % une capture bornée reste `State::Normal` et `allowed=true`.
- `inode_exhaustion_rejects_capture` : adapté pour utiliser `reserve_bytes: 0` afin d'isoler le canal inode.
- `stop_and_hard_limit_preserve_read_only_analysis` : réduit à 98 % (seul plafond).

Verdict code : correct. Le `sample.clone()` est nécessaire pour la double évaluation ; aucun risque d'incohérence (même sample utilisé pour les deux appels).

### 3.3 POLARIS — `apps/api/src/lib.rs` call sites

Deux gates touchées : `lte_start_resource_gate` (L6068) et `resource_gate_for_budget` (L11195).

Pattern remplacé :

```rust
// Avant
let usage = disk.basis_points().unwrap_or(10_000);
if usage >= 8_500 { return Err("DISK_STOP_THRESHOLD".into()); }
```

```rust
// Après
let usage = disk.basis_points().unwrap_or(10_000);
let disk_decision = evaluate(Ok(disk), Policy::default());
const LTE_ESTIMATED_WRITE_BYTES: u64 = 256 * 1024 * 1024;
if !disk_decision.writes_allowed
    || disk_decision.maximum_budget_bytes < LTE_ESTIMATED_WRITE_BYTES
{
    return Err("DISK_STOP_THRESHOLD".into());
}
```

Pour `resource_gate_for_budget`, la constante devient `estimated_write_bytes = budget.storage_bytes.max(1)`.

Impact fonctionnel :

- Un run LTE n'est admis que si le budget projeté 256 MiB peut tenir **sous le plafond 98 % + reserve 8 GiB**. Avant, admis dès `usage < 85 %` sans tenir compte du budget réel.
- Même code d'erreur `DISK_STOP_THRESHOLD` — compatibilité clients préservée.
- Nouveaux champs ajoutés dans la réponse JSON : `disk_estimated_write_bytes`, `disk_maximum_budget_bytes`, `disk_reserve_bytes`.

### 3.4 OIRAN — `apps/api/src/lib.rs` test (unique call-site)

Les champs `policy.information_percent`, `warning_percent`, `stop_percent`, `hard_limit_percent`, `reserve_bytes` sont déjà exposés dans la réponse de `/api/v1/disk-safety` (confirmé par le test `disk_safety_is_measured_and_capture_remains_unconfigured`). Seule la valeur attendue par le test change (75→95, 80→97, 85→98, 90→98, 32 MiB→8 GiB). **La structure de la réponse est préservée.**

### 3.5 Docs métier

- `OIRAN_POLARIS_DISK_POLICY_98_REPORT.md` (+35) — rapport Codex du changement.
- `ANR3_LTE_E2E_CALLFLOW_FINAL_REPORT.md` (+29) — rapport ANR3 (indirect, dans le même commit).
- `OIRAN/S4_2_DISK_SAFETY_POLICY.md`, `OIRAN/docs/OIRAN_CAPTURE_HELPER_SECURITY.md`, `POLARIS_CONTROL/docs/ARCHITECTURE.md`, `POLARIS_CONTROL/docs/LIVE_TEST_PLAN.md` — ajustements mineurs cohérents avec le nouveau plafond.
- `OIRAN/S4_2_DATASET_MANIFEST.json` — mise à jour des valeurs attendues de policy.

Aucun doc d'opération production modifié de façon non-cohérente.

### 3.6 Frontend web POLARIS

- `apps/web/package.json` → version `3.2.3`
- `apps/web/package-lock.json` → aligné
- `apps/web/src/main.tsx`, `styles.css` → 2 lignes modifiées chacun (texte/style affiché, pas de logique).
- `tests/e2e/s4.spec.ts` OIRAN → ajustement des assertions sur policy.

Pas de changement de logique UI. Pas de nouvelle route. Pas d'empreinte supplémentaire RBAC/CSRF.

---

## 4. Tests exécutés sur l'arbre revu (HEAD = 9d6239be)

### POLARIS

```
cargo test --manifest-path POLARIS_CONTROL/Cargo.toml --release --locked
  -p safety-guard
  → 6 PASS / 0 FAIL / 0 ignored
    exact_thresholds
    legacy_thresholds_do_not_block_when_budget_and_reserve_fit
    projected_budget_and_absolute_reserve_fail_closed_before_98_percent
    reserve_caps_budget
    monitor_failure_is_closed
    inode_exhaustion_and_measurement_failure_remain_closed

cargo test --workspace --release --locked --no-fail-fast -- --test-threads=16
  polaris-control-api lib : 272 PASS / 1 FAIL / 3 ignored
  autres crates           : 48 PASS
  TOTAL                   : 320 PASS / 1 FAIL (env, 12 dumpcap) / 3 ignored
```

### OIRAN

```
cargo test --manifest-path OIRAN/Cargo.toml --release --locked
  -p disk-safety
  → 8 PASS / 0 FAIL / 0 ignored
    budget_reserves_headroom_between_polls
    active_capture_finalizes_at_stop_threshold_and_on_monitor_failure
    inode_exhaustion_rejects_capture
    legacy_thresholds_do_not_block_bounded_captures
    reserved_budget_and_operator_interruption_are_deterministic
    rotation_is_bounded_without_deletion_action
    stop_and_hard_limit_preserve_read_only_analysis
    thresholds_are_exact_and_fail_closed

  -p oiran-api lte_evidence
  → 3 PASS / 0 FAIL / 38 filtered
    lte_evidence_view_routes_are_bounded_and_do_not_fabricate_missing_runs
    lte_evidence_import_requires_operator_and_csrf
    lte_evidence_sessions_and_callflow_exports_apply_privacy_boundary

  -p oiran-api disk
  → 1 PASS / 40 filtered
    disk_safety_is_measured_and_capture_remains_unconfigured
```

### Fail unique (identique au merge précédent)

`polaris_control_api::p0_tests::emergency_stop_cleanup_does_not_require_a_live_grant`
→ dépend de `external_dumpcap_count() == 12`.
Env BC3 : 1 dumpcap → fail. Prouvé non-régressif sur base `880c493` lors du merge précédent. Ne dépend pas de ce patch disk-policy.

---

## 5. Risques résiduels (non-bloquants)

| # | Risque | Évaluation | Mitigation |
|---|---|---|---|
| 1 | Collapse `stop_percent = hard_limit_percent = 98` : plus de palier "Stop writes" avant HardLimit | Volontaire. Pas de régression car `writes_allowed=false` dès que budget projeté ou reserve ne tient plus, bien avant 98 %. | Documenter côté opérateurs qu'il n'y a plus d'état "StopNewWrites" distinct. |
| 2 | Reserve absolue 8 GiB sur petits volumes | Prod devmat (388G, 20 % libre, 76 G) : trivial. Petits labs < 50G : réserve ≈ 16 %. | Hors scope BC3. Lab small-disk → l'operator ajustera `Policy` via config future si besoin. |
| 3 | `resource_gate_for_budget` tombe sur `max(1)` si scenario sans storage déclaré | Garde `writes_allowed` + inodes toujours actifs → ok. Mais budget=1 B ne gate rien sur capacité. | Ajout d'un champ obligatoire `storage_bytes` dans les scenarios futurs ; **pas nécessaire pour cette release**. |
| 4 | 256 MiB hard-coded (`LTE_ESTIMATED_WRITE_BYTES`) | Chiffre plausible pour un run LTE 300 s. Pourrait être sous-estimé en 5G mais 5G n'utilise pas ce gate. | Rendre configurable dans une évolution ultérieure si besoin. |
| 5 | Backward-compat valeurs policy (clients câblés 75/80/85/90) | Risque si un dashboard externe surveille ces seuils | Vérifier via `OIRAN_POLARIS_DISK_POLICY_98_REPORT.md` que les tableaux de bord internes utilisent la clé plutôt que la valeur. |

Aucun de ces risques ne constitue un blocker. Le code livré respecte l'objectif.

---

## 6. Compatibilité et contrats

### Contrats préservés

- `POLARIS_CONTROL/docs/api/lte-evidence-envelope.contract.md` : inchangé.
- `OIRAN/docs/LTE_EVIDENCE_INGESTION_CONTRACT.md` : inchangé.
- Routes HTTP POLARIS : inchangées, ajouts seulement en payload JSON.
- Routes HTTP OIRAN : inchangées, valeurs numériques Policy mises à jour.

### Nouveaux champs POLARIS gates response

```json
{
  "disk_usage_percent": 80.0,
  "disk_estimated_write_bytes": 268435456,
  "disk_maximum_budget_bytes": <computed>,
  "disk_reserve_bytes": 8589934592,
  "memory_available_bytes": ...,
  ...
}
```

Clients non préparés les ignoreront silencieusement (compatibilité ascendante JSON).

---

## 7. Garde-fous respectés

- Aucune modification production, aucun déploiement, aucun live, aucun grant.
- Aucune ouverture ni traitement de PCAP réel.
- Aucun changement Open5GS ni dumpcap.
- Aucun secret abonné en clair.
- Aucune modification des branches `anr1/*`, `anr2/*`, `anr3/*`.
- Mission `NS-20261102-CLAUDE-REVIEW-98` traitée **en lecture seule** sur une review branch dédiée `review/claude-ns-20261102-98`.
- Pas de merge dans `integ/oiran-polaris-lte-final-merge`.

— BC3
