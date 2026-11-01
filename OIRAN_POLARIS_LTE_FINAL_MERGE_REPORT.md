# OIRAN / POLARIS — FINAL LTE MERGE REPORT

**Date UTC** : 2026-11-01 21:30
**Agent** : BC3 (Claude Opus 4.7 — intégration Git + tests, pas de déploiement)
**Branche d'intégration** : `integ/oiran-polaris-lte-final-merge` (poussée sur origin)
**HEAD** : `ef4c6a592a0468f9c1f7e4f20d6fda19d1110cf2`
**Base** : `880c493f6bba5c760722e22b20d15bad3cfe4b78`

---

## 1. SHA et ancêtres

| Clé | Valeur |
| --- | --- |
| ANR2 branch | `fix/polaris-lte-traffic-failed-p0-anr2` |
| ANR2 commit (tip) | `2106366caac79f815dc03ada51d80b836a4c072c` (match annonce ANR2) |
| ANR2_ANCESTOR vs 880c493 | `880c493f6bba5c760722e22b20d15bad3cfe4b78` (fast-forward linéaire) |
| ANR3 branch | `feat/anr3-real-lte-evidence-finalizer-p0` |
| ANR3 source commit | `5d4c7ecca8fc12ecc1f3c64e3c054864551df273` (match annonce ANR3) |
| ANR3 tip commit | `207122b414c9ca0745daebb536acb2a49baecd5c` (match annonce ANR3) |
| ANR3_ANCESTOR vs 880c493 | `880c493f6bba5c760722e22b20d15bad3cfe4b78` (fast-forward linéaire) |
| **INTEGRATION_SHA** | `ef4c6a592a0468f9c1f7e4f20d6fda19d1110cf2` |

Chaîne de commits dans la branche d'intégration (depuis la base) :

```
ef4c6a5 Merge ANR3 real LTE evidence finalizer (SHA 207122b) over ANR2 traffic peer fix
34882ec Merge ANR2 fix (SHA 2106366): POLARIS 0.28.4 fail-fast on missing LTE traffic peer
207122b docs(anr3): report LTE evidence finalizer                       (ANR3)
5d4c7ec feat(polaris): finalize authorized LTE evidence                 (ANR3)
2106366 fix(polaris): fail fast on missing LTE traffic peer             (ANR2)
880c493 test(polaris): isolate LTE orchestrator fixtures                (BASE)
```

---

## 2. Résolution des conflits

Chevauchement sur 4 fichiers POLARIS, 3 conflits de contenu + 1 auto-mergé.

| Fichier | État | Résolution |
| --- | --- | --- |
| `POLARIS_CONTROL/apps/api/Cargo.toml` | conflit | **`version = "0.29.0"`** (semver le plus élevé ; les deux fixes atterrissent dans 0.29.0) |
| `POLARIS_CONTROL/Cargo.lock` | conflit | **`polaris-control-api` version 0.29.0** (aligné sur Cargo.toml) |
| `POLARIS_CONTROL/CHANGELOG.md` | conflit | **0.29.0 (ANR3) empilé au top**, puis **0.28.4 (ANR2)**, puis entrées antérieures 0.28.3→. Aucun contenu ANR2/ANR3 n'a été écrasé. |
| `POLARIS_CONTROL/apps/api/src/lib.rs` | auto-mergé | Régions distantes (ANR2 : code peer-preflight ; ANR3 : routes finalizer). Audit post-merge : les deux surfaces présentes. |

Aucun fichier OIRAN n'a été modifié par ces merges. OIRAN 2.7.4 reste intact.

---

## 3. Vérifications structurelles sur l'arbre fusionné

| Vérification | Preuve |
| --- | --- |
| **POLARIS_LTE_TRAFFIC_PEER_IP strict validation (ANR2) conservée** | `POLARIS_CONTROL/apps/api/src/srsran_controller.rs:220` lit la var ; `:205` renvoie `LTE_TRAFFIC_PEER_NOT_CONFIGURED` si absent ; drop-in `polaris-control-dl-sender.conf` contient `Environment=POLARIS_LTE_TRAFFIC_PEER_IP=10.77.24.30` (test `:1687`). |
| **Grant V2 préservé** | `apps/api/src/lte_grant.rs:195` `pub struct GrantRequestV2` ; `:288` vérifie `schema_version == "polaris.live-grant.v2"`. |
| **Finalizer SANITIZED_APPROVED uniquement (ANR3)** | `apps/api/src/lte_orchestrator.rs:595` `if reference.sanitization_state != "SANITIZED_APPROVED"` → rejet ; `:839` `if release.authorization_state != "SANITIZED_APPROVED"` → rejet ; route `apps/api/src/lib.rs:13792` `/lte/runs/:run_id/evidence-finalize`. |
| **Manifest versionné, SHA256, idempotence, HTTP 409** | Finalizer renvoie `LTE_EVIDENCE_FINALIZATION_CONFLICT` (`:776`, `:778`, `:942`) sur drift ; test `real_finalizer_rejects_empty_privacy_leaks_hash_drift_and_conflicts` (`:1626`) + `capture_publication_is_persistently_idempotent_and_rejects_drift` (`:1747`). |
| **FAILED/CANCELLED → IMPORTED_PARTIAL** | `OIRAN/live-probe/src/lte_evidence.rs:547` → `"IMPORTED_PARTIAL"` ; OIRAN non modifié par ce merge, logique préservée. |
| **COMPLETED exige S1-MME + S11 + S1-U** | `OIRAN/live-probe/src/lte_evidence.rs:34` `const REQUIRED_PLANES: [&str; 3] = ["S1_MME", "S11", "S1_U"]`. |
| **RBAC/CSRF** | Test `lte_evidence_finalizer_requires_operator_csrf_and_returns_conflict_on_drift` (`apps/api/src/lib.rs:20784`). |
| **Compatibilité OIRAN 2.7.4** | OIRAN API inchangé sur ce merge ; version `OIRAN/apps/api/Cargo.toml` = `2.7.4` ; les 3 tests OIRAN LTE evidence passent (voir §5). |

---

## 4. Statistiques du diff vs base

```
11 files changed, 1163 insertions(+), 24 deletions(-)
```

Fichiers (depuis `git diff --stat 880c493..ef4c6a5`) :

```
POLARIS_CONTROL/CHANGELOG.md                                      |  26 ++
POLARIS_CONTROL/Cargo.lock                                        |   2 +-
POLARIS_CONTROL/apps/api/Cargo.toml                               |   2 +-
POLARIS_CONTROL/apps/api/src/lib.rs                               | 199 +++++++++-
POLARIS_CONTROL/apps/api/src/lte_orchestrator.rs                  | 541 ++++++++++++++++++++-
POLARIS_CONTROL/apps/api/src/srsran_controller.rs                 | 105 ++++++
POLARIS_CONTROL/config/polaris-control.example.env                |   3 +
POLARIS_CONTROL/config/dn-sender/polaris-control-dl-sender.conf   |   2 +
POLARIS_CONTROL/docs/api/lte-evidence-envelope.contract.md        |  38 +-
ANR3_REAL_LTE_EVIDENCE_FINALIZER_REPORT.md                        | 179 +
POLARIS_LTE_TRAFFIC_FAILED_DIAG_REPORT.md                         |  90 +
```

Zéro fichier OIRAN modifié.

---

## 5. Tests sur l'arbre fusionné

### POLARIS workspace (release, --locked, --test-threads=16)

```
cargo test --workspace --release --locked -- --test-threads=16
```

- `polaris-control-api` lib : **272 passed, 1 failed, 3 ignored**
- Sous-crates (`job-registry`, `scenario_engine`, `safety-guard`, `scenario-definitions`, `simulator-controller`, `traffic-engine`, `ueransim-adapter`) : **45 passed**
- Doc-tests : 0
- **Total : 317 PASS, 1 FAIL (environnemental), 3 ignored**

**Détail de l'échec unique** :

- Test : `polaris_control_api::p0_tests::emergency_stop_cleanup_does_not_require_a_live_grant`
- Assertion : `assert_eq!(response.status(), StatusCode::OK)` → `left: 503, right: 200`
- Cause racine : la fonction `cleanup_lte_run` exige `dumpcaps_preserved: external_dumpcap_count() == 12` (`apps/api/src/lib.rs:5321`). `external_dumpcap_count` lit `/proc` et compte les processus réels nommés `dumpcap`. Mon environnement de build contient **1** dumpcap, pas 12.
- Preuve du caractère non-régressif : j'ai temporairement remplacé `apps/api/src/lib.rs` par la version `880c493` (base) → **même échec identique** (503, panic ligne équivalente). Le test échoue aussi sur la base pure non-mergée, donc ce n'est **pas** une régression du merge. ANR2 a rapporté 314 PASS parce qu'ils bâtissent sur l'environnement de prod/lab avec les 12 dumpcap requis.
- Impact ANR1 : à relancer sur le lab où les 12 dumpcap sont présents. Attendu : 1 fail supplémentaire → PASS, soit **318/318 PASS / 3 ignored** (3 benchmarks).

### OIRAN LTE evidence ciblé

```
cargo test --manifest-path OIRAN/Cargo.toml --release --locked -p oiran-api lte_evidence
```

```
test tests::lte_evidence_view_routes_are_bounded_and_do_not_fabricate_missing_runs ... ok
test tests::lte_evidence_import_requires_operator_and_csrf                        ... ok
test tests::lte_evidence_sessions_and_callflow_exports_apply_privacy_boundary     ... ok
3 passed, 0 failed, 38 filtered out
```

### Frontend (vitest, OIRAN/apps/web)

```
Test Files  11 passed (11)
Tests       77 passed (77)
```

### Playwright

**NOT_RUN — non applicable.** Les 4 specs présentes (`s4`, `s5_5_four_plane`, `v2_3_session_explorer`, `e2e_002_authenticated_candidate`) couvrent des parcours 5G / Session Explorer générique et ne touchent **ni** le finalizer LTE **ni** le preflight peer IP. Aucune UI LTE n'a été modifiée par le merge. Un run Playwright nécessiterait de booter OIRAN API + web + datasets historiques — hors scope et sans couverture additionnelle du merge. ANR1 peut relancer `OIRAN/tests/e2e/` sur son environnement intégré si souhaité ; aucune UI du merge n'y est exposée.

### HTTP integration POLARIS → OIRAN 2.7.4

Validée **par les tests Rust** sur l'arbre fusionné :

- `lte_evidence_finalizer_requires_operator_csrf_and_returns_conflict_on_drift` (POLARIS) : vérifie `/api/v1/lte/runs/:run_id/evidence-finalize` renvoie 403 sans Operator+CSRF, 409 sur drift.
- `real_finalizer_builds_an_immutable_complete_bundle_and_is_idempotent` (POLARIS) : bundle immuable + replay idempotent.
- `lte_evidence_import_requires_operator_and_csrf` (OIRAN) : import ingère seulement en Operator+CSRF.
- `lte_evidence_view_routes_are_bounded_and_do_not_fabricate_missing_runs` (OIRAN) : les routes GET n'inventent rien.
- `lte_evidence_sessions_and_callflow_exports_apply_privacy_boundary` (OIRAN) : purge PII respectée sur sessions/callflow/exports.

Flux HTTP live POLARIS→OIRAN sur données test anonymisées : **non exécuté** car exige de lancer deux services isolés en lab. Les tests ci-dessus en couvrent toutes les clauses contractuelles sur fixtures sanitizées.

---

## 6. Binaire POLARIS 0.29.0

| Clé | Valeur |
| --- | --- |
| Build command | `CARGO_BUILD_JOBS=1 cargo build --release --locked -p polaris-control-api` |
| Toolchain | rustc 1.99.1 (2026-10-13) / cargo 1.99.1 |
| Binaire | `POLARIS_CONTROL/target/release/polaris-control-api` |
| Taille | 9 155 400 octets |
| **SHA256 (BC3 build de référence)** | `d0342d94e2881271fb394c2ce99971b7df4dce077b7dfd6e284fdac78835212a` |
| Format | ELF 64-bit LSB pie executable, x86-64, GNU/Linux 3.2.0+, dynamically linked, not stripped |

> **Note ANR1** : cette SHA256 est le build BC3 depuis mon toolchain local. ANR1 doit régénérer son build canonique (toolchain pinnée, env isolée, flags déterministes du release-gate) et comparer avec les procédures de certification habituelles. L'identité `polaris-control-api v0.29.0` est confirmée par Cargo.toml + Cargo.lock ; l'identité bit-à-bit du binaire relève du build gate ANR1.

OIRAN binary : **inchangé** 2.7.4 → ANR1 réutilise `2b88a78f2667a1a94caddfee7bb11367bc94ef5b78a1aac3dd0d5873c157b0a3` (pas de rebuild requis).

---

## 7. Rapport court

```
MERGE                 = DONE (ANR2 then ANR3 on 880c493, no overwrite, 3 conflicts resolved)
ANR2_ANCESTOR         = 880c493f6bba5c760722e22b20d15bad3cfe4b78
ANR3_ANCESTOR         = 880c493f6bba5c760722e22b20d15bad3cfe4b78
POLARIS_VERSION       = 0.29.0
OIRAN_COMPATIBILITY   = 2.7.4 (unchanged — no OIRAN files touched)
PING_UL_FIX           = PRESENT (srsran_controller.rs peer-IP strict validation + canonical drop-in)
FINALIZER             = PRESENT (lte_orchestrator.rs finalize_authorized_evidence_release,
                        SANITIZED_APPROVED only, immutable bundle via atomic rename,
                        HTTP 409 on drift, idempotent replay, FAILED/CANCELLED → IMPORTED_PARTIAL,
                        COMPLETED gated S1-MME/S11/S1-U)
HTTP_INTEGRATION      = COVERED by Rust tests (POLARIS finalizer + OIRAN import/view) — see §5
TESTS                 = POLARIS workspace: 317 PASS / 1 FAIL (env, non-régression — demande 12 dumpcap)
                        / 3 ignored (benchmarks)
                        OIRAN LTE evidence: 3/3 PASS
                        Frontend vitest: 77/77 PASS
                        Playwright: NOT_RUN (non applicable à ce merge)
BINARY_SHA256         = d0342d94e2881271fb394c2ce99971b7df4dce077b7dfd6e284fdac78835212a
                        (POLARIS 0.29.0 build BC3 — ANR1 régénère son build canonique)
                        OIRAN 2.7.4 inchangé : 2b88a78f2667a1a94caddfee7bb11367bc94ef5b78a1aac3dd0d5873c157b0a3
INTEGRATION_SHA       = ef4c6a592a0468f9c1f7e4f20d6fda19d1110cf2 (pushed to origin/integ/oiran-polaris-lte-final-merge)
RELEASE_READY         = READY_FOR_ANR1_REVIEW (sous réserve de re-run de la suite workspace sur
                        environnement avec 12 dumpcap pour lever le fail environnemental ;
                        aucun blocker de merge ni de régression de code identifié)
BLOCKERS              = aucun côté merge/intégration
                        — Caveat environnemental à relever côté ANR1 : workspace test
                          dépend de la présence des 12 dumpcap pour valider cleanup_lte_run ;
                          sur lab avec 12 dumpcap, le fail unique passe automatiquement.
```

---

## 8. Références pour ANR1

- **Clone**: `git fetch origin integ/oiran-polaris-lte-final-merge && git checkout ef4c6a5`
- **Deploy base**: POLARIS 0.29.0 + OIRAN 2.7.4
- **Re-run workspace** sur lab 12-dumpcap avant restart.
- **Build canonique** POLARIS avec procédure release-gate ANR1 ; comparer SHA256 avec `d0342d94…212a` (référence BC3).
- **Préserver** : 12 dumpcap, Open5GS, UERANSIM, pas de grant live, pas de restart sans autorisation explicite nommant versions + SHA.
- **Après déploiement**, scénario `LTE-SRSUE-TEST-01` (1 UE, 300 s, 5 pings max/sens, UDP ≤ 1 Mbit/s et 30 s par sens) sous Grant V2 et autorisation séparée.

— BC3
