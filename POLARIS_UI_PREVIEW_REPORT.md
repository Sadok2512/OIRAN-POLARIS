# POLARIS LTE/5G UI Preview V1 — ANR2

Date UTC: 2026-10-31  
Verdict: **PASS (preview locale isolée, mock/read-only)**  
Production: **non modifiée**  
Live LTE/5G, grant et trafic: **non exécutés**

## Git et version retenue

- Dépôt: `Sadok2512/OIRAN-POLARIS`
- Worktree isolé: `/root/OIRAN_POLARIS_UI_PREVIEW_ANR2`
- Branche: `preview/polaris-lte-ui-v1`
- Base demandée: `671282b6e4b540722f82f896d2a95aece924fc51`
- Base de travail avant le commit preview: `75bf23134236c38505db3b3fd185dee2f34c7d75`
- Frontend: `@telecom/simulator-control` **0.15.1**

Lignée vérifiée manuellement:

```text
git merge-base --is-ancestor 671282b6e4b540722f82f896d2a95aece924fc51 HEAD  # YES
git merge-base --is-ancestor a39e692 HEAD                                      # YES (frontend 0.13.1)
git merge-base --is-ancestor a44f23e HEAD                                      # YES (hardening ANR2 le plus récent revu)
```

La branche d'intégration `671282b6` ne contenait pas à elle seule le dernier hardening ANR2. La preview part du merge réel `75bf231` qui réunit la base d'intégration et `a44f23e`; la présence fonctionnelle a ensuite été contrôlée dans le code et par navigateur, sans prendre le merge comme preuve suffisante.

Commits fonctionnels identifiés:

```text
64a066d802135ff37e68a9de6ac0c42824da1c88  integrate LTE into unified control UI
491ec9c7fcca9e90681de186451bda492d9ed045  harden srsRAN LTE lifecycle and grants
14e7a29232187a924cc65b21f2ae1329f83065c6  persistent LTE Grant V2 foundation
538b08b154a4f2103fe40071e074644a83314515  finalize LTE Grant V2 hardening
a44f23ed4026419ac23ea8d22c1539dbd8c33495  final LTE hardening report
```

## Preview livrée

URL vérifiée sur le serveur:

```text
http://127.0.0.1:4331/simulator/
```

Le listener est volontairement limité à `127.0.0.1:4331`; aucune API d'administration n'est exposée publiquement. Pour l'ouvrir depuis le poste du propriétaire:

```bash
ssh -L 4331:127.0.0.1:4331 root@151.242.147.49
```

Puis ouvrir `http://127.0.0.1:4331/simulator/` dans le navigateur local. La disponibilité du tunnel dépend de l'accès SSH du propriétaire; elle n'est pas revendiquée comme testée depuis un poste externe.

Relance locale contrôlée, si nécessaire:

```bash
cd /root/OIRAN_POLARIS_UI_PREVIEW_ANR2/apps/simulator-control
npm run preview:demo
```

La preview comprend:

- UE Manager unifié LTE/5G, avec profils synthétiques et identités protégées;
- Scenario Builder avec sélection LTE/5G et étapes LTE;
- Simulator Control présentant srsENB, srsUE, S1, Attach, IP et session;
- Traffic Generator UDP/TCP, UL/DL, sessions LTE/5G et graphes synthétiques;
- bannière persistante `DEMO SYNTHÉTIQUE · READ-ONLY`;
- rôle `viewer`, actions Start/Stop/Grant/provisioning/trafic désactivées;
- middleware DEMO refusant toute méthode mutante avec HTTP `423 DEMO_READ_ONLY`.

Toutes les données sont synthétiques et marquées DEMO. Aucun IMSI, K, OPc ou autre secret abonné n'est présent.

## Captures vérifiées

Captures 1440 clair:

- `apps/simulator-control/docs/preview/chromium-1440-light/ue-manager-lte.png`
- `apps/simulator-control/docs/preview/chromium-1440-light/scenario-builder-lte.png`
- `apps/simulator-control/docs/preview/chromium-1440-light/simulator-control.png`
- `apps/simulator-control/docs/preview/chromium-1440-light/traffic-generator.png`

Captures 1440 sombre:

- `apps/simulator-control/docs/preview/chromium-1440-dark/ue-manager-lte.png`
- `apps/simulator-control/docs/preview/chromium-1440-dark/scenario-builder-lte.png`
- `apps/simulator-control/docs/preview/chromium-1440-dark/simulator-control.png`
- `apps/simulator-control/docs/preview/chromium-1440-dark/traffic-generator.png`

L'inspection visuelle a trouvé puis corrigé un conflit CSS qui rendait le libellé du bouton technologique sélectionné illisible au survol en thème clair.

## Tests manuels et preuves

```text
npm run typecheck
PASS — tsc -b --pretty false

POLARIS_DEMO_MODE=1 VITE_POLARIS_DEMO_MODE=1 npm run build
PASS — 1708 modules transformed; dist généré
Note — avertissement Vite existant sur l'import dynamique/statique de profileApi.ts

npm test -- --run
PASS — 35 fichiers, 215 tests
Note — avertissements React act(...) existants, aucun échec

POLARIS_DEMO_MODE=1 POLARIS_SIM_E2E_BASE_URL=http://127.0.0.1:4331/simulator/ \
  npx playwright test e2e/demo-preview.spec.ts
PASS — 6/6: Chromium 1280/1440/1920, clair/sombre, sans débordement horizontal

npm audit --omit=dev --json
PASS — 0 vulnérabilité de production

curl http://127.0.0.1:4331/simulator/
HTTP 200

curl http://127.0.0.1:4331/polaris-api/v1/lte/status
HTTP 200 — données synthétiques

curl -X POST http://127.0.0.1:4331/polaris-api/v1/live/grant
HTTP 423 — {"error":"DEMO_READ_ONLY","demo":true}

ss -ltnp '( sport = :4331 )'
LISTEN 127.0.0.1:4331 uniquement

curl -k https://151.242.147.49:8020/simulator/
HTTP 200 — contrôle GET uniquement; aucune mutation production
```

Les premières itérations Playwright ont révélé deux assertions reposant sur des `data-testid` non propagés par le composant bouton et une attente sur le nom au lieu de l'identifiant eNB. Les assertions ont été corrigées vers les rôles accessibles et le contenu réellement rendu; la matrice finale est 6/6.

## Garde-fous hôte

Preuves finales:

```text
df -P /root                           # 79 %
MemAvailable                          # 5,621,756 KiB (> 4 GiB)
pgrep -xc dumpcap                     # 12
```

Les 12 `dumpcap` ont été seulement comptés, jamais signalés, stoppés ou redémarrés. Aucun srsENB, srsUE, UERANSIM, scénario, grant ou trafic live n'a été lancé.

## Limites

- Preview accessible uniquement via localhost ou tunnel SSH authentifié; aucune exposition publique n'a été autorisée.
- Les états, mesures et graphes sont des exemples DEMO, pas une certification LTE réelle.
- Aucun déploiement ni changement de production n'a été effectué.

— ANR2
