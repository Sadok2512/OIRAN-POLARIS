# ANR2 — Rapport final POLARIS LTE Grant V2

Date UTC : 2026-10-31
Branche : `anr2/polaris-lte-grant-v2`
Commit poussé : `14e7a29232187a924cc65b21f2ae1329f83065c6`
Base : `origin/feat/polaris-srsran-lte-ui-v1` (`0d2943c`)
Versions : API `0.22.0`, Simulator Control `0.15.0`

## Résultat

`OFFLINE_IMPLEMENTATION = PASS`
`READY_FOR_LIVE_APPROVAL = BLOCKED`
`PRODUCTION_CHANGED = FALSE`
`LIVE_EXECUTED = FALSE`

Le socle Grant V2, l'ownership persistant et les contrôles de sécurité sont
implémentés et testés hors production. Le profil est désactivé par défaut et
les flags de certification restent fermés. L'orchestrateur asynchrone complet
S1/Attach/ping/UDP/evidence reste à terminer avant toute approbation Live.

## Changements livrés

- Registre profil atomique `0600`, profil exact `LTE-SRSUE-TEST-01`, ownership
  `POLARIS_CONTROLLER`, Compose/services strictement allowlistés.
- Store Grant V2 atomique `0600` avec checksum, nonce et clés d'idempotence
  stockés uniquement sous forme SHA-256, consommation unique, expiration,
  révocation et récupération fail-closed après restart.
- Compatibilité Grant V1 conservée pour UERANSIM ; mélange V1/V2 refusé.
- RBAC/CSRF : lecture Viewer+, émission/consommation Operator+, activation du
  profil Administrator seulement. Stop/cleanup reste grant-independent.
- Runtime : labels Compose + image vérifiés avant action, argv fixe sous
  `/usr/bin/timeout 30s`, aucune valeur HTTP utilisée comme commande/cible.
- UI : identifiant canonique LTE, profil/Grant V2 visible, anciens boutons
  Start direct désactivés ; Stop Operator conservé. La 5G reste inchangée.
- Contrat exact : `docs/api/lte-grant-v2.contract.md`.

## Routes exactes

| Méthode | Route | Contrôle |
|---|---|---|
| GET/PATCH | `/api/v1/lte/profiles/:profile_id` | lecture Viewer ; PATCH Admin+CSRF |
| POST/GET | `/api/v1/live/grant` | V2 Operator+CSRF+Idempotency-Key ; liste expurgée |
| DELETE | `/api/v1/live/grant/:grant_id` | Operator+CSRF |
| POST | `/api/v1/lte/runs` | Operator+CSRF+nonce+Idempotency-Key |
| GET | `/api/v1/lte/runs/:run_id` | état/evidence expurgé |
| POST | `/api/v1/lte/runs/:run_id/stop` | cleanup Operator+CSRF, grant-exempt |

Le run expose `evidence_schema = polaris.lte-evidence.v1`. Pour ANR3, chaque
`evidence_ref` doit pointer vers une `capture_ref` avec SHA-256, bornes de
trames et `SANITIZED_APPROVED`. La corrélation utilise IDs/EBI/TEID+scope et
endpoints, jamais la seule proximité temporelle.

## Tests et preuves

Commandes exécutées manuellement :

```text
cargo test --manifest-path POLARIS_CONTROL/Cargo.toml --workspace
```

Résultat : `250 passed`, `0 failed`, `3 ignored` (benchmarks 100k et test
Mongo restauré déjà marqués manuels dans la lignée). Détail API : `205
passed`, `0 failed`, `3 ignored`. Les 4 tests propres au store/registre et
les 3 tests HTTP LTE ciblés passent.

```text
cd apps/simulator-control
npm ci
npm run typecheck
npm run test
npm run build
npm audit --omit=dev --json
```

Résultat : TypeScript PASS ; Vitest `35 files / 215 tests passed` ; build Vite
PASS (`1708 modules transformed`) ; audit production `0` vulnérabilité toutes
sévérités. `npm ci` signale que Node 18 est inférieur au moteur recommandé de
React Router 7 et six avis incluant les devDependencies ; ils ne figurent pas
dans `npm audit --omit=dev`.

```text
npm run dev
npx playwright test e2e/lte-integration.spec.ts
```

Résultat final : `6 passed` (1280/1440/1920, clair/sombre). Une première
invocation sans le serveur Vite documenté avait produit uniquement
`ERR_CONNECTION_REFUSED`; elle a été fermée en suivant la procédure du dépôt.

```text
git diff --check
git diff --cached --name-status
git diff --cached --no-color | rg '<motifs clés/tokens/private keys>'
```

Résultat : diff propre ; aucun secret/clé/token/identité abonné dans les
fichiers ajoutés. Aucun PCAP ou dataset ajouté.

## Défauts et gates restants

1. La machine d'état asynchrone complète après `ENB_STARTING` n'est pas
   implémentée : attente S1, démarrage UE, Attach/IP, sidecars ping/UDP,
   deadline cleanup et publication d'evidence_refs.
2. Le profil reste `enabled=false`; `POLARIS_SRSRAN_LIVE_ENABLED` et
   `POLARIS_LTE_E2E_CERTIFIED` restent requis et faux par défaut.
3. Aucun test réel srsENB/srsUE/Open5GS n'a été lancé ; certification LTE et
   déploiement restent donc bloqués conformément aux gates.
4. Les trois tests Rust ignorés sont des tests manuels historiques lourds,
   pas des tests Grant V2 ignorés.

## État de sécurité

`OPEN5GS_CHANGED = FALSE`
`UERANSIM_CHANGED = FALSE`
`SRSENB_STARTED = FALSE`
`SRSUE_STARTED = FALSE`
`TRAFFIC_GENERATED = FALSE`
`DUMPCAP_INTERRUPTED = FALSE`
`DEPLOYMENT_EXECUTED = FALSE`

Verdict : `PARTIAL` — fondation offline validée ; Live non certifié.

— ANR2
