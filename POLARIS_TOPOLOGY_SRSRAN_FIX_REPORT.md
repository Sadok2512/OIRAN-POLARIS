# POLARIS Topology srsRAN Visible Fix — ANR2

Date UTC: 2026-10-31  
Verdict: **PASS — preview isolée uniquement**  
Production: **non modifiée**  
Live, grant, simulateurs et trafic: **non exécutés**

## Git et version

- Worktree: `/root/OIRAN_POLARIS_TOPOLOGY_SRSRAN_ANR2`
- Branche: `fix/polaris-topology-srsran-visible-v1`
- Base preview: `0a1fc3e8aace69a00c0d61972e32283265475ad0`
- Commit d'implémentation testé: `973e1cd9116f4578178a3cbe9fcdc6f3be181379`
- Frontend: `@telecom/simulator-control` **0.16.0**
- Lignée confirmée: `0a1fc3e8`, `671282b6` et `a44f23e` sont ancêtres du commit testé.

## Route et bundle réellement servis

La topologie existante a été conservée; aucune deuxième page ni application n'a été créée:

```text
src/app/App.tsx:26
<Route path="/network/topology" element={<TopologyPage />} />
```

URL locale vérifiée:

```text
http://127.0.0.1:4331/simulator/network/topology
```

Bundle avant correction observé dans le navigateur: `index-DW_J_eay.js`.  
Bundle final servi: `index-CPwDJ4dc.js`.  
SHA-256 du bundle final:

```text
2b38f41e5f44ee6efbacae729008f23f06327badb3bb4b6811a46fe412a17a15
```

Le listener reste strictement local:

```text
LISTEN 127.0.0.1:4331
```

Accès navigateur depuis le poste du propriétaire:

```bash
ssh -N -L 4331:127.0.0.1:4331 root@151.242.147.49
```

Puis ouvrir `http://127.0.0.1:4331/simulator/network/topology`.

## Constat avant correction

Le contrôle Playwright du bundle précédent trouvait bien deux nœuds, mais la représentation restait ambiguë:

- un seul bloc de cœur intitulé `5G Core` couvrait visuellement LTE et 5G;
- Open5GS EPC n'était pas représenté comme chaîne distincte;
- `srsENB` et `srsUE` n'étaient pas explicitement nommés comme simulateurs;
- les liens S1 étaient `UNKNOWN` dans la preview car ses endpoints LTE étaient nuls;
- aucune capture Topology n'était livrée par le rapport précédent.

## Correction

La même route Topology affiche maintenant côte à côte:

1. `Open5GS 5GC → N2/NGAP + N3/GTP-U → UERANSIM gNB → UERANSIM UE`;
2. `Open5GS EPC → S1-MME/S1AP + S1-U/GTP-U → srsENB → srsUE`.

Les états de code restent fondés sur `/lab`, `/nodes` et `/ues`. Une interface sans endpoint, un cœur sans preuve par fonction ou un nœud absent affiche `UNKNOWN`. Dans la preview, les endpoints et états sont synthétiques et la page porte à la fois les mentions `DEMO SYNTHÉTIQUE` et `DEMO TOPOLOGY`.

Les pages UE Manager, Scenario Builder, Simulator Control et Traffic Generator restent dans le parcours Playwright. Toutes leurs actions live sont désactivées.

## Captures réelles

- Clair 1440: `apps/simulator-control/docs/preview/chromium-1440-light/topology-lte-5g.png`
- Sombre 1440: `apps/simulator-control/docs/preview/chromium-1440-dark/topology-lte-5g.png`

Les deux captures ont été inspectées: 5GC, EPC, gNB, srsENB, UERANSIM UE, srsUE et les quatre interfaces N2/N3/S1-MME/S1-U sont lisibles sur une même topologie.

## Tests manuels

```text
npm run typecheck
PASS — tsc -b --pretty false

npm test -- --run
PASS — 35 fichiers, 215 tests
Note — avertissements React act(...) préexistants, aucun échec

POLARIS_DEMO_MODE=1 VITE_POLARIS_DEMO_MODE=1 npm run build
PASS — 1708 modules; index-CPwDJ4dc.js
Note — avertissement Vite préexistant sur profileApi.ts importé statiquement et dynamiquement

POLARIS_DEMO_MODE=1 \
POLARIS_SIM_E2E_BASE_URL=http://127.0.0.1:4331/simulator/ \
npx playwright test e2e/demo-preview.spec.ts e2e/topology-lte-5g.spec.ts
PASS — 12/12, Chromium 1280/1440/1920 clair et sombre

npm audit --omit=dev --json
PASS — 0 vulnérabilité de production
```

Le test dédié `topology-lte-5g.spec.ts` exige explicitement `srsENB`, `srsUE`, `Open5GS EPC`, `Open5GS 5GC`, `UERANSIM gNB`, `UERANSIM UE` et les quatre liens. La disparition de `srsENB` ou `srsUE` fait échouer Playwright.

## Sécurité et hôte

```text
GET /simulator/network/topology           HTTP 200
POST /polaris-api/v1/live/grant           HTTP 423 DEMO_READ_ONLY
df -P /root                               58 %
MemAvailable                              4,657,004 KiB (> 4 GiB)
pgrep -xc dumpcap                         12
```

Aucun secret abonné n'est contenu dans les données synthétiques. Les 12 `dumpcap` ont été uniquement comptés. Aucun processus radio, trafic, grant, déploiement ou mutation production n'a été lancé.

— ANR2
