# POLARIS LTE Attach timeout race fix — ANR2

Date UTC: 2026-11-01  
Branch: `fix/polaris-lte-attach-timeout-race-p0-anr2`  
Base: `d22b24ffc0b4fea792310084dbc7b5020aafbbff` (POLARIS API 0.28.2)  
Source SHA: `625712e0560ff242563960e11cfb036ee05178c2`  
Release: POLARIS API 0.28.3 / srsRAN controller 0.2.3

## Verdict

`READY`

Le correctif est validé hors production. Aucun grant réel, simulateur, trafic,
déploiement, changement Open5GS ou commande visant un captureur n'a été
exécuté par ANR2.

## Cause racine

L'orchestrateur utilisait une attente Attach fixe de 45 secondes, sondée par
pas d'une seconde, et une recherche de texte non bornée dans les logs
srsUE/MME. La décision ne portait ni timestamp protocolaire fiable ni
provenance. Une observation arrivant juste après la décision de timeout était
donc perdue et le cleanup démarrait immédiatement, même si le MME avait émis
`Attach Complete` avant la deadline. Les réponses S11/S5-C/PFCP et l'adresse IP
Core ne constituent pas une preuve Attach Complete.

## Correctif

- La preuve d'Attach est maintenant exclusivement l'événement Open5GS MME
  `Attach Complete`, lu dans le conteneur MME résolu par le contrôleur.
- La commande Docker est bornée à cinq secondes et les logs sont limités avec
  `--since`, `--until` et `--tail 400` à la fenêtre du run courant.
- Le timestamp RFC3339 UTC préfixant la ligne Docker est parsé et conservé avec
  la provenance explicite `OPEN5GS_MME_DOCKER_LOG_RFC3339`.
- La fenêtre protocolaire est de 90 secondes, toujours réduite par la deadline
  Grant V2/globale. Une réconciliation maximale de deux secondes accepte une
  observation tardive uniquement si son événement MME a eu lieu au plus tard à
  la deadline protocolaire. Un événement émis après celle-ci reste rejeté et
  conduit au timeout à la fin de la réconciliation.
- La fenêtre d'observation est enregistrée avant le démarrage srsUE afin de ne
  pas perdre un Attach immédiat.
- L'adresse IP reste une étape indépendante et ne peut pas promouvoir Attach.
- Expiration, révocation, cancellation, emergency stop et cleanup restent
  prioritaires. Les contraintes Grant/run sont réévaluées avant chaque ping et
  lancement UDP : aucun trafic ne peut être relancé après expiration ou
  révocation.
- Le redémarrage ne recalcule ni ne prolonge la deadline durable.

## Tests manuels exécutés

### Régression workspace

Commande :

```text
CARGO_BUILD_JOBS=1 cargo test --workspace --locked
```

Résultat agrégé : `307 PASS, 0 FAIL, 3 ignored` (benchmarks/validations
manuelles). Cela couvre notamment API, Grant V2/sécurité, contrôleur,
UERANSIM 5G, scenario, traffic et safety.

### Correctif P0 sur le source final

Commande :

```text
CARGO_BUILD_JOBS=1 cargo test --locked -p polaris-control-api p0_tests:: -- --nocapture
```

Résultat : `136 PASS, 0 FAIL, 2 ignored`. Les cas vérifiés comprennent :

- Attach Complete avant, exactement à, et après la deadline ;
- observation différée de 1,447 seconde d'un événement MME antérieur à la
  deadline ;
- timeout, événement tardif et absence de résurrection du run ;
- deadline bornée par le Grant et non prolongée au redémarrage ;
- IP assignée explicitement refusée comme preuve Attach Complete ;
- révocation et expiration empêchant tout nouveau lancement de trafic ;
- emergency stop, cleanup, RBAC, CSRF, Grant V2 et non-régression 5G.

Tests ciblés contrôleur : le parsing RFC3339 UTC et la preuve MME bornée avec
provenance ont également passé dans la régression workspace.

`git diff --check` : PASS.

## Build release et provenance

Commande :

```text
CARGO_BUILD_JOBS=1 RUSTFLAGS='-C link-arg=-Wl,--no-keep-memory' \
  cargo build --release --locked --offline -p polaris-control-api -j 1
```

Résultat : PASS en 11 min 16 s.

- Artefact :
  `POLARIS_CONTROL/target/release/polaris-control-api`
- Architecture : ELF 64-bit x86-64, PIE, dynamiquement lié.
- Taille : 21 277 416 octets.
- Build ID : `3deafa7486448e7c2d72f6f89ddcaff053ae59bf`.
- SHA-256 :
  `547edc985607c630fc53271cace1189ac02d4ebfa8b51a89e47702d4672d1348`.

Le binaire a été produit après le commit source, avec `--locked --offline`,
mono-job, sans modification du source pendant le build.

## Git et ressources

```text
git merge-base --is-ancestor d22b24ffc0b4fea792310084dbc7b5020aafbbff 625712e0560ff242563960e11cfb036ee05178c2
exit = 0
```

Contrôles finaux :

- mémoire disponible : 11 947 094 016 octets ;
- disque `/` : 70 % ;
- dumpcap : 12 processus actifs. Les PID observés avant le build
  (`2163366,2163376,2163379,2163384,2163397,2163411,2163412,2163430,2163432,2163450,2163452,2163469`)
  ont tous été remplacés avant le contrôle final
  (`2343504,2343508,2343514,2343520,2343529,2343547,2343549,2343560,2343600,2343601,2343606,2343607`).
  ANR2 n'a envoyé aucun signal ni commande à dumpcap. La cause de ce
  remplacement externe et la continuité sans perte ne sont pas démontrées.

## Anomalies et limites

- Trois validations de la suite complète restent explicitement manuelles ;
  elles ne sont pas transformées en PASS.
- La validation LTE E2E réelle reste hors de cette mission. Ce rapport ne
  déclare ni Attach réel certifié ni `REAL_PASS`.
- Les 12 dumpcap sont actifs, mais leur remplacement externe pendant la
  fenêtre doit être investigué séparément ; aucune continuité de capture n'est
  revendiquée.
- Le déploiement de 0.28.3 nécessite une autorisation distincte.

## Résumé obligatoire

```text
ROOT_CAUSE = délai Attach fixe et observation textuelle non horodatée/non bornée, sans réconciliation du timestamp MME avant cleanup
FIX = preuve MME Attach Complete horodatée et sourcée, fenêtre 90 s + grâce 2 s bornées par Grant/global, IP séparée, trafic revalidé avant chaque lancement
TESTS = workspace 307 PASS / 0 FAIL / 3 ignored ; source final P0 136 PASS / 0 FAIL / 2 ignored
SOURCE_SHA = 625712e0560ff242563960e11cfb036ee05178c2
BINARY_SHA256 = 547edc985607c630fc53271cace1189ac02d4ebfa8b51a89e47702d4672d1348
RELEASE_READY = YES
BLOCKERS = aucun bloqueur code/build offline ; remplacement externe des PID dumpcap à investiguer ; LTE E2E réel et déploiement non exécutés
VERDICT = READY
```

— ANR2
