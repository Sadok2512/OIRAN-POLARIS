# POLARIS LTE_TRAFFIC_FAILED — diagnostic ANR2

Date UTC : 2026-11-01  
Run : `lte-run-b12f8f56374b06af8dc4678908f4834b`  
Branche : `fix/polaris-lte-traffic-failed-p0-anr2`  
Base : `880c493f6bba5c760722e22b20d15bad3cfe4b78`

## Cause prouvée

Le run a commencé `ping_ul` à `19:41:58.773Z` et l'a déclaré en échec à
`19:41:58.897Z`, soit 124 ms plus tard. Le contrôleur POLARIS exigeait
`POLARIS_LTE_TRAFFIC_PEER_IP` avant d'exécuter le ping et retournait
`LTE_TRAFFIC_PEER_NOT_CONFIGURED` lorsqu'elle était absente.

L'environnement du processus API actif et
`/root/POLARIS_CONTROL/config/polaris-control.env` ne définissaient pas cette
variable. Le drop-in actif définissait en revanche
`POLARIS_DL_SENDER_IP=10.77.24.30`, et le conteneur controller-owned
`polaris-dn-sender` était sain à cette adresse. L'échec immédiat est donc une
erreur de configuration POLARIS antérieure à toute commande de trafic, et non
une preuve d'échec du bearer, de PFCP ou du chemin utilisateur.

Deux défauts POLARIS ont aggravé l'incident :

1. le preflight acceptait le run sans valider le peer de trafic ;
2. l'orchestrateur remplaçait l'erreur précise du contrôleur par le code
   générique `LTE_TRAFFIC_FAILED`.

## Correctif

- Validation fail-closed du peer avant consommation du nonce/grant et avant
  tout démarrage de simulateur.
- Correspondance exacte obligatoire entre
  `POLARIS_LTE_TRAFFIC_PEER_IP` et le `POLARIS_DL_SENDER_IP` IPv4 validé.
- Ajout de la variable manquante dans le drop-in canonique DN-sender et dans
  l'exemple de configuration ; aucune configuration de production n'a été
  modifiée.
- Conservation du code d'erreur précis dans les preuves du run ; une erreur de
  worker distincte devient `LTE_TRAFFIC_WORKER_FAILED`.
- Stop, expiration, révocation et cleanup restent inchangés.
- Version API : `0.28.4`; controller srsRAN : `0.2.4`; CHANGELOG mis à jour.

## Tests manuels exécutés

```text
cargo test --locked -p polaris-control-api traffic_peer -- --test-threads=1
PASS : 1, FAIL : 0

cargo test --locked -p polaris-control-api traffic_preflight_failure_has_no_lifecycle_side_effect -- --test-threads=1
PASS : 1, FAIL : 0

cargo test --locked -p polaris-control-api udp_iperf_command_enforces_payload_block_length -- --test-threads=1
PASS : 1, FAIL : 0

cargo test --locked -p polaris-control-api certification_mode_breaks_the_bootstrap_cycle_without_marking_certified -- --test-threads=1
PASS : 1, FAIL : 0

cargo test --locked -p polaris-control-api canonical_dn_sender_dropin_sets_the_exact_lte_peer -- --test-threads=1
PASS : 1, FAIL : 0

CARGO_BUILD_JOBS=1 cargo test --workspace --locked -- --test-threads=16
PASS : 314, FAIL : 0, IGNORE : 3 benchmarks manuels

git diff --check
PASS
```

La régression workspace couvre notamment Grant V2, le deadline Attach, le
cleanup, la publication d'evidence, le contrôleur srsRAN et l'adaptateur
UERANSIM 5G.

## Garde-fous observés après tests

```text
MemAvailable = 9,679,757,312 octets
Disque / = 79 % utilisé, 90,468,057,088 octets libres
dumpcap actifs = 12
```

Aucun grant, simulateur, trafic ou déploiement n'a été lancé. Open5GS, OIRAN,
les collecteurs et la production n'ont pas été modifiés.

## Verdict

`READY_FOR_REVIEW`. Le correctif doit être revu et faire l'objet d'une
autorisation de déploiement distincte. Un nouveau run LTE reste soumis à une
autorisation live spécifique ; ce diagnostic ne prouve ni le bearer EPS ni le
trafic UL/DL.

— ANR2
