# SOP — Tests voix SIP/RTP en périmètre IMS-lite (POLARIS / OIRAN)

| Champ | Valeur |
|---|---|
| Version | 1.0.0 (19/11/2026) |
| Statut | **Brouillon** : les champs « À RELEVER » sont remplis par ANR1 en lecture seule avant la première exécution |
| Périmètre | Campagne #10 7011914977, tests V1 à V4 (voix), avec L1/L2 (live trace) et T3 (vTAP plan usager) sur le trafic voix |
| Exécutant | un seul agent ANR à la fois, sous LAB_LOCK |
| Prérequis de version | oiran-api **≥ 2.21.83** en prod (jitter RTP corrigé, pseudonyme SIP = NAS, règle VoNR). Sur 2.21.74, le jitter est faux et l'appel n'est pas rattaché à l'abonné |

## 1. Ce que ce lab peut prouver (et ne peut pas)

A0-LAB (#10 7014973642) : Kamailio **IMS-lite monolithique** + RTPengine, DNN `ims` (10.47.0.0/16) configuré sur SMF/UPF, capture SIP/UDP 5060 et RTP sur `br-oiran-n6`. Pas de P/I/S-CSCF séparés, pas de HSS IMS (Cx), pas de SIPp ni de générateur RTP.

| Capacité | Mesurable ici ? | Raison |
|---|---|---|
| Enregistrement SIP (REGISTER) d'un UE sur la PDU `ims` | **Oui** | UE UERANSIM, PDU `ims`, client SIP dans l'espace réseau de l'UE |
| Appel SIP de bout en bout (INVITE → 200 → ACK → BYE) | **Oui** | UE (UAC) → Kamailio → UAS côté DN, puis UE ↔ UE |
| RTP : débit, perte, jitter par flux | **Oui** sur N6 (en clair) | `decoder-rtp` + corrélation Call-ID |
| Corrélation SIP ↔ PDU `ims` ↔ abonné | **Oui** (≥ 2.21.83) | pseudonyme SIP = NAS, règle `sip-pfcp-ue-ipv4-pseudonym-match` |
| Flux QoS dédié **5QI 1** | **Non, sauf si Rx présent** | sans P-CSCF qui parle Rx/N5 au PCF, aucun flux dédié n'est créé : le RTP passe sur le flux par défaut de la PDU `ims`. **Gate non applicable**, à déclarer comme tel et non comme FAIL |
| SIP/RTP décodés **dans le tunnel GTP-U N3** | **Non** (aujourd'hui) | `decoder-gtpu` ne lit pas l'UDP inner : design CLAUDE1 #9 7012805654, code à venir. Le N3 est capturé, mais seul N6 est décodé en SIP/RTP |
| MOS | **Non** | absent du code (A0-VOIX, ligne 6) : OUVERT |
| VoNR « opérateur » complet (IMS conforme, HSS IMS, SRVCC…) | **Non** | hors périmètre IMS-lite, ne jamais le revendiquer |

## 2. Accords requis (Sadok) avant toute exécution

| # | Geste | Pourquoi c'est un accord |
|---|---|---|
| A1 | Démarrer un UE UERANSIM existant et établir une PDU `ims` | trafic de signalisation réel vers Open5GS |
| A2 | Installer un client SIP (**SIPp** recommandé, sinon pjsua) dans le conteneur de l'UE et dans le conteneur DN | ajout d'outillage sur le lab |
| A3 | (V3 uniquement) `tc netem` sur l'interface du conteneur DN, puis retrait | perturbation volontaire du réseau de test |
| — | **Interdit sans un accord séparé** : créer ou modifier un abonné, un DNN, une slice, la configuration Kamailio, RTPengine ou Open5GS | geste Open5GS |

Si l'abonné de l'UE n'a pas le DNN `ims` autorisé dans son profil, **STOP** : l'ajouter est un geste Open5GS.

## 3. Relevés en lecture seule (à remplir par ANR1, commandes fournies)

| Valeur | Commande (lecture seule) | Relevé |
|---|---|---|
| IP et port SIP de Kamailio (P-CSCF vu par l'UE) | `rg -n 'p-cscf' /root/POLARIS/config/open5gs` ; `docker exec <kamailio> ss -lunp \| rg 5060` | À RELEVER |
| Domaine / realm SIP | `docker exec <kamailio> sh -lc "grep -nE 'alias\|domain\|realm' /etc/kamailio/*.cfg"` | À RELEVER |
| Mode d'authentification REGISTER (aucun / digest / IMS-AKA) | même fichier, `www_authorize\|auth_check\|ims_auth` | À RELEVER |
| Format des identités SIP acceptées (`sip:<imsi>@domaine`, `tel:+…`) | même fichier, `registrar` / `usrloc` | À RELEVER |
| Rx/N5 vers le PCF présent ? (décide le gate 5QI 1) | même fichier, `ims_qos\|diameter\|rx` | À RELEVER |
| RTPengine : mode (relais / ancrage), plage de ports | `docker exec <rtpengine> ps -o args= -C rtpengine` | À RELEVER |
| Conteneur(s) UE et profil UERANSIM avec DNN `ims` | `rg -n 'apn\|dnn' /root/POLARIS/config/ueransim` | À RELEVER |
| Profil abonné : DNN `ims` autorisé ? | lecture seule du profil (sans IMSI en clair dans #10) | À RELEVER |
| Conteneur DN pour l'UAS (côté N6) | `docker ps` (`polaris-dn-sender` ?) | À RELEVER |
| Points de capture actifs N2/N3/N4/N6/SBI | `curl :49152/api/v1/probes/oiran-vprobe-local-01/interfaces` | À RELEVER |
| État du vTAP | `systemctl is-active polaris-vtap` | arrêté depuis le 17/11 (décision séparée) |

## 4. Préflight (STOP si un point échoue)

1. LAB_LOCK publié sur #10.
2. `df -B1 /` : **≥ 25 Go libres**, disk-safety `NORMAL`, `writes_allowed=true`.
3. `oiran-api` healthy, version ≥ 2.21.83, `NRestarts` noté.
4. Garde Control : `active_count=0` avant le test.
5. Captures actives sur N2, N3, N4, N6 (IMS) et SBI. Noter le segment ouvert de chaque interface.
6. Horloge : noter `date -u` de début. Toutes les mesures sont rapportées à cette origine.

## 5. Mise en place

1. **UE** : démarrer le profil UERANSIM retenu (relevé §3), attendre l'enregistrement 5G.
2. **PDU `ims`** : `nr-cli <imsi-ue> -e "ps-establish IPv4 --dnn ims"` (exécuté dans le conteneur, la valeur n'est jamais recopiée dans #10). Vérifier une interface `uesimtunN` avec une IP dans 10.47.0.0/16.
3. **Joignabilité** : depuis l'espace réseau de l'UE, `ping -c 3 -I uesimtunN <IP Kamailio>`.
4. **UAS côté DN** : dans le conteneur DN, `sipp -sn uas -i <IP DN> -p 5060 -rtp_echo -trace_err` (ou un UAS enregistré auprès de Kamailio si celui-ci n'accepte que des utilisateurs enregistrés, selon le relevé §3).

Exécution du client côté UE : `nsenter -t <pid nr-ue> -n sipp …` ou `ip netns exec`, avec **`-i <IP uesimtunN>`** pour forcer le passage par le tunnel 5G.

## 6. Tests

Chaque test produit un bloc de rapport #10 : ID, heure UTC de début et de fin, commandes, `capture_id` concernés, chiffres, verdict PASS / FAIL / OUVERT / NON APPLICABLE.

| ID | Action | Gate |
|---|---|---|
| **V1** REGISTER | `sipp <IP Kamailio>:5060 -sf register.xml -i <IP uesimtun> -m 1` (scénario REGISTER, avec digest si §3 l'exige) | SIP `REGISTER` → (`401`) → `200` décodés sur N6 ; l'event SIP porte le **même `subscriber_pseudonym`** que la session NAS de l'UE ; PDU `ims` visible sur N1/N2/N4 dans le même callflow abonné |
| **V2** appel UE → UAS | `sipp … -sf uac_pcap.xml` avec la lecture d'un RTP G.711 de 30 s (`play_pcap_audio`), puis BYE | INVITE / 100 / 180 / 200 / ACK / BYE décodés et ordonnés (capture_id, seq) ; **durée d'établissement** (INVITE → 200) mesurée ; flux RTP montant et descendant (echo) corrélés au Call-ID (`rtp-sip-call-id-match`) ; 5QI 1 : **NON APPLICABLE** si §3 « Rx absent », sinon flux dédié visible sur N2/N4 |
| **V2b** appel UE ↔ UE | deux UE avec PDU `ims`, l'un en UAS enregistré, l'autre en UAC | mêmes gates que V2, et chaque branche est rattachée à son abonné, sans croisement |
| **V3** qualité RTP | référence : `tc qdisc add dev <if DN> root netem loss 2% delay 20ms 10ms` pendant un appel de 60 s, puis **retrait** obligatoire (`tc qdisc del`) | perte mesurée par OIRAN = 2 % ± 0,5 point ; jitter non nul et cohérent avec netem (fail-closed : `null` + raison si clock_rate inconnu, jamais une valeur fausse) ; débit RTP ≈ 64 kbit/s par sens (G.711) ; sans netem : perte 0 |
| **V4** échecs | appel vers un utilisateur inconnu (404) ; UAS qui répond 486 ; INVITE sans réponse (timeout 408) | code SIP final décodé et attribué au bon abonné ; l'appel est compté comme **échec** |
| **L1/L2** sur la voix | live trace par pseudonyme, puis par IMSI (corps de POST), pendant V2 | events SIP/RTP de l'abonné affichés en < 5 s ; 0 identité en clair (L2d) |
| **T3** voix via vTAP | si le vTAP est redémarré (décision séparée) | RTP vu via vTAP, ou déclaré non couvert : le vTAP actuel ne voit que le SBI déchiffré |

## 7. Vérification dans OIRAN (après chaque test)

- `/sessions/filter` avec une fenêtre sur l'intervalle du test : la session de l'abonné (pseudonyme) est présente.
- `/sessions/:id/callflow` : NAS/NGAP (PDU `ims`), PFCP, SIP, RTP dans l'ordre canonique (capture_id, seq), sans doublon d'`event_id`.
- Events SIP : `decoding_status=DECODED`, `sip_call_id` présent, URIs pseudonymisées.
- Events RTP : un event par (SSRC, sens), avec `packet_count`, `lost`, `jitter_ns` ou `jitter_null_reason`, `jitter_clock_rate_hz`.
- **Recomptage indépendant** : `tshark -r <pcap N6> -Y 'sip' -T fields -e sip.Method -e sip.Status-Code` et `-Y rtp -q -z rtp,streams` sur le même intervalle. Les compteurs OIRAN doivent égaler tshark (méthodes et codes SIP exacts ; paquets et pertes RTP ± 0).

## 8. Fin de test et remise en état

1. Arrêter les SIPp (UAC et UAS).
2. **Retirer netem** si V3 a été joué : `tc qdisc show dev <if>` doit être revenu à l'état initial.
3. Libérer la PDU `ims` (`ps-release`), arrêter l'UE démarré pour le test.
4. Garde Control : `active_count` revenu à sa valeur initiale.
5. Captures : garder les `capture_id`. Copier les pcap de référence dans le **corpus de non-régression** (R1) **uniquement** après l'accord de Sadok sur la place disque.
6. Supprimer la live trace de test (`DELETE /live/traces/:id`).
7. LAB_UNLOCK et rapport final #10.

## 9. Confidentialité

- **Aucun IMSI, MSISDN, IMEI ni URI SIP contenant un numéro en clair dans #10 ou #9.** Désigner l'abonné par `psn-…` et « UE-lab-N ».
- Les valeurs en clair nécessaires à l'exécution restent dans un fichier `0600` du répertoire de preuves de l'agent.
- L2d (recherche de fuite) est rejoué à la fin de chaque session de tests voix.

## 10. Écarts déclarés (connus avant l'exécution)

| Écart | Statut | Suite |
|---|---|---|
| SIP/RTP non décodés dans le GTP-U N3 | OUVERT | design CLAUDE1 #9 7012805654 |
| MOS absent | OUVERT | lot ultérieur (G.107 simplifié) |
| RTP non consolidé entre segments pcap | OUVERT | carry `RtpFlowAggregator` (A0-VOIX, ligne 8) : un appel à cheval sur une rotation donne plusieurs events RTP partiels |
| 5QI 1 dédié | NON APPLICABLE sans Rx/N5 | à requalifier si le relevé §3 montre Rx |
| IMS conforme (CSCF séparés, HSS IMS) | hors périmètre | décision Sadok |
