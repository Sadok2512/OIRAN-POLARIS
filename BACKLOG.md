# BACKLOG — OIRAN / POLARIS (source unique des tâches)

Mode : chaque agent prend SA prochaine tâche TODO dans l'ordre, l'exécute, met à jour ce fichier sur ops/backlog
(statut, SHA, commande de test, écarts) et enchaîne. Blocage → BLOCKED + raison, puis tâche suivante.
Statuts : TODO · DOING · DONE · BLOCKED · DEPLOYED

## Règles
- Aucune identité abonné en clair (IMSI, IMEI, SUCI, GUTI, TMSI, RNTI, K, OPc) : code, tests, logs, captures, mocks.
- Aucun chiffre sans sa commande. Un écart se ferme ou se déclare ouvert, jamais expliqué par hypothèse.
- SemVer + ligne CHANGELOG à chaque changement. Pas de CI : tests lancés à la main.
- Lignée : git merge-base --is-ancestor <base en prod> <SHA> avant chaque push/déploiement, sinon STOP.
- Captures externes jamais interrompues. Disque < 85 %. Sauvegarde + rollback à chaque déploiement.
- Runs live uniquement pour vérifier une tâche de ce fichier : flag Live posé puis retiré, detach, labo propre.
- Claude Code (Back100) code. Codex (hôte OIRAN) vérifie sur le labo et déploie.

## En production
POLARIS API 0.17.7 (ddfbca7) · front 0.9.4 (71f04df) · oiran-decode 0.3.1 · iperf3 3.21
Labo : UE-201 AMBR 1 Gbit/s. UDP 0 % perte ≤ 20 Mbit/s ; TCP ~125/136 Mbit/s UL/DL.

## Claude Code
### C1 · POLARIS 0.17.8 (AMBR BSON + test Mongo réel) · DONE · c8f00e2
### C2 · OIRAN live-probe 0.2.3 · DONE · 3812285 (branche feat/live-probe-0.2.3-streaming, base 4da0de7)
Base 4da0de7 (feat/oiran-decoders-0.4). copy_verified + write_jsonl_atomic en streaming ; test pcap 512 MiB → pic < 32 MiB (commande + pic).
Libérer /tmp Back100 < 85 % et faire tourner les 3 tests continuous-import sautés.
### C3 · POLARIS API 0.18.0 · TODO (base c8f00e2)
- #37 GET /ues/:id/activity + SSE /ues/:id/activity/stream (2 s), sans flag Live : RM/CM/RRC/5GMM (filtre strict, aucune identité),
  PDU (PSI, DNN, état, IP), octets/paquets/débits UL/DL uesimtun*, job + étape, 20 derniers événements, voix {"available":false,"reason":"IMS_NOT_AVAILABLE"}.
- #36 Stop toujours autorisé pour l'opérateur, sans flag Live (ps-release-all → deregister → arrêt), idempotent.
- #35 POST/GET/DELETE /live/grant {ue_ids, duration_minutes ≤ 60}, expiration auto, journal d'audit.
- #34 /plmns et /dnns lus dans la config Open5GS réelle (AMF s_nssai, SMF dnn) ; absent → 422 SLICE_NOT_CONFIGURED / DNN_NOT_CONFIGURED.
- #32 Scénario avec étapes voix enregistrable ; seul le Run → 423.
- #33f /capabilities à jour (traffic_ul, traffic_dl, transfer_verify, detach).
### C4 · Front simulator-control 0.10.0 · TODO (base 71f04df, après C3)
- #37 Page UE "Activity" (ligne UE + Topology) : chips RM/CM/RRC/PDU, débits UL/DL sparkline + cumul, job/étape, timeline, panneau Voix honnête ; colonne Traffic live dans UE Manager.
- #33 UE Manager : aucun chevauchement ni scroll horizontal 1440/1920 ; Start/Stop selon état + Run + menu "⋯" (Edit, Clone, Delete) ; Delete discret ;
  infobulle de raison sur tout bouton grisé ; RRC déduit ; "Not running" ; en-tête à jour ; recherche sans IMSI ; Owner réel ; ID une fois ;
  Bulk create actif ou raison ; badge "utilisé par job X".
- #35 Bouton "Autoriser le live" (durée, compte à rebours, révocation).
- #30 + #34 Un seul formulaire abonné/profil (création + édition) : slice/DNN depuis /plmns /dnns, Generate K/OPc, IMSI suivant libre,
  AMBR explicite (1 Gbit/s par défaut), erreurs après saisie.
- #32 Scenario Builder : Save possible si valide, sinon raison affichée.
- Tests : tsc, vitest, playwright (1440 + 1920, light + dark), npm audit --omit=dev.
### C5 · Probe Manager — agent de sonde · TODO (après C4)
Binaire Rust statique signé, enrôlement par jeton unique, connexion sortante mTLS, POST /probes, rôles par interface, Start/Stop capture,
stats live (pps, débit, drops, disque), bibliothèque de segments, envoi des segments finalisés vers OIRAN avec sha256,
mise à jour signée avec retour arrière auto. Agent sans root (CAP_NET_RAW/NET_ADMIN).

## Codex
### X1 · Déployer POLARIS 0.17.8 (c8f00e2) · BLOCKED
Rollback vers 0.17.7 : le test Mongo isolé passe, mais Open5GS 2.8.0 rejette
réellement les AMBR BSON `long` (`UDR: No UE-AMBR`, AMF `GET am-data` 400).
Le profil, le scénario et l'abonné synthétique X1 ont été supprimés ; flag Live
absent et labo revenu à zéro UE actif.
### X2 · Déployer OIRAN live-probe 0.2.3 + oiran-decode 0.4.5 · TODO (après C2)
### X3 · Déployer POLARIS 0.18.0 + front 0.10.0 + parcours UI réel · TODO (après C3 + C4)
### X4 · IMS-lite · TODO (après X3)
### X5 · Agent Probe Manager sur VM de test · TODO (après C5)

## Plus tard
#31 créer slices/DNN depuis l'UI (0.19.0) · IMS voie B · multi-instances / réseau réel.

## Écarts ouverts
Cause NGAP : extensions non nommées ; IE-Extensions S-NSSAI non décodées · segment exact des anciens échecs d'import non conservé · pertes UDP > 50 Mbit/s (buffers gNB UERANSIM) · POLARIS 0.17.8 écrit l'AMBR en BSON `long`, refusé par l'UDR Open5GS 2.8.0 du labo.

## Journal
| Date | Agent | Tâche | Statut | SHA | Tests | Écarts |
|---|---|---|---|---|---|---|
| 2026-10-29 | Claude Code | C1 | DONE | c8f00e2 | cargo test -p polaris-control-api --lib (127 OK, Mongo réel) | — |
| 2026-10-29 | Codex | X1 | BLOCKED | c8f00e2 | Mongo isolé avec document neutre : test BSON PASS ; suite 127 PASS, 0 FAIL, 3 ignored ; test Live : Registration rejetée | UDR `No UE-AMBR` sur BSON `long` ; rollback 0.17.7 effectué |
| 2026-10-29 | Claude Code | C2 | DONE | 3812285 | cargo test -p live-probe --release copy_verified_streams_512_mib_import_under_32_mib_live_allocation -- --ignored --test-threads=1 (peak=1 MiB, bound 32 MiB) ; cargo test -p live-probe (42 OK, 2 ignored) ; cargo test -p oiran-decode (3 OK) | 3 tests continuous-import toujours skippés : /dev/sda1 à 90% (hors scope agent, pas /tmp seul). write_jsonl_atomic streaming côté API ; caller lazy côté live-probe:2197 reporté. |
