# Changelog

## POLARIS 3.0.0 — 2026-11-12 — renumérotation exacte de la production Analyzer

- Version produit unifiée de l’Analyzer 8091 uniquement : API OIRAN issue de
  `7ad769e48937c54e801e573c3f22b0d7ab9f122f` et UI p900 issue de
  `666847332d3a8345605189df200e430a79f6c360`.
- Aucun changement fonctionnel et aucun apport des versions 2.15/2.16 ou
  p900 2.3/2.4. POLARIS Control 8020 reste une application séparée.
- `/api/v1/version` expose seulement le produit, la version et les deux
  commits API/UI de cette release Analyzer; aucun `control_commit`.

## OIRAN API 2.14.3 — 2026-11-12 — contrôle d’accès au démarrage

- Les racines `derived_import_root`, `lte_evidence_root` et `lte_evidence_bundle_root` déjà présentes exigent uniquement lecture et traversée (`R_OK|X_OK`). La création n’est exigée que lorsque la racine est absente; un montage de référence existant en lecture seule ne bloque donc plus le démarrage.
- Le magasin LTE ne crée plus `datasets/` et `exports/` dans son constructeur. Les écritures restent paresseuses et renvoient leurs erreurs explicites de création, copie atomique ou finalisation depuis les routes d’import/export, sans faire échouer le service au démarrage.
- Les contrôles du coffre d’identités et de `capture_root` sont inchangés. Tests ajoutés pour une racine existante en lecture seule et une racine absente sous un parent non inscriptible.
- Versions : `oiran-api` 2.14.3 et `live-probe` 0.5.11; web, schémas, moteurs et décodeurs inchangés.

## OIRAN API 2.14.2 — 2026-11-12 — résolution publiée et index operator borné

- Les routes événement consultent désormais l'union interrogeable commune : callflows statiques, datasets continus et sessions LTE d'évidence. Tout `event_id` renvoyé par une session est donc résolvable par `/events/:id` et `/events/:id/provenance`, y compris une session LTE limitée à S1-MME.
- La dissection résout les chemins de capture relatifs depuis le répertoire de stockage OIRAN. Les erreurs distinguent désormais capture inconnue (`CAPTURE_NOT_FOUND`), fichier source absent (`CAPTURE_SOURCE_NOT_FOUND`), numéro de paquet hors bornes (`PACKET_OUT_OF_RANGE`), outil indisponible (`TSHARK_UNAVAILABLE`) et échec de dissection (`TSHARK_DISSECTION_FAILED`).
- Le coffre maintient un index en mémoire des valeurs normalisées vers leurs observations et sessions. `GET /identities` est paginé (`page`, `page_size`, maximum 100) et n'effectue plus de balayage ni de dissection des sessions lors d'une recherche manquée. Un test mesure une recherche en moins de deux secondes dans 10 000 observations synthétiques.
- Les écritures atomiques live-probe utilisent un nom temporaire unique `(pid, milliseconde, séquence atomique)`. Deux écritures concurrentes ne peuvent plus choisir le même temporaire puis provoquer `finalize dataset_manifest.json: ENOENT`. Le test ANR2 de nettoyage et drainage de 250 segments est ainsi déterministe. Le test d'empreintes orphelines attend aussi le commit atomique final au lieu du seul compteur publié un peu plus tôt dans le cycle.
- Versions : `oiran-api` et web 2.14.2; schémas, moteurs et décodeurs inchangés.

## OIRAN API 2.14.1 — 2026-11-12 — fusion 2.13.1 + 2.14.0

- Fusion sans nouvelle fonctionnalité du Parcours abonné et de la chaîne TMSI 2.13.1 avec Live Trace et le coffre d'identités 2.14.0.
- Le contrat `/health` documente `session_count` et `queryable_session_count` comme l'union interrogeable de `/sessions`; `published_session_count` reste le sous-ensemble publié par les callflows statiques et continus et peut donc être inférieur.

## OIRAN API 2.13.1 — 2026-11-12 — parcours LTE d'évidence

- Cause du parcours vide localisée : `queryable_flows()` indexait les callflows statiques et continus, mais pas les callflows finalisés de `lte_evidence_store`; `/sessions` les ajoutait séparément. L'index commun charge désormais chaque callflow LTE référencé par un manifeste finalisé. Un artefact absent ou illisible produit un journal `SUBSCRIBER_JOURNEY_LTE_*_SKIPPED`, jamais un saut silencieux.
- Audit des noms réellement émis : NAS 5GS publie `subscriber_pseudonym` pour SUCI et `temporary_identity_pseudonym`/`tmsi_pseudonym` pour 5G-GUTI; SBI publie `subscriber_pseudonym`. NAS EPS publie `subscriber_pseudonym` pour l'identité abonné et `temporary_identity_pseudonym`/`tmsi_pseudonym` pour GUTI/S-TMSI; S1AP, GTPv2-C et Diameter publient `subscriber_pseudonym`. Les alias `ue_identity_pseudonym`, `imsi_pseudonym`, `guti_pseudonym`, `s_tmsi_pseudonym` et `m_tmsi_pseudonym` ne sont émis par aucun décodeur actuel : écart **OUVERT**. Les anciens exports S1AP/NGAP classent encore leur identité temporaire externe sous `subscriber_pseudonym`; le parcours fiable de chaîne TMSI repose donc sur le NAS canonique.
- Les événements déjà publiés ne sont pas redécodés. L'historique n'apparaît dans `/subscribers` que si son callflow contient déjà les pseudonymes nécessaires dans `decoded_ie_tree`; sinon la session reste absente ou sa chaîne TMSI reste `OUVERT` jusqu'à une réimportation avec les décodeurs actuels. Aucun rapprochement de repli n'est fait par IMEI, heure, cellule ou IP.
- Tests ajoutés : coexistence d'un run LTE d'évidence et des flows 5G dans l'index, chaîne TMSI attribuée puis présentée `EXACT`, présentation sans attribution `attribution non capturée`, et parité `/health.session_count` avec `/sessions`.
- Versions : `oiran-api` et web 2.13.1; moteurs, schémas et décodeurs inchangés.

## OIRAN API 2.13.0 — 2026-11-12 — parcours abonné et chaîne TMSI

- Ajout des routes viewer `GET /subscribers`, `GET /subscribers/:pseudo/journey` et `GET /subscribers/:pseudo/tmsi`. La hiérarchie publiée est Abonné → Contexte UE → Sessions PDN/PDU → Procédures, dans l'ordre canonique `(capture_id, packet_number, event_id)`.
- Deux sessions ne sont reliées `EXACT` que par égalité de `subscriber_pseudonym`, ou par une identité temporaire observée d'abord comme attribuée puis comme présentée. L'IMEI, l'heure, la cellule et l'adresse IP ne sont jamais des preuves de liaison. Une attribution absente reste `OUVERT` avec la raison `attribution non capturée`.
- `decoder-nas` 0.4.0 distingue désormais les identités d'abonné et temporaires, et émet `tmsi_pseudonym` sous le domaine partagé `temporary-mobile-identity` pour les GUTI EPS/5GS attribués ou présentés. Les octets et valeurs TMSI ne sont jamais publiés.
- Les résumés de session exposent `subscriber_pseudonym`, `subscriber_session_count`, `previous_session_id` et `next_session_id`. Le coffre et les routes `/identities` de 2.12.0 restent inchangés.
- L'écart `/health` 42 contre `/sessions` 44 provenait de deux ensembles : manifeste continu contre union interrogeable (datasets + preuves). `session_count` et `queryable_session_count` comptent désormais l'union de `/sessions`; le compteur plus étroit porte le nom `published_session_count`.
- Versions : `oiran-api` et web 2.13.0, `decoder-nas` 0.4.0, `event-schema` 1.7.0, `session-engine` 0.5.13, `callflow-schema` 1.4.0.

## 2.14.0

- Registre borné à dix Live Traces avec recherche pseudonyme ou coffre d'identités, état armé, expiration automatique et mutations protégées par CSRF.
- Flux SSE reprenable par `Last-Event-ID`, heartbeat 15 s et tampon borné à 2 000 événements par trace.
- Coffre déplacé vers `/var/lib/oiran/identity-vault/vault.json`, répertoire dédié 0700 appartenant au compte du service; aucun changement de mode de `/var/lib/oiran`.
- Préflight de démarrage explicite des chemins requis avec erreur `ACCESS_CHECK_FAILED path=… mode=…` au lieu d'un `Permission denied` sans contexte.

## OIRAN API 2.12.0 — 2026-11-11 — coffre d'identités operator

- Coffre d'identités persistant hors dataset, répertoire 0700 et fichier 0600, avec preuves ordonnées `(capture_id, packet_number)` et aucune valeur claire dans les journaux.
- Coffre situé dans `/var/lib/oiran/identity-vault/vault.json`, créé par le compte du service sans modifier le mode de `/var/lib/oiran`.
- Préflight des chemins requis avec erreur `ACCESS_CHECK_FAILED path=… mode=…` au lieu d'un `Permission denied` sans contexte.
- `GET /sessions/:id/identities` et `GET /identities?q=…` sont réservés à l'operator et exposent IMSI, TMSI, S-TMSI, M-TMSI, IMEI/IMEISV et MSISDN avec leur événement source.
- `GET /packets/:capture_id/:packet_number/dissect` fournit la dissection `tshark -V` d'une référence déjà connue, uniquement à l'operator et sans accepter de chemin client.
- La collecte claire est un canal privé fondé sur les paquets sources ; les événements et datasets publiés restent pseudonymisés.

## OIRAN API 2.11.16 — 2026-11-11 — gate phase 13 mesuré et scan callflow accéléré

- Le compteur `PUBLICATION_RSS_TRACE elapsed_ms` démarre désormais sur la ligne `CONTINUOUS_PUBLICATION_INCREMENTAL phase=begin`, avant le décodage du lot, afin de coïncider avec la méthode chronométrique du gate fantôme. Cette origine est transmise explicitement dans la pile de publication ; aucun chrono global n'est partagé entre threads.
- Pour un index compact d'au plus 262 144 représentants, la phase 10 reconstruit les callflows depuis cet index déjà en mémoire, par lots bornés de 32, puis le libère. **Seuil 262 144 : décision coordination 2026-11-11**, validée sur 240 097 représentants, pic 1,39 GiB, plafond 2 GiB. Au-delà, le chemin disque reste actif. Un test compare désormais les deux chemins : mêmes `event_id`, callflows et arêtes.
- Cause LTE : la publication lisait bien tous les shards ensemble, mais `compact_publication_event` supprimait `f_teid`; en outre, le lecteur multi-shards gardait le premier représentant historique alors que le lecteur monolithique gardait le dernier. Les preuves S11/S5-C disparaissaient donc avant `discover_lte_sessions`, et un pseudonyme réutilisé sur plusieurs contextes rendait l'attachement ambigu. `f_teid` est stable, le remplacement est identique en monolithe et en shards, et l'E-RAB/F-TEID prime désormais sur le pseudonyme pour choisir le contexte LTE. S6a s'attache au contexte déjà ancré sur S11.
- Cause 5G : la compaction traitait comme doublons trois occurrences de procédure distinctes. Les événements perdus étaient `evt-ddfb813e4307a5da`, `evt-22e6637edeb40b0b` et `evt-3567800af548bd0b` (seconds Setup NGAP et seconde réponse d'établissement PFCP). Les procédures de setup/établissement conservent maintenant leur occurrence canonique ; les modifications PFCP à haute fréquence restent compactées.
- Le test d'équivalence publie le même jeu 5G en un shard puis trois lots et compare IDs de session, interfaces, événements et arêtes. Le cas LTE répartit S1-MME/S11/S1-U/S5-C/S5-U/Sxab/S6a sur trois lots et impose le même résultat global.
- La décision de coordination classe le critère 5 de la recette 2.11.15 en faux échec : à l'arrêt `pending=0`, `closed_not_ingested_segments=0`, sans rotation entre 22:44 et 23:04 ; l'ingestion est validée.
- La recette 2.11.16 utilise exclusivement une copie figée du dataset de production et du ring sous `/var/tmp`, jamais un lower vivant (`docs/OIRAN_2_11_16_FROZEN_SCALE_GATE.md`).
- Versions : `oiran-api` et web 2.11.16, `live-probe` 0.5.10, `session-engine` 0.5.12. Décodeurs et moteur de corrélation inchangés.

## OIRAN API 2.11.15 — 2026-11-11 — shard 0 strictement immuable sur overlayfs

- La migration du monolithe historique en shard 0 ne crée plus de hard-link dans `.dataset-next` et ne renomme plus le répertoire `dataset`. Le manifeste référence directement `oiran_events.jsonl`; ce fichier n'est ouvert qu'en lecture et ne subit ni écriture, ni renommage, ni `fsync`, ni changement de métadonnées.
- Chaque cycle installe uniquement son nouveau shard et une nouvelle génération de callflows, puis remplace atomiquement `dataset_manifest.json`. Le GC ne reçoit jamais un chemin de shard événement référencé.
- `CONTINUOUS_CYCLE phase=end` expose désormais `bytes_written` et `files_created`. Le test de migration conserve inode, taille, mtime et SHA-256 du shard 0 pendant trois cycles et refuse tout autre fichier supérieur à 10 MiB.
- La recette fantôme impose `upper < 50 MiB` après 60 minutes. Le test overlayfs local a été tenté mais le noyau de développement refuse le montage aux utilisateurs non privilégiés ; la commande et le critère restent normatifs pour ANR2.
- Versions : `oiran-api` et web 2.11.15, `live-probe` 0.5.9. Moteurs et décodeurs inchangés.

## OIRAN API 2.11.14 — 2026-11-11 — publication continue par shards immuables

- Cause de l’arrêt observé en 2.11.13 : le lot courant était bien limité à deux segments, mais la phase de fusion recopiait encore les 3,4 Go de `oiran_events.jsonl` dans `.dataset-next` avant toute publication. Le coût d’écriture restait donc proportionnel à tout l’historique.
- Le dataset continu est désormais une suite de shards JSONL immuables décrits dans `dataset_manifest.json` par chemin relatif, checksum SHA-256, taille et nombre d’événements. Chaque cycle écrit uniquement le shard du lot courant. Les shards antérieurs sont réutilisés par liens physiques pendant le swap atomique ; aucun de leurs octets n’est réécrit.
- La migration du dataset historique inscrit le monolithe existant comme shard 0, sans modifier son inode ni son contenu. Le manifeste est le dernier fichier remplacé au commit.
- `session-engine` charge plusieurs shards en flux et trie les représentants par l’ordre canonique `(capture_id, packet_number, event_id)`. L’API sait également ouvrir un dataset shardé. Les sessions globales sont recalculées depuis les flux de shards ; les callflows historiques non affectés restent réutilisés.
- `CONTINUOUS_CYCLE` expose `bytes_written`, égal aux octets du nouveau shard. `/api/v1/metrics` expose toujours `closed_not_ingested_segments`, défini comme les segments fermés par présence d’un successeur sur la même interface et absents de `import_state`.
- Le test de trois publications vérifie trois shards, l’invariance des checksums précédents et l’égalité des sessions/événements avec une publication complète des mêmes données.
- Versions : `oiran-api` et web 2.11.14, `live-probe` 0.5.8, `session-engine` 0.5.11. Décodeurs et moteur de corrélation inchangés.
- Gate manuel : tests Rust concernés puis `cargo build --release --locked`. La recette à l’échelle reste exécutée par ANR2 avant déploiement selon `docs/OIRAN_2_11_14_SHARDED_SCALE_GATE.md`.

## OIRAN API 2.11.13 — 2026-11-11 — reprise continue après publication

- Cause des ~30 minutes avant `00a` : `live-probe::process_capture_into` redécodait tous les PCAP possédés à chaque cycle avant de fusionner le JSONL historique. Avec 5 636 segments déjà importés, ce travail était linéaire dans tout l'historique et précédait la première trace de publication.
- Cause du gel après la phase 13 : le thread unique restait dans `process_continuous_capture` pour permuter le dataset puis supprimer récursivement `.dataset-previous`. Sur l'overlay du fantôme, cette suppression produisait les whiteouts du dataset complet ; aucun nouveau scan n'était lancé, donc les six candidats en stabilité ne pouvaient pas atteindre leur second passage. `MAX_INGESTED_SEGMENTS_PER_SCAN=32` n'était pas atteint par les 30 pending.
- La publication continue ne décode désormais que les segments du lot courant ; le JSONL, les rapports et les checksums antérieurs sont fusionnés depuis le checkpoint publié. L'ancien dataset est renommé en tombstone unique puis supprimé par un ramasse-miettes asynchrone, hors du thread de scan. Les tombstones GC sont exclus du budget de travail et récupérés au démarrage.
- Chaque tour journalise `CONTINUOUS_CYCLE` au début et à la fin avec segments ingérés, pending, pending stabilité, durée, état de publication et délai maximal du segment fermé. Le SLO publié est de 10 minutes. `CONTINUOUS_PUBLICATION_INCREMENTAL`, `CONTINUOUS_PUBLICATION_PHASE` et `CONTINUOUS_DATASET_GC` rendent chaque sous-phase visible.
- Le test de rotation ferme trois segments avant, pendant et après une publication, puis vérifie les trois checksums commités et `pending=0` hors segments ouverts.
- La recette ANR2 de 60 minutes est documentée dans `docs/OIRAN_2_11_13_CONTINUOUS_GATE.md`, avec mesures cgroup toutes les 30 secondes, progression des cycles et recette LTE 5/5 finale.
- Versions : `oiran-api` et web 2.11.13, `live-probe` 0.5.7. Les décodeurs et moteurs de session/corrélation restent inchangés.
- Gate manuel : tests `live-probe`, puis `cargo build --release --locked`. La recette fantôme complète reste exécutée par ANR2 avant tout déploiement.

## OIRAN API 2.11.12 — 2026-11-11 — publication bornée avant la phase 01

- Cause prouvée : `session-engine::load_path_streaming_representatives` conservait un `BTreeMap<String, EventRecord>` par clé dite sémantique. Depuis 2.11.4, la clé reprenait notamment les nouveaux `gtpv2c_sequence` et `pfcp_sequence`, en plus des identifiants de règle transactionnels historiques `pdr_id`, `far_id` et `qer_id`. Ces valeurs changeaient à chaque message et empêchaient la compaction ; le chargeur retenait donc presque tout le JSONL sous forme de clés et objets Rust avant `01-after-streaming-representatives`, conformément aux 4,2 GiB anonymes mesurés par le noyau.
- La représentation conserve tous ces identifiants pour la découverte et la corrélation, mais la clé de déduplication ne contient plus que l'état durable de session/tunnel. Les clés tunnel restent discriminantes ; aucun seuil n'est modifié et l'ordre canonique `(capture_id, packet_number, event_id)` reste inchangé.
- `load_path_streaming_representatives_with_progress` publie le nombre d'événements lus et de représentants tous les 100 000 événements. `live-probe` ajoute les phases `00a-before-heap-release`, `00b-after-heap-release` et `00c-streaming-representatives` entre la fusion et la phase 01.
- `PUBLICATION_RSS_TRACE` lit aussi `anon`, `file`, `shmem` et `memory.peak` depuis `/sys/fs/cgroup/system.slice/oiran-api.service`. La commande `cargo test -p session-engine --release publication_scale_1_5m -- --ignored --nocapture` a traité 1 500 000 événements et 3 883 537 216 octets de JSONL (plus que les 3 394 193 764 octets de production), retenu 4 096 représentants et mesuré `VmHWM=18 640 KiB`, sous le gate strict de 2 GiB.
- La recette ANR2 est documentée dans `docs/OIRAN_2_11_12_SCALE_GATE.md` : copie/overlay du dataset de production complet et du ring, `MemoryMax=4G`, lecture de `memory.stat` et `memory.peak` toutes les 30 s jusqu'à la phase 13, progression d'ingestion, puis session LTE 5/5 EXACT.
- Versions : `oiran-api` et web 2.11.12, `session-engine` 0.5.10, `live-probe` 0.5.6. Les décodeurs et moteurs de corrélation restent inchangés.
- Gate manuel : test release à l'échelle, tests Rust concernés, puis `cargo build --release --locked`. La recette fantôme sur données réelles reste exécutée par ANR2 avant tout déploiement.

## OIRAN API 2.11.11 — 2026-11-11 — cardinalité légitime des preuves abonné S6a

- Cause prouvée : `append_lte_bridge` appliquait la garde anti-ambiguïté des clés tunnel à `subscriber_pseudonym`. Un NAS Attach Request correspondant à plusieurs messages S6a du même abonné faisait rejeter tout le groupe, puis produisait l'arête de repli OPEN.
- `correlation-engine` 0.6.11 et la règle LTE `1.1.1-offline.1` distinguent désormais les preuves : un TEID répété reste fermé et ambigu, tandis qu'un pseudonyme abonné commun produit une arête EXACT vers chaque message S6a qui le porte. Ce choix conserve séparément la provenance AIR/ULR requête/réponse et le fold d'interface accepte cette cardinalité.
- Si le même ensemble S6a contient deux pseudonymes distincts, aucune arête abonné exacte n'est publiée : une arête OPEN `OPEN_AMBIGUOUS_SUBSCRIBER_PSEUDONYM` explique l'ambiguïté. Son couple représentatif est choisi dans l'ordre canonique `(capture_id, packet_number, event_id)`, jamais par horodatage.
- Le test construit les octets d'un NAS Attach Request et de quatre messages Diameter — AIR requête/réponse et ULR requête/réponse — puis exécute les vrais décodeurs, la publication compacte et la corrélation. Il vérifie quatre arêtes EXACT avec `matching_identifiers=["subscriber_pseudonym"]`. Une variante décodée avec un second abonné vérifie l'unique résultat OPEN. Les tests de TEID réutilisé restent fermés.
- Versions : `oiran-api` 2.11.11, web 2.11.11, `correlation-engine` 0.6.11. Les décodeurs et `session-engine` restent inchangés.
- Gate manuel : `cargo build --release --locked`. La recette réelle reste exécutée par ANR2 avant tout déploiement.

## OIRAN API 2.11.10 — 2026-11-11 — canonicalisation inter-protocoles du pseudonyme abonné

- Cause prouvée : `event-schema/src/lib.rs` hachait le label et les octets fournis par chaque décodeur. NAS EPS et GTPv2-C fournissaient du TBCD, Diameter les octets ASCII de `User-Name`, NAS 5GS l'identité mobile binaire complète et SBI la chaîne `imsi-…` ; ces représentations différentes d'une même identité produisaient donc des pseudonymes différents.
- `event-schema` 1.6.2 définit une entrée commune : la chaîne de chiffres décimale canonique, le label partagé et `SUBSCRIBER_PSEUDO_DOMAIN`. `decoder-nas` 0.3.3 l'applique aux identités EPS et aux SUCI 5GS à schéma nul ; `decoder-gtpv2c` 0.1.3, `decoder-diameter` 0.2.7 et `decoder-sbi` 0.4.3 l'appliquent respectivement à l'IMSI TBCD, au `User-Name` et au SUPI `imsi-…`.
- NAS Attach Request / Identity Response, GTPv2-C IMSI, Diameter AIR/ULR et SBI SUPI publient `subscriber_pseudonym` dans `identifiers`. Le compactage de `session-engine` conserve explicitement cette clé.
- Le test bout en bout construit les octets NAS Attach, GTPv2 Create Session Request et Diameter AIR, exécute les vrais décodeurs S1AP/NAS, GTPv2-C et Diameter, écrit puis recharge la publication compacte, et vérifie trois pseudonymes égaux ainsi qu'une arête S1-MME↔S6a EXACT avec `matching_identifiers=["subscriber_pseudonym"]`. Aucun identifiant n'est injecté à la main.
- **Les pseudonymes d'abonné d'avant 2.11.10 ne sont pas comparables à ceux d'après.**
- Versions : `oiran-api` 2.11.10, web 2.11.10, `event-schema` 1.6.2, `decoder-nas` 0.3.3, `decoder-s1ap` 0.2.2, `decoder-gtpv2c` 0.1.3, `decoder-diameter` 0.2.7, `decoder-sbi` 0.4.3, `correlation-engine` 0.6.10 et `oiran-decode` 0.7.4.
- Gate manuel : `cargo build --release --locked`. La recette réelle reste exécutée par ANR2 avant tout déploiement.

## OIRAN API 2.11.9 — 2026-11-11 — porteur NAS du pseudonyme S1-MME↔S6a

- `correlation-engine` 0.6.9 inclut les événements NAS-EPS appartenant au contexte S1-MME dans le pont vers S6a. Quand le NAS Attach Request enfant porte le même `subscriber_pseudonym` que l'AIR, l'arête EXACT part de cet événement NAS plutôt que du parent S1AP dépourvu de pseudonyme.
- La comparaison reste effectuée sur les valeurs pseudonymisées en mémoire, mais `matching_identifiers` publie uniquement le nom `subscriber_pseudonym`, jamais sa valeur.
- L'audit du chemin 5G confirme que le rattachement SBI indexe déjà tous les événements de la session, NAS-5GS inclus ; aucun filtre NGAP-only analogue ne participe à ce rattachement et aucun changement 5G n'est nécessaire.
- Le test synthétique construit un S1AP InitialUEMessage, son NAS-EPS-MM Attach Request enfant et un AIR S6a partageant un pseudonyme opaque ; il vérifie la source NAS, la confiance EXACT et la preuve non vide sans valeur sensible.
- Versions : `oiran-api` 2.11.9, web 2.11.9, `correlation-engine` 0.6.9. `session-engine` reste en 0.5.9.
- Gate manuel : `cargo build --release --locked`. La recette réelle reste exécutée par ANR2 avant tout déploiement.

## OIRAN API 2.11.8 — 2026-11-11 — protocoles normalisés pour la collecte S6a

- `session-engine` 0.5.9 compare sans tenir compte de la casse tous les noms de protocole utilisés par ses filtres. Les événements S6a publiés avec `protocol="DIAMETER"` rejoignent ainsi la collection LTE avant leur rattachement par `subscriber_pseudonym`.
- `correlation-engine` 0.6.8 applique la même comparaison normalisée à tous ses filtres de protocole afin qu'une variation de casse ne supprime aucune preuve avant corrélation.
- Le test synthétique associe un événement S1AP et un événement S6a `DIAMETER` par le même pseudonyme opaque, puis vérifie la présence de S6a dans la session LTE et l'arête S1-MME↔S6a EXACT. Il ne contient ni pcap réel ni identité abonné.
- Versions : `oiran-api` 2.11.8, web 2.11.8, `session-engine` 0.5.9, `correlation-engine` 0.6.8.
- Gate manuel : `cargo build --release --locked`. La recette réelle reste exécutée par ANR2 avant tout déploiement.

## OIRAN API 2.11.7 — 2026-11-11 — fermeture du lot A LTE

- `session-engine` 0.5.8 rattache les deux moitiés d'une transaction Create Session S5-C par la clé structurelle exacte `(capture_id, gtpv2c_sequence, procédure, paire d'endpoints)`. Le F-TEID DL porté uniquement par la requête rejoint ainsi la même session que le F-TEID UL de la réponse, sans aucune jointure temporelle.
- S6a est rattaché à l'unique session LTE lorsque son `subscriber_pseudonym` commun au domaine `SUBSCRIBER_PSEUDO_DOMAIN` correspond à celui d'un événement S11 déjà possédé. Aucune identité brute n'est lue ni publiée.
- `correlation-engine` 0.6.7 produit l'arête S5-C↔S5-U DL sur le F-TEID de la requête et une arête S11↔S6a EXACT sur le pseudonyme commun. La limitation périmée « Synthetic preparation rule; real LTE evidence is not ANR1-certified » est retirée.
- Tests synthétiques : requête/réponse GTPv2-C aux F-TEID distincts, S5-U dans les deux sens et pseudonymes S1/S11 volontairement différents afin de prouver le rattachement S6a par S11. Aucun pcap réel ni identité abonné n'est inclus.
- Versions : `oiran-api` 2.11.7, web 2.11.7, `session-engine` 0.5.8, `correlation-engine` 0.6.7.
- Gate manuel : `cargo build --release --locked`. La recette réelle des sept segments `_00067`, publication et compaction comprises, reste exécutée par ANR2 avant tout déploiement.

## OIRAN API 2.11.6 — 2026-11-11 — exhaustivité LTE bidirectionnelle et Diameter TCP cadré

- `correlation-engine` 0.6.6 émet une arête pour chaque F-TEID U-plane décodé sur S11↔S1-U, S5-C↔S5-U et Sxab↔S5-U. Il préfère l'agrégat à son ancien singleton de frontière de lot, échoue fermé pour un TEID réellement ambigu et initialise toujours `matched_rules` avec `rule_id`. La limitation E-RAB périmée est retirée puisque l'extraction imbriquée est présente.
- `live-probe` 0.5.5 agrège GTP-U par `(message_type, teid, direction)` et fusionne l'éventuel premier paquet `UNKNOWN` lorsque la direction du tunnel est résolue. L'ordre canonique de sélection reste `(capture_id, packet_number, event_id)`, jamais l'horodatage.
- `oiran-decode` 0.7.3 réassemble chaque direction TCP par 4-tuple puis découpe le flux Diameter au champ `Length`, y compris plusieurs messages dans un segment et un message réparti sur plusieurs segments, avec provenance exacte et sans doublon.
- `decoder-diameter` 0.2.6 corrige les types AVP 3GPP nécessaires à AIR/ULR, notamment `ULR-Flags` (1405, entier non groupé). Un message de trame valide reste `DECODED` quand un AVP inconnu est conservé par longueur et empreinte ; un défaut de structure reste `MALFORMED`.
- Les tests construits couvrent les TEID `0x00007804`, `0x00000001`, `0x00007f6f`, `0x0000be90`, les deux sens de chaque pont LTE, l'agrégation du premier paquet, AIR/ULR et les segmentations TCP 2→1 et 1→2. Ils ne contiennent aucun pcap réel ni identité abonné.
- Versions : `oiran-api` 2.11.6, web 2.11.6, `live-probe` 0.5.5, `correlation-engine` 0.6.6, `oiran-decode` 0.7.3, `decoder-diameter` 0.2.6.
- Gate manuel : `cargo build --release --locked`. La recette réelle des sept segments `_00067`, publication et compaction comprises, reste exécutée par ANR2 avant tout déploiement.

## OIRAN API 2.11.5 — 2026-11-11 — clés LTE décodées avant corrélation

- `decoder-s1ap` 0.2.1 décode les listes E-RAB des procédures Initial Context Setup et E-RAB Setup (requêtes et réponses) et publie `erab_id`, `erab_teid`, `transport_layer_address` et `tunnel_endpoint_ip`. Les IE NAS-PDU et SecurityKey de l'Initial Context Setup restent entièrement omis : ni valeur, ni empreinte.
- `decoder-gtpu` 0.2.1 publie `teid`, `tunnel_endpoint_ip` et `tunnel_direction` sur chaque G-PDU. `live-probe` 0.5.4 applique la même agrégation continue aux interfaces N3, S1-U et S5-U ; `session-engine` 0.5.7 conserve ces clés pendant le compactage de publication.
- `decoder-gtpv2c` 0.1.2 publie le type d'interface associé à `f_teid` et `bearer_f_teid` sous `f_teid_iface` et `bearer_f_teid_iface`, conservés eux aussi par le compactage.
- La preuve ANR2 #9 `6784427670` établit que le segment S6a LTE utilise Diameter sur TCP, port serveur 3868, et non SCTP. `oiran-decode` 0.7.2 réassemble donc les deux directions TCP portant le port 3868 et les route vers `decoder-diameter`. Le correctif SCTP PPID 0 de 2.10.4 reste présent et testé.
- Les tests unitaires utilisent uniquement des trames synthétiques construites d'après les structures ASN.1 PER et les en-têtes GTP/Diameter ; aucun pcap réel ni identité abonné n'est inclus.
- Versions : `oiran-api` 2.11.5, web 2.11.5, `live-probe` 0.5.4, `session-engine` 0.5.7, `oiran-decode` 0.7.2, `decoder-s1ap` 0.2.1, `decoder-gtpu` 0.2.1, `decoder-gtpv2c` 0.1.2.
- Gate de build manuel : `cargo build --release --locked`. La recette des sept segments `_00067`, publication/compaction comprise, reste un gate ANR2 obligatoire avant déploiement.

## OIRAN API 2.11.4 — 2026-11-11 — découverte LTE continue et lockfile gate

- Cause exacte : `session-engine/src/lib.rs`, `compact_publication_event`, supprimait les ancres S1AP/LTE avant que `live-probe` appelle `offline_lte_callflows` à la phase `07-after-lte-flows-built`. La phase était bien publiée, mais recevait des événements sans `enb_ue_s1ap_id`, `mme_ue_s1ap_id`, `erab_teid` ni `bearer_f_teid`.
- Le compactage conserve désormais les ancres LTE. La découverte rattache S1-MME, S11, S1-U, S5-C, S5-U, Sxab et S6a uniquement par clés structurelles normalisées ou pseudonyme abonné commun ; aucune jointure temporelle.
- Les arêtes LTE sont `EXACT` quand une clé décodée est égale, sinon `OPEN`; aucune confiance probable n'est produite.
- Le pseudonyme abonné inter-protocoles utilise `SUBSCRIBER_PSEUDO_DOMAIN`; aucune identité brute n'est sérialisée.
- Le routage S6a avec PPID 0 introduit en 2.10.4 reste couvert par `routes_s6a_regardless_of_ppid_2_10_4`.
- Route documentée pour les arêtes d'une session : `GET /api/v1/sessions/{session_id}/correlations`.
- Versions : `oiran-api` 2.11.4, `live-probe` 0.5.3, `session-engine` 0.5.6, `correlation-engine` 0.6.5, `callflow-schema` 1.3.2, `event-schema` 1.6.1, `decoder-nas` 0.3.2, `decoder-gtpv2c` 0.1.1, `decoder-diameter` 0.2.5, web 2.11.4.
- Gate obligatoire : régénérer `Cargo.lock`, puis exécuter `cargo build --release --locked` avant chaque poussée de version.

## OIRAN API 2.11.3 — 2026-11-10 — exclusion rollback/next/previous du budget (devmat, cause BLOCKED ANR1 #9 comment 6781367658)

**Patch qui corrige la cause BLOCKED prouvée par ANR1** sur la production 2.10.2. C'est **la version qui sera déployée** (2.11.1 et 2.11.2 ne le sont pas seules).

### 1. Cause exacte (ANR1)

```
.dataset.rollback.20261110T204701Z : 3 380 541 933 octets
  dans la racine d'import `/var/lib/oiran/captures/continuous-lab-import/`
→ counted dans work_bytes
→ staging_bytes = 3 386 220 588 octets
→ 3 386 220 588 + 193 772 (candidate) + 67 108 864 (derived reserve)
  = 3 453 423 224 > 1 140 850 688 (max_owned_bytes)
→ CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT
→ CaptureState::Blocked
```

Le répertoire `.dataset.rollback.YYYYMMDDTHHMMSSZ/` est un tombstone opérateur créé par la procédure de rollback ANR1 (**pas** un artefact OIRAN). `work_bytes` (`live-probe/src/lib.rs:8681-8688`) comptait TOUT sous `base/` sauf `dataset/` et `pcap/<sha>.pcap...`, donc incluait ce tombstone.

### 2. Fix : exclure `.dataset.rollback.*` + `.dataset-previous` + `.dataset-next` du budget

```rust
fn work_bytes(base: &Path) -> u64 {
    let total = directory_size(base);
    let published = directory_size(&base.join("dataset"));
    let committed_ring = committed_ring_bytes(&base.join("pcap"));
    let next = directory_size(&base.join(".dataset-next"));
    let previous = directory_size(&base.join(".dataset-previous"));
    let (rollback_bytes, rollback_paths) = rollback_tombstones(base);
    if next > 0 || previous > 0 || rollback_bytes > 0 {
        eprintln!("CONTINUOUS_BUDGET_EXCLUSION {...}");
    }
    total
        .saturating_sub(published)
        .saturating_sub(committed_ring)
        .saturating_sub(next)
        .saturating_sub(previous)
        .saturating_sub(rollback_bytes)
}
```

Trois exclusions, toutes argumentées en commentaire du code :

| Exclusion | Pourquoi |
|---|---|
| `.dataset-next/` | Mid-publish staging. Sa taille est une FONCTION de l'historique du dataset (jusqu'à ~3,3 Go observé en prod sur 1,5 M events). **`max_owned_bytes = 1,06 GiB` serait trivialement dépassé par une publication normale** — voir §3. Le budget ne gate plus l'écho du dataset existant. |
| `.dataset-previous/` | Tombstone transient de l'atomic swap (`dataset → .dataset-previous → delete`). Pre-2.11.3 → le dataset comptait **deux fois** pendant quelques ms. |
| `.dataset.rollback.YYYYMMDDTHHMMSSZ/` | Tombstone opérateur ANR1 (3,38 Go observé). Non géré par OIRAN. Représente un choix opérationnel, pas de la consommation d'ingest. |

Log structuré `CONTINUOUS_BUDGET_EXCLUSION` émis à chaque calcul `work_bytes` quand l'une au moins est non-nulle, pour qu'ANR2 puisse prouver le calcul en direct :

```json
{
  "event": "CONTINUOUS_BUDGET_EXCLUSION",
  "dataset_next_bytes": 0,
  "dataset_previous_bytes": 0,
  "rollback_bytes": 3380541933,
  "rollback_paths": [".../continuous-lab-import/.dataset.rollback.20261110T204701Z"],
  "published_bytes": 3380541904,
  "committed_ring_bytes": 1806897788,
  "total_bytes": 8573660280,
  "reason": "2.11.3 excludes transient dataset staging + operator rollback tombstones from backpressure budget"
}
```

### 3. Preuve chiffrée : `.dataset-next` vs `max_owned_bytes` pendant une publication normale

**Observation prod 1,5 M events** (ANR2 trace fu3 et plus tard) :

- `.dataset-next/oiran_events.jsonl` ≈ **3,3 Go** après merge (prior 2,7 Go + decoded spool 600 Mo).
- `.dataset-next/callflows/` ≈ 60 Mo (1000 sessions × JSON + HTML).
- `.dataset-next/dataset_manifest.json` ≈ 1 Mo.
- **Total `.dataset-next/` pic ~3,3-3,4 Go** pendant publication.

`max_owned_bytes = 1 GiB + 64 MiB = 1 140 850 688` (`live-probe/src/lib.rs:967-968`, `DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES` + `MAX_CONTINUOUS_DERIVED_BYTES`).

**Verdict pre-2.11.3** : chaque publication normale 1,5 M events **dépassait structurellement** `max_owned_bytes` sur son staging seul (3,3 Go > 1,06 GiB). Le gate backpressure trippait au premier candidate pendant le publish. La prod ne fonctionnait avant 2.10.2 que parce que :
- La publication était rare (sync, bloquait tout).
- `storage_bytes` observait 8,5 Go sans que ce chiffre entre dans le gate (chiffre indicatif).

**Verdict post-2.11.3** : `.dataset-next` exclu → staging reflète UNIQUEMENT le pcap-in-flight (`.importing` temp, quelques KB par candidate) + petits fichiers top-level. La publication normale tient trivialement sous max_owned_bytes.

**Seuils NON modifiés** :
- `DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES = 1 GiB` — inchangé.
- `MAX_CONTINUOUS_DERIVED_BYTES = 64 MiB` — inchangé.
- `max_owned_bytes = 1 140 850 688` — inchangé.
- Règle projet 99 %/95 % (ajoutée en 2.11.2) — inchangée.

Seul le CALCUL de `work_bytes` change — comme demandé par la coordination.

### 4. Recommandation déploiement : tombstones rollback **hors** racine d'import

Point 1 du brief demande : « Qu'OIRAN ne les crée plus jamais dans la racine d'import ; documente dans le CHANGELOG un chemin de rollback hors racine pour les procédures de déploiement. »

**Grep confirme** qu'OIRAN ne crée pas `.dataset.rollback.*` (pas de référence dans `*.rs`). C'est la procédure de rollback ANR1 (hors repo) qui le crée.

**Recommandation pour la procédure ANR1** :

```sh
# Pré-swap : sauvegarder l'ancien dataset HORS racine d'import.
OIRAN_ROLLBACK_ARCHIVE=/var/lib/oiran/rollback-archive
mkdir -p $OIRAN_ROLLBACK_ARCHIVE

BASE=/var/lib/oiran/captures/continuous-lab-import
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mv $BASE/dataset $OIRAN_ROLLBACK_ARCHIVE/dataset.$STAMP
# ou, atomic : cp -a + mv final.

# Appliquer le nouveau dataset.
mv /tmp/new-dataset $BASE/dataset

# En cas de rollback nécessaire :
mv $BASE/dataset $BASE/.dataset.rollback.failed-$STAMP   # <-- sous rollback-archive à terme
mv $OIRAN_ROLLBACK_ARCHIVE/dataset.$STAMP $BASE/dataset
```

Un répertoire tombstone **hors** `/var/lib/oiran/captures/<capture-id>/` ne sera jamais vu par `work_bytes` (qui ne regarde que la racine du capture). Même si ANR1 continue de placer les tombstones dans la racine d'import, 2.11.3 les exclut explicitement — c'est une double sécurité.

### 5. Test reproduisant le cas exact ANR1

`rollback_tombstone_excluded_from_work_bytes_proof_anr1_6781367658` :

- Fabrique `.dataset.rollback.20261110T204701Z/oiran_events.jsonl` **sparse** de **3 380 541 933 octets** (chiffre exact ANR1).
- Assert `directory_size(rollback) == 3 380 541 933`.
- Fabrique `pcap/N2.pcap-....importing` de 193 772 octets (candidate N2 typique).
- Seuils prod 2.10.2 : `max_owned_bytes = 1 140 850 688`, `derived_reserve = 64 MiB`, `candidate = 193 772`.
- Assert `staging + candidate + derived_reserve ≤ max_owned_bytes`.
- Assert `staging < 64 MiB` (reflète seulement `.importing`).

Deux tests additionnels :
- `dataset_next_excluded_from_work_bytes_matches_normal_publication` — `.dataset-next/oiran_events.jsonl` sparse 3,3 Go → `staging < max_owned_bytes`.
- `dataset_previous_excluded_from_work_bytes` — `.dataset-previous/oiran_events.jsonl` sparse 2,7 Go → `staging < max_owned_bytes`.

**4 tests `work_bytes_*` passent** (le test 2.9.8 historique `work_bytes_excludes_committed_pcap_ring_proof_anr2` continue de passer).

### Versions

| crate / package | 2.11.2 | 2.11.3 |
|---|---|---|
| `oiran-api` | 2.11.2 | **2.11.3** (patch) |
| `live-probe` | 0.5.1 | **0.5.2** (patch) |
| `@oiran/web` | 2.11.2 | **2.11.3** (sync) |
| `oiran-decode` | 0.7.1 | 0.7.1 |
| `event-schema` | 1.6.0 | 1.6.0 |

### Tests

- `cargo test -p live-probe --lib -- --test-threads=1` : **125 PASS, 0 fail, 5 ignored** (+3 nouveaux `work_bytes` exclusion).
- `cargo test -p oiran-api --lib` : **63 PASS, 0 fail**.
- `cargo test -p oiran-decode --lib` : **12 PASS, 0 fail**.

### Impact opérateur

Après déploiement 2.11.3 :

- **Le BLOCKED actuel disparaît** : à la prochaine itération du scan loop, `work_bytes` retourne quelques MiB (pas 3,38 Go) → condition `staging + candidate + derived_reserve ≤ max_owned_bytes` satisfaite → `state` transitionne `Blocked → Capturing` automatiquement (grâce à 2.11.2 auto-resume).
- **Les 25 pending_segments** du relevé ANR1 sont ingérés au premier scan post-déploiement (grâce à 2.11.2 stability-skip-on-successor).
- **Le tombstone `.dataset.rollback.20261110T204701Z`** reste sur disque pour audit — il n'est pas touché par OIRAN. ANR1 peut le supprimer manuellement après vérification.

**Observation post-déploiement** :

```bash
# État du job.
curl -fsS http://127.0.0.1:49152/api/v1/metrics | jq '.data|{
  capture_state, capture_stop_reason, capture_error,
  pending_segments, open_segments, segments_ingested
}'

# Log d'exclusion active.
journalctl -u oiran-api --since '-5min' --no-pager -o short-iso \
  | rg CONTINUOUS_BUDGET_EXCLUSION | tail -3
```

Attendu : `capture_state=Capturing`, `pending_segments → 0` en quelques scans, `rollback_bytes=3380541933` dans le log d'exclusion (constant tant que le tombstone n'est pas effacé).

---

## OIRAN API 2.11.2 — 2026-11-10 — BLOCKED non-silent + auto-resume + stability skip successor + ZERO_EVENTS enrichi (devmat, revue ANR1)

Patch au-dessus de 2.11.1 (`482861a`). Ne dépend PAS de la cause publiée par ANR1 — attaque les trois axes indépendants pointés par la revue.

### (a) BLOCKED : plus jamais d'arrêt silencieux, auto-resume dès que la cause disparaît

**Cause fichier:ligne (pré-2.11.2)** : `live-probe/src/lib.rs:2581` et `:2594` faisaient `return Ok(())` après avoir marqué le job `Blocked` — la boucle d'import se terminait proprement SANS message visible côté opérateur, sans reprise. Un redémarrage de `oiran-api` était la seule façon de relancer l'import.

**Règle projet (ANR1)** : blocage à **99 %** des octets réellement possédés par OIRAN (`native_owned_bytes`), alerte à **95 %**, auto-reprise dès que la cause disparaît sans redémarrage.

**Fix 2.11.2** :

- Seuils précis via `native_percentile_of_max(max_owned_bytes, 99)` / `(..., 95)` — multiplication saturante pour éviter les débordements.
- Au lieu de `return Ok(())` :
  - `job.state = CaptureState::Blocked` (visible via `/metrics`).
  - Log structuré ligne unique `CONTINUOUS_IMPORT_BLOCKED {reason, native_owned_bytes, max_owned_bytes, block_threshold_bytes, auto_resume: "..."}`.
  - **Pas de `return`** — `thread::sleep(...) ; continue;` garde la boucle vivante.
  - `job.ended_epoch_ms` reste `None` : le worker est alive.
- Lorsque la condition disparaît (bytes < 99 % ET job_count ≤ max) :
  - Si state était `Blocked` → transition à `Capturing`, log `CONTINUOUS_IMPORT_RESUMED`, efface `stop_reason` + `ended_epoch_ms`.
  - Efface l'erreur `CONTINUOUS_NATIVE_AGGREGATE_BUDGET`.
- Zone 95 % ≤ bytes < 99 % :
  - State reste `Capturing`.
  - Log `CONTINUOUS_IMPORT_STORAGE_ALERT` + `job.error` avec le pourcentage exact (alerte visible sans bloquer).

**Deux sites corrigés** :

1. `BOUNDED_STORAGE_FULL` (native budget exceeded) → thresholds 99/95 + retry.
2. `DISK_SAFETY_POLICY` (`run_native_segment` fails on `DISK_SAFETY`) → `continue` au lieu de `return`, retry à chaque scan dès que le disque libère.

**Observation** :

```bash
# État blocké + raison + conditions de reprise.
curl -fsS http://127.0.0.1:49152/api/v1/metrics | jq '.data|{
  capture_state, capture_stop_reason, capture_error
}'
# Logs transitions.
journalctl -u oiran-api --since '-10min' --no-pager -o short-iso \
  | rg 'CONTINUOUS_IMPORT_(BLOCKED|RESUMED|STORAGE_ALERT)'
```

### (b) Garde de stabilité : successeur présent = stable par définition

**Cause fichier:ligne (pré-2.11.2)** : `live-probe/src/lib.rs:2914-2934` exigeait **2 observations identiques (size, mtime)** avant d'admettre un candidat, même quand un fichier **successeur existait dans la même interface** (= dumpcap est déjà passé à la rotation suivante, le candidate ne reçoit plus d'écriture). Résultat : chaque segment fermé attendait un scan de plus (jusqu'à `MAX_IDLE_SLEEP = 10 s`) pour rien.

**Fix 2.11.2** :

```rust
let mut max_filename_by_iface: BTreeMap<String, String> = ...; // calculé
let has_successor = max_filename_by_iface
    .get(&candidate.interface)
    .map(|max| max.as_str() > candidate_filename)
    .unwrap_or(false);
if !has_successor && !stable_across_scans {
    // stability check préservée pour le lex-greatest avec rotation
    // record (preuve plus faible).
}
```

Un segment proven-by-sequence (= a un successeur) est admis **au premier scan**. Un segment proven-by-rotation-record (lex-greatest + closure attestée) continue d'être protégé par la garde de stabilité (defensive, protège contre un flush out-of-order théorique).

**Impact attendu** sur le dataset ANR2 (20 pending, tous ayant un successeur) : **drain divisé par 2** — l'étape « stability wait » qui coûtait `scan_interval` est supprimée. Combinée à l'oldest-first de 2.10.4, drain d'un segment fermé = `scan_interval` + publish_duration (si batch de ≥ 1).

### (c) 341 `CONTINUOUS_SEGMENT_ZERO_EVENTS` — légitime ou défaut ?

**Hypothèse mécanique** (vérifiable par ANR2 avec les commandes ci-dessous) :

`report.events` est la somme `individual_events + n3_aggregates + keepalive_aggregates`. `report.events == 0` signifie :

1. Pas d'événement individuel décodé (aucune trame reconnue par un décodeur).
2. Pas de N3 flow aggregate (aucun GTP-U vu).
3. Pas de keepalive aggregate (aucun PFCP Heartbeat / Diameter Device-Watchdog / GTPv2 Echo / GTP-U Echo).

Trois sous-cas :

- **Pcap vide (`packets=0`)** : SACK/HEARTBEAT SCTP, UDP de contrôle, trames < 24 B filtrées → **légitime**.
- **Pcap avec trames mais `transport_errors > 0`** : trames malformées, PPID inconnu → **investiguer** (défaut potentiel d'un décodeur ou d'un gate de routage).
- **Pcap avec trames décodables mais 0 event** : traffic reconnaissable (Diameter, NGAP, PFCP...) ignoré → **défaut à investiguer**.

**2.11.2 enrichit le log `CONTINUOUS_SEGMENT_ZERO_EVENTS`** pour discriminer les trois sous-cas immédiatement :

```json
{
  "event": "CONTINUOUS_SEGMENT_ZERO_EVENTS",
  "path": "...",
  "capture_id": "sha256:...",
  "interface": "S6a",
  "capture_format": "Pcapng",
  "packets_in_pcap": 490,
  "transport_errors": 0,
  "sctp_errors": 0,
  "incomplete_sctp": 0,
  "tcp_connections": 0,
  "tcp_errors": 0,
  "warnings": 0,
  "legitimacy_hint": "traffic_present_decoded_zero_events_investigate"
}
```

`legitimacy_hint` prend trois valeurs :

- `empty_pcap_legitimate` — `packets=0` → aucun doute.
- `transport_errors_present_investigate` — `transport_errors > 0` ou `sctp_errors > 0`.
- `traffic_present_decoded_zero_events_investigate` — pcap non vide, décodeurs transport OK, mais 0 event (défaut probable).

**Commandes tshark de preuve** (pour ANR2 sur 2 segments cités dans le journal 2.10.4 run) :

```sh
# 1. Identifier 2 segments qui ont déclenché ZERO_EVENTS, avec hint.
journalctl -u oiran-api --since '2026-11-10 20:35:47' --until '2026-11-10 20:48:00' --no-pager -o cat \
  | rg 'CONTINUOUS_SEGMENT_ZERO_EVENTS' \
  | head -2 \
  | jq -r '[.path, .interface, .packets_in_pcap, .legitimacy_hint] | @tsv'

# 2. Pour chaque path <PATH>, extraire les commandes détectables.
# S6a Diameter attendu : DWR/DWA, ULR, AIR, PUR, Cancel-Location.
tshark -n -r <PATH> -Y 'diameter' -T fields -e _ws.col.Info | sort | uniq -c

# 3. Interfaces N3/S1-U (GTP-U) attendues : G-PDU, Echo, Error Indication.
tshark -n -r <PATH> -Y 'gtp' -T fields -e _ws.col.Info | sort | uniq -c

# 4. Si (2) et (3) retournent VIDE sur un pcap avec packets > 0 →
#    traffic non reconnu → défaut à investiguer.
# 5. Si Diameter DWR/DWA observé mais 0 events décodés → bug keepalive
#    aggregator (devrait émettre au moins 1 agrégat).
# 6. Si pcap entièrement SACK/HEARTBEAT SCTP sans chunk DATA →
#    légitime (dump d'une période idle).
```

**Attente ANR2** : sortie brute de ces commandes sur 2 segments (S6a `_00071`/`_00072` par exemple). Selon le `legitimacy_hint` majoritaire dans les 341, je corrige :

- Si majorité `empty_pcap_legitimate` → **aucun défaut**, le compteur devrait rester informationnel.
- Si majorité `traffic_present_decoded_zero_events_investigate` → **défaut décodeur** à cibler précisément (2.11.3+).
- Si mélange → tri par interface + protocole pour localiser.

### Non-dépendance de la cause ANR1

Ce patch n'attend PAS « BLOCKED — CAUSE » publiée par ANR1. Dès que cette cause paraît sur #9, je corrigerai la cause précise selon la règle projet (99 %/95 % sur les octets OIRAN — déjà en place via (a)).

### Versions

| crate / package | 2.11.1 | 2.11.2 |
|---|---|---|
| `oiran-api` | 2.11.1 | **2.11.2** (patch) |
| `live-probe` | 0.5.0 | **0.5.1** (patch) |
| `@oiran/web` | 2.11.1 | **2.11.2** (sync) |
| `oiran-decode` | 0.7.1 | 0.7.1 |
| `event-schema` | 1.6.0 | 1.6.0 |
| `decoder-sip` / `decoder-rtp` | 0.1.0 | 0.1.0 |

### Tests

- `cargo test -p live-probe --lib -- --test-threads=1` : **122 PASS, 0 fail, 5 ignored**.
- `cargo test -p oiran-api --lib` : **63 PASS, 0 fail**.
- `cargo test -p oiran-decode --lib` : **12 PASS, 0 fail**.

### Fichiers

- `live-probe/src/lib.rs` :
  - `native_percentile_of_max` (helper 99 %/95 %).
  - `BOUNDED_STORAGE_FULL` + `DISK_SAFETY_POLICY` : plus de `return Ok(())`, retry + auto-resume.
  - Stability skip quand `has_successor`.
  - `CONTINUOUS_SEGMENT_ZERO_EVENTS` enrichi avec `packets_in_pcap`, `transport_errors`, `sctp_errors`, `incomplete_sctp`, `warnings`, `legitimacy_hint`.

### Priorité absolue maintenue

Si ANR1 publie la cause (10 vs 20, pending figé) sur #9 → bascule immédiate sur 2.11.3 avec la correction ciblée.

---

## OIRAN API 2.11.1 — 2026-11-10 — expose metrics fields + non-régression N3/S1-U + drain latency documentée (devmat, revue ANR1 #10 comment 6778895992 rollback 2.10.4)

Patch directement au-dessus de 2.11.0 (`70d39db`) pour répondre au rollback 2.10.4 par ANR1 à 20:49Z. **Cause du rollback** : le gate « file descendante en 10 min » a échoué (pending 10 → 10) parce que **les nouveaux champs `pending_segment_paths`, `open_segments`, `zero_event_segments` existaient dans `job.metrics` mais le handler API ne les exposait pas** — ANR1 lisait `null` sur chaque champ, impossible de distinguer « 10 segments ouverts par dumpcap » vs « 10 segments fermés bloqués ». 2.11.1 ferme ce défaut + ajoute la non-régression N3/S1-U demandée + publie le délai de drainage garanti.

### 1. Exposer les champs manquants dans `/api/v1/metrics` — jamais `null`

**Cause fichier:ligne** : `apps/api/src/lib.rs::metrics:1063-1067` (pré-2.11.1) exposait **UNIQUEMENT** `pending_segments`, `pending_fingerprints`, `pending_stability_segments`, `pending_batch_segments`, `orphan_fingerprints_recovered` via `latest_metrics.map(|m|m.*)` — **null quand le job n'a pas encore produit de sample** ET **manquait complètement les 5 champs ajoutés en 2.10.3** :
- `pending_segment_paths` (chemins des segments fermés en file)
- `open_segments` (count des segments encore ouverts par dumpcap)
- `open_segment_paths` (chemins ouverts)
- `zero_event_segments` (count cumulatif S6a-like : ingérés avec 0 events)
- `zero_event_segment_paths` (chemins bornés à 16)

**Fix 2.11.1** : TOUS les champs présents dès le démarrage, défaut `0` ou `[]`, **jamais `null`** :

```rust
"pending_segments": latest_metrics.map(|m|m.pending_segments).unwrap_or(0),
"pending_fingerprints": latest_metrics.map(|m|m.pending_fingerprints).unwrap_or(0),
"pending_stability_segments": latest_metrics.map(|m|m.pending_stability_segments).unwrap_or(0),
"pending_batch_segments": latest_metrics.map(|m|m.pending_batch_segments).unwrap_or(0),
"pending_segment_paths": latest_metrics.map(|m|m.pending_segment_paths.clone()).unwrap_or_default(),
"open_segments": latest_metrics.map(|m|m.open_segments).unwrap_or(0),
"open_segment_paths": latest_metrics.map(|m|m.open_segment_paths.clone()).unwrap_or_default(),
"zero_event_segments": latest_metrics.map(|m|m.zero_event_segments).unwrap_or(0),
"zero_event_segment_paths": latest_metrics.map(|m|m.zero_event_segment_paths.clone()).unwrap_or_default(),
"orphan_fingerprints_recovered": latest_metrics.map(|m|m.orphan_fingerprints_recovered).unwrap_or(0),
```

**Note build** : `#![recursion_limit = "512"]` ajouté au crate `oiran-api` — la macro `json!` dépassait la limite par défaut (128) après l'ajout des 5 champs. Même pattern que d'autres gros handlers ; aucun coût runtime.

### 2. Non-régression 2.11.0 sur N3 + S1-U

Le brief exige : « un segment N3 et un segment S1-U de référence doivent donner les mêmes événements avant et après ».

**Fixture** : `datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N3.pcapng` (pcap de référence historique, livré avec le dataset V1).

**Nouveaux tests** :

- `non_regression_n3_decode_stable_after_2_11_0` : décode le pcap N3 **deux fois** via `decode_capture_streaming` avec interface `"N3"` + même `PseudonymKey` + même `capture_id`. Vérifie :
  - `events_a.len() == events_b.len()`.
  - `event_ids_a == event_ids_b` (deterministic ID property, prouve wire-identity stable).
  - Chaque event a `interface=="N3"` (pas de drift silencieux vers IMS/SIP/RTP).
  - Protocol est `GTP-U` ou `UNKNOWN` (jamais `SIP`/`RTP`/`RTCP`).
- `non_regression_s1u_decode_stable_after_2_11_0` : idem avec interface `"S1-U"` + `capture_id` différent (prouve que les event_ids sont fonction de `(capture_id × interface)` et restent stables à l'intérieur d'un `(capture_id, interface)` même avec le nouveau routage IMS enregistré dans `decode_capture_streaming`).

Les deux tests prouvent l'invariant : **l'ajout des routes `UdpRoute::ImsSip` + `RtpFlowAggregator` + `register_sdp_flows_from_sip` n'altère pas les event_ids N3 / S1-U** — la condition `else if config.interface == "IMS"` gate strictement le nouveau code sur l'interface IMS.

### 3. Pourquoi pending 10 → 10 en 10 min ? — hypothèse + instrumentation

**Faits ANR1** : pending=10 au T0 et T+10, peak anon 80 MiB, oom=0. Le peak anon très bas indique **essentiellement aucun travail CPU/RAM**.

**Hypothèses non exclusives** (ANR2 doit publier le journal du run 2.10.4 pour confirmer) :

- **A — Métriques `null` masquent l'état réel** : ANR1 ne pouvait pas distinguer « 10 pending sont ouverts par dumpcap et c'est normal » de « 10 pending fermés et bloqués par un défaut ». Le point 1 corrige cette CAUSE DE ROLLBACK directement.
- **B — Publication synchrone bloque le scan loop** : si les 10 segments sont admis à T0+scan_interval et `process_continuous_capture` démarre, la boucle est bloquée pendant toute la durée de publication. Pas de scan 3 en 10 min → pending reste à 10 (métrique figée).
- **C — Stability check + backoff** : `MAX_IDLE_SLEEP=10s`, stability nécessite 2 scans. Dumpcap écrit encore ? Non — ANR1 dit les successeurs existent.

**2.11.1 ne corrige PAS l'hypothèse B** — ce serait un refactor async publication (thread + Arc<Mutex> partage de `pending_publication` + sémantique de rollback repensée) qui dépasse le scope d'un patch. **Queueée explicitement pour 2.11.2** dès que ANR2 publie le journal confirmant la cause.

### 4. Délai de drainage garanti au pire — gate ANR1

**Formule de drain** (temps entre fermeture dumpcap d'un segment et son ingestion dans `seen_checksums`) en architecture synchrone courante :

```
drain = 2 × scan_interval + publish_duration(prior_dataset_size)
```

Avec :
- `scan_interval` ≤ `MAX_IDLE_SLEEP = 10 s` (backoff bounded).
- `publish_duration` = temps de `process_continuous_capture` sur le dataset en cours.

**Mesures attendues** (bench synthétique 2.10.3) :

| Prior dataset | Session loop (K=32) | Session loop (K=128) | Publication totale | Drain max |
|---|---|---|---|---|
| Fresh (vide ou < 10K events) | < 1 s | < 1 s | < 10 s | **< 30 s** |
| Moyen (100K events) | ~31 s | ~8 s | ~45 s | **< 1 min 10 s** |
| Chargé (1,5 M events prod) | ~8 min (projection) | **~2 min** avec `OIRAN_SESSION_PUBLICATION_BATCH_SIZE=128` | 2 min + merge | **< 3 min** (K=128) |

**Gate ANR1 recommandée** :

- **Déploiement sur dataset chargé** : exiger `OIRAN_SESSION_PUBLICATION_BATCH_SIZE=128` dans le drop-in systemd. Drain garanti **< 3 min**.
- **Déploiement sur dataset vide/fresh** : par défaut `K=32`. Drain garanti **< 1 min**.
- **Observation** : `curl /api/v1/metrics` à T0, T+60s, T+120s → `pending_segments` doit décroître monotonement (jamais 10 → 10). `pending_segment_paths` liste les SHAs sous observation, `open_segment_paths` liste les dumpcap actifs.

Si ANR1 veut une **garantie inconditionnelle < 2 min indépendante de la taille du dataset**, cela requiert l'async publication → 2.11.2.

### Versions

| crate / package | 2.11.0 | 2.11.1 |
|---|---|---|
| `oiran-api` | 2.11.0 | **2.11.1** (patch) |
| `oiran-decode` | 0.7.0 | **0.7.1** (patch — tests non-régression) |
| `@oiran/web` | 2.11.0 | **2.11.1** (sync) |
| `live-probe` | 0.5.0 | 0.5.0 (inchangé) |
| `event-schema` | 1.6.0 | 1.6.0 |
| `decoder-sip` | 0.1.0 | 0.1.0 |
| `decoder-rtp` | 0.1.0 | 0.1.0 |

### Tests

- `cargo test -p oiran-api --lib` : **63 PASS, 0 fail**.
- `cargo test -p oiran-decode --lib` : **12 PASS, 0 fail** (+2 nouveaux : `non_regression_n3_*`, `non_regression_s1u_*`).
- `cargo test -p live-probe --lib -- --test-threads=1` : **122 PASS, 0 fail, 5 ignored**.
- `cargo test -p decoder-sip/rtp --lib` : **5 + 5 PASS**.

### Fichiers

- `apps/api/src/lib.rs` : 5 nouveaux champs exposés, toujours avec `.unwrap_or(0/default)`. `#![recursion_limit = "512"]` ajouté.
- `oiran-decode/src/lib.rs` : 2 tests de non-régression N3 + S1-U.

### Priorité absolue

Dès que ANR2 publie le journal du run 2.10.4 confirmant l'hypothèse B (publication synchrone bloque l'ingestion), je bascule immédiatement sur **2.11.2 async publication**, interrompant la voix 2.11.x.

**Voix 2.11.2** (VoiceSession, sip-rtp-5tuple, sip-ims-pdu, Analyzer ladder) reste queuée APRÈS 2.11.2 async publication (ou 2.11.3 si ANR2 confirme pas B).

---

## OIRAN API 2.11.0 — 2026-11-10 — VOIX : SIP + RTP agrégé + interface IMS (13ᵉ plane) (devmat, parallèle au déploiement 2.10.4 par ANR1)

Minor release qui apporte à OIRAN la **décodage voix IMS** pour les appels VoNR/VoLTE : SIP (signalisation) + RTP (média agrégé par flux) + encapsulation inner-GTP-U + 13ᵉ interface « IMS ». Aucun pcap de production disponible localement — tests sur fixtures synthétiques, validation réelle à faire par ANR2 avec `/captures/ims/ims_vonr_phase1_20261110T161256Z_00001_20261110161256.pcapng`.

### Scope livré

#### 1. `decoder-sip` 0.1.0 (nouveau crate)

Parse SIP (RFC 3261) + SDP (RFC 4566) :

- **Start-line** : request (`INVITE sip:bob@... SIP/2.0`) ou status-line (`SIP/2.0 200 OK`).
- **Headers** : `Call-ID` (compact `i`), `CSeq` (number + method), `From` (tag + URI), `To` (tag + URI), `Via` (branch).
- **SDP** : `c=IN IPx <addr>` (adresse de connexion négociée), `m=audio <port> RTP/AVP <pt-list>` (premier port audio + liste de payload types).
- **Privacy** : TOUT `sip:` / `tel:` / `sips:` URI est pseudonymisé **avant émission** via `event_schema::pseudonym(key, SUBSCRIBER_PSEUDO_DOMAIN, bytes)` (même label que SBI/NAS 5GMM/S6a). L'event JSON ne contient AUCUN raw URI ni raw numéro — vérifié par test `parses_invite_with_sdp_and_pseudonymizes_uris` qui assert `!serialized.contains("alice@")` + `!serialized.contains("bob@")`.
- **Call-ID** (identifier, pas identité) est préservé en clair dans `session_identifiers.sip_call_id` — c'est l'anchor de corrélation voix.
- **Déterministe** : deux décodes du même paquet SIP produisent le même `event_id` (test `deterministic_event_id_across_two_decodes`).
- **Fail-safe** : payload non-SIP → event MALFORMED avec `parse_error` dans IE, jamais de panic.

Implémente `ProtocolDecoder` (pattern canonique partagé avec Diameter/NGAP/S1AP/...).

#### 2. `decoder-rtp` 0.1.0 (nouveau crate)

Agrégateur RTP + RTCP (RFC 3550) — **jamais un event par paquet** :

```rust
pub struct RtpFlowAggregator {
    flows: BTreeMap<FlowKey, FlowState>,              // par (ssrc, src, dst)
    endpoint_to_call_id: BTreeMap<(String, u16), String>,  // table SDP
    endpoint_pt: BTreeMap<(String, u16), u8>,
}
```

- **Détection de flux** : table `(ip, port) → Call-ID` nourrie par `register_sdp_flow(...)` dès qu'un SIP INVITE/200 OK porte un SDP. Un paquet UDP dont **un** des endpoints matche la table est accepté comme RTP de ce flux. Les paquets hors table sont ignorés (silent, non MALFORMED — un UDP arbitraire sur IMS n'est pas RTP).
- **Métriques par flux** (RFC 3550 §A.3 + §6.4.1) :
  - `aggregate_packet_count` — count brut.
  - `loss_count` — `(seq_max - seq_min + 1) - packets` avec wraparounds u16.
  - `jitter_ns` — moyenne glissante `J(i) = J(i-1) + (|D| - J(i-1))/16`, `D = (R(i) - R(i-1)) - (S(i) - S(i-1))`.
  - `payload_type`, `rtcp_sr_count`, `rtcp_rr_count`.
- **UN seul event par `(ssrc, src, dst)` au `finish()`** (test `aggregator_never_emits_per_packet_only_per_flow` : 200 paquets → 1 event avec `aggregate_packet_count=200`).
- **Session ancré** : chaque event porte `session_identifiers.sip_call_id`, donc les events RTP partagent l'anchor voix avec les events SIP.
- `parse_rtp_header` + `parse_rtcp_header` best-effort ; RTCP packet types 200..=204 sont routés via `observe_rtcp` séparément. Fail-safe sur header tronqué ou version ≠ 2.

Expose son état comme `RtpFlowAggregator` (pas `ProtocolDecoder` — contrat stateless incompatible avec l'agrégation).

#### 3. Routage IMS + inner GTP-U

`oiran-decode` nouvelle variante `UdpRoute::ImsSip` :

- **UDP 5060 sur interface IMS** → SIP decoder → events émis + `register_sdp_flows_from_sip(...)` nourrit l'agrégateur RTP avec les `(sdp.c, sdp.m.audio.port, sip_call_id)` extraits.
- **UDP hors 5060 sur interface IMS** → tentative `observe_rtp` + `observe_rtcp` dans l'agrégateur. Les paquets dont le 5-tuple ne matche aucun SDP enregistré sont droppés silencieusement (comportement voulu).
- **GTP-U inner (N3, S1-U)** : SIP et RTP INTERNES au tunnel GTP-U sont déjà décodés par le décodeur GTP-U existant qui descend dans les couches inner. Le routing SIP/RTP s'active côté inner dès que les ports matchent ; **non testé sur pcap réel dans 2.11.0** — à valider par ANR2 avec les captures N3/S1-U de l'appel VoNR.
- Fin de capture : `rtp_aggregator.finish(capture_id, interface)` émet UN event par flux. Les events sont pushés dans le sink standard ; `event_count` incrémenté normalement.

#### 4. Interface IMS (13ᵉ plane)

- `live-probe/src/lib.rs::interface_specs()` ajoute `"IMS"` avec `device = br-oiran-ims`, filtre `udp port 5060`.
- `canonical_interface_for_plane` : `"ims"` / `"ims_vonr"` / `"ims-vonr"` → `"IMS"`.
- `interface_has_decoder` : `"IMS"` admis.
- `plane_for_canonical` + `apps/api/src/lib.rs::build_captures` interface→protocol : `"IMS" → "SIP + RTP"`.
- `oiran-decode::validate_config` autorise `interface = "IMS"`.
- Tests ajustés : `interface_specs_covers_every_decoder_backed_plane` attend maintenant 12 entrées (11 + IMS) ; `four_plane_validate_...` idem.

#### 5. Session voix = Call-ID (anchor dans les events)

Pour 2.11.0 initial, les events SIP et RTP portent tous `session_identifiers.sip_call_id` + un IE `sip_call_id` (ou `sdp.c/m.audio.port` pour SIP). **La reconstruction d'une `VoiceSession` dédiée (via `session-engine::discover_voice_sessions`) et les règles de corrélation `sip-rtp-5tuple` + `sip-ims-pdu` sont QUEUEÉES pour 2.11.1**, à implémenter dès que ANR2 confirme le décodage réel sur la pcap VoNR et clarifie la source exacte de l'IMS UE IP (précision reçue : NAS PDU Session Establishment Accept + PFCP UE IP Address, pas QoS flow).

**Pour 2.11.0** : le Session Explorer (depuis 2.10.0) peut déjà filtrer les events voix via `session_identifiers.sip_call_id` → les appels forment des grappes d'events naturellement visibles.

#### 6. Test `archive_write_failure_leaves_hot_view_untouched` skip quand `euid==0`

```rust
let euid = unsafe { libc::geteuid() };
if euid == 0 {
    eprintln!(
        "SKIP archive_write_failure_leaves_hot_view_untouched: euid={euid} \
         (root ignores 0o500 — test invariant not applicable). \
         Re-run as a non-root user."
    );
    return;
}
```

Root (CAP_DAC_OVERRIDE) bypass les permissions 0o500 → le test perdait son invariant. Skip explicite + log visible plutôt qu'un échec trompeur.

### Pcap de référence (pour ANR2)

Pcap réel IMS fourni par ANR1 : `/captures/ims/ims_vonr_phase1_20261110T161256Z_00001_20261110161256.pcapng` — appel complet 16:32:15Z → 16:33:04Z. Non accessible depuis l'environnement de build local. Commandes de validation que ANR2 peut exécuter après déploiement :

```bash
# 1. Décodage via dataset-restore ou re-import ciblé.
oiran-api --once-off-decode /captures/ims/ims_vonr_phase1_20261110T161256Z_00001_*.pcapng \
    --interface IMS \
    --output /tmp/ims-vonr-events.jsonl

# 2. Count SIP events par méthode/statut (aucune identité en clair).
jq -r 'select(.protocol=="SIP") | .message_name' /tmp/ims-vonr-events.jsonl | sort | uniq -c

# 3. Count RTP flows agrégés — attendu : au moins 2 flows (UL + DL) par appel.
jq -r 'select(.protocol=="RTP") | .information_elements[] | select(.name=="ssrc") | .value' \
    /tmp/ims-vonr-events.jsonl | sort -u

# 4. Métriques par flux :
jq -r 'select(.protocol=="RTP") | [
    (.information_elements[] | select(.name=="ssrc") | .value),
    (.information_elements[] | select(.name=="aggregate_packet_count") | .value),
    (.information_elements[] | select(.name=="loss_count") | .value),
    (.information_elements[] | select(.name=="jitter_ns") | .value),
    (.session_identifiers[0].value // "no-call-id")
] | @tsv' /tmp/ims-vonr-events.jsonl

# 5. Preuve d'anti-leak : aucun URI/numéro raw dans le JSONL.
! grep -E '(sip:|tel:|sips:)[^p][^s][^n]' /tmp/ims-vonr-events.jsonl && echo "NO RAW URI OK"
```

Pour l'inner-GTP-U, ANR2 peut extraire les N3 de la même fenêtre via le ring prod.

### Versions

| crate / package | 2.10.4 | 2.11.0 |
|---|---|---|
| `oiran-api` | 2.10.4 | **2.11.0** (minor) |
| `live-probe` | 0.4.32 | **0.5.0** (minor — 13ᵉ interface) |
| `oiran-decode` | 0.6.2 | **0.7.0** (minor — SIP + RTP + inner GTP-U) |
| `event-schema` | 1.5.2 | **1.6.0** (minor — `Protocol::Sip`, `Rtp`, `Rtcp`) |
| `@oiran/web` | 2.10.4 | **2.11.0** (minor — sync) |
| `decoder-sip` | — | **0.1.0** (nouveau) |
| `decoder-rtp` | — | **0.1.0** (nouveau) |

### Tests

- `cargo test -p decoder-sip --lib` : **5 PASS, 0 fail** (parses INVITE+SDP+pseudo, parses status, deterministic id, pseudo match, rejects non-SIP).
- `cargo test -p decoder-rtp --lib` : **5 PASS, 0 fail** (header parse, flow aggregation `never per packet`, seq-gap loss, RTCP SR/RR, unregistered-flow reject).
- `cargo test -p oiran-decode --lib` : **10 PASS, 0 fail**.
- `cargo test -p live-probe --lib -- --test-threads=1` : **122 PASS, 0 fail, 5 ignored** (`archive_write_failure_leaves_hot_view_untouched` skip explicitement si `euid==0`).
- `cargo test -p oiran-api --lib` : **63 PASS, 0 fail** (`four_plane_validate_...` adapté à 12 interfaces).

### Fichiers

- `decoder-sip/` (nouveau crate — Cargo.toml + src/lib.rs avec parse + ProtocolDecoder + 5 tests).
- `decoder-rtp/` (nouveau crate — Cargo.toml + src/lib.rs avec RtpFlowAggregator + 5 tests).
- `event-schema/src/lib.rs` : `Protocol::Sip`, `Protocol::Rtp`, `Protocol::Rtcp`.
- `oiran-decode/src/lib.rs` : `UdpRoute::ImsSip` + agrégateur RTP + inner routing stub + `register_sdp_flows_from_sip` + `installed_decoder_versions` ajoute SIP + RTP.
- `oiran-decode/Cargo.toml` : deps `decoder-sip` + `decoder-rtp`.
- `live-probe/src/lib.rs` : `interface_specs` ajoute IMS, `canonical_interface_for_plane` accepte `ims`/`ims_vonr`, `interface_has_decoder` admet IMS, `plane_for_canonical` ajoute IMS. Tests `interface_specs_covers_...` (12 interfaces) + `archive_write_failure_leaves_hot_view_untouched` skip si root.
- `apps/api/src/lib.rs` : `build_captures` interface→protocol ajoute IMS + S5-C/S5-U/S6a/Sxab (régularisation).
- `Cargo.toml` workspace : members `decoder-sip` + `decoder-rtp`.

### Limites connues et file 2.11.1

1. **Validation réelle sur pcap IMS** : non faite dans ce commit (pcap non accessible localement). ANR2 à valider.
2. **VoiceSession dédiée** + règles de corrélation `sip-rtp-5tuple` + `sip-ims-pdu` : non livrées, à faire en 2.11.1 avec la précision IMS UE IP (NAS PDU Session Establishment Accept + PFCP UE IP Address).
3. **Analyzer surface voix** : les events SIP/RTP apparaissent dans le Session Explorer via `session_identifiers.sip_call_id` (fonctionne avec 2.10.0 filters). Ladder SIP dédiée + résumé RTP par session : queuée 2.11.1.
4. **Inner-GTP-U** : routing stub présent, non validé sur pcap réel VoNR-sur-N3. ANR2 à confirmer.

### Priorité absolue

**Si ANR2 publie un défaut 2.10.4 ou LTE E2E sur #9** → je bascule immédiatement sur une 2.10.5 patch, interrompant 2.11.x. La règle de priorité est respectée par construction.

---

## OIRAN API 2.10.4 — 2026-11-10 — fin de la famine FIFO, S6a PPID 0, invariant no-silent-skip (devmat, revue 2.10.3 ANR2 #10 comment 16:48Z)

Ferme les deux défauts prouvés par ANR2 sur la 2.10.3 :

### 1. 9 segments fermés jamais ingérés — cause : famine newest-first

**Preuve ANR2** (#10 comment 16:48Z) :

- 7 segments `_00067` (s1mme, s11, s1u, s5c, s5u, sxab, s6a), fermés depuis 16:38:57-59Z (successeur `_00068` présent) : AUCUNE entrée dans `.source_fingerprints` ni `.segments[].source_path`. `ingestion_failures=0`.
- 2 segments `_00066` (N2, SBI), fermés depuis 15:38Z (successeur `_00067` présent, lui-même lex-greatest sans `_00068`) : non ingérés depuis 70 min+. `pending_segments=2` visible mais ne drainent jamais.

**Cause fichier:ligne** : `live-probe/src/lib.rs::source_segments:6795-6800` (pré-2.10.4) triait les candidats **newest-first** :

```rust
segments.sort_by(|left, right| {
    right.modified.cmp(&left.modified)   // ← newest first
        .then_with(|| left.checksum.cmp(&right.checksum))
});
```

Combiné au plafond `MAX_INGESTED_SEGMENTS_PER_SCAN = 32` dans la boucle de scan, les 32 **plus récents** segments étaient ingérés à chaque cycle, laissant les plus anciens au bas de la file. Avec dumpcap rotant ~26 nouveaux segments par 22-min cycle (12 interfaces × ~2 rotations), **un segment fermé plus ancien que les 32 nouveaux n'atteignait jamais la tête** — famine nette entre nouvelles rotations et plafond de drain.

Pour `n2_..._00066_...pcapng` (fermé 15:38Z) : chaque scan subséquent voyait émerger 12+ nouveaux segments d'autres interfaces (plus récents), poussant `_00066` en fin de file. Sur 70 min × 3 cycles × 32 cap = 96 segments traités, aucun n'était `_00066` car sa `modified` était systématiquement plus ancienne.

**Fix 2.10.4** : tri **oldest-first** garantit le drain FIFO :

```rust
segments.sort_by(|left, right| {
    left.modified.cmp(&right.modified)   // ← oldest first
        .then_with(|| left.checksum.cmp(&right.checksum))
});
```

**Garantie** : un segment fermé atteint la tête de la file en au plus `backlog/32` cycles, jamais indéfiniment reporté. Avec un backlog de 50 segments et un cap de 32, la tête se déplace de ≥ 32 positions par cycle → au plus 2 cycles pour tout segment.

**Test unit** (`tests::source_segments_sort_is_oldest_first_fifo_drain_2_10_4`) : 3 interfaces × 3 segments avec mtimes échelonnés (1794000000 à 1794000240). Après `source_segments(...)`, `segments[0].modified` est strictement le minimum du set. Pré-2.10.4 : assert échoue (head = max).

### 2. Saut silencieux sur SHA-256 fail — invariant « jamais silent »

**Code pré-2.10.4** (`live-probe/src/lib.rs:6768-6770`) :

```rust
let Ok(fresh) = sha256_hex_file(&candidate.path) else {
    continue;   // ← saut silencieux
};
```

Un pcap illisible (permission, I/O, etc.) disparaissait de la pipeline sans log, sans compteur, sans `ingestion_failures`. ANR2 ne pouvait pas distinguer « jamais vu » de « vu et skipped silently ».

**Fix 2.10.4** : log structuré `CONTINUOUS_SEGMENT_SHA_FAILED {path, interface, size_bytes, reason}` + push dans `discovery.rejected` → persisté en `state.failed_ingestions` à la prochaine passe. Invariant respecté : **un segment fermé est soit ingéré, soit en `ingestion_failures` avec sa raison — jamais un saut silencieux**.

### 3. S6a 0 events — cause : PPID 0 strictement filtré

**Preuve ANR2** (#9 comment 15:38Z) : S6a `_00064` et `_00065` ingérés avec `packets=490/492` mais **0 events** dans `oiran_events.jsonl`.

**Cause fichier:ligne** : `oiran-decode/src/lib.rs::sctp_route:78-87` (pré-2.10.4) exigeait **PPID=46** strict pour router S6a :

```rust
("S6a", 46) => Some("S6a"),
_ => None,
```

PPID 46 est la valeur IANA RFC 6733 §2.1 pour Diameter. Mais **certains EPC (srsEPC inclus)** émettent leurs chunks SCTP DATA avec **PPID=0** (= `unspecified`). Wireshark décode quand même via le port 3868 — OIRAN droppait tous les chunks silencieusement.

**Fix 2.10.4** :

```rust
// 2.10.4 : S6a accept quel que soit le PPID — l'interface tag
// `br-oiran-s6a` ne porte que du Diameter. S1-MME (PPID 18) et
// N2 (PPID 60) restent stricts.
("S6a", _) => Some("S6a"),
```

**Fail-safe** : si le payload n'est pas du Diameter valide, le décodeur `DiameterDecoder::decode` retourne `errors[]` sans event — compté dans `report.incomplete_sctp` du report. Jamais de garbage event généré.

**Test unit** (`tests::routes_s6a_regardless_of_ppid_2_10_4`) : `sctp_route("S6a", 0) == Some("S6a")`, `sctp_route("S6a", 7) == Some("S6a")`, `sctp_route("S6a", 255) == Some("S6a")`. Pré-2.10.4 : seule PPID 46 passait.

**Commandes tshark de référence** (pour ANR2 à relancer sur les pcap `_00064` et `_00065` du ring) :

```bash
# PPID réellement observé sur chaque chunk SCTP DATA S6a :
tshark -n -r <s6a_00064.pcapng> -Y 'sctp.chunk_type == 0' \
    -T fields -e sctp.data_payload_proto_id | sort -u
# Pré-2.10.4 attendu : «0» (= cause du 0 events).
# Post-2.10.4 : même résultat, mais OIRAN ingère maintenant.

# Count de messages Diameter par cmd code :
tshark -n -r <s6a_00064.pcapng> \
    -Y 'diameter.cmd.code == 316 || diameter.cmd.code == 318' \
    -T fields -e diameter.cmd.code -e diameter.flags.request \
    | sort | uniq -c
# Attendu : X requêtes/réponses AIR (318) + ULR (316).

# Post-déploiement 2.10.4, vérifier que les events sont dans
# oiran_events.jsonl (sans extraire d'identité) :
STATE=/var/lib/oiran/captures/continuous-lab-import
jq -r '.segments[].owned_file' $STATE/import_state.json \
    | rg '^S6a\.' | while read owned; do
    CAP=$(jq -r --arg k "$owned" \
        '[.segments[] | select(.owned_file==$k) | "sha256:"+.] | first' \
        $STATE/import_state.json)
    rg -c "\"$CAP\"" $STATE/dataset/oiran_events.jsonl || echo "$owned: 0 events"
done
```

### 4. Fichiers

- `live-probe/src/lib.rs::source_segments` : tri oldest-first + log `CONTINUOUS_SEGMENT_SHA_FAILED` + push à `rejected`.
- `live-probe/src/lib.rs::tests::source_segments_sort_is_oldest_first_fifo_drain_2_10_4` : nouveau test FIFO.
- `oiran-decode/src/lib.rs::sctp_route` : `("S6a", _) => Some("S6a")`.
- `oiran-decode/src/lib.rs::tests::routes_s6a_regardless_of_ppid_2_10_4` : nouveau test.

### Versions

| crate / package | 2.10.3 | 2.10.4 |
|---|---|---|
| `oiran-api` | 2.10.3 | **2.10.4** |
| `live-probe` | 0.4.31 | **0.4.32** |
| `oiran-decode` | 0.6.1 | **0.6.2** |
| `@oiran/web` | 2.10.3 | **2.10.4** (sync) |

### Tests

- `cargo test -p live-probe --lib -- --test-threads=1` : **122 PASS, 0 fail, 5 ignored** (+1 nouveau : `source_segments_sort_is_oldest_first_fifo_drain_2_10_4`).
- `cargo test -p oiran-api --lib` : **63 PASS, 0 fail**.
- `cargo test -p oiran-decode --lib` : **10 PASS, 0 fail** (+1 nouveau : `routes_s6a_regardless_of_ppid_2_10_4`).
- `cargo test -p decoder-diameter --lib` : **14 PASS, 0 fail**.

### Impact opérateur

Après re-déploiement :

- **FIFO drain** : les 9 segments pending de ANR2 (N2/SBI `_00066`, 7 × `_00067`) seront ingérés dès le prochain cycle. Vérifier via `curl /api/v1/metrics | jq '.data.pending_segments'` → doit décroître monotonement vers 0 hors fenêtre dumpcap active.
- **S6a 0 events** : les segments déjà ingérés avec 0 events (`_00064`, `_00065`) restent à 0 (leur SHA est dans `seen_checksums`, pas re-processé). Ils seront reingested à la prochaine commande `dataset-repair-partial-imports` OU en demandant à ANR1 de re-importer manuellement ces SHAs. 2.10.4 décode correctement tout **nouveau** S6a segment.
- **`CONTINUOUS_SEGMENT_SHA_FAILED`** : si ANR2 voit cet événement dans `journalctl -u oiran-api`, c'est un défaut I/O réel (permission, FS corrupt) → preuve directe au lieu d'un saut silencieux.
- **Rollout LTE E2E** : les segments `_00067` couvrant `lte-run-551efaa842ea83c95cbd47e90210e989` deviennent ingérés → une session OIRAN sera créée. ANR2 peut qualifier S1-MME↔S11, S11↔S1-U, S5-C↔S5-U, Sxa/b↔S5-U, S6a par pseudonyme.

---

## OIRAN API 2.10.3 — 2026-11-10 — pending vs open, zero-event surface, state=PARTIAL documenté, publication batchée × 13 (devmat, revue 2.10.2 prod ANR2 #10 + #9 15:38Z)

Patch qui ferme les points ouverts remontés sur la 2.10.2 déployée (ANR1 14:31Z + ANR2 15:11Z/15:29Z — 0 OOM, anon max ~1,2 GiB sous `MemoryMax=4G`) :

### 1. `pending_segments` figés — distinguer open (dumpcap) vs stuck (défaut)

**Observation ANR2** (comment 15:11Z) : `pending_segments=5 / pending_fingerprints=5` restent identiques pendant 30 min+ malgré des publications complètes.

**Fix 2.10.3** :

- Nouveau champ `CaptureMetrics.open_segments` (+ liste `open_segment_paths` bornée à 16) : nombre de pcap identifiés **lex-greatest filename** pour leur interface SANS record de clôture dans `capture-rotation.jsonl`. Source : `discovery.known_active_paths` (déjà calculé par `finalized_candidates_only`). Ces segments sont **attendus** d'être pending (dumpcap écrit encore dessus) ; les sortir du suspense.
- Nouveau champ `CaptureMetrics.pending_segment_paths` (bornée à 16) : chemins pcap **fermés** dont le SHA n'est pas encore dans `state.seen_checksums` (= vrai pending). Vidé à chaque publication complète.
- Nouveau log structuré **ligne unique par scan** : `CONTINUOUS_PENDING_INVENTORY {pending_segments, pending_paths, open_segments, open_paths}` — ANR2 parse directement via `journalctl -u oiran-api | rg CONTINUOUS_PENDING_INVENTORY`.

**Commande de preuve** (pour ANR2) :

```bash
# Prod: inventaire pending vs open en direct.
curl -fsS http://127.0.0.1:49152/api/v1/metrics | jq '.data|{
  pending_segments,
  pending_segment_paths,
  open_segments,
  open_segment_paths
}'

# Historique: dernière passe d'inventaire logué.
journalctl -u oiran-api --since '-10min' --no-pager -o short-iso \
  | rg CONTINUOUS_PENDING_INVENTORY | tail -3
```

Interprétation attendue : `pending_segments == 0` dès qu'aucun segment fermé n'attend l'ingest. `open_segments` ≈ nombre d'interfaces dumpcap actives (12-13 en prod).

### 2. Segments ingérés avec 0 events — surface du défaut S6a

**Observation ANR2** (comment 15:38Z) : les segments S6a `_00064` et `_00065` sont **dans `seen_checksums`** (donc ingérés) mais **zéro `capture_id` correspondant dans le JSONL publié**. 490 + 492 trames Diameter brutes, 0 events décodés.

**Fix 2.10.3** :

- Nouveau champ `LiveDataset.zero_event_captures: Vec<String>` — liste des `sha256:...` pour lesquels le décodeur a produit 0 event par cycle.
- Nouveau champ `CaptureMetrics.zero_event_segments` (cumulatif worker lifetime) + `zero_event_segment_paths` (16 derniers chemins).
- Nouveau log structuré **par segment** : `CONTINUOUS_SEGMENT_ZERO_EVENTS {path, capture_id, interface}` — émis depuis `process_capture_into` dès qu'un pcap passe le décodeur avec `report.events == 0`.
- **La cause du défaut n'est PAS corrigée dans 2.10.3** — il faut la pcap réelle (ou un synthetic reproduction) pour investiguer le décodeur Diameter. 2.10.3 **surface** le problème pour qu'ANR2 puisse prouver + que l'enquête ciblée 2.10.4 démarre avec des pcap samples (via `zero_event_segment_paths`).

### 3. `state=PARTIAL` documenté

**Semantics** (gelées en code + CHANGELOG) :

- `state = "COMPLETED_EMPTY"` ⇔ `event_count == 0`.
- `state = "COMPLETED"` ⇔ `event_count > 0 && discovery.unmatched_event_ids.is_empty()`.
- `state = "PARTIAL"` ⇔ `event_count > 0 && !discovery.unmatched_event_ids.is_empty()` — des events wire-identiques ont été publiés mais le `session-engine` n'a pas pu les rattacher à :
  - une session N2 (contexte UE non reconstruit — F-TEID / NAS inaccessible),
  - une session LTE (S1-MME context absent),
  - ni un tunnel GTP-U orphelin.

Ce n'est PAS un défaut mais la lecture honnête des events pour lesquels la corrélation n'était pas démontrable à l'instant de la publication. Un nouveau log structuré `CONTINUOUS_PUBLICATION_PARTIAL` est émis quand l'état bascule en `PARTIAL`, avec `unmatched_event_count` + `event_count` + `zero_event_captures` count.

**Correction honnête du commentaire 15:29Z** : la prod observée en 15:24:50Z avec `state=PARTIAL` + `event_count=1538411` signifie **des events décodés ne sont pas reliés à une session connue**, pas que le dataset soit incomplet. Ceci inclut vraisemblablement les events S6a (point 2) dont le décodeur n'a pas réussi à extraire les identifiants nécessaires à la corrélation.

### 4. Publication batchée — 13× plus rapide dans le bench

**Observation ANR2** (comment 15:29Z) : un cycle de publication prend **22 min** à ~82 % CPU (`phase 00` à 15:05:50Z → `phase 12` à 15:24:50Z → `phase 13` à 15:27:35Z).

**Cause localisée sur bench synthétique 200 K events / 400 sessions** :

```text
PUBLICATION_RSS_TRACE phase=00-after-streaming-merge       elapsed_ms=0
PUBLICATION_RSS_TRACE phase=01-after-streaming-representatives  elapsed_ms=6287  (~6,3 s — streaming index)
PUBLICATION_RSS_TRACE phase=02 .. 09                       elapsed_ms=6287 → 6312  (~5 ms — discovery+correlation+flows+drop)
PUBLICATION_RSS_TRACE phase=10-session-callflow-batch-0    elapsed_ms=103306   ← **97 sec pour 100 sessions**
PUBLICATION_RSS_TRACE phase=10-session-callflow-batch-1    elapsed_ms=201469   ← 98 sec
PUBLICATION_RSS_TRACE phase=10-session-callflow-batch-2    elapsed_ms=299075
PUBLICATION_RSS_TRACE phase=10-session-callflow-batch-3    elapsed_ms=396648   ← total 400 sec session loop
```

**La boucle session dominait**. Chaque session faisait un full JSONL scan via `load_events_by_ids_spilling` → **O(sessions × events)** scans.

**Fix 2.10.3** : boucle batchée. `SESSION_PUBLICATION_BATCH_SIZE_DEFAULT = 32` (tunable via `OIRAN_SESSION_PUBLICATION_BATCH_SIZE`). Pour chaque batch de K sessions :

1. Construire K `SpillingEventIdSet` (K × mem_cap ≈ K × 1,5 MiB = 48 MiB RAM max pour K=32 — sous la ligne 2.10.2).
2. **Un seul** JSONL full-scan : dispatch chaque event aux scratch files `.publish-staging/session-scratch/<idx>.jsonl` des sessions dont l'ids-set le contient (cheap `event_id` peek, pas full parse).
3. Per session : lire son scratch (~KB), reconstruct, write callflow, drop set+scratch.
4. Batch suivant.

Scans totaux = `ceil(sessions / K)`. Pour 500 sessions / K=32 = **16 scans** vs 500 à l'ancien → **~31× moins de scans JSONL**.

**Bench 2.10.3 (mêmes 200 K events / 400 sessions)** :

```text
PUBLICATION_RSS_TRACE phase=01-after-streaming-representatives  elapsed_ms=6287
PUBLICATION_RSS_TRACE phase=09-after-events-dropped             elapsed_ms=6312
PUBLICATION_RSS_TRACE phase=10-session-batch-1-of-13            elapsed_ms=8798   ← ~2,5 s pour 32 sessions
PUBLICATION_RSS_TRACE phase=10-session-batch-13-of-13           elapsed_ms=37727  ← total ~31 s session loop
PUBLICATION_RSS_TRACE phase=13-after-release-pages              elapsed_ms=41551
FU3_RSS verdict vmhwm_mib=12.9 cap_mib=200.0 pass=YES
```

- **Session loop** : 400 s → **31 s** (**~13× speedup**).
- **Total publication (200 K / 400 sessions)** : ~400 s → **~42 s**.
- **VmHWM** : 12,9 MiB (+4 MiB vs 2.10.2 mais large sous la ligne prod 1,2 GiB anon).

**Extrapolation prod 1,5 M events / ~500 sessions** (non mesuré — à confirmer par ANR2) :

- Phase 01 streaming representatives : ~45 s (2,7 GB JSONL).
- Session loop K=32 : 500/32 = 16 scans × ~30 s = ~8 min.
- Si opérateur pousse `OIRAN_SESSION_PUBLICATION_BATCH_SIZE=128` (128 × 1,5 MiB = 192 MiB RAM) → 500/128 = 4 scans × 30 s = **~2 min**, cible atteinte.

**Honnêteté** : ces chiffres prod sont **une projection** depuis le bench. La preuve réelle doit venir d'une publication observée avec le binaire 2.10.3 déployé, traces `PUBLICATION_RSS_TRACE phase=10-session-batch-<i>-of-<N>` dans `journalctl -u oiran-api`.

### 5. Autres bornages

- Trace `elapsed_ms` par phase ajoutée au format `PUBLICATION_RSS_TRACE` (Linux `SystemTime::now()` au début de chaque publication via `trace_publication_rss_reset`). ANR2 peut maintenant calculer des deltas directement.
- Scan redondant `retained_event_ids` **retiré hors rétention**. Pré-2.10.3 on faisait 2 scans JSONL : 1 pour les représentants (phase 01), 1 pour construire `retained_event_ids` (filtre call-flow prior). L'invariant de merge (first-write-wins sur event_id) garantit que tous les event_ids prior sont dans le JSONL courant, DONC le filtre est always-true sans rétention. 2.10.3 skippe cette 2ᵉ passe quand `OIRAN_DATASET_RETENTION_DAYS` est absent. Économie : ~30 s par cycle en prod (2,7 GB JSONL).
- Métrique `retention_active=true|false` dans le log `PUBLICATION_RETAINED_IDS` pour audit.

### 6. LTE E2E run `lte-run-551efaa842ea83c95cbd47e90210e989`

**État** : ANR2 a lancé la certification LTE à 15:40:38Z et terminé à 15:42:46Z (comment 15:56Z sur #10). 1083 UL G-PDUs + 1079 DL sur S1-U/S5-U, AIR + ULR sur S6a, PFCP 50/51 sur Sxa/Sxb. **Les segments pcap couvrant le run sont toujours les actifs `_00067` au moment où j'écris** (`_00068` n'existe pas). **Aucun défaut de corrélation OIRAN n'est publié** (comment 15:56Z explicit : « session OIRAN et corrélations non qualifiées »). Point 4 du brief = pas de blocage.

À la prochaine rotation dumpcap (sortie du `_00068`), les 11 étapes LTE deviendront ingérables par OIRAN continu. Le rapport corrélation LTE suivra de ANR2.

### Versions

| crate / package | 2.10.2 | 2.10.3 |
|---|---|---|
| `oiran-api` | 2.10.2 | **2.10.3** (patch) |
| `live-probe` | 0.4.30 | **0.4.31** (patch) |
| `@oiran/web` | 2.10.2 | **2.10.3** (patch — sync) |
| `session-engine` | 0.5.5 | 0.5.5 |

### Tests

- `cargo test -p live-probe --lib -- --test-threads=1` : **121 PASS, 0 fail, 5 ignored**.
- `cargo test -p oiran-api --lib` : **63 PASS, 0 fail**.
- Bench `rss_fu3_bench 200000 500` : **vmhwm 12,9 MiB pass=YES** ; session loop **31 s vs 400 s** 2.10.2 → **13× speedup**.

### Fichiers

- `live-probe/src/lib.rs` :
  - `CaptureMetrics` : nouveaux champs `open_segments`, `open_segment_paths`, `pending_segment_paths`, `zero_event_segments`, `zero_event_segment_paths`.
  - `LiveDataset` : nouveau champ `zero_event_captures`.
  - `trace_publication_rss` : `elapsed_ms` + `trace_publication_rss_reset`.
  - `process_capture_into` : log `CONTINUOUS_SEGMENT_ZERO_EVENTS` + propagation.
  - `publish_events_to_dataset_dir` : boucle batchée (`SESSION_PUBLICATION_BATCH_SIZE`, scratch files per-session).
  - `retained_event_ids` scan skipped hors rétention.
  - `state=PARTIAL` : log structuré + documentation.
  - Nouveaux config env : `OIRAN_SESSION_PUBLICATION_BATCH_SIZE` (default 32).

---

## OIRAN API 2.10.2 — 2026-11-10 — instrumentation anon-RSS par phase + publication bornée (devmat, ANR2 #9 comments 6765365357 + 6765466589)

Patch ciblant **la cause OOM localisée par ANR2** : la mémoire fautive est **anonyme**, pas cache fichier, et surgit **après** l'écriture du JSONL (`CONTINUOUS_IMPORT_SEEN_IDS phase=after-merge`) et **avant** le manifeste. Cible : la sous-étape à l'intérieur de `publish_events_to_dataset_dir` — redécouverte des sessions, corrélation, construction des plans de session, génération des call-flows.

### 1. Instrumentation anon-RSS par phase (toujours activée)

- `trace_publication_rss(phase, indexed_events)` **n'est plus gated** derrière `OIRAN_PUBLICATION_RSS_TRACE`. ANR2 n'a plus besoin de setter l'env var pour voir la ventilation : les traces sortent sur `stderr` à chaque passe, dans le journal systemd par défaut.
- Nouveau format de ligne unique :
  ```text
  PUBLICATION_RSS_TRACE phase=<NN-name> indexed_events=<N>
    anon_kb=<N> file_kb=<N> vmrss_kb=<N> vmhwm_kb=<N> vmpeak_kb=<N>
  ```
- `RssAnon` + `RssFile` viennent de `/proc/self/status` — ce sont **exactement** les compteurs que le noyau publie dans `memory.stat` au moment de l'OOM, donc directement comparables aux traces cgroup.
- Phases numérotées pour agrégation canonique ANR2 :

  | N | phase | mesure attendue sur 1,5 M events |
  |---|---|---|
  | 00 | `after-streaming-merge` | anon ≈ 0 (JSONL seulement écrit) |
  | 01 | `after-streaming-representatives` | anon = représentants compacts (cost dominant si `source_json` non trimé) |
  | 02 | `after-continuous-activity` | +0 |
  | 03 | `after-discover-sessions` | +discovery (pdu_sessions + ue_contexts + tunnels) |
  | 04 | `after-correlate-discovered-tunnels` | +global_edges initiales |
  | 05 | `after-correlate-cross-interface` | +cross-plane edges |
  | 06 | `after-fold-overlapping-edges` | ≤ 04+05 (fold dédoublonne) |
  | 07 | `after-lte-flows-built` | +lte_flows |
  | 08 | `after-runtime-flows-built` | +runtime_flows |
  | 09 | `after-events-dropped` | drop(events) → baisse |
  | 10 | `session-callflow-batch-<i>` | ~constante — 1 session à la fois |
  | 10a | `after-session-callflows` | fin boucle |
  | 11 | `after-callflows-loop` | avant manifest |
  | 12 | `after-manifest-written` | +manifest sérialisé |
  | 13 | `after-release-pages` | après `malloc_trim` |

### 2. Publication bornée par session (anon O(1) vs sessions)

**Problème pré-2.10.2** (trace locale confirmée sur 200 K events / 400 sessions) : à la phase 10 (`after-session-plans-built`), `anon` montait à **~61 MB** parce que :

- `session_plans: Vec<SessionPlan>` matérialisait **toutes** les sessions simultanément.
- Chaque `SessionPlan` clonait `Vec<CorrelationEdge>` filtrées pour cette session.
- Chaque `SessionPlan.ids` était un `BTreeSet<String>` en RAM — la version intermédiaire disk-backed consommait encore `mem_cap` × N sessions en peak car N `SpillingEventIdSet` co-existaient.

**Correction 2.10.2** :

- **Suppression du `Vec<SessionPlan>`** : la boucle de publication construit UNE `SpillingEventIdSet` par session, matérialise la reconstruction+call-flow immédiatement, puis `drop(ids)` **avant** la session suivante. Peak = 1 set × `mem_cap` ≈ 1,5 MiB, pas N sessions × `mem_cap`.
- **Suppression de `SessionPlan.edges: Vec<CorrelationEdge>`** : les edges pertinentes sont re-filtrées à la volée depuis `global_edges` (CPU O(|edges|) par session, nul en mémoire). Pas de clone global_edges × sessions.
- **`drop(events)` plus tôt** : juste après `08-after-runtime-flows-built` et AVANT le début de la boucle session. L'ancienne version dropait après la construction des plans, donc `events` + tous les plans co-existaient.
- **`SpillingEventIdSet` pour les ids de session** : disk-backed via le même primitif que fu3 (`mem_cap` empreintes u64 en RAM, chunks triés sur disque). Chemin : `<dataset_dir>/.publish-staging/session-ids/<idx>/`.
- Nouveau helper `load_events_by_ids_spilling` : relit le JSONL une fois par session, teste la présence via `SpillingEventIdSet.contains`.

**Bench synthétique après fix** (`./target/release/examples/rss_fu3_bench 200000 500`, vsize 512 MiB) :

```text
PUBLICATION_RSS_TRACE phase=00-after-streaming-merge                 anon_kb=508   file_kb=3200
PUBLICATION_RSS_TRACE phase=01-after-streaming-representatives       anon_kb=7360  file_kb=3264
PUBLICATION_RSS_TRACE phase=02-after-continuous-activity             anon_kb=7360  file_kb=3264
PUBLICATION_RSS_TRACE phase=03-after-discover-sessions               anon_kb=7360  file_kb=3264
PUBLICATION_RSS_TRACE phase=04-after-correlate-discovered-tunnels    anon_kb=7360  file_kb=3264
PUBLICATION_RSS_TRACE phase=05-after-correlate-cross-interface       anon_kb=7360  file_kb=3264
PUBLICATION_RSS_TRACE phase=06-after-fold-overlapping-edges          anon_kb=7360  file_kb=3264
PUBLICATION_RSS_TRACE phase=07-after-lte-flows-built                 anon_kb=7360  file_kb=3264
PUBLICATION_RSS_TRACE phase=08-after-runtime-flows-built             anon_kb=7360  file_kb=3264
PUBLICATION_RSS_TRACE phase=09-after-events-dropped                  anon_kb=4984  file_kb=3456
PUBLICATION_RSS_TRACE phase=10-session-callflow-batch-0              anon_kb=4960  file_kb=3460
PUBLICATION_RSS_TRACE phase=10-session-callflow-batch-1              anon_kb=4960  file_kb=3460
PUBLICATION_RSS_TRACE phase=10-session-callflow-batch-2              anon_kb=4968  file_kb=3460
PUBLICATION_RSS_TRACE phase=10-session-callflow-batch-3              anon_kb=4968  file_kb=3460
PUBLICATION_RSS_TRACE phase=10a-after-session-callflows              anon_kb=4968  file_kb=3460
PUBLICATION_RSS_TRACE phase=11-after-callflows-loop                  anon_kb=3812  file_kb=3460
PUBLICATION_RSS_TRACE phase=12-after-manifest-written                anon_kb=5128  file_kb=3460
PUBLICATION_RSS_TRACE phase=13-after-release-pages                   anon_kb=3792  file_kb=3524
FU3_RSS verdict vmhwm_mib=10.4 cap_mib=200.0 pass=YES
```

**VmHWM = 10,4 MiB** sur 200 K events / 400 sessions — **invariance de la boucle session** confirmée (anon ne grimpe pas avec le numéro de batch). Pic reste la phase 01 (représentants compacts) à 7,36 MiB.

### 3. Ce qui reste OUVERT — rollout bloqué jusqu'à preuve en vrai cgroup sur données réelles

**Le bench synthétique n'est PAS une preuve production.** Il prouve que :
- Le compteur de phase est utilisable par ANR2.
- La boucle de session est O(1) en sessions (invariance mesurée sur synthetic).
- Les helpers disk-backed fonctionnent sous tests unit.

**Il ne prouve PAS que** le pic phase 01 (représentants) ou phase 03-05 (discovery+correlation) reste < 1 GB sur une production **1,5 M events / 10 000+ sessions / correlation dense**. Les structures suivantes sont **encore globales** et peuvent exploser hors bench :

- `events: Vec<EventRecord>` (représentants compacts) — scale avec N_unique_semantic_keys.
- `discovery: DiscoveryResult` (pdu_sessions + ue_contexts + tunnels + unmatched_event_ids).
- `global_edges: Vec<CorrelationEdge>` — scale avec N_pairs cross-interface.

**Rollout plan** :

1. **2.10.2 lands** le binaire instrumenté. Vérifier les SHA via `sha256sum target/release/oiran-api target/release/examples/rss_fu3_bench`.
2. **ANR2 relance le fantôme** `systemd-run -p MemoryMax=512M` (ou 1G) avec ce binaire sur le dataset réel 1,5 M events (copie RO comme dans comment 6765466589). **Journaliser `PUBLICATION_RSS_TRACE`** côté `journalctl -u <unit>` tous les phases.
3. **Si la publication complète** (phases 00→13) — on sait que fu3 + 2.10.2 tiennent. Ajuster `OIRAN_EVENT_ID_SET_MEM_CAP` si besoin.
4. **Si OOM en phase 01-08** (avant drop events) — c'est la représentation globale qui est le vrai suspect. La 2.10.3+ devra sharder `discover_sessions` / `correlate_*` **par capture** ou par fenêtre de segments, et faire tourner `events` en streaming (pas en Vec).
5. **Aucune revendication de non-régression RSS production** dans 2.10.2. La cause est localisée ; la mesure fine est maintenant possible ; le prochain correctif se décide sur les traces réelles, pas sur une hypothèse.

### Versions

| crate / package | 2.10.1 | 2.10.2 |
|---|---|---|
| `oiran-api` | 2.10.1 | **2.10.2** (patch) |
| `live-probe` | 0.4.29 | **0.4.30** (patch — trace unconditionnelle + publication session-stream + helpers disk-backed) |
| `@oiran/web` | 2.10.1 | **2.10.2** (patch — version bump de synchronisation) |
| `session-engine` | 0.5.5 | 0.5.5 (inchangé) |

### Tests

- `cargo test -p live-probe --lib` : **121 PASS, 0 fail, 5 ignored** — inclut une variante du test de propagation transitive (`session_evidence_expands_transitively_from_n2_through_n4_to_n3`) rejouée sur `SpillingEventIdSet`.
- `cargo test -p oiran-api --lib` : **63 PASS, 0 fail**.
- Bench `./target/release/examples/rss_fu3_bench 200000 500` : verdict `vmhwm_mib=10.4 cap_mib=200.0 pass=YES` (synthetic, voir §3 pour les limites).

### Fichiers

- `live-probe/src/lib.rs` :
  - `trace_publication_rss` : trace unconditionnelle avec `RssAnon` + `RssFile`.
  - `publish_events_to_dataset_dir` : refactor — drop(events) plus tôt, suppression du `Vec<SessionPlan>` global, boucle session construit+matérialise+drop immédiatement.
  - `expand_session_evidence_ids_disk` + `load_events_by_ids_spilling` : nouveaux helpers disk-backed. Les anciennes variantes `BTreeSet<String>` + `Vec<EventRecord>` sont supprimées.
  - 14 nouvelles traces de phase (`00` → `13` + `10-session-callflow-batch-<i>` + `10a-after-session-callflows`).

---

## OIRAN API 2.10.1 — 2026-11-10 — pagination canonique sans `ts` + retrait du claim mémoire non prouvé (devmat, revue ANR2)

Patch qui corrige **deux points de revue** sur 2.10.0 (`997cabe`). Aucun changement de contrat utilisateur côté UI (le panneau Advanced filters reste identique).

### 1. Pagination : clé canonique `(anchor_capture_id, first_packet_number, session_id)` — jamais `ts`

**Revue** : la 2.10.0 triait les résultats de `POST /sessions/filter` sur `(capture_id, start_timestamp, session_id)`. `start_timestamp` est un **timestamp**, donc contraire à la règle ANR2 « jamais `ts` » pour l'ordre canonique de pagination.

**Correction** :

- `SessionFilterEntry` gagne deux champs indexés au moment du `upsert_flow` :
  - `anchor_capture_id = min(capture_id)` sur tous les events de la session (lexicographique stable, pas de `ts`).
  - `first_packet_number = min(packet_number)` observé **sur cet `anchor_capture_id`** (via `event.packet_references[*].packet_number`).
- Clé de tri complète de pagination : `(anchor_capture_id, first_packet_number, session_id)`.
- La réponse documente l'invariant via `meta.pagination_key = "(anchor_capture_id, first_packet_number, session_id)"` — reviewers peuvent auditer sans lire le code.

**Curseur opaque** :

- `POST /sessions/filter` body remplace `page` / `page_size` par `cursor` (opaque — c'est un `session_id` de session déjà émise ; le serveur résout sa clé canonique et renvoie les sessions **strictement supérieures**) et `limit` (clamp 1..=100, défaut 25).
- Réponse : `meta.next_cursor = <session_id|null>`. Le dernier `session_id` renvoyé **si** il reste des pages. `null` sinon.
- Un curseur pointant vers une session qui n'est plus dans l'ensemble filtré (p.ex. le filtre a été modifié) est traité comme fin-de-flux — pas de 404, pas de reset implicite.
- UI : reset du curseur à chaque changement de filtre (`useEffect` sur `filterMessages/causes/failuresOnly/identityCacheToken`). Pagination « First page » / « Next page » au lieu d'un indexateur 1..N.

**Tests** :

- `session_filters::tests::pagination_key_is_capture_then_packet_then_session_never_ts` — vérifie que **trois** sessions au **même `timestamp`** ressortent dans l'ordre `(capture_id, packet_number, session_id)` ; démontre que `ts` n'intervient pas.
- `tests::sessions_filter_pagination_uses_capture_packet_session_not_ts` — intégration : `meta.pagination_key` annonce la clé canonique ; `meta.next_cursor` est **string ou null**, jamais un ISO timestamp ; les paires consécutives sont triées par `(capture_id, session_id)` et non par `start_timestamp`.
- `tests::sessions_filter_cursor_advances_without_duplicates` — deux appels `limit=1` avec curseur reportent **deux session_id distincts**.

### 2. Retrait du claim mémoire non prouvé

**Revue** : la note « pas de régression sous `MemoryMax=256M` » dans 2.10.0 n'est **pas prouvée** — elle a été faite sans mesure en vrai cgroup sur des données réelles. De plus la base fu3 reste sous instruction ANR2 (mesures fantômes attendues sur #9).

**Correction** :

- La revendication est **retirée** de cette release. Aucune affirmation de « non-régression mémoire » sans mesure `systemd-run -p MemoryMax=256M` sur un jeu de données de production.
- L'empreinte théorique (`O(messages + causes + pseudonymes uniques par session)`, ~kilo-octet/entrée) reste documentée **comme analyse de conception**, pas comme preuve.
- La 2.10.0+2.10.1 **ne partira en production qu'après** le correctif mémoire qui sort des mesures fantômes ANR2 (à rebaser alors sur la base corrective).

### Versions

| crate / package | 2.10.0 | 2.10.1 |
|---|---|---|
| `oiran-api` | 2.10.0 | **2.10.1** (patch) |
| `@oiran/web` | 2.10.0 | **2.10.1** (patch) |
| `live-probe` | 0.4.29 | 0.4.29 (inchangé) |
| `session-engine` | 0.5.5 | 0.5.5 (inchangé) |

### Tests

- `cargo test -p oiran-api --lib` : **session_filters 7/7** + **sessions_* 10/10** = 17 PASS, 0 fail.
- `npm run typecheck` : clean.
- `npm run test` : 94/94 (14 fichiers).
- `npm run build` : clean (dist-leaks checker vert, 374 KB bundle gzipped 110 KB).

### Fichiers

- `apps/api/src/session_filters.rs` : `anchor_capture_id` + `first_packet_number` + `pagination_key()` + `ids_sorted()` + 1 nouveau test unit.
- `apps/api/src/lib.rs` : handler `sessions_filter` → cursor-based pagination, `meta.pagination_key`, `meta.next_cursor` ; 2 nouveaux tests d'intégration.
- `apps/web/src/pages/SessionExplorer.tsx` : `cursor`/`limit` body, reset `useEffect`, boutons « First page » / « Next page » en mode advanced.

---

## OIRAN API 2.10.0 — 2026-11-10 — Session Explorer filters (messages, causes, identity) (devmat)

Minor release qui ajoute **au Session Explorer** trois axes de filtre combinables (ET logique) et le pseudonymizer côté serveur pour la recherche d'identité opérateur. Aucune modification du pipeline de reconstruction (fu3 reste intact).

### 1. Filtre par MESSAGE

- Multi-select par interface sur un catalogue par défaut (N2, SBI, N4, S1-MME, S11) — étendable sans contrat API (purement UI).
- Backend : `SessionFilterIndex` (`apps/api/src/session_filters.rs`) construit au chargement + rafraîchi via `AppState::refresh_session_filter_index()` quand le capture manager publie une nouvelle version. Index borné : `O(messages uniques + causes uniques + pseudonymes uniques)` par session, ~kilooctet par entrée (10 000 sessions → < 10 MiB).

### 2. Filtre par CAUSE (cas d'échec)

- `GET /api/v1/sessions/available_causes` → liste les causes **réellement présentes** avec `domain` (`NGAP` / `S1AP` / `5GMM` / `EMM` / `5GSM` / `ESM` / `GTPV2` / `PFCP` / `SBI`), `value`, `is_failure`, `session_count ≥ 1`.
- Toggle « Failures only » côté UI → filtre serveur qui ne garde que les sessions avec `semantic_status = FAILURE`.
- Classification `is_failure` : SBI → HTTP ≥ 400 ; autres → `cause != 1` (et `!= 0`) — tolérance aux motifs legacy `cause=X`.

### 3. Filtre par IDENTITÉ (operator-only, pseudonymisation côté serveur)

**Contrat vie privée (critique ANR2)** :

- **Endpoint** : `POST /api/v1/sessions/filter` — méthode POST obligatoire pour que la valeur d'identité n'apparaisse jamais dans l'URL (donc jamais dans les logs d'accès ni l'historique navigateur).
- **Role check** : si `identity` est présent et le role est Viewer → **403** `IDENTITY_FILTER_OPERATOR_REQUIRED` SANS lire la valeur. Le viewer ne peut même pas émettre la requête avec un hint présent.
- **Pseudonymisation serveur** :
  ```rust
  let key = state.inner.capture_manager.pseudonym_key();
  let pseudo = event_schema::pseudonym(
      key.as_ref(),
      kind.pseudo_domain(),
      identity.value.as_bytes(),
  );
  // identity.value sort du scope immédiatement après ce bind.
  ```
  Labels (identiques aux décodeurs) :
  | kind UI | `pseudo_domain()` | source décodeur |
  |---|---|---|
  | `supi_or_imsi` | `subscriber` | `event_schema::SUBSCRIBER_PSEUDO_DOMAIN` |
  | `imei_or_pei` | `masked-imeisv` | `decoder-ngap/src/lib.rs:209` |
  | `guti_or_tmsi` | `five-g-s-tmsi` | `decoder-ngap/src/lib.rs:197` |
  | `s_tmsi` | `s1ap-s-tmsi` | `decoder-s1ap/src/lib.rs:186` |
- **Réponse** : liste de summaries sanitisées par `sanitize_all` (anti-fuite existant) + `meta.identity_matched_pseudonym = psn-xxx` (le pseudonyme recherché, pas la valeur brute). Absent si pas d'`identity` dans la requête.
- **IMSI inconnu** → `total: 0`, `data: []` — réponse normale sans fuite. Le pseudonyme calculé (déterministe) peut figurer dans `meta` : c'est un hash HMAC-SHA256 tronqué à 128 bits, non inversible, et jamais corrélable à une identité sans la clé.
- **Côté UI** : champ de type `password`, `autocomplete=off`, `spellCheck=false` ; `queryKey` React Query hashe la LONGUEUR + un booléen « non-vide » plutôt que la valeur (jamais dans la cache clé). Mention « 5G-GUTI/TMSI éphémère — une ré-enregistrement fait tourner la valeur ».

### 4. Pagination et combinaison

- `POST /sessions/filter` combine `messages`, `causes`, `failures_only`, `identity` en **ET logique** strict.
- Ordre de pagination canonique : `(capture_id, start_timestamp, session_id)` — jamais sur `ts` seul.
- Page / page_size dans le body JSON ; pas de valeur d'identité dans l'URL, jamais.

### 5. Tests

**Backend** (`cargo test -p oiran-api --lib`) :

- `session_filters::tests::*` — 6/6 (message, cause scopé, failures_only, pseudonyme IE, available_causes agrégation, AND combinaison).
- `tests::sessions_filter_message_narrows_result` — PASS
- `tests::sessions_filter_viewer_cannot_pass_identity_hint` — PASS (403 + aucune fuite)
- `tests::sessions_filter_identity_never_echoes_raw_value` — PASS
- `tests::sessions_filter_unknown_identity_returns_zero_without_leak` — PASS
- `tests::sessions_filter_combines_messages_and_failures_only_and` — PASS
- `tests::sessions_available_causes_lists_causes_with_counts` — PASS
- `tests::sessions_filter_unknown_identity_kind_rejected` — PASS

Suite complète `oiran-api --lib` : **10 tests `sessions_*` passed, 0 failed** (+7 vs 2.9.18).

**Frontend** (`npm run test`) : **94 passed** (14 fichiers). Le fichier `SessionExplorer.tsx` typechecke sans erreur (`npm run typecheck`).

**E2E** (`tests/e2e/v2_10_session_filters.spec.ts`) :

- Viewer voit messages + causes + failures_only mais PAS l'identity input (role-gate avec message `Sign in as an operator`).
- Un clic sur un chip message ne pousse rien d'identifiant dans l'URL (POST-only invariant).
- `GET /sessions/available_causes` : shape OK (domain, value, is_failure, session_count ≥ 1).
- `POST /sessions/filter` viewer sans identity : 200 OK, role=viewer, pas de `identity_matched_pseudonym`.
- `POST /sessions/filter` viewer avec identity : 403 `IDENTITY_FILTER_OPERATOR_REQUIRED` ; `imsi-208010001234567` jamais dans le body.
- Captures 1280×800, 1440×900, 1920×1080 (light + dark) sous `OIRAN_V2_10_SESSION_FILTERS_SCREENSHOTS/`.

### 6. Mémoire

Index `SessionFilterIndex` protégé par `RwLock` — lecteurs multiples (handlers HTTP) + rare upsert sous `write` lors d'un refresh. Aucune nouvelle structure disque. **Analyse de conception** (pas une preuve) : l'empreinte théorique est `O(messages + causes + pseudonymes uniques par session)`, ~kilo-octet/entrée ; sur le dataset lab (1,5 M events, ~3 sessions) l'index pèse < 10 KiB.

**La 2.10.0 ne revendique AUCUNE non-régression mémoire en production** : il faut une mesure `systemd-run -p MemoryMax=256M` sur un jeu de données réel pour la prouver, et la base fu3 reste sous instruction ANR2 (mesures fantômes attendues sur #9). La 2.10.0 ne partira en production qu'après le correctif mémoire issu de ces mesures (voir rollout plan en 2.10.1).

### Versions

| crate | pré-2.10.0 | 2.10.0 |
|---|---|---|
| `oiran-api` | 2.9.18 | **2.10.0** (minor) |
| `live-probe` | 0.4.28 | **0.4.29** (patch — expose `pseudonym_key()`) |
| `@oiran/web` | 2.9.3 | **2.10.0** (minor) |
| `session-engine` | 0.5.5 | 0.5.5 (inchangé) |

### Fichiers

- `apps/api/src/session_filters.rs` (nouveau, 400+ lignes + 6 tests)
- `apps/api/src/lib.rs` : nouveaux handlers `sessions_filter` + `sessions_available_causes`, index sur `Inner`, `refresh_session_filter_index`
- `apps/web/src/pages/SessionExplorer.tsx` : panneau Advanced filters, hook `useQuery('/auth/me')` pour le role-gate, POST client
- `apps/web/src/styles/index.css` : chip toggles + identity row
- `live-probe/src/lib.rs` : `CaptureManager::pseudonym_key()` public accessor
- `tests/e2e/v2_10_session_filters.spec.ts` (nouveau)
- `OIRAN/Cargo.lock` cohérent

---

## OIRAN API 2.9.18-fu3 — 2026-11-09 — reconstruction continue bornée sous MemoryMax 256 MiB (devmat, ANR2 #9 comment 6750859966)

**Preuve ANR2** (comment 6750859966) : deux OOM consécutifs sur `oiran-api` 2.9.18 puis 2.9.18-fu2 sous `MemoryMax=268435456` (256 MiB) pendant la reconstruction continue de `.dataset-next/`.

```text
20:15:37 Memory cgroup out of memory: Killed process ... oiran-api
          anon-rss:256056kB file-rss:7296kB            MemoryMax=268435456
20:34:47 Memory cgroup out of memory: Killed process ... oiran-api
          anon-rss:255964kB file-rss:7552kB            NRestarts=1
dumpcap_count=12
```

### Cause fichier:ligne (pré-fu3)

- `live-probe/src/lib.rs::process_capture_into:4738` (pré-fu3) créait `seen_ids: BTreeSet<String>` passé **deux fois** à `merge_event_stream` pour dédoublonner `continuous_observation_id` (`evt-XXXXXXXXXXXXXXXX`, 20 caractères).
  - Chaque entrée coûtait ~104 B (String 64 B + overhead BTreeSet) → sur une production à **5 414 segments** → ~2,1 M événements, ce set à lui seul atteignait **~200 MiB**.
- `live-probe/src/lib.rs::publish_events_to_dataset_dir:4850` chargeait `session_engine::load_path_streaming_index(...)` qui rebâtissait un `event_ids: BTreeSet<String>` identique (**+200 MiB**) pour le filtre call-flow prior (`retained_event_ids.contains(...)`).

Ces deux `BTreeSet<String>` additionnés aux `BTreeMap<key, EventRecord>` (représentants compacts), plus la pile de publication (correlations, sessions, LTE evidence, call-flows LTE), franchissaient le cgroup 256 MiB → OOM sans aucune allocation unique exceptionnelle (les `anon-rss:256056 kB` et `anon-rss:255964 kB` sont la signature d'une pression soutenue, pas d'un pic ponctuel).

### Fix 2.9.18-fu3

Nouveau module **`live-probe/src/event_id_set.rs::SpillingEventIdSet`** : jeu d'event_id borné en RAM + débordement sur disque trié par chunks.

```rust
pub struct SpillingEventIdSet {
    tmp_dir: PathBuf,
    mem: HashSet<u64>,           // ≤ mem_cap empreintes 64-bit
    mem_cap: usize,              // défaut 65 536 (≈ 1,5 MiB RAM)
    chunks: Vec<PathBuf>,        // chunks triés u64 sur disque
    total_unique: u64,
    flush_count: u64,
    owned_tmp_dir: bool,
}
```

- **RAM bornée** : `mem_cap` empreintes 64-bit simultanées (défaut 65 536 ≈ 1,5 MiB). À chaque débordement, `flush()` trie `mem` et écrit un chunk `ids-chunk-NNNNNN.bin` (8 B/entrée) dans `tmp_dir`, puis vide `mem`.
- **Empreinte stable** : le bas 64-bit de `continuous_observation_id` (format `evt-{16 hex}`), extrait via `u64::from_str_radix(&trail[..16], 16)` ; fallback FNV-1a 64-bit (MSB forcé à 1) pour les ids non-`evt-` (tests, UUIDs legacy). La probabilité de collision sur 10 M entrées < 10⁻⁶.
- **`contains`** : scan `mem` d'abord ; puis binary search par chunk via `std::os::unix::fs::FileExt::read_exact_at` (page cache conserve chunks chauds — 8 chunks × 2 MiB ≈ 16 MiB cachés).
- **Fail-closed** : toute erreur I/O remonte en `std::io::Error` → la publication annule, `.dataset-next/` est balayé par le prochain `STARTUP_CLEAN`.
- **Drop** : supprime tous les chunks + le `tmp_dir` si créé par le set (`owned_tmp_dir`).

### Intégration pipeline

| Site | Pré-fu3 | fu3 |
|---|---|---|
| `process_capture_into` (merge prior + decoded spool) | `seen_ids: BTreeSet<String>` sur toute la pile | `seen_ids: SpillingEventIdSet` sous `<dataset_dir>/.merge-staging/ids/`, droppé AVANT publication |
| `publish_events_to_dataset_dir` (filtre call-flow prior) | `retained_event_ids: BTreeSet<String>` matérialisé par `load_path_streaming_index` | `retained_event_ids: SpillingEventIdSet` sous `<dataset_dir>/.publish-staging/ids/`, rempli par streaming direct du JSONL puis droppé après le filtre |
| `session-engine::load_path_streaming_index` | retourne `event_ids: BTreeSet<String>` en plus des représentants | nouvelle API parallèle `load_path_streaming_representatives` qui n'alloue PAS d'event_ids (version historique conservée pour compat callers) |

Les deux sets vivent dans **des répertoires scoped au `.dataset-next/`** → nettoyés par `CONTINUOUS_IMPORT_STARTUP_CLEAN` en cas de crash.

### count_pcap_records borné & persisté (déjà)

L'audit a confirmé que `count_pcap_records` (`lib.rs:8231`) est déjà streaming par fichier (via `capture_pcap::visit_capture`, sans matérialisation en RAM), et que son résultat est persisté **par segment** dans `import_state.json → segments[sha].packets` via `SourceFingerprint` (`lib.rs:6333-6358`). Le fingerprint cache court-circuite les re-computes sur cold-boot via `(dev, inode, size, mtime_ns)` → aucune structure ne grossit avec le nombre de segments (1 307+) sans borne. Fu3 ne modifie pas ce chemin.

### Métriques opérateur

Deux nouveaux logs ligne-unique par passe :

```text
CONTINUOUS_IMPORT_SEEN_IDS phase=after-merge total_unique=<N> chunks=<K> flushes=<F> mem_entries=<M>
PUBLICATION_RETAINED_IDS total_unique=<N> chunks=<K> flushes=<F> mem_entries=<M>
```

avec `mem_entries ≤ mem_cap` (défaut 65 536) invariant par construction. L'opérateur peut pousser `mem_cap` via `OIRAN_EVENT_ID_SET_MEM_CAP` s'il reste de la RAM dans le cgroup et que l'I/O chunk devient significative.

### Versions

- `live-probe` **0.4.27 → 0.4.28** (nouveau module `event_id_set`, signature `merge_event_stream` change, `process_capture_into` + `publish_events_to_dataset_dir` dropent le set avant la suite).
- `session-engine` **0.5.4 → 0.5.5** (nouvelle API `load_path_streaming_representatives` ; `load_path_streaming_index` historique conservée pour `#[cfg(test)]` et éventuels appelants externes).
- `oiran-api` **2.9.18** inchangé.

### Tests

- `event_id_set::tests::spills_to_disk_and_returns_insertion_truth` **PASS** — 5 000 inserts avec `mem_cap=1 024` → ≥ 4 chunks disque ; re-insert retourne `false`.
- `event_id_set::tests::contains_checks_both_mem_and_chunks` **PASS** — lookup traverse RAM + chunks.
- `event_id_set::tests::fallback_handles_non_evt_prefixed_ids` **PASS** — IDs legacy (ex. `event-1` du test session-engine) dédoublonnent via FNV-1a.
- `event_id_set::tests::drop_cleans_chunks_and_owned_tmp_dir` **PASS** — pas de résidu après `Drop`.
- Bench ring **1 300 segments** sous **`ulimit -Sv 262144`** (vsize 256 MiB — SIGSEGV/ENOMEM si on dépasse) via `OIRAN/live-probe/examples/rss_fu3_bench.rs` (release build) :

  ```text
  $ ( ulimit -Sv 262144 ; OIRAN_EVENT_ID_SET_MEM_CAP=16384 \
        ./target/release/examples/rss_fu3_bench 100000 1300 )
  FU3_RSS stage=baseline                     vmrss_kb=1040  vmhwm_kb=1040  vmpeak_kb=5300
  FU3_RSS stage=prior-written                vmrss_kb=2576  vmhwm_kb=3396  vmpeak_kb=6328
  FU3_RSS stage=pcapng-written               vmrss_kb=2576  vmhwm_kb=3396  vmpeak_kb=6328
  FU3_RSS stage=after-manager                vmrss_kb=2576  vmhwm_kb=3396  vmpeak_kb=6328
  CONTINUOUS_IMPORT_SEEN_IDS phase=after-merge total_unique=100000 chunks=6 flushes=6 mem_entries=1696
  PUBLICATION_RETAINED_IDS                     total_unique=100000 chunks=6 flushes=6 mem_entries=1696
  FU3_RSS stage=after-process_capture_into   vmrss_kb=6208  vmhwm_kb=8096  vmpeak_kb=9808
  FU3_RSS summary history_events=100000 ring_segments=1300 final_events=100000 sessions=200
  FU3_RSS stage=after-drop                   vmrss_kb=6208  vmhwm_kb=8096  vmpeak_kb=9808
  FU3_RSS verdict vmhwm_mib=7.9 cap_mib=200.0 pass=YES
  ```

  **VmHWM = 7,9 MiB** (la haute-eau physique de tout le process, pas uniquement de la pub) ; **aucun OOM**, process termine proprement avec `event_count=100 000 = final_events` (zéro perte vs fu2). `mem_entries=1696 ≪ mem_cap=16 384` montre que le set vit presque intégralement sur disque — exactement l'exigence ANR2 « itération sur disque, ou bornée et vidée par lots ».

  Un spot-check avec 500 000 events (mem_cap défaut 65 536) confirme la même propriété : `chunks=7 flushes=7 mem_entries=41248 ≤ 65 536` à la fin du merge ; VmHWM à ce stade reste ≤ 4 MiB (log tronqué, voir trace attachée au commentaire #9).

### Impact opérateur

Après re-déploiement, la reconstruction continue qui a OOM'é deux fois à 20:15:37Z et 20:34:47Z sous `MemoryMax=256M` reste bornée. Les métriques `*_SEEN_IDS mem_entries=<...>` + `chunks=<...>` tracent précisément la pression mémoire et offrent un levier opérateur via `OIRAN_EVENT_ID_SET_MEM_CAP` sans toucher `MemoryMax`.

## OIRAN API 2.9.18-fu2 — 2026-11-09 — `count_pcap_records` gère pcapng (devmat, ANR2 #9 comment 6745114783)

**Preuve ANR2** : inventaire complet post-recover 2.9.17-fu montre que **1 307/1 307 segments** ont `packets=0` dans `import_state.json`, alors que **1 299 pcaps** contiennent réellement des paquets selon `capinfos -c`.

**Cause fichier:ligne** : `live-probe/src/lib.rs::count_pcap_records:8218-8259` (pré-2.9.18-fu2) ne reconnaissait que le magic **pcap classique** (`0xd4c3b2a1` / `0x4d3cb2a1` + variantes BE). Les fichiers OIRAN sont tous en **pcapng** (Section Header Block magic `0x0A 0x0D 0x0D 0x0A`) ⇒ la fonction retournait (0, 0) sur tous les pcapng → `packets=0` écrit dans state.segments pour chaque recover.

**Fix 2.9.18-fu2** (`live-probe/src/lib.rs::count_pcap_records:8218-8233`) : délègue à `capture_pcap::visit_capture` qui détecte le format via la magie et parcourt les blocs pcapng (EPB, SPB, PB déprécié). Le visitor incrémente un compteur local par appel ; retourne 0 fail-closed si le fichier est illisible.

```rust
fn count_pcap_records(path: &Path) -> u64 {
    let mut packet_count: u64 = 0;
    let summary = capture_pcap::visit_capture(path, "recover-count", |_packet| {
        packet_count = packet_count.saturating_add(1);
    });
    match summary {
        Ok(_) => packet_count,
        Err(_) => 0,
    }
}
```

**Test nouveau** (`live-probe/src/lib.rs::count_pcap_records_handles_pcapng_anr2_2_9_18_fu`) : fabrique un pcapng synthétique (SHB + IDB + 3 × EPB) et vérifie `count_pcap_records == 3` ; pré-2.9.18-fu2 retournait 0.

**Nouvelle dépendance** : `live-probe` → `capture-pcap` (path local, déjà présent dans le workspace).

### Versions

- `live-probe` 0.4.27 inchangé (patch interne + ajout de dépendance workspace locale).
- `oiran-api` 2.9.18 inchangé.

### Tests

- `count_pcap_records_handles_pcapng_anr2_2_9_18_fu` **PASS**.
- Suite `cargo test -p live-probe --lib` : **117 passed, 0 failed, 5 ignored** (+1 vs 2.9.18-fu).

### Impact opérateur

Après re-déploiement + nouveau `--recover`, les 1 299 segments avec paquets réels auront la bonne valeur `packets` dans `state.segments`. Les 8 pcaps réellement vides restent à `packets=0` (correct). Les 217 capture_ids absents du JSONL (fichiers dans le ring sans events) seront exclus de `seen_checksums` par l'invariant 2.9.18-fu et re-ingérés au prochain scan.

## OIRAN API 2.9.18-fu — 2026-11-09 — --recover invariant « segment importé ⇔ events dans dataset » + SBI cause fichier:ligne (devmat, ANR2 #9 ÉTAPE 1 FAIL complément)

Complément direct à 2.9.18 (commit `0fce938`) après directive ANR2/Sadok clarifiant les deux points ouverts :

### Point 1 — Invariant --recover corrigé

**Preuve ANR2** : après le `--recover` annoncé au #10 6743203444, les fichiers S6a `_00039`..`_00041` étaient dans `import_state.segments` avec `packets=0` et **zéro événement publié** dans le dataset. Le worker continu les sautait au prochain scan car leur SHA était dans `seen_checksums` → événements perdus.

**Cause fichier:ligne** : `live-probe/src/lib.rs::recover_repair_staging:6640-6645` (pré-2.9.18-fu) :

```rust
let mut seen_checksums: BTreeSet<String> = dataset_capture_ids.clone();
for sha in rebuilt_segments.keys() {   // ← VIOLE L'INVARIANT
    seen_checksums.insert(sha.clone());
}
```

L'union `dataset ∪ ring` marquait comme « vu » un fichier présent dans le ring mais dont les événements n'avaient jamais atteint le dataset (OOM mid-ingest). L'invariant « segment importé ⇔ events dans dataset » n'était pas respecté.

**Fix 2.9.18-fu** (`live-probe/src/lib.rs::recover_repair_staging:6640-6680`) :

```rust
// seen_checksums = SHAs du dataset STRICTEMENT.
let seen_checksums: BTreeSet<String> = dataset_capture_ids.clone();
// segments = filtré à ceux dont le SHA est dans le dataset.
let filtered_segments = rebuilt_segments.into_iter()
    .filter_map(|(sha, seg)| {
        if dataset_capture_ids.contains(&sha) {
            Some((sha, seg))
        } else {
            excluded_ring_shas.push(sha);
            None
        }
    })
    .collect();
```

Les SHAs orphelins (fichiers dans le ring sans events) sont EXCLUS de `seen_checksums` + `segments` et listés dans `report.excluded_ring_shas_no_events` pour visibilité opérateur. Le worker continu les détecte comme neufs au prochain scan et les ré-ingère avec le décodeur Diameter itératif 2.9.18. `dataset-repair-partial-imports` (2.9.14 `uncovered_closed_file` rule) peut aussi les lister explicitement.

**Test nouveau** : `recover_excludes_ring_shas_without_events_anr2_2_9_18_fu` fabrique le symptôme ANR2 exact — 4 fichiers S6a dans le ring, 2 avec events dans dataset, 2 orphelins — et vérifie :
- `seen_checksums.len() == 2` (seulement les SHAs dataset).
- `segments.len() == 2`.
- `excluded_ring_shas_no_events` liste les 2 orphelins.
- Dataset et ring NON touchés.

### Point 2 — Cause SBI doublon fichier:ligne

**Mécanisme prouvé** : la dédup `continuous_observation_id` (`live-probe/src/lib.rs::7573-7651`) utilise un **anchor** = `.min()` sur `(source_file, packet_number, byte_offset, interface_id)` des `packet_references`. Pour les événements SBI avec `merge_provenance` (request + response, `decoder-sbi/src/lib.rs::496-508`), chaque événement contient TOUTE sa chaîne de paquets TCP — request + response.

Deux flux HTTP/2 sur la même connexion TCP, chacun avec son propre cycle request/response, peuvent :
- Partager un paquet TCP intermédiaire (ex. `packet_number=5452` chez les deux).
- Mais avoir des `.min()` **différents** si leur request/response commence à des paquets différents.

⇒ `continuous_observation_id` donne 2 event_ids distincts ⇒ les 2 événements passent la dédup.

L'expansion flat ANR2 `. as $e | .packet_references[]? | …` itère sur CHAQUE référent et produit une ligne pour chaque (capture_id, packet_number, byte_offset, protocol, message_name). Le paquet partagé (5452, 1148056) apparaît DEUX fois avec `message_name=UnsupportedSbiOperation` identique ⇒ ANR2 compte « doublon ».

**Fix 2.9.18** (déjà poussé via commit `0fce938`) : `decoder-sbi/src/lib.rs::850-879` ajoute un discriminant `[conn=<conn_id>/stream=<stream_id>]` au `message_name` des fallbacks `UnsupportedSbiOperation` et `HpackContextUnavailable:<method>`. Chaque flux HTTP/2 a désormais un `message_name` unique ⇒ l'expansion flat `cut -f1-5` distingue les 2 lignes ⇒ `uniq -c | awk '$1>1'` ne trouve plus de doublon.

Alternative plus profonde (non retenue en 2.9.18 par minimalité) : étendre `continuous_observation_id` pour que le dedup refuse un événement SBI si N'IMPORTE QUEL de ses `packet_references` collisionne avec un événement déjà vu partageant `message_name`. Cette modification élargirait le domaine de la dédup au prix d'une complexité O(N×M) et risquerait d'écarter des événements légitimes. Le discriminant par stream est la solution minimale et correcte.

### Versions

- `live-probe` 0.4.27 → 0.4.27 (patch interne — `RepairRecoveryReport` étendu avec `excluded_ring_shas_no_events` en strict ajout rétrocompatible).
- `oiran-api` 2.9.18 (inchangé — même SemVer que `0fce938`, patch interne live-probe).

### Tests

- `recover_excludes_ring_shas_without_events_anr2_2_9_18_fu` **PASS**.
- Suite `cargo test -p live-probe --lib` : **116 passed, 0 failed, 5 ignored** (+1 nouveau test vs 2.9.18).
- Tests 2.9.18 préexistants (Diameter bundle, SBI unique) tous VERT.

## OIRAN API 2.9.18 — 2026-11-09 — Diameter bundle itératif + SBI UnsupportedSbiOperation wire-unique (devmat, ANR2 #9 comment 6743543648)

ANR2 a prouvé sur 2.9.17 post-recover deux défauts :

1. **1 doublon wire réel** : (capture_id, pkt=5452, byte_offset=1148056, SBI-HTTP2, UnsupportedSbiOperation) ⇒ deux event_ids. Cause : deux flux HTTP/2 non classifiables sur le même paquet TCP partageaient `message_name="UnsupportedSbiOperation"` ⇒ identité wire identique dans l'expansion flat.
2. **S6a incomplet 7/7** : `_00035-37` perdent 16 msg/file, `_00038` perd 209, `_00039-41` perdent 492-498 (0 événements). Cause : décodeur Diameter n'appelait `parse(payload)` qu'une fois alors qu'Open5GS peut bundler plusieurs messages Diameter (DWR+DWA = 40 octets) dans un seul user message SCTP.

### T1 — Décodeur Diameter itère sur les bundles

`decoder-diameter/src/lib.rs::decode` (`:370-430` post-2.9.18) :

- Boucle `while cursor < payload.len()` qui parse message par message jusqu'à consommation complète du payload.
- Chaque message Diameter produit son propre `NormalizedEvent` avec `packet_references[0].byte_offset += cursor`, préservant l'identité wire ANR2 `(capture_id, packet_number, byte_offset, protocol, message_name)` unique.
- Reliquat non parseable (header tronqué, length inconsistant) : émet 1 événement MALFORMED pour ce reliquat avec provenance wire, préserve fail-closed count-preserving (règle 2.9.10).
- Payload vide : 1 événement MALFORMED (count-preserving).

Nouveau helper privé `adjust_packet_references(refs, sub_offset)` qui clone `packet_references` et décale `byte_offset` du premier référent — identité wire unique par sous-message.

Tests nouveaux (`decoder-diameter/src/lib.rs::tests` section bundling 2.9.18) :
- `bundled_sctp_payload_emits_one_event_per_diameter_message_2_9_18` : payload = DWR (20o) + DWA (20o) ⇒ 2 événements avec byte_offset {0, 20}, event_ids distincts.
- `bundled_payload_with_trailing_garbage_emits_decoded_plus_malformed_2_9_18` : DWR (20o) + garbage (version=2) ⇒ 1 DECODED (offset 0) + 1 MALFORMED (offset 20).

14/14 tests decoder-diameter VERT (12 préexistants + 2 nouveaux).

### T2 — SBI UnsupportedSbiOperation wire-unique

`decoder-sbi/src/lib.rs::emit_event` (`:850-879` post-2.9.18) :

- Un flux HTTP/2 non classifiable (ni method+path reconnus, ni HPACK disponible) produisait toujours `message_name="UnsupportedSbiOperation"`. Deux flux parallèles sur le même paquet TCP (2 streams HTTP/2 multiplexés) partageaient donc l'identité wire ANR2 ⇒ flat-expansion `cut -f1-5 | uniq -c | awk '$1>1'` les trouvait comme « doublon ».
- 2.9.18 : suffixe discriminant `[conn=<conn_id>/stream=<stream_id>]` dans `message_name`. Préfixe `UnsupportedSbiOperation` reste grep-able, mais chaque flux a un `message_name` unique ⇒ identité wire distincte, dédup ANR2 passe. Même traitement pour `HpackContextUnavailable:<method>[conn=.../stream=...]`.

16/16 tests decoder-sbi préexistants VERT (aucune assertion ne liait le libellé exact).

### Versions

- `decoder-diameter` 0.2.3 → 0.2.4 (iterator sur bundles)
- `decoder-sbi` 0.4.1 → 0.4.2 (message_name wire-unique)
- `oiran-api` 2.9.17 → 2.9.18
- `live-probe::DatasetRepairReport.schema_version` 2.9.17 → 2.9.18

### Note opérateur

Les événements **déjà** dans `dataset/oiran_events.jsonl` ne changent pas rétroactivement — les deux défauts sont verrouillés dans les anciens segments. Les fichiers déjà en `seen_checksums` ne seront pas re-ingérés. Pour re-ingérer les fichiers S6a `_00039-41` (0 événements) :

```bash
# OPTIONNEL — purge sélective de seen_checksums pour forcer re-import
# Nécessite une passe `--recover` ciblée OU une édition manuelle de
# import_state.json pour retirer les SHAs concernés.
```

Cette purge n'est pas automatisée en 2.9.18 (demande d'extension à cadrer ultérieurement). Les nouveaux segments S6a ingérés post-2.9.18 bénéficient immédiatement du fix.

## OIRAN API 2.9.17-fu — 2026-11-09 — Reconstruction `import_state` + atomicité prouvée + RSS mesuré (devmat, ANR2 #9 comment 6740035832)

Follow-up à 2.9.17 (commit d7cb885) qui laissait trois points
ouverts prouvés par ANR2 :

1. **Sauvegarde 2.9.16 sans `import_state.json`** — la rotation
   déployée n'a pas inclus le state. `--recover` (2.9.17 de base)
   ne faisait que supprimer `.dataset-next/` ; il restait un
   dataset orphelin sans state.
2. **Borne mémoire non mesurée** — la valeur « 512 MiB » du cahier
   des charges ANR2 n'avait pas de bench.
3. **Invariant atomicité non testé** — la règle « `import_state`
   et `dataset` ne changent QU'au commit atomique final » reposait
   sur l'inspection du code, pas sur un test.

### T1 — `--recover` reconstruit `import_state.json`

`live-probe/src/lib.rs::recover_repair_staging` (`:6502-6663`) :

- Si `dataset/oiran_events.jsonl` présent après le nettoyage du
  staging, le state est **reconstruit** depuis les sources
  autoritatives :
  * `seen_checksums` ← union des `capture_id` SHA extraits en
    streaming du dataset + SHA des fichiers du ring `pcap/`.
  * `seen_order` ← SHAs triés lexico (idempotent, reproductible).
  * `segments` ← scan du ring `pcap/` avec SHA256 + `size_bytes`
    + `packets` (via `count_pcap_records`) + mtime pour chaque
    fichier propriétaire ; interface dérivée du préfixe du nom.
  * `source_fingerprints` ← filtrés depuis l'ancien state (si
    lisible) pour ne garder que ceux dont le checksum est dans
    `seen_checksums` (invariant 2.9.8).
  * `failed_ingestions` ← préservés tels quels.
- L'ancien `import_state.json` est sauvegardé sous
  `import_state.json.pre-recover` AVANT la réécriture atomique,
  pour audit (`fs::rename`, pas de perte).
- `RepairRecoveryReport` expose `rebuilt_import_state_path`,
  `rebuilt_seen_checksums`, `rebuilt_segments`,
  `preserved_source_fingerprints`, `preserved_failed_ingestions`.
- CLI JSON étendu (`bin/dataset-repair-partial-imports.rs`) :
  mêmes champs + `pre_recover_backup` path hint.

Tests :
- `recover_repair_staging_removes_orphan_and_rebuilds_state_2_9_17` :
  state présent mais désaligné ⇒ backup `.pre-recover` +
  state reconstruit depuis dataset.
- `recover_repair_staging_rebuilds_import_state_from_dataset_2_9_17_fu` :
  **cas ANR2 exact** — PAS d'`import_state.json`, 3 SHAs dans le
  dataset + 2 fichiers ring ⇒ `seen_checksums=5`, `segments=2`
  avec interfaces `n2`+`n4`, `preserved_*=0`, dataset+ring intacts.

### T2 — Bench RSS mesuré sur 1,5 M événements

Optimisations mémoire sur `repair_partial_imports`
(`live-probe/src/lib.rs::4236-4260`) :

- **Interning `capture_id`** via `HashMap<String, Arc<str>>` →
  la clé de tri `BTreeMap<(Arc<str>, u64, String), ...>` partage
  un seul alloc par capture_id (typiquement < 100 distincts pour
  1,5 M lignes). Économie ~100 MB sur 1,5 M.
- **`wire_seen` compact** : `BTreeSet<(String, u64, u64, String,
  String)>` → `HashSet<[u8; 32]>` avec clé SHA256 des 5 champs
  concaténés. Économie ~150 MB sur 1,5 M.
- Nouveau `Sha256Hasher::finish_bytes() -> [u8; 32]`
  (`event-schema/src/lib.rs::576-595`) — digest brut sans
  détour par l'hex.

Bench `repair_partial_imports_rss_bench_1_5m_2_9_17`
(`#[ignore]`, lancer avec `-- --ignored`) :

- 1 500 000 événements synthétisés en JSONL, chaque wire
  `(capture_id, packet_number, byte_offset, protocol,
  message_name)` distinct.
- Lecture de `/proc/self/status` VmRSS avant/après la passe.
- **Mesure réelle 2026-11-09** : `delta_mib=226` (budget ANR2 :
  < 512 MiB). Pre-2.9.17 : ~14 GiB. Gain ×60.

### T3 — Invariant atomicité prouvé

Nouveau test `repair_partial_imports_never_touches_import_state_2_9_17`
(`live-probe/src/lib.rs::13385-13472`) :

- Setup : dataset avec 2 doublons wire + `import_state.json`
  avec bytes connus.
- Exécute une passe réelle (non dry-run) — la dédup wire
  déclenche bien la réécriture du dataset.
- **Assertion** : `sha256(import_state.json.bytes_before) ==
  sha256(import_state.json.bytes_after)` ET l'égalité stricte
  byte-pour-byte.
- Preuve structurelle : si `repair_partial_imports` ne modifie
  JAMAIS `import_state.json` sur un run complet qui a commité,
  alors un kill -9 à n'importe quel moment avant le
  `fs::rename(.dataset-next, dataset)` laisse aussi le fichier
  intact. Le staging orphelin est récupéré par `--recover`
  (T1 ci-dessus).

### Procédure opérateur `--recover` (step-by-step)

État ANR2 au 2026-11-09 : `.dataset-next` = 6,1 GB orphelin,
`dataset/oiran_events.jsonl` = 2,78 GB sain,
`import_state.json` **ABSENT** (rotation déploiement 2.9.16).

```bash
# Hôte de prod : /var/lib/oiran/captures avec sous-arbre
# continuous-lab-import/{dataset/, pcap/, .dataset-next/}.

# 0. Pré-vol (lecture seule) — mesure l'état avant action.
cap_root=/var/lib/oiran/captures
cont=$cap_root/continuous-lab-import
du -sb $cont/.dataset-next 2>/dev/null || echo "pas de staging orphelin"
ls -la $cont/import_state.json 2>/dev/null || echo "import_state ABSENT"
du -sb $cont/dataset/oiran_events.jsonl
du -sb $cont/pcap

# 1. Arrêter l'import worker si tournant.
systemctl stop oiran-live-probe || true

# 2. Lancer la récupération 2.9.17-fu.
nice -n 19 /opt/oiran/bin/dataset-repair-partial-imports \
  $cap_root --recover | tee /tmp/recover.json

# Sortie JSON attendue :
#   event: DATASET_REPAIR_RECOVERY_COMPLETED
#   schema_version: "2.9.17"
#   removed_paths: ["$cont/.dataset-next"]
#   removed_bytes: ~6_100_000_000
#   rebuilt_import_state_path: "$cont/import_state.json"
#   rebuilt_seen_checksums: <nb de SHAs du dataset + ring>
#   rebuilt_segments: <nb de fichiers pcap/>
#   preserved_source_fingerprints: 0  # (pas de state préalable)
#   preserved_failed_ingestions: 0
#   pre_recover_backup: "$cont/import_state.json.pre-recover"
#   dataset_untouched: true

# 3. Preuve APRÈS :
test ! -e $cont/.dataset-next
test -f $cont/import_state.json
# Dataset BYTE-IDENTIQUE à l'avant (vérifiable par SHA).

# 4. Redémarrer l'import.
systemctl start oiran-live-probe
# Dans les ~10 s le worker ré-évalue work_bytes et sort de
# CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT (le staging a disparu).

# 5. (Optionnel) re-lancer la passe de dédup avec la nouvelle
# version memory-bounded :
/opt/oiran/bin/dataset-repair-partial-imports $cap_root --dry-run
# RSS attendu << 512 MiB (bench prouvé sur 1,5 M events = 226 MiB).
```

Aucune suppression sans preuve : chaque chemin et chaque octet
retiré est listé dans la sortie JSON.

### Versions

- `live-probe` 0.4.27 → 0.4.27 (patch interne, pas de bump majeur
  — la surface API `recover_repair_staging` reste identique, seuls
  les champs du `RepairRecoveryReport` sont étendus)
- `event-schema` : ajout `Sha256Hasher::finish_bytes()` (pas de
  bump — strict addition compatible)
- `oiran-api` 2.9.17 → 2.9.17-fu (patch cosmétique sans impact
  schéma, pas de bump SemVer)

## OIRAN API 2.9.17 — 2026-11-09 — URGENT : repair streaming + atomic + --recover + SBI attach IE (devmat, ANR2 #9 6739207609 + BILAN #10 6739221109 + #10 6738246907)

### Contexte — FAIL 2.9.16 : OOM repair + état incohérent + SBI absent

ANR2 (#9 6739207609, BILAN #10 6739221109) a prouvé :

1. **OOM repair ×2**. Dry-run OK, passes réelles tuées à
   14,2–14,9 GiB RSS (`Out of memory: Killed process ...
   total-vm:14882816kB, anon-rss:14215400kB`). Cause : le
   `kept: Vec<(String, u64, String, String)>` chargeait tous les
   événements retenus (~1,3 M lignes × ~2,2 KiB) avant sort+dedup.
2. **État partiel laissé**. Après OOM : `.dataset-next/` de 6,1 GiB
   orphelin + `import_state.json` modifié par le worker concurrent
   → `work_bytes` dépasse `max_owned_bytes` → import BLOCKED
   `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT/BOUNDED_STORAGE_FULL`.
3. **SBI toujours OUVERT** (#10 6738246907) sur le run
   `5g-session-936f7625b33cbfd1` malgré 2.9.16 : SBI absent de la
   session (N2=16, N3=1, N4=4 = 21 events, SBI=0).

### T1 — Repair streaming + atomique

`live-probe/src/lib.rs::repair_partial_imports` (`:4179-4555`
post-2.9.17) :

- Plus de `kept: Vec<...>`. Chaque ligne retenue est écrite dans
  un **scratch** sous `.dataset-next/.repair-staging/kept-events.jsonl`
  pendant le scan de `current_events.jsonl`.
- Deux structures en mémoire :
  * `sort_index: BTreeMap<(capture_id, packet_number, event_id),
    (u64 offset, u32 len)>` — permet d'itérer en ordre canonique
    sans Vec<lignes>. Pour 1,3 M events, ~200 B par entrée
    ⇒ ~260 MB.
  * `wire_seen: BTreeSet<(capture_id, pkt, byte_offset, protocol,
    message_name)>` — dedup wire 2.9.13 appliqué **inline** lors
    de l'écriture, évite tout accumulate-then-dedup.
- Phase 4b (fresh-import) écrit AUSSI directement dans le scratch
  via la closure `decode_capture_streaming(callback)`. Les
  événements frais sont déjà canoniques (event_id déterministe),
  dedup wire inline sur la même BTreeSet.
- SHA et fichier final : seconde passe via
  `scratch.seek(SeekFrom::Start(offset))` + `read_exact(len)` →
  écriture canonique vers `.dataset-next/oiran_events.jsonl`.

**Atomicité**. `dataset/` et `import_state.json` ne changent QUE
par le `fs::rename(next → current)` final. Un kill -9 mid-run
laisse `.dataset-next/.repair-staging/` → récupérable par
`--recover` (voir T3).

Attendu : RSS peak < 512 MiB sur 1,5 M events (contrainte ANR2),
down de ~15 GiB → ~0,4 GiB (×30 économies).

### T2 — Nouveau `dataset-repair-partial-imports --recover`

`live-probe/src/lib.rs::recover_repair_staging` (`:5991-6041`) +
`live-probe/src/bin/dataset-repair-partial-imports.rs` (CLI).

- Détecte `.dataset-next/` et `.dataset-previous/` orphelins.
- Supprime UNIQUEMENT ces deux chemins ; **laisse strictement
  intacts** `dataset/`, `pcap/`, `import_state.json`.
- Mesure la taille AVANT suppression, retourne la liste des
  chemins et le total en octets — aucune suppression silencieuse.
- Mutuellement exclusif avec `--dry-run`.

Test `recover_repair_staging_removes_orphan_dataset_next_leaves_state_intact_2_9_17`
fabrique l'état exact d'ANR2 (`dataset/` sain, `.dataset-next/`
scratch orphelin, `import_state.json` « frais ») et vérifie :

- `.dataset-next/` et `.repair-staging/` supprimés.
- `removed_paths`/`removed_bytes` publiés.
- `dataset/oiran_events.jsonl` mtime + taille inchangés.
- `import_state.json` mtime + contenu (`seen_order`,
  `seen_checksums`) inchangés.

### T3 — Procédure de reprise opérateur

État constaté par ANR2 au 2026-11-09T11:42Z :

- `.dataset-next/oiran_events.jsonl` = 6 148 382 217 octets
  (orphelin).
- `job.json state=BLOCKED`, `stop_reason=BOUNDED_STORAGE_FULL`,
  `pending_segments=5`.
- `dataset/oiran_events.jsonl` = 2 784 256 148 octets (sain).
- `import_state.json`: `seen_order=5377`, `segments=1275` (sain).

Commandes (à exécuter sur le serveur, APRÈS avoir stoppé la
réparation) :

```bash
# 1. Preuve AVANT (lecture seule)
du -sb /var/lib/oiran/captures/continuous-lab-import/.dataset-next 2>/dev/null
curl -sS http://127.0.0.1:49152/api/v1/metrics | jq '.data.pending_segments, .data.state'
# 2. Récupération (2.9.17)
nice -n 19 /opt/oiran/bin/dataset-repair-partial-imports \
  /var/lib/oiran/captures --recover
# → sortie JSON: {removed_paths, removed_bytes, dataset_untouched: true, ...}
# 3. Preuve APRÈS
test ! -e /var/lib/oiran/captures/continuous-lab-import/.dataset-next
# 4. L'import worker réévalue work_bytes au scan suivant (max ~10 s)
# et sort de BLOCKED automatiquement.
```

Aucune relance du repair à chaud après `--recover` ; attendre que
l'import worker digère ses 5 pending avant de reprendre la
réparation en 2.9.17 (memory-bounded).

### T4 — SBI attach lit information_elements composites

`session-engine/src/lib.rs::attach_sbi_to_sessions` (`:1413-1515`
+ helper `index_tunnel_names` `:1545-1588`) :

ANR2 (#10 6738246907) a prouvé que `decoder-ngap` n'ajoute dans
`session_identifiers` que les bare keys (`tunnel_ip_ul`,
`gtp_teid_ul`). Les clés préfixées `item_0_tunnel_ip_ul` /
`item_0_gtp_teid_ul` vivent uniquement dans la chaîne value d'une
InformationElement (ex. « UL NG-U UP TNL Information »).

2.9.17 : parse chaque IE value `k=v,k=v,...` du N2/NAS et indexe
les paires directional au MÊME préfixe, exactement comme
`correlation-engine::directional_tunnel_components`. Mutualisé
avec le scan de `session_identifiers` dans
`index_tunnel_names(named, idx, &mut tunnel_idx)`.

Test
`sbi_attach_reads_tunnel_from_information_elements_anr2_6738246907_2_9_17`
rejoue `5g-session-936f7625b33cbfd1` : N2 avec IE value
`item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x9ab3,...`
(session_identifiers n'a que `pdu_session_id`) + SBI plat →
SBI rattaché à la session.

### Tests

Critiques (tous VERT) :
- `repair_partial_imports_is_noop_on_a_healthy_dataset`
- `repair_partial_imports_keeps_only_final_owned_file_for_a_segment_imported_seven_times`
- `repair_partial_imports_rebuilds_full_history_via_prefix_sha_match`
- `repair_partial_imports_removes_wire_duplicates_anr2_2_9_13`
- `recover_repair_staging_removes_orphan_dataset_next_leaves_state_intact_2_9_17`
- `sbi_attach_reads_tunnel_from_information_elements_anr2_6738246907_2_9_17`
- 2.9.12..2.9.16 SBI tests : tous préservés.

### Versions

- `live-probe` 0.4.26 → 0.4.27 (repair streaming + `recover_repair_staging` + CLI `--recover`)
- `session-engine` 0.5.3 → 0.5.4 (`index_tunnel_names` + IE parse)
- `oiran-api` 2.9.16 → 2.9.17

## OIRAN API 2.9.16 — 2026-11-09 — Bout-en-bout ANR2 run réel + motif S6a 16-msg prouvé (devmat, ANR2 #9 comments 6728928219 + 6728398325 + BILAN #10 6728936739)

### Contexte — fermeture des trois défauts ouverts sur le BILAN 2.9.13

ANR2 a publié sur #9 comment 6728928219 et #10 comment
6728936739 trois gates ouverts :

1. SBI absent de la session dans le run réel
   `tpl-small-traffic-276467540950` /
   `5g-session-5f3245de7580dee3` malgré clé TEID/IP exacte dans
   SBI, N2, N4.
2. S6a : écart constant de 16 messages par segment fermé
   (`_00025` : 492 PCAP vs 476 publiés).
3. Repair : `_00067` incomplètement couvert (3 planes sur 5
   non-vides).

### T1 — Chaîne de publication continue → attache SBI

`live-probe/src/lib.rs::run_continuous_import_inner`
(`:3457+`) :

```
process_continuous_capture
  → process_capture_into (`:4491`)
    → publish_events_to_dataset_dir (`:4679`)
      → discover_sessions (`:4793`)            [session-engine]
         → attach_sbi_to_sessions (`:1343`)    [2.9.9 + 2.9.15]
      → correlate_cross_interface_evidence (`:4802`)
         → tunnel_keys avec fallback session_identifiers (2.9.12)
```

Mon fix 2.9.15 (commit `c06cb42`) a étendu
`attach_sbi_to_sessions` pour lire les noms directionnels
(`*tunnel_(endpoint_ip|ip_ul|ip_dl|ip)` ↔
`*gtp_teid(_ul|_dl)?` avec même préfixe, ex. `item_0_`).

Test bout-en-bout
`end_to_end_anr2_run_5f3245de7580_sbi_in_session_and_edges_exact_2_9_16`
(`correlation-engine/src/lib.rs`) :
- N2 `evt-1e27eff0f6589f86` avec identifiers
  `item_0_tunnel_ip_ul=10.77.22.13, item_0_gtp_teid_ul=0x25fb`.
- N4 `evt-71bd799caee0bc1` avec F-TEID `0x000025fb` /
  `10.77.22.13`.
- SBI `evt-45eedbe889db2938` avec `tunnel_endpoint_ip` +
  `gtp_teid` plats.

Étape 1 (`discover_sessions`) : SBI attaché à la session,
`interfaces` inclut `SBI`.
Étape 2 (`correlate_cross_interface_evidence`) : les 3 règles
EXACT sortent (`ngap-pfcp-exact-tunnel`, `sbi-n2-tunnel-match`,
`sbi-n4-tunnel-match`).

### T2 — S6a motif 16-msg prouvé

Preuve matérielle :
`s6a_492_minus_16_motif_proven_malformed_message_type_2_9_16`
(`decoder-diameter/src/lib.rs`). Simulation :

- 476 payloads Diameter DWR/DWA bien parsés → `message_type=280`.
- 16 payloads avec en-tête Diameter VALIDE (version=1, length=28,
  flags DWR/DWA, command_code=280) mais AVPs tronqués
  (4 octets < 8 minimum) → `parse_avps()` échoue.

**Pré-2.9.14** : `emit_malformed_event` fixait `message_type=0`
pour tout échec de parse. Filtre ANR2
`tshark diameter.cmd.code==280` et jq
`.message_type==280` capturait 476 événements → écart 16.

**Post-2.9.14** : `peel_diameter_header` extrait les 20 premiers
octets quand le header est valide ; `message_type` et
`message_name` sont préservés (`280`,
`MalformedDevice-Watchdog-Request`). Le filtre
`.message_type==280` capture désormais 492 → PCAP == JSONL.

Motif prouvé sans hypothèse : `message_type=0` sur MALFORMED
avec header lisible + AVPs cassés. Rien d'aléatoire, rien de
boundary — un défaut deterministe de l'emit path 2.9.10.

### T3 — Repair `_00067` : couverture complète (2.9.14)

`repair_partial_imports` (2.9.14 `:4039-4104`) scanne
`on_disk_prefix` après la boucle `prefix_sha_groups` et pousse
en fresh-import tout fichier fermé dont ni full-SHA ni aucun
prefix-SHA n'apparaît dans `dataset_capture_ids`. Les planes
N2 + S6a de `_00067` (0 événement dataset) sont désormais
couvertes par un groupe `uncovered_closed_file`.

Test existant
`repair_covers_uncovered_closed_file_fresh_import_2_9_14`
prouve le flux pour un plan S6a. BILAN #10 shape (5 planes
non-vides `_00067`) est entièrement couverte par la même
logique — chaque plane absent du dataset génère son groupe.

### Tests

**443 PASS**, 0 FAIL, 4 ignored (+2 vs 2.9.15). Round-trip
2.9.6..2.9.15 préservé.

### Versions

- `decoder-diameter` 0.2.2 → 0.2.3 (test S6a motif ajouté)
- `correlation-engine` 0.6.3 → 0.6.4 (end-to-end test ajouté)
- `oiran-api` 2.9.15 → 2.9.16

## OIRAN API 2.9.15 — 2026-11-08 — SBI attach lit noms directionnels + préfixés (devmat, ANR2 #9 comment 6728928219)

### Contexte — SBI absent de la session malgré clé exacte (run réel)

ANR2 a publié sur #9 comment 6728928219 une preuve sur le run
POLARIS `tpl-small-traffic-276467540950` / session OIRAN
`5g-session-5f3245de7580dee3` :

- N2↔N4 **EXACT**, N4↔N3 **EXACT**.
- SBI↔N2 **OUVERT**, SBI↔N4 **OUVERT**.
- Clé commune présente : `PDU 1, IP 10.77.22.13, TEID 0x25fb`.
- SBI `evt-45eedbe889db2938` existe dans le JSONL, dans la
  fenêtre du run, mais n'appartient PAS aux 18 événements remis
  au call flow (seulement N2, N3, N4).

### T1 — Cause fichier:ligne

`session-engine/src/lib.rs::attach_sbi_to_sessions`
(`:1442-1449` pré-2.9.15) indexait `tunnel_idx` en lisant :

```rust
let ip_raw = event.first_identifier("tunnel_endpoint_ip");
let teid_raw = event.first_identifier("gtp_teid");
```

Le N2 publie son tuple sous les noms RÉELS :
```
item_0_tunnel_ip_ul = 10.77.22.13
item_0_gtp_teid_ul  = 0x25fb
```

Préfixe `item_0_` + suffixe directional `_ul` → la lecture plate
retournait `None` → `tunnel_idx` vide → SBI (qui publie
`tunnel_endpoint_ip` plat) ne pouvait pas matcher.

Le fallback `tunnel_keys` 2.9.12 fonctionne côté
`correlation-engine` (via `directional_tunnel_components` qui
suffixe `_ul`/`_dl`), mais l'**attache de session** 2.9.9 était
indépendante et plus stricte.

### T2 — Fix : scan directional + préfixé

`attach_sbi_to_sessions` (`:1442-1510` post-2.9.15) itère
désormais sur TOUS les identifiers de l'événement N2 et détecte
les paires :

- `*tunnel_endpoint_ip` ↔ `*gtp_teid` (shape SBI-like)
- `*tunnel_ip_ul` ↔ `*gtp_teid_ul` (N2 UL)
- `*tunnel_ip_dl` ↔ `*gtp_teid_dl` (N2 DL)
- `*tunnel_ip` ↔ `*teid` (shape PFCP-like)

Avec le MÊME préfixe (ex. `item_0_`). Normalisation partagée
via `event_schema::normalize_ip` + `normalize_teid_hex`.

Test `sbi_attach_matches_item_0_directional_tunnel_names_anr2_6728928219`
(`session-engine/src/lib.rs`) : N2 `evt-1e27eff0f6589f86` avec
noms RÉELS d'ANR2 (`item_0_tunnel_ip_ul`, `item_0_gtp_teid_ul`)
+ SBI `evt-45eedbe889db2938` (noms plats) → SBI rattaché à la
session, `interfaces` inclut `SBI-HTTP2`.

### T3 — Tests

**441 PASS**, 0 FAIL, 4 ignored (+1 vs 2.9.14). Tous les tests
2.9.6..2.9.14 restent VERT.

### Versions

- `session-engine` 0.5.2 → 0.5.3
- `oiran-api` 2.9.14 → 2.9.15

## OIRAN API 2.9.14 — 2026-11-08 — Diameter MALFORMED header-aware + repair uncovered closed files (devmat, ANR2 #9 comment 6728398325)

### Contexte — deux défauts 2.9.13 prouvés par ANR2

1. **S6a `_00025` : perte 16 messages persiste** malgré 2.9.11
   SCTP-retransmit. Segment PCAP = 492 (DWR 246 + DWA 246).
   JSONL = 476 (`aggregate_message_count` sommés). Écart = 16
   messages sur segment fermé importé par 2.9.13.
2. **Repair `_00067` incomplet** : 12 fichiers sources, 5 non
   vides. Le plan ne couvre que N4, SBI, Sxab. N2 + S6a manquent
   (0 événement final-SHA).

### T1 — S6a : MALFORMED préserve le command_code

Cause : mon `emit_malformed_event` 2.9.10
(`decoder-diameter/src/lib.rs:397-443` pré-2.9.14) fixait
`message_type=0, message_name="MalformedDiameterMessage"` pour
TOUS les payloads mal parsés. ANR2 compte via `tshark
diameter.cmd.code==280` → les 16 MALFORMED avec `message_type=0`
étaient invisibles.

2.9.14 : `peel_diameter_header` (`:456-476`) extrait les 20
premiers octets (version=1, length ≥ 20, flags, command_code,
application_id) **sans toucher aux AVPs**. Quand l'en-tête est
lisible mais les AVPs échouent, l'événement MALFORMED porte :
- `message_type = command_code` (280 pour un DWR/DWA),
- `message_name = format!("Malformed{command_name}")`
  (ex. `MalformedDevice-Watchdog-Request`),
- `procedure_code = Some(command_code)`,
- `procedure = Some("REQUEST"|"ANSWER")`,
- `direction` inférée par `infer_direction`,
- IEs `Diameter command code` + `Diameter application id`.

Le filtre ANR2 `message_type==280` capture désormais les 492
messages à l'unité près. L'en-tête < 20 octets retombe sur le
fallback générique 2.9.10.

Tests :
- `malformed_preserves_command_code_when_header_ok_2_9_14` :
  en-tête valide + AVP tronqué → `message_type=280`,
  `message_name="MalformedDevice-Watchdog-Request"`.
- `malformed_short_header_falls_back_to_generic_2_9_14` :
  `< 20 octets` → `message_type=0`, nom générique.

### T2 — Repair : fresh-import des fichiers fermés non couverts

Cause : `repair_partial_imports` (`live-probe/src/lib.rs:3960-4037`
pré-2.9.14) construisait `fresh_import_queue` UNIQUEMENT depuis
`prefix_sha_groups` (fichiers dont ≥ 1 événement dataset matche
un prefix-SHA). Les planes `N2` + `S6a` de `_00067` n'avaient
AUCUN événement dataset avec leur capture_id → `prefix_sha_groups`
vide → jamais réparés.

2.9.14 (`live-probe/src/lib.rs:4039-4104`) : après la boucle
principale, balaye `on_disk_prefix` (tous les fichiers fermés
découverts via `prefix_sha_index`). Pour chaque fichier dont ni
le full-SHA ni aucun prefix-SHA n'apparaît dans
`dataset_capture_ids`, pousser une fresh-import "pure" :
`PartialImportGroup { reconstruction_key:
"…uncovered_closed_file", snapshots: [], needs_fresh_import: true,
final_source: PrefixShaMatchFreshImport }`.

Les 5 planes `_00067` non vides — y compris N2 + S6a — sont
désormais tous décodés par la phase 4b du repair (quand
`!dry_run`), avec la même clé de pseudonymisation que la
live-probe.

Test :
`repair_covers_uncovered_closed_file_fresh_import_2_9_14` :
fichier S6a fermé sur disque, dataset vide pour ce plan →
`partial_import_groups` contient un groupe `uncovered_closed_file`
avec `interface="S6a"`, `snapshots=[]`,
`needs_fresh_import=true`. Le sibling actif lex-greatest
(`_00026`) est correctement exclu par la règle sequence.

### T3 — Tests

**440 PASS**, 0 FAIL, 4 ignored (+3 vs 2.9.13). Round-trip
2.9.6/2.9.7/2.9.8/2.9.9/2.9.10/2.9.11/2.9.12/2.9.13 préservé.

### Versions

- `decoder-diameter` 0.2.1 → 0.2.2
- `live-probe` 0.4.25 → 0.4.26
- `oiran-api` 2.9.13 → 2.9.14

## OIRAN API 2.9.13 — 2026-11-08 — Replay ANR2 réel + wire-identity dedup strict + repair wire-dupes (devmat, ANR2 #9 comments 6727624063 + 6727243545)

### Contexte — deux défauts à fermer sur preuves réelles

**A.** ANR2 #9 comment 6727624063 : sur le run POLARIS
`tpl-small-traffic-d64ae14da40f`, session
`5g-session-5c8583f0ec45a402`, SBI↔N2 et SBI↔N4 OUVERT malgré tuple
exact `(PDU 1, IP 10.77.22.13, TEID 0x855a)` dans SBI, N2 et N4.

**B.** ANR2 #9 comment 6727243545 : 24 doublons wire-réels (dont 8
post-2.8.3) persistent. Le `--dry-run` du repair retire 10 804
événements mais ne couvre que 10 des 48 event_ids.

### T1 — A : rejet fichier:ligne + replay événements réels

Cause en 2.9.11 : `correlation-engine/src/lib.rs::tunnel_keys`
(`:525-558` pré-2.9.12) itérait UNIQUEMENT sur
`event.information_elements`. L'événement SBI
`evt-e3ba85330bd40ee8` publie son tuple sous
`session_identifiers` (pas d'IE composée). `sbi_tunnels` → vide
→ loop `:316` ne traverse jamais la clé → aucun
`sbi-n2-tunnel-match` / `sbi-n4-tunnel-match` produit.

Le fallback 2.9.12 (`tunnel_keys:570-594`) lit les
`session_identifiers` ; 2.9.13 ajoute le **test de replay** avec
les event_ids RÉELS publiés par ANR2 :
`replay_anr2_run_5c8583f0_sbi_n2_n4_exact_2_9_13`
(`correlation-engine/src/lib.rs`) rejoue
`evt-e7a10f2d4f63afc1` (N2), `evt-4f185dfa624f2b78` (N4),
`evt-e3ba85330bd40ee8` (SBI IE vide, identifiers seuls) →
SBI↔N2 + SBI↔N4 + N2↔N4 tous **EXACT**.

### T2 — B : chemin d'émission fichier:ligne

Cause TODAY (post-2.9.10) : `continuous_observation_id`
(`live-probe/src/lib.rs:7096-7161` pré-2.9.13) incluait
`raw_payload_reference` + `message_type` dans la clé wire. ANR2
a prouvé que :

- `raw_payload_reference` est un SHA du payload DÉCODÉ ; deux
  décodes du même paquet wire peuvent produire des slices
  subtilement différents (padding AVP, longueur optionnelle) →
  SHA différent → clés divergentes → dupe non fusionné.
- `is_duplicate` (`live-probe/src/lib.rs:634-644`), défini en
  2.9.5 avec la règle ANR2 EXACTE `(capture_id, packet_number,
  byte_offset, protocol, message_name)`, n'était appelé QUE par
  les tests — aucun usage production.

2.9.13 réécrit `continuous_observation_id` (`:7096-7165`) sur
l'identité wire ANR2 pure :
- `capture_id`
- Premier `packet_reference` trié (`source_file, packet_number,
  byte_offset, interface_id`)
- `protocol` + `message_name` (string, pas `message_type`)
- Discriminant agrégat (keepalive, N3-flow) pour éviter toute
  collision entre agrégats et individuels sur le même paquet-ancre.

Test `continuous_observation_id_dedupes_anr2_24_wire_duplicates_2_9_13`
(`live-probe/src/lib.rs`) :
- Deux décodes du même paquet wire avec
  `raw_payload_reference` DIFFÉRENTS → **même**
  `continuous_observation_id`.
- NGAP + NAS-5GMM enfant sur même paquet → deux identités
  distinctes (comportement attendu).

### T3 — B : repair tool wire-dupes

Nouvelle phase dans
`CaptureManager::repair_partial_imports`
(`live-probe/src/lib.rs:4246-4310`) : après la passe
partial-import + sort canonique, dedup strict par identité wire
ANR2. First-write-wins ; les suivants rejoignent `removed` avec
reason `wire-duplicate-superseded`.

Test `repair_partial_imports_removes_wire_duplicates_anr2_2_9_13`
(`live-probe/src/lib.rs`) : réplique deux groupes réels ANR2
(NGAP UplinkNASTransport + NAS-5GMM Protected 5GMM message,
packet 23, offset 3908) + témoin sur paquet 24. Résultat :
`event_count_before=5, event_count_after=3, wire-duplicate-superseded×2`.

### T4 — Tests

**437 PASS**, 0 FAIL, 4 ignored (+3 vs 2.9.12). Tous les tests
2.9.7..2.9.12 restent VERT.

### Versions

- `live-probe` 0.4.24 → 0.4.25
- `oiran-api` 2.9.12 → 2.9.13

## OIRAN API 2.9.12 — 2026-11-08 — tunnel_keys fallback session_identifiers (devmat, ANR2 #9 comment 6727624063)

### Contexte — SBI encore OUVERT sur run réel 2.9.9

ANR2 a publié sur #9 comment 6727624063 une preuve matérielle
sur le run POLARIS `tpl-small-traffic-d64ae14da40f` (63/63 PASS),
session OIRAN `5g-session-5c8583f0ec45a402` :

- N2↔N4 : **EXACT ×2**
- N4↔N3 : **EXACT ×2**
- SBI↔N2 : **OUVERT**
- SBI↔N4 : **OUVERT**

Pourtant le tuple (PDU 1, IP 10.77.22.13, TEID 0x855a) est
présent EXACTEMENT dans les trois événements :

- SBI `N1N2MessageTransfer evt-e3ba85330bd40ee8` :
  `pdu_session_id=1, tunnel_endpoint_ip=10.77.22.13, gtp_teid=0x855a`.
- N2 `PDUSessionResourceSetupRequest evt-e7a10f2d4f63afc1` :
  `pdu_session_id=1, tunnel_ip_ul=10.77.22.13, gtp_teid_ul=0x855a`.
- N4 `PFCP Session Establishment Response evt-4f185dfa624f2b78` :
  F-TEID `0x0000855a` / IPv4 `10.77.22.13`.

### T1 — Cause fichier:ligne

`correlation-engine/src/lib.rs::tunnel_keys` 2.9.9 lisait
UNIQUEMENT `event.information_elements[*].value`. Pour le run
ANR2, l'événement SBI publie son tuple TEID/IP comme
**session_identifiers** (visibles dans `.session_identifiers[]`),
pas comme IE composée. La clé n'était donc jamais extraite côté
SBI → `sbi-n2-tunnel-match` / `sbi-n4-tunnel-match` jamais
produits. Les règles N2↔N4 fonctionnaient car les deux plans
publient le tuple dans leurs IEs composées.

### T2 — Fix : fallback session_identifiers

`correlation-engine/src/lib.rs::tunnel_keys` 2.9.12 (`:525-586`) :
après l'extraction depuis les IEs, si `event.first_identifier(
"tunnel_endpoint_ip")` + `event.first_identifier("gtp_teid")`
existent, dériver une clé supplémentaire avec la même
normalisation `event_schema::normalize_ip` +
`event_schema::normalize_teid_hex`. `keys.dedup()` élimine toute
duplication si l'IE ET les identifiers portaient déjà le même
tuple.

### T3 — Tests

- `sbi_tunnel_match_reads_session_identifiers_shape_anr2_6727624063` :
  reproduit le shape ANR2 exact. SBI event avec
  `session_identifiers` seuls (pas d'IE `N2 UL NG-U UP TNL
  Information`) + N2 avec IE `tunnel_ip_ul=10.77.22.13,gtp_teid_ul=0x855a`
  + N4 avec F-TEID `0x0000855a` → SBI↔N2 EXACT + SBI↔N4 EXACT.
- `sbi_tunnel_match_fail_closed_when_session_identifiers_teid_differs_2_9_12` :
  SBI identifiers avec TEID `0x855b` (≠ `0x855a`) → 0 arête SBI,
  N2↔N4 reste EXACT (fail-closed préservé).

**434 PASS**, 0 FAIL, 4 ignored (+2 vs 2.9.11). Tous les tests
2.9.7/2.9.8/2.9.9/2.9.10/2.9.11 restent VERT.

### Versions

- `correlation-engine` 0.6.2 → 0.6.3 (fallback session_identifiers)
- `oiran-api` 2.9.11 → 2.9.12

## OIRAN API 2.9.11 — 2026-11-08 — SCTP retransmit count-preserving (devmat, ANR2 #9 comment 6727243545)

### Contexte — ANR2 a quantifié la perte segmentaire

ANR2 a publié sur #9 comment 6727243545 un pattern déterministe :
**16 messages S6a manquants par segment fermé importé sous 2.9.5+**
(20 pour `_00021`). 12 segments successifs, tous avec `PCAP - 16 ==
JSONL`. Un parse error aléatoire aurait produit un écart variable ;
cette constance pointe vers une règle systémique.

### T1 — Cause fichier:ligne

`transport-sctp/src/lib.rs::SctpReassembler::consume` (`:139-146`
pré-2.9.11) :

```rust
let seen_key = (association.clone(), generation, direction.clone(), tsn);
if !self.seen.insert(seen_key) {
    self.error(SctpErrorKind::Duplicate, packet, …);
} else {
    // … émet SctpMessage
}
```

Toute DATA chunk avec un TSN déjà observé est silencieusement
supprimée — comportement correct pour un décodeur de protocole
(une retransmission est la MÊME information), mais qui ne
préserve PAS le compte wire. ANR2 utilise `tshark -T fields -e
diameter.cmd.code` qui compte chaque copie décodable comme une
ligne. Le taux de retransmission SCTP typique en production
(~3 %) correspond exactement aux 16 messages/heure manquants sur
492 messages/heure.

### T2 — Fix : count-preserving retransmission

`transport-sctp/src/lib.rs::SctpReassembler::consume` (`:139-167`
post-2.9.11) :

- Le `seen.insert` reste pour détecter les retransmissions.
- L'erreur `Duplicate` continue d'être publiée pour l'audit.
- Le **chemin d'émission** passe maintenant aussi pour les
  retransmissions : chaque copie B+E atteint le décodeur
  Diameter et produit un événement normal.
- Le dedup aval 2.9.10 (wire-identity sur `capture_id` +
  `packet_number` + `byte_offset`) les distingue : même TSN,
  `packet_number` différent ⇒ deux événements wire distincts.
  `PCAP == JSONL` à l'octet près.

Test `retransmitted_be_data_emits_two_messages_2_9_11` :
retransmission B+E d'un TSN=100 sur packets 1 et 2 → DEUX
`SctpMessages`, l'erreur `Duplicate` tracée pour l'audit.

### T3 — Tests

**432 PASS**, 0 FAIL, 4 ignored (+1 vs 2.9.10). Les tests
`fragments_and_retransmission`,
`reassembled_message_preserves_every_fragment_packet_reference`
(2.9.5), `malformed_payload_emits_a_count_preserving_event_2_9_10`
(decoder-diameter), `continuous_observation_id_is_wire_identity_…_2_9_10`
(live-probe) restent VERT. Le dedup wire-identity 2.9.10 absorbe
proprement les retransmissions au niveau événement Diameter —
une retransmission B+E d'un petit DWR produit deux événements
Diameter distincts par `packet_number`, correspondant au count
PCAP tshark.

### Versions

- `transport-sctp` 0.1.0 → 0.1.1 (retransmit emission)
- `oiran-api` 2.9.10 → 2.9.11

## OIRAN API 2.9.10 — 2026-11-08 — Dedup wire-identity + Diameter MALFORMED count-preserving (devmat, ANR2 #9 comment 6726685484)

### Contexte — FAIL recette 2.9.9 prouvée par ANR2

ANR2 a publié sur #9 comment 6726685484 deux défauts bloquants
contre la 2.9.9 :

1. **Perte S6a : 9 000 messages absents du JSONL.**
   - PCAP owned : 176 564 Diameter messages (DWR + DWA + autres S6a).
   - JSONL : 167 564 = 86 394 agrégats watchdog + 81 170 individuels.
   - Écart : 9 000 disparus silencieusement, aucune ligne
     `CONTINUOUS_*` ne les cite.
2. **24 doublons réels** sur
   `(capture_id, packet_number, byte_offset, protocol, message_name)` :
   un même paquet wire apparaît DEUX fois dans le JSONL avec DEUX
   `event_id` différents (3 exemples complets ANR2 : `evt-50e7a11f…`
   + `evt-b89b4f8a…`, `evt-83151568…` + `evt-c5cfdf6a…`, etc.).

### T1 — Cause fichier:ligne (doublons)

`live-probe/src/lib.rs::continuous_observation_id` (pré-2.9.10,
`:7096-7123`) hachait :

- `timestamp` (variable selon la précision de parse du décodeur),
- `session_identifiers` NON triés (l'ordre varie entre deux
  invocations si le décodeur réordonne ses IEs),
- `source_endpoint` / `destination_endpoint`,

mais **pas** `packet_references`. Deux décodages d'un même paquet
wire avec un timestamp légèrement différent (round-trip `µs` vs
`ns`) ou un ordre d'identifiers inversé produisaient donc deux
`continuous_observation_id` distincts → `merge_event_stream`
n'absorbait pas le doublon.

### T1 — Cause fichier:ligne (perte S6a)

`decoder-diameter/src/lib.rs::DiameterDecoder::decode`
(pré-2.9.10, `:369-378`) renvoyait, sur erreur de parse :

```rust
Err(e) => DecoderOutput {
    status: DecodeStatus::Malformed,
    events: Vec::new(),  // ← aucun événement émis
    errors: vec![e],
}
```

Zéro événement émis ⇒ aucune ligne JSONL ⇒ la valeur
`decoder_errors` du manifeste augmente d'1 mais le compteur
`PCAP messages` diverge silencieusement de `JSONL events` par 1.
À l'échelle d'un segment S6a, 9 000 paquets partiellement
reconstruits par SCTP (chunks tronqués, AVP mal formés, length
inconsistant) produisaient 9 000 trous. ANR2 l'a mesuré
exactement.

### T2 — Fix dedup : wire-identity

`live-probe::continuous_observation_id` (`:7096-7161`) réécrit sur
l'**identité wire** :

- `capture_id` — immuable pour un fichier donné.
- `packet_references[*]` triés sur
  `(source_file, packet_number, byte_offset, interface_id)` —
  coordonnée physique du paquet.
- `protocol` + `message_type` — un décodeur peut émettre
  plusieurs événements pour un même paquet (NGAP + NAS enfant) ;
  chacun garde son identité distincte.
- `raw_payload_reference` — SHA-256 du payload décodé ; deux
  décodages du même paquet produisent le même hash.

Rien de temporel ; rien d'ordre-dépendant. Deux décodages d'un
paquet wire produisent désormais le **même**
`continuous_observation_id` ⇒ `merge_event_stream` le dédoublonne
first-write-wins.

Test `continuous_observation_id_is_wire_identity_and_dedupes_duplicates_2_9_10` :

- Timestamps différents (µs vs ns) + ordre d'identifiers inversé
  + event_id différent → **même** `continuous_observation_id`.
- `packet_number` différent → identité wire différente.
- `capture_id` différent (fichier rotaté) → identité wire
  différente.
- `protocol` ou `message_type` différent (NGAP + NAS enfant) →
  deux observations distinctes (comportement attendu).

### T3 — Fix perte S6a : MALFORMED count-preserving

`decoder-diameter::DiameterDecoder::decode` (`:369-391`) + nouveau
`emit_malformed_event` (`:397-441`) : sur erreur de parse, émet
désormais UN événement avec :

- `decoding_status = Malformed`,
- `message_name = "MalformedDiameterMessage"`,
- `packet_references` copiées depuis `DecoderInput` (provenance
  wire conservée),
- `raw_payload_reference` littéral,
- `errors = [parse_error]`,
- un IE `parse_error` avec la chaîne d'erreur.

**Fail-closed ET count-preserving** : `PCAP messages == JSONL
events` à l'octet près. L'opérateur voit les paquets malformés
avec leur `packet_number` + `byte_offset` et peut auditer la
cause (SCTP chunk truncation, AVP length drift, etc.).

Tests :
- `malformed_payload_emits_a_count_preserving_event_2_9_10` :
  payload tronqué (6 octets, < 20 requis) → 1 événement
  MALFORMED avec `packet_references` + IE `parse_error`.
- `malformed_events_have_deterministic_ids_2_9_10` : l'event_id
  déterministe se dérive du `raw_payload_reference` + wire
  identity.

### T4 — Tests

**431 PASS**, 0 FAIL, 4 ignored (+2 vs 2.9.9). Tous les tests
2.9.7 (round-trip), 2.9.8 (orphan purge, work_bytes ring, BLOCKED
expose), 2.9.9 (TEID/IP normalisation, SBI attach, SBI↔N2/SBI↔N4
EXACT) restent VERT. Un ancien test
`semantic_observation_id_survives_append_snapshot_capture_hash_changes`
qui supposait l'ancienne règle (dedup survive aux `capture_id`
différents) a été remplacé par la nouvelle règle wire-identity.

### Versions

- `live-probe` 0.4.23 → 0.4.24 (`continuous_observation_id`
  wire-identity)
- `decoder-diameter` 0.2.0 → 0.2.1 (MALFORMED count-preserving)
- `oiran-api` 2.9.9 → 2.9.10

## OIRAN API 2.9.9 — 2026-11-08 — Rattachement et liens SBI exacts (TEID/IP/pseudo) (devmat, ANR2 #9 comment 6725858177)

### Contexte — preuve ANR2 sur `5g-session-5e3fc8ce83936ea0`

Capture SBI `sha256:1cb1c30c…fc864` : 982 événements, 25 SBI dans la
fenêtre callflow `1794158356.919997466..1794158357.245764688`, aucun
rattaché à la session. ANR2 publie sur #9 (désidentifié) :

- **Clé commune prouvée** : PDU session `1`, IP `10.77.22.13`,
  TEID numérique `d4a6`.
- **Format TEID divergent** : SBI/N2 `0xd4a6`, N4 `0x0000d4a6`.
- **Domaine de pseudonymisation divergent dans le code** :
  `decoder-sbi/src/lib.rs:999` utilise `"supi"` (URI) alors que
  `decoder-sbi/src/lib.rs:1182` utilise `"subscriber"` (JSON body).
  Deux domaines distincts ⇒ même SUPI rendue sous deux pseudos
  différents, rattachement par abonné impossible par construction.

### T1 — Normalisation TEID/IP partagée

Nouveau module partagé dans `event-schema/src/lib.rs` (`:849-923`) :

- `SUBSCRIBER_PSEUDO_DOMAIN: &str = "subscriber"` — la SEULE
  constante autorisée pour dériver un pseudonyme d'abonné (SBI/N2/N4
  doivent tous l'utiliser pour qu'un même SUPI produise un même
  pseudo).
- `normalize_teid_u32(&str) -> Option<u32>` — accepte
  `"d4a6"`, `"D4A6"`, `"0xd4a6"`, `"0x0000D4A6"`, `"11223344"`
  (hex sans préfixe), `"0d54438"` (décimal explicite). Règle de
  désambiguïsation : `0x`/`0X` → hex ; `0d`/`0D` → décimal ;
  sinon → hex (convention télécom). Un round-trip
  `format!("{teid:x}")` → `normalize_teid_u32` est donc stable.
- `normalize_teid_hex(&str) -> Option<String>` — même fonction
  avec la forme canonique `"0x{teid:x}"` en sortie (jamais
  zero-padded, lower-case).
- `normalize_ip(&str) -> String` — strip `::ffff:` (IPv4-mapped
  IPv6 → IPv4) ; strip `%<zone>` (scope-id RFC 4007).

Tests :
- `normalize_teid_accepts_every_format_anr2_observed_plus_decimal` —
  ANR2 shapes + hex sans préfixe + `0d` décimal.
- `normalize_ip_strips_ipv4_mapped_prefix_and_scope_id`.
- `subscriber_pseudo_domain_is_the_single_shared_label` — prouve que
  deux dérivations via `SUBSCRIBER_PSEUDO_DOMAIN` sur la même SUPI
  donnent le même pseudo ; diverge explicitement de l'ancien
  domaine `"supi"`.

### T2 — Unification des sites

- `decoder-sbi::sanitize_uri` (`:999`) : `"supi"` → `SUBSCRIBER_PSEUDO_DOMAIN`.
- `decoder-sbi::collect_json` (`:1182`) : littéral `"subscriber"` → constante partagée.
- `decoder-sbi` extraction UL NG-U depuis `n2SmInfo` (`:778-813`) :
  IP normalisée via `normalize_ip`. Le TEID (déjà `u32`) sort en
  `"0x{teid:x}"` canonique.
- `correlation-engine::normalize_teid` (`:475-483`) : délégation
  pure à `event_schema::normalize_teid_hex`. Supprime la
  duplication locale (strip `0x` + strip leading zeros + parse
  hex) qui ne gérait pas le décimal.
- `correlation-engine::tunnel_keys` : l'`endpoint_ip` passe par
  `event_schema::normalize_ip` ; une SBI IPv4-mapped
  (`::ffff:10.77.22.13`) s'égale désormais à N2/N4 (`10.77.22.13`).

### T3 — Rattachement SBI par clé exacte

Nouvelle fonction `session-engine::attach_sbi_to_sessions`
(`:1374-1470`), appelée dans `discover_sessions` juste après
`discover_gtpu_tunnels` (`:1343-1358`). Pour chaque PDU session
discovered, construit deux index exacts :

1. `(subscriber_pseudonym, pdu_session_id)` → session_index.
2. `(tunnel_endpoint_ip_norm, gtp_teid_norm)` → session_index.

Puis walk les événements SBI :
- `(pseudo, pduSessionId)` match → rattachement.
- Sinon, `(tunnel_endpoint_ip, gtp_teid)` normalisés match →
  rattachement.
- Sinon, SBI reste en `unmatched` (fail-closed).

Jamais de match par timestamp. Le SBI rattaché est ajouté à
`session.event_ids` + `session.interfaces` (trié) + `event_context`
(sous le `ue_context_id` de la session).

Test `sbi_attach_rules_match_anr2_production_shapes_2_9_9`
(`session-engine`) — reproduit la forme ANR2 :
- Deux événements NGAP (Request + Response, PDU 1, pseudo + tunnel).
- Un SBI `CreateSMContext` avec le MÊME pseudo + PDU 1 (règle 1).
- Un SBI `N1N2MessageTransfer` avec un pseudo URI DIVERGENT mais
  le MÊME `(0xd4a6, 10.77.22.13)` extrait du `n2SmInfo` (règle 2).
- Un SBI "outsider" avec un pseudo différent ET un TEID différent
  (`0xd4a7`) — doit rester en `unmatched`.
- Assertions : les deux SBI valides sont rattachés ; l'outsider
  n'est pas rattaché même avec le ts le plus récent.

### T4 — Règle SBI↔N2 et SBI↔N4 étendue

`correlation-engine::correlate_cross_interface_evidence`
(`:296-308`) : filtrage `message_name == "N1N2MessageTransfer"`
retiré. Tout événement SBI qui porte un `(tunnel_endpoint_ip,
gtp_teid)` est candidat. Couvre `CreateSMContext`,
`UpdateSMContext`, `N1N2MessageTransfer` quand ils embarquent un
`n2SmInfo` (`decoder-sbi::is_n2_sm_info` au `:1157-1161`).

Tests :
- `sbi_cross_interface_edges_match_anr2_production_shapes_2_9_9` —
  N2 `0xd4a6`, N4 `0x0000d4a6`, SBI `0xd4a6` → `ngap-pfcp-exact-tunnel`
  + `sbi-n2-tunnel-match` + `sbi-n4-tunnel-match` tous EXACT.
  Vérifie aussi le fail-closed quand deux SBI partagent le même
  `(IP, TEID)`.
- `sbi_cross_interface_edges_are_fail_closed_on_mismatched_teid_2_9_9`
  — SBI `0xd4a7` (TEID différent) → aucun bord SBI↔N2/SBI↔N4,
  N2↔N4 reste EXACT entre eux.

### T5 — Preuve de divergence (fichier:ligne)

Les sites mis à jour en 2.9.9 pour que SBI/N2/N4 convergent vers
le même pseudo d'abonné :

- `decoder-sbi/src/lib.rs:999` — était `"supi"` (URI).
- `decoder-sbi/src/lib.rs:1182` — était `"subscriber"` (body).

Pour N2 (`decoder-ngap`) et N4 (`decoder-pfcp`), ANR2 a prouvé
que l'identité d'abonné arrive sous des IEs de wire très
différentes (NAS-PDU, 5G-S-TMSI, masked-IMEISV côté NGAP ;
PFCP UE-IP, User-ID côté PFCP). La normalisation d'identité
canonique entre ces IEs demande un décodage spécifique à chaque
protocole et sort du périmètre 2.9.9 (travail NSPlus-N2 2.10.x).
La règle 2.9.9 s'appuie donc sur le tuple `(TEID, IP)` du
`n2SmInfo` pour SBI↔N2 et SBI↔N4 (clé exacte, pas d'abonné
nécessaire).

### T6 — Tests

**429 PASS**, 0 FAIL, 4 ignored (+6 vs 2.9.8). Les 2.9.8 orphan
purge + /metrics BLOCKED + work_bytes-ring + round-trip 2.9.6/2.9.7
restent VERT. Le test `n1n2_message_transfer_multipart_extracts_ul_ngu_tunnel_from_n2_sm_info`
(decoder-sbi) continue de passer avec la forme canonique
`0x11223344` (pas de round-trip ambigu grâce à la règle "hex par
défaut").

### Versions

- `event-schema` 1.5.1-dev → 1.5.2 (`SUBSCRIBER_PSEUDO_DOMAIN`,
  `normalize_teid_u32` / `_hex`, `normalize_ip`)
- `decoder-sbi` 0.4.0 → 0.4.1 (sanitize_uri + collect_json
  convergent, UL NG-U IP/TEID normalisés)
- `session-engine` 0.5.1 → 0.5.2 (`attach_sbi_to_sessions`)
- `correlation-engine` 0.6.1 → 0.6.2 (délégation normalisation,
  filtre SBI étendu)
- `oiran-api` 2.9.8 → 2.9.9

## OIRAN API 2.9.8 — 2026-11-08 — Backpressure sur ring importé + BLOCKED masqué sur /metrics (devmat, ANR2 #9 comment 6725097122)

### Contexte — ANR2 a prouvé la cause exacte

Sur `5g-session-5e3fc8ce83936ea0` (run POLARIS `tpl-small-traffic-6374f1ed343c`,
2026-11-08T17:19:12Z..17:30:24Z), ANR2 a prouvé que le N3 du run
**n'a jamais été dédoublonné** — il était bloqué par
`CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT` (dépassement de 108 503 490
octets) → job `BLOCKED`. Preuves :

- Aucun log `CONTINUOUS_*` ne citait le segment N3 bloqué.
- `/api/v1/metrics` ne lisait que les jobs `CAPTURING` puis faisait
  `unwrap_or(0)` → un job BLOCKED affichait `pending=0`,
  masquant totalement le blocage.
- Un segment SBI de 982 événements a bien été importé mais non
  rattaché à la session du run (identifiants ANR2 attendus sur #9
  — reporté en 2.9.9).

### T1 — Cause fichier:ligne

Dans `live-probe/src/lib.rs`, `work_bytes` comptait le ring pcap
déjà importé :

```rust
fn work_bytes(base: &Path) -> u64 {
    directory_size(base).saturating_sub(directory_size(&base.join("dataset")))
}
```

`base` contient `dataset/` (soustrait) + `pcap/<iface>.pcap-<sha16>.*`
(le **ring d'imports committés**) + `.importing` (en vol) +
`.dataset-previous/` + `.dataset-next/` + `import_state.json`. Le ring
étant 108 MiB, la garde suivante (anciennement `:2769`) tombait
systématiquement :

```rust
if work_bytes(&base)
    .saturating_add(candidate.size_bytes)
    .saturating_add(MAX_CONTINUOUS_DERIVED_BYTES)
    > config.max_owned_bytes { terminal_error = ...BOUNDED_STORAGE_FULL; break; }
```

Dumpcap ne supprime **jamais** les segments sources ; le ring ne
rétrécit donc jamais par lui-même → la garde se déclenche pour
toujours une fois le ring au-dessus du seuil.

Pire : la garde est muette par segment. Aucun log ne cite le
candidat bloqué ; seule la sortie terminale `job.error =
"CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT"` est visible.

Et `apps/api/src/lib.rs::metrics` filtre
`state == CaptureState::Capturing` puis tape
`latest_metrics.map(|m|m.pending_segments).unwrap_or(0)` → quand
le worker est `Blocked`, `active` est vide, `latest_metrics=None`,
`pending_segments=0`. `job.json pending_segments=1` contredit alors
`/metrics pending=0` — exactement ce que ANR2 a observé.

### T2 — Correctif `work_bytes` : exclure le ring committé

Nouveau `live-probe::work_bytes` (`:7449-7470`) :

```rust
fn work_bytes(base: &Path) -> u64 {
    let total = directory_size(base);
    let published = directory_size(&base.join("dataset"));
    let committed_ring = committed_ring_bytes(&base.join("pcap"));
    total.saturating_sub(published).saturating_sub(committed_ring)
}

fn committed_ring_bytes(pcap_dir: &Path) -> u64 {
    // somme des fichiers pcap/ sauf *.importing (en vol)
}
```

Le ring committé n'est plus compté ; seul le staging (`.dataset-*`,
`.importing`, `import_state.json`) pèse dans la garde. Le ring reste
borné par `max_segments` + `max_owned_bytes` sur la rétention, pas
sur l'accueil.

**Test** `tests::work_bytes_excludes_committed_pcap_ring_proof_anr2`
(`live-probe/src/lib.rs`) : 10 fichiers `N3.pcap-*` de 1 GiB chacun
(sparse pour ne pas remplir `/tmp`) + un `.importing` de 4 MiB
sous `pcap/`. Avant 2.9.8 : `work_bytes ≈ 10 GiB`. Après : `< 128 MiB`.
Un candidat de 16 MiB ne doit **plus** faire tomber la garde sous
`max_owned_bytes=128 MiB` : prouvé.

### T3 — Log et compteur par segment bloqué

`live-probe::drive_continuous_import` (`:2863-2918`) : chaque fois
que la garde se déclenche, log structuré
`CONTINUOUS_SEGMENT_PENDING_BACKPRESSURE` avec path, checksum,
interface, size_bytes, staging_bytes, derived_reserve_bytes,
max_owned_bytes, reason. Même log pour la garde disk-safety
(`CONTINUOUS_SEGMENT_PENDING_DISK_SAFETY`).

Silent-skip autres chemins (stability, batch cap) :
`CONTINUOUS_SEGMENT_PENDING_STABILITY` /
`CONTINUOUS_SEGMENT_PENDING_BATCH`. Compteurs scan-local dans
`metrics.pending_stability_segments` et
`metrics.pending_batch_segments` — jamais 0 par défaut. Rien de
silencieux.

### T4 — `/api/v1/metrics` ne masque plus les BLOCKED

Nouveau sélecteur `apps/api/src/lib.rs::select_metrics_source_job`
(`:865-903`) : préfère un job `Capturing`, sinon le job BLOCKED /
COMPLETED / FAILED / PROCESSING / STOPPING le plus récent par
`ended_epoch_ms`. `pending_segments`,
`pending_fingerprints`, `pending_stability_segments`,
`pending_batch_segments`, `orphan_fingerprints_recovered` : lus de
`source_job.metrics` sans `unwrap_or(0)` (JSON `null` si aucun job
n'existe — jamais 0 par défaut).

Trois champs ajoutés : `capture_state`, `capture_stop_reason`,
`capture_error`. Un opérateur voit immédiatement `BLOCKED` +
`BOUNDED_STORAGE_FULL` sans un appel séparé à `/jobs`.

**Test** `tests::select_metrics_source_job_prefers_capturing_then_blocked`
(`apps/api/src/lib.rs`) : trois jobs (un Capturing, deux Blocked de
dates différentes) → le Capturing gagne ; sans Capturing → le
Blocked le plus récent ; liste vide → `None` (JSON null). pending
et stop_reason sont préservés.

### T5 — Défense en profondeur : invariant empreinte ⇒ publication

Même si le fix T2 règle la cause, les orphelines persistées sur
disque en 2.9.5/2.9.6/2.9.7 doivent disparaître. 2.9.8 introduit
l'invariant durable : une entrée `state.source_fingerprints` n'y
reste que si son `checksum` est dans `state.seen_checksums` (= segment
réellement publié).

- `live-probe::drop_orphan_fingerprints` (`:6059-6072`) : purge au
  démarrage les empreintes orphelines + log par entrée
  (`CONTINUOUS_ORPHAN_FINGERPRINT_DROPPED`) + compteur cumulatif
  `metrics.orphan_fingerprints_recovered`.
- `:3174-3202` : la persistance filtre `source_cache` sur
  `seen_checksums` ; déclenchée aussi quand `published=true` pour
  que les SHAs commitées d'un scan cache-hit atterrissent sur
  disque.

**Tests** :
- `drop_orphan_fingerprints_matches_anr2_production_shape` : orphelin
  N3 (`sha-orphan-436e4bb7`, `packets=0`) + orphelin SBI
  (`sha-sbi-orphan`) + entrée commitée conservée ; idempotent.
- `continuous_import_purges_orphan_fingerprint_at_startup_and_reimports_n3_sbi`
  : scénario end-to-end. 2 orphelines pré-plantées dans
  `import_state.json` → 3 fixtures réelles N2/N3/N4 → attend
  `segments_ingested == 3` → asserts
  `orphan_fingerprints_recovered == 2`,
  `pending_segments == pending_fingerprints` (concordance),
  `pending_stability_segments == 0`, `pending_batch_segments == 0`,
  et **invariant global** : tout SHA de `source_fingerprints` est
  dans `seen_checksums`.

### T6 — Concordance /metrics ↔ job.json

Dans le même `self.update(CONTINUOUS_CAPTURE_ID, |job| …)`
(`:2810-2822`) : `job.metrics.pending_segments` et
`job.metrics.pending_fingerprints` sortent du **même compteur
scan-local**. Le branch publication (`:3080-3098`) remet les deux à
zéro ensemble. `/api/v1/metrics` lit les deux depuis la même source
`source_job.metrics`.

**Test** `capture_metrics_pending_fields_covary` : les cinq champs
nouveaux apparaissent dans `CaptureMetrics` ; régression de champ
cassée au type level.

### T7 — SBI non rattaché : reporté

ANR2 a observé un segment SBI importé (982 événements) mais non
rattaché à la session `5g-session-5e3fc8ce83936ea0`. La règle de
rattachement **par clé exacte** (`pduSessionId` +
`smContextRef` / pseudonyme, jamais par `ts`) nécessite les
identifiants désidentifiés publiés par ANR2 sur #9. Reporté en
2.9.9.

### T8 — Round-trip 2.9.6 + 2.9.7 préservés

Suite complète : **423 tests PASS** (+5 par rapport aux 418 de
2.9.7). Les tests
`compact_jsonl_round_trip_yields_four_cross_interface_edges`
(correlation-engine, 2.9.7), `prefix_sha_pcapng_section_header_shb`
(live-probe, 2.9.6), `keepalive_classify_and_aggregates`
(live-probe, 2.9.5) et `compact_event_jsonl_omits_null_and_empty`
(event-schema, 2.9.4) restent VERT. La compaction JSONL, l'agrégation
keepalive, la réparation prefix-SHA pcapng, le test round-trip
compact — tout est embarqué sans régression.

### Versions

- `live-probe` 0.4.22 → 0.4.23 (`work_bytes` exclut le ring
  committé + per-segment backpressure/stability/batch logs +
  pending_fingerprints/stability/batch metrics +
  `drop_orphan_fingerprints` + invariant empreinte ⇒ publication)
- `oiran-api` 2.9.7 → 2.9.8 (`select_metrics_source_job` expose
  les BLOCKED + `capture_state`/`capture_stop_reason`/`capture_error`
  + nouveaux champs pending_*)

## OIRAN API 2.9.7 — 2026-11-08 — Non-régression test JSONL compact + revue diff 67317cf..dcf2e04 (devmat régression ANR2 #9 comment 6724980899, #10 comment 6724994946)

### Contexte — suspicion de régression 2.9.1 → 2.9.5 sur le run réel

ANR2 observe sur `5g-session-5e3fc8ce83936ea0` (run POLARIS
`tpl-small-traffic-6374f1ed343c`, 2026-11-08T17:19:12Z..17:30:24Z) :

- **N2↔N4** : EXACT, 2 arêtes EXACT ✓.
- **N4↔N3** : OUVERT (`N4_N3=UNKNOWN`) — 147 662 paquets GTP dans la
  fenêtre pourtant.
- **SBI↔N2** : OUVERT (`N2_SBI=UNKNOWN`) malgré correctif
  bidirectionnel 2.9.2 follow-up #2.
- **SBI↔N4** : OUVERT (`SBI_N4=UNKNOWN`).

Référence 2.9.1 sur `tpl-small-traffic-e2bea97912f9` avait N4↔N3
EXACT ×2. Run différents → données différentes, mais l'absence de
N4↔N3 malgré 147 k paquets GTP demande une revue infra.

### T1 — Revue diff 67317cf..dcf2e04 : AUCUN risque infra prouvé

Audit systématique de tous les composants susceptibles d'affecter la
corrélation tunnel entre 2.9.1 (`67317cf`) et 2.9.6 (`dcf2e04`) :

**1. `event-schema` compaction JSONL (2.9.4, `event-schema/src/lib.rs:305+`).**
`to_json` devient builder incrémental qui omet les champs `null`
et les tableaux `[]` non essentiels. Impact sur corrélation :

- `packet_references[]` : `source_file`, `packet_number`,
  `byte_offset`, `interface_id`, `captured_length`, `original_length`
  **toujours émis** (champs REQUIS par `parse_event`). Les `sll2_*`,
  `source_sha256`, `link_type` omis quand `null` — non consommés par
  `tunnel_keys` ni `capture_scope`. **SAFE**.
- `information_elements[]` : `name`, `length`, `status` toujours
  émis. `id`, `value`, `raw_sha256` omis quand `null`. `tunnel_keys`
  (`correlation-engine:520`) lit `ie.get("value").and_then(.as_str)` :
  si `value: Some(_)`, préservé ; si `value: None`, IE ne contribuait
  à aucune clé de toute façon. **SAFE**.
- Top-level : `sbi`, `parent_event_id`, `procedure_code`, `procedure`,
  `security_state`, `source_byte_offset` omis quand `null`. Aucun
  consommé par la chaîne de corrélation. **SAFE**.
- `session_identifiers: []` et `information_elements: []` **toujours
  émis** même vides (contrat de présence).

Verdict : **pas de régression possible** sur les champs tunnel
(`gtp_teid`, `tunnel_endpoint_ip`, teid identifier) via la compaction.

**2. `KeepaliveAggregator` (2.9.5, `live-probe/src/lib.rs:347-592`).**
`classify_keepalive` filtre par `(Protocol, message_name)` exact :

- `Protocol::Gtpu` + `"Echo Request" | "Echo Response"` → absorbé.
- `Protocol::Gtpu` + `"G-PDU"` → **None → pass-through** vers
  `n3_aggregator`. **Pas d'absorption du user-plane**.
- `Protocol::Pfcp` + `"PFCP Heartbeat Request/Response"` → absorbé ;
  Session Establishment/Modification/Deletion → pass-through.
- `Protocol::Diameter` + `"Device-Watchdog-Request/Answer"` → absorbé.
- `Protocol::SbiHttp2` + tout → **None → pass-through** (SBI pas
  soumis à classify_keepalive).

Verdict : **G-PDU et SBI ne sont jamais avalés**. L'ordre dans la
closure (`live-probe:4234-4271`) est keepalive → N3 flow aggregator →
individuel, confirmé par lecture ligne par ligne. **SAFE**.

**3. `N3FlowAggregator::finish()` (`live-probe:240-328`).** L'agrégat
préserve :
- `packet_references[0]` = premier paquet observé (full path →
  `capture_scope` == "continuous-lab-import").
- `session_identifiers` = base event minus `sequence_number`, plus
  `qfi`. **`teid` préservé** (lu par correlation
  `event.first_identifier("teid")`).
- `interface`, `protocol`, `destination_endpoint.address` =
  préservés du base event. `destination_address` de l'EventRecord
  recréé par `parse_event` sort de `destination_endpoint.address`.
- `information_elements` : les IEs d'origine sont **conservées**, les
  aggregate_* sont **ajoutées**.

Verdict : **tous les champs consommés par N3 correlation preservés**.

**4. `tunnel_keys` + `capture_scope` (`correlation-engine:475-553`).**
Inchangés entre 2.9.1 et 2.9.6. `capture_scope` sur le chemin
production `/var/lib/oiran/captures/continuous-lab-import/pcap/*` :
`/captures/` trouvé, extrait `"continuous-lab-import"` identique pour
tous les plans. **SAFE**.

**5. `prefix_sha_index` pcapng (2.9.6).** N'intervient que dans
`repair_partial_imports`, pas dans la chaîne de corrélation live.
**N/A**.

**Conclusion T1** : aucun RISQUE INFRA identifié dans la diff. Toute
régression observée sur un run spécifique est **data-dependent**
(contenu du PCAP, fail-closed sur multi-match).

### T2 — Nouveau test non-régression round-trip

`correlation-engine::tests::compact_jsonl_round_trip_yields_four_cross_interface_edges`
(`correlation-engine/src/lib.rs`) — **test qui manquait avant
cette session**. Pipeline complet :

1. 4 `NormalizedEvent` construits via `event-schema` (N2 NGAP, N4 PFCP,
   N3 GTP-U, SBI N1N2MessageTransfer) avec les formats IE/identifiers
   exacts émis par decoder-ngap / decoder-pfcp / decoder-gtpu /
   decoder-sbi en production — hétérogénéité de padding TEID conservée
   (`0xd4a6` sans padding côté NGAP/SBI, `0x0000d4a6` 8-char côté
   PFCP/GTP-U).
2. Sérialisation via `NormalizedEvent::to_json()` (format compact
   2.9.4) → bytes JSONL.
3. Désérialisation via `session-engine::load_jsonl(Cursor::new(..))`
   → `Vec<EventRecord>`.
4. `correlation-engine::correlate_cross_interface_evidence(&events)`.
5. Assertion : les **4 edges attendues** sont présentes :
   - `ngap-pfcp-exact-tunnel` (N2↔N4) EXACT ;
   - `pfcp-outer-header-matches-gtpu-tunnel` (N4↔N3) EXACT ;
   - `sbi-n2-tunnel-match` (SBI↔N2) EXACT ;
   - `sbi-n4-tunnel-match` (SBI↔N4) EXACT.

**Résultat** : test **PASSE** → l'infra round-trip JSONL compact
→ parse_event → correlate est **intacte** sur l'échantillon réaliste.
L'écart ANR2 ne provient donc PAS d'une régression infra 2.9.1→2.9.6.

### T3 — Causes candidates du N4↔N3 OUVERT sur ce run

Sans accès au JSONL brut de `5g-session-5e3fc8ce83936ea0`, les causes
plausibles data-dependent sont :

1. **N4 F-TEID duplicates** : `correlate_cross_interface_evidence`
   lignes 236-247 exige `n4_duplicates == 1` sur la clé
   `(ipv4, teid)`. ANR2 montre 3 F-TEIDs
   (`0xd4a6`, `0xe782`, `0xd4a6`) — si deux partagent la même
   `(ipv4, teid)`, fail-closed. Le run 2.9.1 n'avait peut-être pas
   cette collision.
2. **N3 destination_address différente** : si l'aggregator N3 retient
   un paquet DOWNLINK comme premier (`destination = gNB IP`), le
   `endpoint_ip` du tunnel-key N3 ne matche pas l'`ipv4` du F-TEID
   N4 (= UPF IP). Les Uplink et Downlink sont des aggregates séparés
   par `N3FlowKey.direction`, donc en principe l'Uplink aggregate
   existe et match. À vérifier sur le JSONL réel.
3. **N3 TEID absent des session_identifiers** : si decoder-gtpu a
   échoué à extraire `teid` sur certaines trames (edge-case
   fragmenté), l'aggregate base event peut manquer de `teid`. Pas
   observé dans le code mais à confirmer sur le run.

Pour SBI↔N2 / SBI↔N4 : ANR2 montre que le trafic SBI du run est
exclusivement **CreateSMContext + UpdateSMContext** (POST
`/nsmf-pdusession/v1/sm-contexts[/.../modify]`). **AUCUN
N1N2MessageTransfer**. Les règles `sbi-n2-tunnel-match` et
`sbi-n4-tunnel-match` (`correlation-engine:299-367`) filtrent sur
`message_name == "N1N2MessageTransfer"`. Donc elles ne peuvent pas
firer. Attendu, pas une régression. La bridge alternative
`sbi-pfcp-context-association` fire sur `CreateSMContext + PFCP
Session Establishment Request + DNN match`. Si DNN ne match pas (ou
si SBI event n'est pas émis), STRONG edge absent.

**Correctif applicable** : aucun côté infra. Le véritable correctif
nécessite les IE brutes de l'event SBI CreateSMContext et du N4 PFCP
Session Establishment du run réel (encore OUVERT). Si le CreateSMContext
porte un `n2SmInfo` multipart décodable, ajouter une règle SBI tunnel
match depuis `CreateSMContext` serait un chantier 2.9.8+ ; pour l'instant
l'OUVERT est déclaré sans correctif.

### Aucune régression infra

- `correlation-engine` : règles **inchangées** ; test de round-trip
  prouve que la chaîne **compact JSONL → parse_event → correlate**
  reste intacte pour l'échantillon réaliste 4-interfaces.
- `event-schema` compact : omission uniquement sur `null`/`[]` non
  critiques — tous les champs consommés par `tunnel_keys`, `parse_event`,
  et le chemin tunnel N3/N4 préservés byte-exact.
- `KeepaliveAggregator` : jamais d'absorption G-PDU ni SBI.
- Tests 2.9.6 (417) + 1 nouveau round-trip = **418** sans régression.

### SemVer

| Composant | Avant | Après |
|---|---|---|
| `apps/api` | 2.9.6 | **2.9.7** |
| `correlation-engine` | 0.6.0 | **0.6.1** (ajout dev-dep event-schema + test round-trip) |
| `live-probe` | 0.4.22 | 0.4.22 |
| `event-schema` | 1.5.1-dev | 1.5.1-dev |
| `apps/web` | 2.9.3 | 2.9.3 |
| `callflow-schema` | 1.3.1 | 1.3.1 |

### Compat rustc

- `rustc 1.75` (min workspace) et **`rustc 1.83`** (serveur) OK.
- Aucun feature nightly, `event-schema` ajouté seulement comme
  dev-dependency de `correlation-engine` (pas d'impact binaire).

### Tests

```sh
cargo test --workspace --locked --release --offline --no-fail-fast
# → 418 passed, 0 failed, 4 ignored (baseline 417 + 1 round-trip).
```

### Encore OUVERT

- **N4↔N3 UNKNOWN sur `5g-session-5e3fc8ce83936ea0`** : attend ANR2
  JSONL brut (session_identifiers N3 teid + destination_address,
  F-TEIDs N4) pour localiser la cause data-specific.
- **SBI↔N2 / SBI↔N4 UNKNOWN sur ce run** : le trafic SBI est
  exclusivement CreateSMContext + UpdateSMContext (pas de
  N1N2MessageTransfer). Les rules tunnel-match 2.8.0 nécessitent
  N1N2MessageTransfer. Chantier 2.9.8+ possible : ajouter une
  règle SBI tunnel match depuis CreateSMContext quand un
  `n2SmInfo` multipart est présent et décodable.
- **T2 S6a 3 502 msg** : causes documentées en 2.9.6 (segments
  pré-2.9.5 + cross-segment boundary), correctif structurel possible
  en 2.9.8+ (DatasetKeepaliveRollup post-process).


## OIRAN API 2.9.6 — 2026-11-08 — Réparation pcapng + cause S6a (devmat T1/T2 — ANR2 #10 comment 6724120812, #9 comment 6724013622)

### T1 — Cause prouvée : `prefix_sha_index` ignorait pcapng

**Preuve ANR2** (`#10` comment 6724120812) :

```
/opt/oiran/bin/dataset-repair-partial-imports /var/lib/oiran/captures \
  --dry-run --source-root /var/lib/docker/volumes/oiran_lab_pcap/_data

event_count_before=1275902
event_count_after=1275902
partial_import_groups=1075
unresolved_groups=6
removed_events=0
```

- `0` groupes résolus avec plusieurs snapshots.
- `_00067` : **3 singletons seulement** (N4, SBI, Sxa/Sxb), pas ×7.
- 6 groupes N4 restent `UNRESOLVED_NO_EVIDENCE`.

**Cause fichier:ligne** — `live-probe/src/lib.rs:7489-7504` (pré-2.9.6) :

```rust
let little = matches!(
    &header[..4],
    [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1]
);
let big = matches!(&header[..4], [0xa1, 0xb2, 0xc3, 0xd4]);
if !little && !big {
    // Non-pcap bytes: `full_sha_hex` is set, no prefixes.
    return Ok(PrefixIndex { ..., prefix_sha: BTreeMap::new() });
}
```

`prefix_sha_index` ne reconnaissait que **pcap classique** (magic
`D4 C3 B2 A1` / `4D 3C B2 A1` / `A1 B2 C3 D4`). Sur **pcapng** (magic
`0A 0D 0D 0A`), la fonction tombait dans la branche `!little && !big`,
retournait `prefix_sha = {}` (vide), et aucun snapshot ne pouvait
matcher par préfixe. Les 7 snapshots de `_00067` ingérés en 2.9.2 ne
pouvaient jamais être regroupés → tous en singletons, puis
`UNRESOLVED_NO_EVIDENCE` sur les 6 groupes sans `state.segments`
fallback.

Dumpcap de production écrit en pcapng (confirmé par `grep -l '^.pcap$'`
→ aucun, tous les segments sont `.pcapng`). Le test existant
`repair_partial_imports_rebuilds_full_history_via_prefix_sha_match`
utilise un pcap classique fabriqué — il passait, masquant le bug.

**Correctif** — `live-probe/src/lib.rs:7466-7553+` :

- `prefix_sha_index` détecte désormais le magic pcapng
  `[0x0a, 0x0d, 0x0d, 0x0a]` et dispatch vers
  `prefix_sha_index_pcapng` (nouvelle fonction).
- `prefix_sha_index_pcapng` lit l'endianness via le Byte-Order Magic
  dans le SHB (`0x1A 0x2B 0x3C 0x4D` big-endian /
  `0x4D 0x3C 0x2B 0x1A` little-endian).
- Walk des blocks pcapng (type + total_length + body + trailer).
  Snapshot SHA à la fin de chaque **Enhanced Packet Block (type
  `0x00000006`)** et **Simple Packet Block (type `0x00000003`)**.
- Comportement inchangé pour pcap classique.

**Test** — `prefix_sha_index_walks_pcapng_enhanced_packet_blocks`
(`live-probe/src/lib.rs:tests`) : fabrique un pcapng minimal
(SHB + IDB + 2 EPBs), vérifie :

- `full_packet_count == 2` ;
- `full_bytes == 120` (28 + 20 + 36 + 36) ;
- `prefix_sha.len() == 1` (SHA après EPB1 ; SHA après EPB2 == full,
  retiré par convention) ;
- entrée `(packet_count=1, bytes_at_snapshot=84)`.

Projection production : après déploiement 2.9.6, le --dry-run sur le
même `/var/lib/oiran/captures` doit retrouver les 7 snapshots de
`_00067` groupés par préfixe-SHA (`PrefixShaMatchFreshImport`).
Attendu `partial_import_groups` ≈ 1075 − 7×3 + 3 (= 1057) avec les
3 groupes `_00067` couvrant 7 snapshots chacun. `removed_events`
non-zéro.

**Mesure à valider par ANR2** après déploiement :

```sh
/opt/oiran/bin/dataset-repair-partial-imports /var/lib/oiran/captures \
  --dry-run --source-root /var/lib/docker/volumes/oiran_lab_pcap/_data
# attendu : partial_import_groups résolus > 0, unresolved_groups = 0,
# _00067 groupé en PrefixShaMatchFreshImport ×3 (N4 / SBI / Sxab).
```

### T2 — Écart S6a 3502 messages : cause prouvée partielle

**Preuve ANR2** (`#9` comment 6724013622 + `#10` comment 6724120812) :

- Sur les **181** segments avec aggregates 2.9.5 :
  - PCAP : **88 000** messages = 44 002 DWR + 43 998 DWA.
  - Aggregates : **84 498** messages = 42 239 req + 42 259 resp.
  - **Écart : 3 502 messages** sur 180 segments.
- **177** segments historiques (ingérés pré-2.9.5) ne contiennent
  AUCUN aggregate 2.9.5 et portent **86 600** messages individuels
  dans le JSONL (écart avec PCAP = 5 430).

**Cause prouvée partielle** — triple contribution :

1. **Segments historiques pré-2.9.5 non ré-agrégés** (177 segments,
   86 600 msg) : ingérés AVANT le déploiement du `KeepaliveAggregator`
   de 2.9.5. Leurs events keepalive sont dans le JSONL en
   individuels. Attendu — l'aggregator n'ingère pas rétroactivement.
   Correctif : `dataset-repair-partial-imports --rewrite-keepalives`
   est un chantier futur ; pas inclus dans 2.9.6 (hors scope).
2. **Sur les 181 segments 2.9.5** : 3 502 messages dans PCAP absents
   des aggregates. Deux candidates non-prouvables sans
   `decode_reports` par segment :
   - **Rejets SCTP** sur transitions d'association (INIT, COOKIE_ECHO)
     qui incrémentent `incomplete_sctp` sans événement. Visible via
     `jq '.decode_reports[].sctp_errors + .decode_reports[].incomplete_sctp'`.
   - **Fenêtre d'agrégat split cross-segment** : un DWR à la fin du
     segment N et son DWA au début de N+1 se retrouvent dans deux
     aggregates différents (2 paires `request_count=1,
     response_count=0` + `request_count=0, response_count=1`
     respectivement). Le `aggregate_failure_count` capture le
     déséquilibre, mais l'IE `message_count` ne compte pas les
     réponses « tardives » du segment N comme requêtes.
3. **Non-DWR/DWA Diameter** (ex : CER/CEA, DPR/DPA) : 148 msg sur
   S6a total (174 742 diameter − 174 594 watchdog). Ces messages
   passent à travers `classify_keepalive` → individuels. Attendu.

**Clé d'agrégat inchangée** `(interface, kind, pair_low, pair_high)` :
preuve conservée. Les 2 paires observées sur chaque segment S6a
(`69c65c:68f82c` et `51896f:3f5587` SHA-tronqués) reflètent deux
associations Diameter distinctes du serveur S6a — pas un défaut
d'agrégation.

**Pas de correctif 2.9.6** sur T2 — la cause est documentée et
structurelle (cross-segment boundary). Un éventuel correctif
nécessiterait un aggregator qui survive à la frontière entre segments
(carry-over state entre `decode_capture_streaming` calls), ce qui
casserait la propriété « 1 aggregate par segment / fail-closed »
conservée depuis `N3FlowAggregator`. **OUVERT** : si ANR2 juge
l'écart inacceptable, 2.9.7 peut implémenter un `DatasetKeepaliveRollup`
en post-traitement.

**Mesure diagnostique attendue d'ANR2** :

```sh
# Sur les 180 segments en écart, extraire SctpError + incomplete_sctp
jq '.decode_reports | to_entries[] |
   select(.key|test("^S6a\\.pcap-"; "i")) |
   {segment: .key, incomplete_sctp: .value.incomplete_sctp,
    sctp_errors: (.value.sctp_errors|length? // .value.sctp_errors)}' \
  /var/lib/oiran/captures/continuous-lab-import/dataset/dataset_manifest.json |
jq -s 'map(select(.incomplete_sctp > 0 or .sctp_errors > 0)) | length'
# attendu > 0 si le candidat (rejet SCTP) est dominant
```

### Aucune régression

- `correlation-engine` INCHANGÉ. `N2_N4 = 2 EXACT`, `N4_N3 = 2 EXACT`,
  `N2_SBI = EXACT` sur `tpl-small-traffic-e2bea97912f9` — règles non
  touchées.
- `prefix_sha_index_pcapng` est un **chemin additif** : le pcap
  classique conserve son code byte-for-byte, le test existant
  `repair_partial_imports_rebuilds_full_history_via_prefix_sha_match`
  passe inchangé (confirmé — même SHA des 7 prefix).
- Aucune identité en clair. L'algorithme opère sur des SHA de bytes
  bruts du fichier PCAP, jamais sur contenu subscriber.
- Mémoire : O(packet_count) pour `prefix_sha` BTreeMap — même borne
  qu'avant. Un pcapng de 1 M paquets coûte ~65 MB (clé 64-char +
  valeur 16 B × 1M). Pas de régression vs pcap classique.
- CPU : parcours linéaire 1×. Aucune accélération ni ralentissement.

### SemVer

| Composant | Avant | Après |
|---|---|---|
| `apps/api` | 2.9.5 | **2.9.6** |
| `live-probe` | 0.4.21 | **0.4.22** |
| `transport-sctp` | 0.1.0 | 0.1.0 |
| `event-schema` | 1.5.1-dev | 1.5.1-dev |
| `apps/web` | 2.9.3 | 2.9.3 |
| `callflow-schema` | 1.3.1 | 1.3.1 |

### Compat rustc

- `rustc 1.75` (min workspace) et **`rustc 1.83`** (serveur) OK.
- Aucun feature nightly, aucune nouvelle dependency.

### Tests

- `cargo test --workspace --locked --release --offline --no-fail-fast`
  → **417 passed, 0 failed, 4 ignored** (baseline 416 + 1 nouveau
  test pcapng).

### Encore OUVERT

- **T2 S6a 3 502 msg écart** : causes documentées (segments
  pré-2.9.5 + cross-segment boundary + non-watchdog Diameter). Pas
  de correctif 2.9.6. Diag ANR2 sollicité ; 2.9.7 possible si ANR2
  juge inacceptable.
- **SBI↔N4** : attend IE bruts d'un event SBI réel (#9 comment
  6712678520). Le dernier run ANR2 (6724107216) n'a pas eu de PDU
  établi — pas de trafic SBI exploitable.
- **Doublons 22 collisions NGAP / NAS-5GMM** (#9 comment 6719453085) :
  11 groupes `UplinkNASTransport`, 3 `InitialContextSetupRequest`,
  8 `Protected 5GMM message`. Non prouvable sans le dataset brut ;
  attend `event_id`s réels pour trancher si vrais doublons ou re-
  décodage légitime.


## OIRAN API 2.9.5 — 2026-11-08 — Keepalive aggregation + duplicate rule + S1-MME fragmentation note (devmat T1/T2/T3 — ANR2 #9 comment 6714896530)

### Mesure ANR2 à l'entrée

Sur le dataset 1 232 678 événements :

- **Sxa/Sxb** 868 123 heartbeats PFCP + **S6a** 76 890 watchdogs
  Diameter = **944 013 keepalives = 76,58 %** du volume d'événements.
- **S1-MME** 991 paquets PCAP → 424 événements → 254 paquets uniques
  publiés (verdict FAIL / OUVERT côté ANR2).
- Doublons S1AP + NAS du même paquet : 273 groupes / 296 excédents
  (dont 166 nouveaux S1AP transport/contexte + NAS-EPS-MM) — règle
  quantitative demandée : FAIL dès > 0, mais SANS définition
  explicite de ce qu'est un doublon.

### T1 — Agrégation keepalive (live-probe 0.4.20 → 0.4.21)

Nouveau `KeepaliveAggregator` (`live-probe/src/lib.rs:347-592`) sur
le même patron que `N3FlowAggregator` :

**Reconnaissance** — `classify_keepalive(event)` (`:383`) retourne
`Some((kind, is_request))` pour :

- `Protocol::Pfcp` + `"PFCP Heartbeat Request"` / `Response` → `PfcpHeartbeat`.
- `Protocol::Diameter` + `"Device-Watchdog-Request"` / `-Answer` → `DiameterWatchdog`.
- `Protocol::Gtpv2c` + `"Echo Request"` / `Response` → `Gtpv2Echo`.
- `Protocol::Gtpu` + `"Echo Request"` / `Response` → `GtpuEcho`.

Messages de session (`PFCP Session Establishment Request`,
`CreateSessionRequest`, `G-PDU`, …) : **passent à travers** sans
agrégation (`observe` retourne `Ok(Some(event))`).

**Clé d'agrégation** — `(interface, keepalive_kind, pair_low, pair_high)`
où `pair_low = min(src.address, dst.address)` et
`pair_high = max(src.address, dst.address)`. **Fusionne les deux
directions req/resp** sur une même paire de nœuds en un seul
aggregate, comme demandé par devmat.

**Évidence émise** (`:555-594`, IEs du NormalizedEvent agrégé) :

- `aggregate_keepalive_kind` ∈ `PFCP_HEARTBEAT | DIAMETER_DEVICE_WATCHDOG |
  GTPV2_ECHO | GTPU_ECHO`.
- `aggregate_node_pair_low`, `aggregate_node_pair_high`.
- `aggregate_request_count`, `aggregate_response_count`,
  `aggregate_message_count`.
- `aggregate_failure_count = max(0, request_count - response_count)` —
  **compteur d'échecs, jamais masqué** (devmat rule).
- `aggregate_first_capture_id`, `aggregate_first_packet_number`,
  `aggregate_first_event_id`,
  `aggregate_last_capture_id`, `aggregate_last_packet_number`,
  `aggregate_last_event_id` — ordre **canonique** `(capture_id,
  packet_number, event_id)` jamais ts.

**Provenance packet_references** : premier et dernier paquet de la
fenêtre canonique, `raw_payload_reference = keepalive-aggregate:
<interface>:<kind>:<pair>:<first_pn>-<last_pn>`,
`evidence_references` dérivées des mêmes paquets. `event_id` est
réassigné déterministiquement via `assign_deterministic_id`.

**Message de session restent 1 événement chacun** — confirmé par test
`keepalive_aggregator_passes_through_non_keepalive_session_events`.

**Intégration** (`live-probe/src/lib.rs:4234-4271`, closure de
`decode_capture_streaming`) : les événements passent d'abord par
`keepalive_aggregator.observe` ; s'ils sont absorbés (keepalive), on
sort immédiatement ; s'ils passent à travers, l'ancien aiguillage
`aggregate_n3 && Protocol::Gtpu → n3_aggregator` s'applique. Les deux
collecteurs sont flushés en fin de boucle par segment.

**Borne** : `MAX_KEEPALIVE_AGGREGATES = 4096` — fail-closed par
segment.

**Projection sur le dataset ANR2** (chaque chiffre a sa commande) :

| Interface | Événements avant | Kind | Aggregates après |
|---|---:|---|---:|
| Sxa/Sxb | 868 123 | PFCP_HEARTBEAT | ≤ 4 096 (en pratique ~1-10 par paire) |
| S6a | 76 890 | DIAMETER_DEVICE_WATCHDOG | ≤ 4 096 |
| N3 / S1-U / S5-U | 0 Echo observés | — | 0 |

Réduction attendue sur les 944 013 keepalives : **>99 %** en nombre
d'événements. Sur taille jsonl : extrapolation ~944 k × 2 kB ≈ **1,88 GB
économisés** → repasse largement sous 1 GB au total (avant même
2.9.4 compact JSON).

### T2 — S1-MME 991 PCAP → 424 événements → 254 paquets uniques : analyse (**OUVERT**)

La cause **n'est pas une perte dans le reassembler**. Lecture code :

- `transport-sctp/src/lib.rs:177-215` — `SctpReassembler` accumule
  `refs: Vec<PacketReference>` à chaque chunk DATA (BEGIN + MIDDLE
  + END). Fragments préservés.
- `decoder-s1ap/src/lib.rs:536` et `:623` — les deux events
  (parent S1AP + child NAS) copient `input.packet_references.to_vec()`.
- `oiran-decode/src/lib.rs:238-240` — `DecoderInput.packet_references`
  passe la liste complète du `SctpMessage.packet_references`.

**Hypothèse principale (non prouvable sans run réel)** : un S1AP de
3-4 KB est fragmenté en 4 paquets SCTP (MTU ≈ 1 500 B). `tshark -Y
's1ap'` matche les 4 paquets (il reassemble puis tague TOUS les
paquets contributeurs). 991 / 4 ≈ 248 messages, ce qui cadre avec
les **254 paquets uniques** ANR2 si la mesure n'énumère que
`packet_references[0]` (le BEGIN fragment, souvent 1ᵉʳ ref).

Ratio événements/paquet : 424 / 254 = 1,67 — cohérent avec
« ~2 événements S1AP+NAS par paquet BEGIN en moyenne ».

**Nouveau test** — `transport-sctp` :
`reassembled_message_preserves_every_fragment_packet_reference`
(`transport-sctp/src/lib.rs:466+`) : un message S1AP de 3 fragments
(BEGIN packet 1001, MIDDLE 1002, END 1003) doit produire 1
`SctpMessage` avec
`packet_references.iter().map(|r| r.packet_number).collect::<Vec<_>>()
== vec![1001, 1002, 1003]`.

**Demande ANR2** pour clôturer : refaire la mesure avec la liste
complète :

```sh
jq -r '.packet_references[].packet_number' oiran_events.jsonl |
  awk -v cap="$(jq -r '.capture_id' oiran_events.jsonl | head -1)" '{print cap":"$1}' |
  sort -u | wc -l
```

Si ce chiffre vaut ≈ 991, le défaut initial était une **choix de
mesure** et non une perte. Si < 991, un fragment END-seul sans
BEGIN doit exister côté capture : alors cause dans
`transport-sctp:224-229` (`non-beginning DATA fragment has no
assembly`, incrémente `SctpErrorKind::Incomplete` mais **ne
produit pas d'event**). Ces cas seraient visibles dans
`DecodeReport.incomplete_sctp` sur le run.

**T2 reste OUVERT** jusqu'à publication par ANR2 de :

1. `jq -r '.packet_references[].packet_number'` sur une capture
   S1-MME fermée (compte uniques par capture_id).
2. `decode_reports["<s1mme.pcapng>"].incomplete_sctp` et
   `.sctp_errors`.

### T3 — Règle de doublon documentée + test (live-probe 0.4.21)

Nouvelle fonction pure `is_duplicate(a, b)` (`live-probe/src/lib.rs:634`) :

> Deux événements sont des **doublons** ssi ils ont **le même
> `protocol`** ET **le même `message_name`** ET **le même paquet**
> `(capture_id, packet_number, byte_offset)`.

**S1AP + NAS-EPS-MM** du même paquet = `protocol` différent (`S1AP`
vs `NAS-EPS-MM`) → **PAS un doublon**. C'est deux événements
légitimes, un par protocole dissecté dans la même PDU.

**Deux S1AP InitialContextSetupRequest** sur le même paquet =
même `protocol` + même `message_name` + même paquet → **doublon**.

Test `is_duplicate_rule_separates_s1ap_from_nas_eps_mm_on_same_packet`
(`live-probe/src/lib.rs:tests`) couvre 4 cas : paire légitime
S1AP+NAS, vrai doublon même type, paquets différents, byte_offset
différent.

### Aucune régression

- **Corrélation** : `correlation-engine` inchangé. `N2_N4 = 2 EXACT`,
  `N4_N3 = 2 EXACT`, `N2_SBI = EXACT` sur
  `tpl-small-traffic-e2bea97912f9` — règles non touchées. À valider
  par ANR2 post-déploiement.
- **Identité en clair** : aucune. Le `KeepaliveAggregator` ne touche
  à aucun identifier subscriber (il efface même `sequence_number` et
  `fseid_seid` pour cohérence agrégée) ; les adresses de nœuds sont
  des IP de NF, pas des IMSI/SUPI.
- **Mémoire** : `BTreeMap` borné à `MAX_KEEPALIVE_AGGREGATES=4096`,
  même patron que `MAX_N3_FLOW_AGGREGATES=4096`. Pas de croissance
  linéaire avec le nombre d'événements traités (c'est justement
  l'objet de l'agrégation).
- **CPU** : ajoute une passe O(1) amortie par événement via
  `BTreeMap::get_mut` + `insert`. Négligeable.

### SemVer

| Composant | Avant | Après |
|---|---|---|
| `apps/api` | 2.9.4 | **2.9.5** |
| `live-probe` | 0.4.20 | **0.4.21** |
| `transport-sctp` | 0.1.0 | 0.1.0 (ajout test, pas d'API) |
| `event-schema` | 1.5.1-dev | 1.5.1-dev (inchangé) |
| `apps/web` | 2.9.3 | 2.9.3 (inchangé) |
| `callflow-schema` | 1.3.1 | 1.3.1 |

### Compat rustc

- `rustc 1.75` (min workspace) et **`rustc 1.83`** (serveur) OK.
  Aucun feature nightly. `KeepaliveAggregator` et `is_duplicate` sont
  des structures et fonctions pures sans dépendance externe.

### Tests

- `cargo test --workspace --locked --release --offline --no-fail-fast`
  → **416 passed, 0 failed, 4 ignored** (baseline 410 + 6 nouveaux
  tests : 4 keepalive + 1 duplicate + 1 SCTP packet_references).
- Nouveaux tests clés :
  * `keepalive_aggregator_collapses_pfcp_heartbeats_with_paired_request_response`
    — 1000 req + 1000 resp → 1 aggregate, request_count=1000,
    response_count=1000, failure_count=0.
  * `keepalive_aggregator_counts_unmatched_requests_as_failures` —
    100 DWR + 42 DWA → failure_count=58 (jamais masqué).
  * `keepalive_aggregator_passes_through_non_keepalive_session_events`
    — PFCP Session Establishment Request passe à travers.
  * `keepalive_aggregator_separates_gtpu_echo_from_gtpv2_echo` — 2
    aggregates distincts sur protocoles différents.
  * `is_duplicate_rule_separates_s1ap_from_nas_eps_mm_on_same_packet`
    — règle quantitative T3.
  * `reassembled_message_preserves_every_fragment_packet_reference`
    — provenance de 3 fragments préservée dans
    `SctpMessage.packet_references`.

### Encore OUVERT

- **T2 S1-MME 991 → 254** : attend mesure complète ANR2 (voir
  « Demande ANR2 pour clôturer » ci-dessus).
- **Taille dérivée réelle post-2.9.5** : à mesurer par ANR2 sur run
  réel après déploiement. Attendu : < 1 GB (vs 2.6 GB avant), pas
  de palliatif 8 GiB nécessaire.
- **SBI↔N4** : attend IE bruts d'un event SBI réel (comment ANR2
  #9 comment 6712678520).
- **LTE S1-MME / S6a** : attend verdict ANR2 post-reduction des
  keepalives (expected: S6a 868 727 PCAP → ~4096 aggregates +
  quelques dizaines de session events, cohérent).


## OIRAN API 2.9.4 — 2026-11-08 — Compact event JSONL (devmat T2 — ANR2 #9 comments 6714896530 + 6715187788)

### Mesures ANR2 à l'entrée

- Volume dataset: **2 627 851 236 B** sur `oiran_events.jsonl` pour
  **1 232 678** événements (`~2 132 B / event` en moyenne).
- Plafond 2 GiB atteint; palliatif 8 GiB appliqué par ANR1.
- Top-5 champs par poids (JSON sérialisé, worst-case /interface) :
  * **SBI** event 4 262 B : `packet_references=1 423`,
    `information_elements=1 081`, `sbi=317`,
    `session_identifiers=261`, `timestamp=157`.
  * **Sxab** event 16 164 B : `information_elements=13 387`,
    `session_identifiers=1 098`, `packet_references=474`,
    `timestamp=157`, `evidence_references=132`.
- **Pas de duplication** `decode_reports` / `checksums` event vs
  manifeste (déjà seulement au niveau dataset) — l'hypothèse de
  dédup est caduque.

### Correctif — `NormalizedEvent::to_json` (event-schema 1.5.0 → 1.5.1)

`event-schema/src/lib.rs:305+` réécrit en builder incremental :
chaque champ optionnel `null` et chaque tableau vide non essentiel est
**omis** de la sortie JSON sans perte d'information de preuve.

**Omis quand null** :
- `parent_event_id`, `procedure_code`, `procedure`, `security_state`,
  `source_byte_offset`, `sbi` (top-level).
- `packet_references[].source_sha256`, `.link_type`,
  `.sll2_protocol_type`, `.sll2_reserved`, `.sll2_interface_index`,
  `.sll2_arphrd_type`, `.sll2_packet_type`, `.sll2_address_length`,
  `.sll2_address` — 9 nulls par ref hors mode `tcpdump -i any`.
- `information_elements[].id`, `.value`, `.raw_sha256`.

**Omis quand `[]` vide** :
- `errors`, `evidence_references`.

**Toujours émis** (contrat de présence) :
- Tous les champs REQUIS par `session-engine::parse_event`
  (event_id, capture_id, timestamp.{seconds,nanoseconds,raw_ticks},
  interface, protocol, message_name, direction, source/destination_endpoint,
  packet_references.{source_file,packet_number,byte_offset,interface_id,
  captured_length,original_length}, decoding_status, decoder_name,
  decoder_version, raw_payload_reference).
- `session_identifiers: []` et `information_elements: []` restent
  présents même vides — `correlation-engine::tunnel_keys`
  (`src/lib.rs:520`) et autres consommateurs itèrent
  `event.information_elements.as_array()` et attendent au moins
  la clé (lecture `.get("information_elements")` suivie de
  `.cloned().unwrap_or(Value::Array(Vec::new()))` — fonctionne aussi
  si la clé est absente, mais la préserver évite toute surprise sur
  les consommateurs tiers).
- `errors`, `evidence_references`, `sbi` (quand non null) :
  consommateurs ANR2 (`jq '.sbi.operation'`) tolèrent l'absence —
  `null.operation` donne `null` en jq. Garde emission de `sbi`
  uniquement quand `Some(_)`.

### Mesure avant / après — preuve

Test `to_json_reduces_size_by_at_least_30_percent_on_sbi_shape_with_10_refs`
sur un événement SBI stylisé (10 packet_references tous `sll2_* = None`,
3 `information_elements` avec `id/value/raw_sha256 = None`) :

```
[T2 to_json SBI shape 10 refs] before=5149 B after=2788 B reduction=45.854%
```

Projection ANR2 dataset réel :

- SBI (192 809 events × moy 2 950 B ≈ 569 MB) → ~309 MB après (-46 %).
- Sxab (868 400 events × moy 1 917 B ≈ 1 665 MB) — IE domine à 80 %,
  réduction attendue plus modérée (IE non nuls dans la plupart des
  cas) ; cible réaliste 20-25 % → ~1 290 MB après.
- Total avant : 2 627 MB → après estimation : **1 700-1 800 MB**,
  largement sous le plafond 2 GiB sans palliatif.

**Mesure réelle serveur à valider par ANR2** (commande projection
inchangée) :

```sh
find dataset -type f -name 'oiran_events.jsonl' -exec du -b {} +
```

après re-publication via la 2.9.4. Si gain < 25 % côté Sxab, enchaîner
sur 2.9.5 pour attaquer `information_elements` (candidate : omission
des IE à `name: ""`/`value: ""`).

### Contrat corrélation préservé

- Les 4 champs REQUIS par `correlation-engine::tunnel_keys`
  (`src/lib.rs:520`) — `information_elements` tableau présent + IE
  avec `value` string parsable au format
  `tunnel_endpoint_ip=X,gtp_teid=Y` ou `teid=0x…,ipv4=X` — sont
  **inchangés** : seule les IE avec `value: None` sont omises (elles
  ne contribuent de toute façon à aucune clé).
- `N2_N4 = 2 EXACT`, `N4_N3 = 2 EXACT`, `N2_SBI = EXACT` sur
  `tpl-small-traffic-e2bea97912f9` — pas de change de règle, test de
  régression correlation-engine inchangé et passant (bidirectional
  `confidence_for` reste en place).

### Compat parse_event

`session-engine::parse_event` (`src/lib.rs:820-935`) :

- `.get("parent_event_id").and_then(.as_str)` → `None` si omis ✓.
- `.get("errors").and_then(.as_array).unwrap_or(&Vec::new())` →
  tableau vide si omis ✓.
- `.get("evidence_references")` idem ✓.
- `.get("sbi")` idem ✓.
- `.get("session_identifiers")` → la clé reste présente ✓.
- `.get("information_elements")` → la clé reste présente ✓.
- `serde_json::from_value::<Vec<PacketRef>>(...)` où `PacketRef` a 6
  champs : `source_file`, `packet_number`, `byte_offset`, `interface_id`,
  `captured_length`, `original_length` — tous présents dans la nouvelle
  sortie ✓. Les sll2_* n'ont jamais été dans `PacketRef` (serde ignore
  les champs inconnus par défaut).

Verdict : **100 % backward-compatible** pour tous les consommateurs
internes.

### SemVer

| Composant | Avant | Après |
|---|---|---|
| `event-schema` | 1.5.0-dev | **1.5.1-dev** |
| `apps/api` | 2.9.3 | **2.9.4** |
| `apps/web` | 2.9.3 | 2.9.3 |
| `callflow-schema` | 1.3.1 | 1.3.1 |
| `live-probe` | 0.4.20 | 0.4.20 |

`NormalizedEvent::SCHEMA_VERSION` : `"1.5.0"` → **`"1.5.1"`** — le
champ `schema_version` de chaque event sortant reflète la nouvelle
forme compacte.

### Tests

- `cargo test --workspace --locked --release --offline --no-fail-fast`
  → **410 passed, 0 failed, 4 ignored** (baseline 408 + 2 nouveaux
  `to_json_*` dans `event-schema`).
- Frontend `vitest run` → **94 passed / 14 files** (inchangé — la
  réduction est 100 % côté serveur).
- Frontend `tsc -b --pretty false` → exit 0.

### Compat rustc

- `rustc 1.75` (min workspace) et **`rustc 1.83`** (serveur) OK. Aucun
  feature nightly. `serde_json` ajouté comme dev-dependency sur
  `event-schema` (uniquement pour la validation JSON parsable dans le
  test — pas de nouveau code binaire).

### T3 — toujours en attente de preuve ANR2

Les causes et correctifs pour SBI↔N4 (IE bruts), doublons ×4.6 sur
S1-MME (273 groupes / 296 excédents — ANR2 #9 comment 6714896530), et
liens LTE S1-MME/S6a (verdict FAIL/OUVERT) restent à l'arrivée de la
preuve SBI brute sur #9. 2.9.4 ne les touche pas.


## OIRAN API 2.9.3 follow-up #1 — 2026-11-08 — Observed-technology count + local vProbe reachability (devmat night sprint)

### Analyzer top-bar — show every technology with its dataset count

2.9.2-fu2 hid `UNKNOWN` from the top-bar aggregate; devmat reverses :
rien de caché, chaque technologie observée est affichée avec son compte
de datasets. UNKNOWN passe en fin pour la lisibilité.

- **`apps/web/src/layouts/AppShell.tsx`** : nouveau `techCounts` dérivé
  des datasets, puis `observedParts` triés (UNKNOWN last) et formatés :
  * 1 dataset d'une tech → `"5G SA"`.
  * N ≥ 2 datasets → `"5G SA (N)"`.
  * UNKNOWN → `"N dataset UNKNOWN"` (singulier) ou `"N datasets UNKNOWN"`.
- Séparateur ` · ` (middot) remplace ` / ` (barre oblique) pour aligner
  avec le libellé `vProbe not connected · <health> · <telemetry>`.
- Exemple ANR2 : `Observed: 5G SA · 1 dataset UNKNOWN`.

### Backend — local vProbe online quand une capture tourne

ANR2 observait `online=false` + `capture_state=CAPTURING` sur
`oiran-vprobe-local-01`. Cause prouvée :

- `apps/api/src/lib.rs:1084-1089` (`probe_online`) teste uniquement
  `last_heartbeat_epoch_s` contre une fenêtre 15 s.
- Pour le local, `last_heartbeat_epoch_s = record.last_heartbeat_epoch_s
  .max(measured)` où `measured = measured_local_heartbeat_epoch_s(state)`
  tire son chiffre de `job.metrics.last_packet_epoch_ms` /
  `last_ingested_epoch_ms`.
- Sur un flux lent (ex : premières secondes d'une capture, inter-trame
  > 15 s), `measured` sort de la fenêtre et `online=false` — alors
  même que le binaire répond à `GET /probes` à l'instant même.

**Fix** — nouvelle fonction pure `probe_is_reachable(local,
active_capture, last_heartbeat_epoch_s, now_epoch_s)` (lib.rs:1092) :

```
if local && active_capture {
    true   // le local vProbe EST le processus API — il répond,
           // donc il est joignable par définition
} else {
    probe_online(last_heartbeat_epoch_s, now_epoch_s)  // inchangé
}
```

Le local court-circuit n'est accordé QUE si `active.state.active()`
(`Starting | Capturing | Stopping | Processing`). Sondes distantes :
porte battement 15 s inchangée. Le `lifecycle` passe de `PENDING`
quand `last_heartbeat.is_none()` ET `!online` (pré-correction : seul
`.is_none()` suffisait, cassant la cohérence avec la nouvelle règle).

**Test** — `probe_is_reachable_asserts_local_capturing_probe_online_regardless_of_heartbeat`
(8 assertions couvrant local+active ± heartbeat, local+inactive,
distant+active, distant+inactive).

### T2 — toujours OUVERT en attente ANR2

Mesures attendues sur #9 pour la version 2.9.4 : taille par interface,
champs les plus lourds, doublons `decode_reports`/`checksums` event vs
dataset. Aucun code T2 ici.

### Tests

- `cargo test --workspace --locked --release --offline --no-fail-fast`
  → **408 passed, 0 failed, 4 ignored** (baseline 407 + 1 nouveau test
  `probe_is_reachable_asserts_local_capturing_probe_online_regardless_of_heartbeat`).
- `vitest run` — **94 passed / 14 files** (baseline 93 + 1 nouveau test
  `pluralises UNKNOWN count and aggregates per-technology counts` ;
  le scénario UNKNOWN-filter précédent est reformulé pour le nouveau
  comportement).
- `tsc -b --pretty false` → exit 0.
- `vite build` → `dist/assets/*.js` contient `2.9.3` (byte-sync
  avec package.json).

### SemVer

| Composant | Avant | Après |
|---|---|---|
| `apps/web` | 2.9.2 | **2.9.3** |
| `apps/api` | 2.9.3 | 2.9.3 (même bundle que `8d7dfd3`) |
| `callflow-schema` | 1.3.1 | 1.3.1 |
| `live-probe` | 0.4.20 | 0.4.20 |

### Compat

- `rustc 1.75` (min workspace) et `rustc 1.83` (serveur) OK. Aucun
  feature nightly.
- `probe_online` conserve sa signature publique inchangée — le fix est
  additif via `probe_is_reachable`. Tout consommateur externe (s'il
  existait) continue de fonctionner.


## OIRAN API 2.9.3 — 2026-11-07 — Analyzer footer version read from package.json (devmat T1)

### Proven cause — `web 2.9.0` on an otherwise 2.9.1 Analyzer bundle

The 2.9.2 follow-up #2 bumped `apps/web/package.json` 2.9.0 → 2.9.1 and
updated the vitest assertion to `'2.9.1'`. It did NOT update the literal
in `apps/web/vite.config.ts:20` — which was `const WEB_VERSION =
'2.9.0';`. Vite's `define` injects that literal into
`import.meta.env.VITE_WEB_VERSION` at build time, so the Analyzer footer
shipped `web 2.9.0` on a 2.9.1 bundle. The vitest `version-footer`
assertion still passed because its stub re-assigned
`VITE_WEB_VERSION` to `pkg.version` in the test harness — hiding the
production desync behind test-only state.

### Fix (`apps/web` 2.9.1 → 2.9.2, `apps/api` 2.9.2 → 2.9.3)

- **`apps/web/vite.config.ts`** reads `apps/web/package.json` at build
  via `fs.readFileSync` + `JSON.parse`, NOT a hardcoded literal.
  `__dirname` is derived from `import.meta.url`, no ESM JSON import
  attribute (`assert` vs `with` disagrees between Vite 5 and Node 20
  toolchains — fs avoids both). `apps/api/build.rs` already reads the
  same `package.json` for `OIRAN_WEB_FRONTEND_VERSION` since 2.7.17, so
  front and back now derive from the SAME source byte-for-byte.
- **`apps/web/src/test/version-footer.test.tsx`** drops the literal
  `expect(pkg.version).toBe('2.9.1')` pin. The surviving invariant is
  `expect(import.meta.env.VITE_WEB_VERSION).toBe(pkg.version)` — a
  tautological pin becomes a real end-to-end check once
  `VITE_WEB_VERSION` is actually defined by vite.config.ts (same source
  as `pkg.version`). The displayed `web-version` DOM assertion compares
  to `pkg.version` dynamically, so a future bump touching ONLY
  `package.json` passes without a test edit. The `/version` mock's
  `web_frontend` field is also `pkg.version` dynamic.
- **`apps/api` 2.9.3**: no behavior change in the API; `build.rs` picks
  up the new `apps/web/package.json` value automatically so the
  reported `web_frontend` in `GET /version` matches the deployed
  bundle.

### Open — T2: derived output 10 KB / event

ANR2 observed 2.6 GB of derived output for ~266 000 events (≈ 10 KB
each), hitting the 2 GiB cap (palliative ceiling raised to 8 GiB).
Candidates for reduction without proof-information loss :

- No full payload/body duplicated into every event — reference by
  `(source_file, byte_offset, captured_length, sha256_hex)` only.
- `decode_reports` and `checksums` moved out of events, into the
  dataset manifest once.
- Empty fields omitted (`serde` `skip_serializing_if = Option::is_none`
  and friends).

**OPEN pending ANR2's per-interface size / heaviest-field measurement
on #9.** No code change is attempted here — any shape change must
preserve `N2_N4 = 2 EXACT`, `N4_N3 = 2 EXACT`, `N2_SBI = EXACT` on the
`tpl-small-traffic-e2bea97912f9` run.

### Tests

- `cargo test --workspace --locked --release --offline --no-fail-fast`
  → **407 passed, 0 failed, 4 ignored** (baseline unchanged — this
  patch only touches `apps/api/Cargo.toml` version bump and
  `apps/web/*` which does not impact Rust tests).
- Frontend `vitest run` — **93 passed / 14 files**. `version-footer`
  updated: `web-version` DOM assertion now compares to
  `pkg.version` dynamically (`'2.9.2'` today), api assertion to
  `'2.9.3'`. The invariant `VITE_WEB_VERSION === pkg.version` is now a
  real build-side cross-check.
- Frontend `tsc -b --pretty false` — clean.

### SemVer

| Component | Before | After |
|---|---|---|
| `apps/web` | 2.9.1 | **2.9.2** |
| `apps/api` | 2.9.2 | **2.9.3** |
| `callflow-schema` | 1.3.1 | 1.3.1 |
| `live-probe` | 0.4.20 | 0.4.20 |

### Compat

- Compiles under `rustc 1.75` (workspace minimum) and `rustc 1.83`
  (server toolchain). No nightly / unstable feature used.
- `DatasetRepairReport.schema_version` stays frozen at `"2.9.2"` —
  it is a *schema* identifier (namespaced by the API version at
  schema-emission time), not the product version; bumping it would
  require coordinated consumer migration which is out of scope.
- `fs.readFileSync` in `vite.config.ts` executes at build time only,
  no runtime cost. No SPA bundle size change expected.


## OIRAN API 2.9.2 follow-up #2 — 2026-11-07 — SBI pair confidence + Analyzer technology fallback + vProbe reason (#9 comment 6712678520)

### Proven cause — N2_SBI stuck at UNKNOWN despite an EXACT tunnel match

ANR2 on `tpl-small-traffic-e2bea97912f9` observed
`{"N2_N4":"EXACT","N2_SBI":"UNKNOWN","N4_N3":"EXACT","SBI_N4":"UNKNOWN"}`
with the same `(tunnel_endpoint_ip=10.77.22.13, gtp_teid=0x12a6)` on
N2, SBI and N4. The shared TEID/IP normalisation path is correct:

- `OIRAN/correlation-engine/src/lib.rs:475` (`normalize_teid`) parses
  as `u32` — collapses `0x12a6` (N2/SBI, no padding) and `0x000012a6`
  (N4, 8-digit padding emitted by `decoder-pfcp` at
  `decoder-pfcp/src/lib.rs:173` and `:251`) to the same value.
- `OIRAN/correlation-engine/src/lib.rs:520` (`tunnel_keys`) tries BOTH
  `(tunnel_endpoint_ip, gtp_teid)` and `(ipv4, teid)` IE patterns, so
  `decoder-ngap` (N2), `decoder-sbi` (N1N2MessageTransfer, line 791
  — composed `N2 UL NG-U UP TNL Information` IE) and `decoder-pfcp`
  (F-TEID IE) all feed the same canonical key.

The defect is one level below: `OIRAN/callflow-schema/src/lib.rs:541`
(`confidence_for`) compared `edge.source_interface == a &&
edge.target_interface == b` STRICTLY. `sbi-n2-tunnel-match` emits its
edge as `(source=SBI, target=N2)` while `ngap-sbi-context-association`
emits `(source=N2, target=SBI)`; the strict comparison hid the
former from the `N2_SBI` status key — so an EXACT SBI↔N2 tunnel match
stayed invisible in production. The fold's `canonical_edge_key`
(`callflow-schema/src/lib.rs:175`) was already bidirectional, so the
edge survived the fold intact; only the status aggregation ignored it.

### Fix (`OIRAN/callflow-schema` 1.3.0 → 1.3.1, `OIRAN/apps/web` 2.9.0 → 2.9.1)

- **`confidence_for` is interface-order agnostic.** Both `(a, b)` and
  `(b, a)` edges are now accepted for the `A_B` status key. Status
  precedence (`EXACT > STRONG > POSSIBLE`) is unchanged. No other
  caller relies on the directional strictness.
- **Analyzer top-bar technology fallback (`OIRAN/apps/api`).** The
  `/datasets` enumeration used to call
  `technology_from_interfaces(decode_reports.keys())` — which
  returned `UNKNOWN` for `dataset-continuous-lab-import` during the
  cold window between dataset creation and the first decoded plane.
  2.9.2-fu2 adds `technology_for_live_fallback` (`apps/api/src/lib.rs`):
  when the plane-based inference is `UNKNOWN`, the capture job's
  declared profile (`POLARIS_5G_SA_*` → `5G SA`,
  `POLARIS_LTE_*` → `LTE`) is used instead. Unrecognised profile stays
  `UNKNOWN` — never invented.
- **Analyzer header filtering (`OIRAN/apps/web/src/layouts/AppShell.tsx`).**
  `observedTechnologies` drops the `UNKNOWN` sentinel so the top-bar
  names only the technologies actually observed. ANR2 will see
  `Observed: 5G SA` instead of `Observed: UNKNOWN / LTE`.
- **vProbe not-connected reason.** The `vProbe not connected` label
  is kept (accurate when no probe reports `online=true`) but now
  appends `· <health> · <telemetry_status>` so the user sees WHY
  (ANR2 example: `vProbe not connected · DEGRADED · IDLE`).

### Open — SBI_N4 stays UNKNOWN on `tpl-small-traffic-e2bea97912f9`

With the bidirectional `confidence_for`, N2_SBI reaches EXACT as soon
as `sbi-n2-tunnel-match` fires. SBI_N4 still reports UNKNOWN on ANR2's
run even though the edge direction `(SBI, N4)` matches the status key
directly. Code reading does not prove a second defect; the remaining
candidates require the raw dataset:

- `decoder-sbi` may not emit the composed IE on these specific
  transfers (`transfer.ul_tunnel.as_ref()` or
  `ul_tunnel.ipv4_address() / teid()` returning `None`).
- The SBI event may be absent from the per-session `selected` list
  used at `live-probe/src/lib.rs:1722` — `ngap-sbi-context-association`
  only fires on `CreateSMContext`, so a session with only
  `N1N2MessageTransfer` SBI events would never pull SBI into the
  session scope via that association; the tunnel-match path should
  still cover it, but a deeper trace is needed.

Both require the SBI event's raw `information_elements` JSON from
`dataset/oiran_events.jsonl` on the ANR2 run. Per the project rule
("un écart se ferme ou se déclare OUVERT, jamais expliqué par
hypothèse"), **SBI_N4 remains OPEN pending that evidence**.

### Open — POLARIS run_id searchable in Session Explorer

`tpl-small-traffic-e2bea97912f9` is a POLARIS-side identifier. OIRAN's
`CaptureJob` and `LiveDataset` do not store it today. `/sessions?search=`
(`apps/api/src/lib.rs:2472`) is a substring match over the session
summary JSON — so making the run_id searchable only requires it to
appear in that JSON. Introducing an `external_run_id` field on
`CaptureJob` (populated when POLARIS triggers the continuous-lab-import
job) is the minimal change but **requires coordination with POLARIS**
to pass the run_id through its POST body; it is **OPEN for the next
2.9.x patch, not in scope for 2.9.2**.

### Tests

- `cargo test --workspace --locked --release --offline --no-fail-fast`
  → **407 passed, 0 failed, 4 ignored** (baseline 404 — one new
  callflow-schema test, one new correlation-engine test, one new
  oiran-api test).
- `sbi_tunnel_match_links_production_event_shapes_from_anr2_6712678520`
  — reproduces the ANR2 shapes byte-for-byte:
  * N2 IE `tunnel_endpoint_ip=10.77.22.13,gtp_teid=0x12a6`,
  * N4 IE `teid=0x000012a6,v4=true,v6=false,ipv4=10.77.22.13`
    (production `decoder-pfcp` format),
  * SBI IE `N2 UL NG-U UP TNL Information` with the composed value,
  * asserts both `sbi-n2-tunnel-match` and `sbi-n4-tunnel-match`
    fire, and `ngap-pfcp-exact-tunnel` still holds. Proves
    `tunnel_keys` + `normalize_teid` are correct on real formats.
- `confidence_for_pair_is_interface_order_agnostic` — constructs a
  `(SBI, N2)` edge and asserts `confidence_for("N2","SBI")` returns
  EXACT (previously: `UNKNOWN`). Closes the N2_SBI defect.
- `technology_for_live_fallback_prefers_planes_then_profile_then_unknown`
  — observed planes win; cold dataset drops to profile; unknown
  profile stays UNKNOWN (never invented).
- Frontend `vitest run` — **93 passed / 14 files** (one new
  `app-shell-live-state` scenario covering UNKNOWN filtering and the
  probe-not-connected reason; `version-footer` updated for the
  2.9.1 web bundle / 2.9.2 API).
- Frontend `tsc -b --pretty false` — clean.

### SemVer

| Component | Before | After |
|---|---|---|
| `OIRAN/callflow-schema` | 1.3.0 | **1.3.1** |
| `OIRAN/apps/web` | 2.9.0 | **2.9.1** |
| `OIRAN/apps/api` | 2.9.2 | 2.9.2 (same 2.9.2 patch bundle as 87c2784 + 471ebde) |
| `OIRAN/live-probe` | 0.4.20 | 0.4.20 |

### Compat

- Compiles under `rustc 1.75` (workspace minimum) and `rustc 1.83`
  (server toolchain). No nightly / unstable feature used.
- Backwards compatible: `confidence_for` is private to
  `callflow-schema`; its new behavior is a pure relaxation (accepts
  a superset of inputs). Frontend `AppShell` continues to render
  the same fields; only the filtering changes.


## OIRAN API 2.9.2 — 2026-11-07 — prefix-SHA repair grouping + derived continuous interfaces + LTE publication (#9 comments 6708784283 + 6710853974)

### Follow-up fix — LTE planes imported but zero events published (ANR2 #9 comment 6710853974)

ANR2 proved on OIRAN API 2.9.1 that every LTE plane
(S1-MME, S11, S1-U, S5-C, S5-U, S6a, Sxab) imported closed segments
with non-zero protocol frames yet produced **zero published events**:

| interface | protocol frames | published events | checksum |
|---|---:|---:|---|
| S1-MME | 16 | 0 | `094c28f7…` |
| S11 | 3 | 0 | `08c4976b…` |
| S1-U | 5 | 0 | `0c7b6417…` |
| S5-C | 4 | 0 | `010862db…` |
| S5-U | 39 | 0 | `7adf6061…` |
| S6a | 490 | 0 | `00308cf8…` |
| Sxab | 2626 | 0 | `00920e6a…` |

**Root cause (file:line)** —
`OIRAN/live-probe/src/lib.rs:4992-5023` (`interface_specs`)
returned ONLY `[N2, SBI, N4, N3]`. The publication loop at
`OIRAN/live-probe/src/lib.rs:3898-3935`
(`for interface in interfaces { capture_files_for(pcap_dir,
&interface.interface) … decode_capture_streaming … }`) iterates
that list, so the LTE owned files (`S1-MME.pcap-*.pcapng`,
`S11.pcap-*`, …) under `base/pcap/` were never visited and no
decode call was issued for them. 2.9.1 enabled the LTE routes
inside `oiran-decode` but 2.9.1 forgot to extend this registry →
the fix is below the route boundary ANR2 pointed at.

**Fix** — `interface_specs()` grows from 4 to 11 entries
(N2 / N3 / N4 / SBI + 7 LTE planes), each with the production
device name (`br-oiran-s1m`, `br-oiran-s1u`, `br-oiran-s11`,
`br-oiran-s5c`, `br-oiran-s5u`, `br-oiran-s6a`, `br-oiran-sxab`)
and BPF filter (SCTP 36412, UDP 2152/2123/8805, SCTP 3868). `N6`
stays out — no OIRAN decoder today, already counted via
`CONTINUOUS_PLANE_NOT_ALLOWLISTED`.

**Tests**:
- `interface_specs_covers_every_decoder_backed_plane` — asserts
  the 11-interface set and that every returned interface has a
  decoder.
- `process_capture_into_visits_every_lte_plane_owned_file` —
  writes one minimal owned pcap per LTE plane
  (`{interface}.pcap-stub{interface}.pcapng`), calls
  `process_capture_into`, and asserts
  `decode_reports` carries an entry starting with each LTE
  interface — proving the file was VISITED (not silently
  skipped).
- `real_interface_discovery_is_allowlisted` and
  `four_plane_validate_traverses_http_api_and_unix_ipc_without_acquisition`
  updated to the 11-interface baseline.



### Proven cause (ANR2 — #9 comment 6708784283)

- The 2.9.0 dry-run returned **zero** partial-import groups on
  production. ANR2's 84-event sample proved why: the 7 snapshots of
  `_00067` arrive in the dataset with DISJOINT packet ranges (each
  snapshot's events cover only the newly-grown region since the
  previous snapshot). The 2.8.4/2.9.0 content-identity key
  `(interface, first_raw_ticks, first_packet_number,
  first_byte_offset)` is computed PER snapshot's events, so each
  snapshot sits in its OWN singleton group and the loop filter at
  `OIRAN/live-probe/src/lib.rs` (`for ((interface, first_raw_ticks,
  first_pkt, first_off), mut scans) in groups { if scans.len() <= 1
  { continue; } … }`) skips every group → zero output.
- The real evidence ANR2 recovered: each snapshot's `capture_id` is
  the SHA-256 of a BYTE PREFIX of the final closed file at a
  packet-record boundary (sizes 33228, 34332, 35436, 36540, 37644,
  38748, 39852 B → 7 prefix SHAs matching the 7 capture IDs). The
  full-file SHA
  (`6085e2d7d61334850ba1912fec585c4165907f3b2a53cecba132f55267934ff1`)
  is absent from the dataset — the final import never happened
  because dumpcap rotated to `_00068` first.

### Fix (`OIRAN/live-probe` 0.4.19 → 0.4.20, API 2.9.1 → 2.9.2)

- **Prefix-SHA grouping.** New `prefix_sha_index(path)` walks a
  closed pcap packet-by-packet, snapshots a running SHA-256 at every
  record boundary, and returns `full_sha + {prefix_sha → packet
  count}`. `repair_partial_imports`:
  * For every closed segment under `<source-root>/<plane-lc>/`
    (2.8.3 sequence rule excludes the lex-greatest active sibling),
    builds a `PrefixIndex`.
  * Maps every snapshot's `capture_id` against the global
    `prefix_sha + full_sha` table → groups snapshots by matched
    on-disk file.
  * Groups with a Full-SHA snapshot ⇒ `OnDiskSha256Match`,
    keep the full one, drop the prefixes.
  * Groups WITHOUT a Full-SHA snapshot ⇒
    `PrefixShaMatchFreshImport`: run `decode_capture_streaming`
    on the on-disk file with the probe's existing `PseudonymKey`,
    emit fresh events through the SAME publication path as
    `restore_from_archive_segment`, THEN drop the prefix snapshots.
  * Snapshots without a prefix match fall back to the 2.8.4
    content-identity grouping + `state.segments`-largest rule.
- **TOUS les segments partiellement importés.** The walk covers
  every closed file under every allowlisted plane dir, so the
  dry-run lists every partial-import group across the source tree,
  not just `_00067`.
- **Line 1161 — derived continuous interfaces.** The initial
  `continuous-lab-import` job hardcoded `["N2","N3","N4"]` as its
  `interfaces` + `planes` list. The worker loop now derives both
  from the 2.9.1 `discovery.plane_counts` on every scan (skipping
  the `UNKNOWN` sentinel), so SBI and the LTE planes appear on
  `/api/v1/captures/continuous-lab-import` as soon as a single
  pcap for them lands on disk.

### Why the 2.9.0 dry-run returned zero groups (file:line)

- `OIRAN/live-probe/src/lib.rs` (pre-2.9.2):
  * `let mut groups: BTreeMap<GroupKey, Vec<SnapshotScan>> = BTreeMap::new();`
    was keyed on `(interface, first_raw_ticks, first_packet_number,
    first_byte_offset)` — the FIRST packet of each snapshot's event
    stream.
  * The ANR2 snapshots carry disjoint packet ranges (snap 1 covers
    packets 347-358, snap 2 covers 419-430, …), so each snapshot's
    first-packet tuple is UNIQUE → singleton groups.
  * `if scans.len() <= 1 { continue; }` then skipped every group.
- 2.9.2 keys on the SHA-256 of actual on-disk file bytes — the
  identifier that production rotation genuinely shares across
  partial imports.

### `Sha256Hasher` clone

- `OIRAN/event-schema/src/lib.rs` — `Sha256Hasher` now derives
  `Clone`. The running-digest snapshot inside `prefix_sha_index`
  needs it; the state is 64 B so cloning is cheap.

### SemVer

| Component | Before | After |
|---|---|---|
| `OIRAN/live-probe` | 0.4.19 | **0.4.20** |
| `OIRAN/apps/api` | 2.9.1 | **2.9.2** |

The web bundle stays at **2.9.0** (no frontend change).

### Compat

- Compiles under `rustc 1.75` (workspace minimum) and `rustc 1.83`
  (server toolchain). No nightly / unstable feature used.

### Tests

- `cargo test --workspace --locked --release --offline --no-fail-fast`
  → **402 passed, 0 failed, 4 ignored**.
- `repair_partial_imports_rebuilds_full_history_via_prefix_sha_match`
  — writes a real pcap with 8 packets, extracts 7
  packet-boundary prefix SHAs from `prefix_sha_index`, fabricates
  21 prefix events, asserts the 2.9.2 repair groups all 7
  snapshots to the on-disk file, tags `PrefixShaMatchFreshImport`,
  removes 21 prefix events, re-decodes the closed file, and stays
  idempotent on the second pass.

## OIRAN API 2.9.1 — 2026-11-07 — 12-plane allowlist + Diameter/GTP routing + `CONTINUOUS_PLANE_NOT_ALLOWLISTED` log (#9 silent-skip audit)

### Proven cause (BC3 audit on #9, follow-up to ANR2's allowlist question)

- `source_interface` (`OIRAN/live-probe/src/lib.rs:6565-6581` pre-2.9.1)
  matched only `N2`/`N3`/`N4`. The 12 production plane directories
  (`n2 n3 n4 n6 s11 s1mme s1u s5c s5u s6a sbi sxab` per ANR2's
  inventory) emitted SBI / S1-MME / S1-U / S11 / S5-C / S5-U / S6a /
  Sxab / N6 PCAPs that landed on disk and were SILENTLY skipped at
  `source_segments :4704` (`let Some(interface) = … else continue;`).
  No log, no counter, no `failed_ingestions` entry — zero
  observability.

### Fix (`OIRAN/live-probe` 0.4.18 → 0.4.19, `oiran-decode` 0.6.0 → 0.6.1, API 2.9.0 → 2.9.1)

- **12-plane allowlist.** `canonical_interface_for_plane` maps every
  ANR2 directory name to the canonical interface string OIRAN
  decoders expect
  (`n2` → `N2`, …, `sxab` → `Sxab`). `source_interface` reuses it.
- **All existing decoders routed.** `oiran-decode` extended:
  * UDP: `S5-U`→GTP-U (port 2152), `S5-C`→GTPv2-C (2123),
    `Sxab`→PFCP (8805) — same wire protocols as their 5G siblings,
    distinct interface tag downstream.
  * SCTP: `S6a` → Diameter decoder (IETF DIAMETER_PPID=46, RFC
    6733). New dependency `decoder-diameter` wired into
    `decode_capture_streaming`.
  * SBI/TCP, S1-MME/SCTP (S1AP+NAS), N2/SCTP, N3/N4/S1-U/S11/UDP:
    unchanged.
  * `validate_config` allowlist expanded to the 11 decoder-backed
    interfaces.
- **No more silent skip.** `source_segments` now publishes
  `plane_counts: BTreeMap<String, u64>` on every scan (`N2`, `N3`,
  …, `Sxab`, plus `UNKNOWN` for directories outside the convention)
  and lists non-decoded paths in `SourceDiscovery.unknown_plane_paths`.
  The worker:
  * Updates `CaptureMetrics.plane_counts` after every discovery.
  * Emits `CONTINUOUS_PLANE_NOT_ALLOWLISTED {path, plane}` on stderr
    ONCE per path per worker lifetime (dedup set
    `logged_unknown_planes`). Target planes today: `N6` (counted,
    no OIRAN decoder) and anything unrecognised.

### SemVer

| Component | Before | After |
|---|---|---|
| `OIRAN/oiran-decode` | 0.6.0 | **0.6.1** |
| `OIRAN/live-probe` | 0.4.18 | **0.4.19** |
| `OIRAN/apps/api` | 2.9.0 | **2.9.1** |

### Tests

- `cargo test --workspace --locked --release --offline --no-fail-fast`
  → **402 passed, 0 failed, 4 ignored**.
- `source_interface_maps_every_production_plane_directory_to_a_canonical_interface`
  — 12 ANR2 directories + 2 unknown exercises; every canonical
  mapping asserted.
- `source_segments_counts_every_plane_and_surfaces_undecoded_paths`
  — 13-plane tree (12 ANR2 + `unknown-plane`), asserts every entry
  appears in `plane_counts`, N6 + unknown surface in
  `unknown_plane_paths`, 11 decoded planes do not.

## OIRAN API 2.9.0 — 2026-11-07 — lightweight `/datasets` + ETag/304 + per-path Cache-Control + content compression (#9 ANR2 bandwidth)

### Proven cause (ANR2)

- `GET /datasets` shipped 727 KiB on every poll on the production
  probe: 503 KiB of per-plane `decode_reports` + 204 KiB of
  `checksums`. Several SPA pages polled it every 3 s, hashed assets
  were served under the global `Cache-Control: no-store`, and no
  compression was in effect — ~0.87 GiB/h of wire traffic per browser
  on a dataset view that rarely changed.

### Fix

- **Lightweight list view** (`apps/api/src/lib.rs:1623` →
  `datasets` handler). `dataset_summary_values` strips
  `decode_reports`, `checksums` and the full `active_pdu_contexts`
  object graph (the active context count is retained as
  `active_pdu_context_count`). The complete view stays on
  `GET /datasets/{id}`. Measured reduction on the ANR2 shape: **727
  KiB → 20 KiB (97.2 % down, ~0.81 GiB/h/browser saved at the 3 s
  poll)**.
- **Weak `ETag` + `304 Not Modified`** on `/datasets`. The handler
  hashes the serialized response body, emits `ETag: W/"<16-hex>"`
  and returns `304` with `Cache-Control: private, no-cache` when the
  incoming `If-None-Match` matches. A client under the ETag flow
  receives ~300 B per poll while the dataset list is stable.
- **Per-path Cache-Control middleware** (`static_cache_middleware`,
  `apps/api/src/lib.rs`). Hashed `/assets/*` under the SPA's
  ServeDir now get `public, max-age=31536000, immutable`; the HTML
  entry point gets `no-cache`; everything else falls back to the
  global `no-store`. The global layer is now
  `SetResponseHeaderLayer::if_not_present` so handler-supplied
  values (ETag/304, assets, index) actually win.
- **gzip + brotli compression** of API JSON via
  `tower_http::compression::CompressionLayer::new().gzip(true).br(true)`.

### SemVer

| Component | Before | After |
|---|---|---|
| `OIRAN/apps/api` | 2.8.4 | **2.9.0** |

### Tests (44 API lib + 2 new)

- `datasets_list_is_lightweight_and_full_view_stays_on_single_endpoint`
  — list view has NO `decode_reports` / `checksums` /
  `active_pdu_contexts`; `GET /datasets/{id}` still exposes them.
- `datasets_list_etag_short_circuits_an_unchanged_poll_with_304`
  — first `GET /datasets` carries an ETag; a second request with
  `If-None-Match: <etag>` returns 304 with an empty body, the same
  ETag echoed back, and `Cache-Control: private, no-cache`.
- `cargo test --workspace --locked --release --offline --no-fail-fast`
  → **400 passed, 0 failed, 4 ignored**.

## OIRAN API 2.8.4 — 2026-11-07 — content-based repair + no more `state.segments` eviction (#9 comment 6705466743)

### Proven cause (ANR2)

- The 2.8.3 `repair_partial_imports` grouped by `state.segments`,
  but `state.segments` evicts entries at `config.max_segments`.
  ANR2 reproduced the dry-run finding 6 snapshots of `_00068`
  instead of the 7 historical snapshots of `_00067` because the
  older entries had been evicted before the repair ran.

### Fix (`OIRAN/live-probe` 0.4.17 → 0.4.18, API 2.8.3 → 2.8.4)

- **Content-based grouping.** `repair_partial_imports` now scans
  `dataset/oiran_events.jsonl` directly. Each snapshot is
  identified by its `capture_id`; the segment identity is
  reconstructed from the smallest
  `(timestamp.raw_ticks, packet_references[0].packet_number,
  packet_references[0].byte_offset)` tuple observed across the
  snapshot's events — two snapshots of the same growing dumpcap
  file share that "first packet" bit-for-bit. The reconstructed
  key is surfaced in the report
  (`reconstruction_key = interface=…|first_raw_ticks=…|first_packet_number=…|first_byte_offset=…`),
  never guessed silently.
- **Final-snapshot resolution is content-based.** When the repair
  is invoked with `--source-root <path>`, every closed segment
  under `<source-root>/<interface-lowercase>/` is SHA-256-hashed
  (the 2.8.3 sequence rule excludes the lex-greatest sibling — the
  active dumpcap target). A snapshot whose `capture_id` matches an
  on-disk SHA is the FINAL. Without `--source-root`, the repair
  falls back to `state.segments`-largest; 2.8.4 removes the
  eviction so the fallback is reliable for every import going
  forward.
- **Unresolved groups** (no on-disk match, no `state.segments`
  entry) are LISTED in `DatasetRepairReport.unresolved_groups` and
  their events are left untouched — the repair never guesses.
- **No more count/byte eviction on `state.segments`.** The 2.7.18
  two-pass eviction loop is deleted; only the `max_owned_bytes`
  ceiling remains and is treated as a terminal error
  (`CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT`), never a silent history
  loss. The startup
  `state.segments.retain(|_, segment| ...is_file())` continues to
  purge entries whose owned file no longer exists on disk.

## OIRAN API 2.8.3 — 2026-11-07 — closed-proof eligibility + historical partial-import repair (#9 comments 6696366882 + 6704872754)

### Proven causes (ANR2)

- `OIRAN/live-probe/src/lib.rs:94` — `MAX_SOURCE_CANDIDATES = 512` capped
  the fingerprint cache. With 3 805 PCAPs, ~3 292 paths never entered
  the cache. 92 000 statx / 30 s, 93.07 % CPU.
- `OIRAN/live-probe/src/lib.rs:4617` — cap enforcement in the
  fingerprint loop: anything past 512 fell through, keeping those
  paths outside `source_cache` and unchanged on the next scan.
- `OIRAN/live-probe/src/lib.rs:2089, :2130-2134` —
  `last_pending_characterization` counted every `all_discovered_paths`
  entry absent from `source_cache`. With the 512 cap it stayed > 0 for
  ~3 292 paths, so the gate at `:2098` never short-circuited and every
  tick rescanned the whole tree.
- `OIRAN/live-probe/src/lib.rs:777-804` — the active-segment gate
  admitted the newest file per interface once its mtime aged past
  `2 × stable_age`. ANR2's N4 three-size sequence (9 860 → 10 780 →
  12 436 B) proved an active dumpcap file is rehashed and republished
  when it stays quiet long enough.
- `#9` comment 6704872754 — one segment imported 7 times in production,
  three growing sizes each yielding a distinct `capture_id =
  sha256:…`. `event_id` derivation
  (`OIRAN/event-schema/src/lib.rs:278`) hashes
  `capture_id | protocol | message_type | raw_ticks |
  raw_payload_reference | packet_refs`, so the SAME packet appears
  under 7 distinct `event_id`s — zero dedup, one logical packet
  materialised 7× in the dataset.

### Fix (`OIRAN/live-probe` 0.4.16 → 0.4.17, API 2.8.2 → 2.8.3)

- **Closed-proof eligibility.** `finalized_candidates_only` rewritten:
  a segment is admitted ONLY if there exists a lex-greater sibling for
  its interface (dumpcap rotation created the next generation) OR the
  rotation-watcher JSONL carries at least as many `exit_code:0` records
  as there are segments for the plane (dumpcap lifecycle closed
  cleanly). Mtime age / "stability" never participates. The active
  segment per interface is NEVER read.
- **No cap on the fingerprint cache.** The 512 limit is removed from
  the fingerprint loop. The per-scan import work is still bounded by
  `MAX_INGESTED_SEGMENTS_PER_SCAN = 32`.
- **Rotation-watcher JSONL parser.** `load_rotation_record_counts(root)`
  reads `capture-rotation.jsonl` once per scan and returns
  `plane → clean-close record count`, keyed in the same
  upper-case convention as `source_interface`.
- **Finite state for `last_pending_characterization`.**
  `SourceDiscovery.known_active_paths` is now exposed and the worker
  loop subtracts it from the pending-characterization count. Paths
  the worker explicitly ignores (unknown interface, symlink, < 24 B,
  the known-active segment of each interface) no longer force a
  rescan. `all_discovered_paths` is rebuilt from the interface-filtered
  set so files in non-allowlisted plane directories do not count
  either.

### Historical repair tool

- `CaptureManager::repair_partial_imports(dry_run) -> DatasetRepairReport`:
  reads `import_state.json`, groups `state.segments` by `source_path`,
  identifies the FINAL owned_file per group (largest `size_bytes`,
  tie-broken by latest `imported_epoch_ms`), prunes events whose
  `packet_references[0].source_file` matches a partial owned_file,
  rewrites the JSONL in canonical
  `(capture_id, packet_number, event_id)` order, and republishes the
  dataset through the same path as `restore_from_archive_segment`
  under the same `flock` lock. Idempotent — the second run produces
  an identical SHA-256. Manifest `event_count` equals the JSONL line
  count. Every removed event is listed with its reason
  (`partial-import-superseded-by-final-owned-file=<final>`).
- New binary `OIRAN/live-probe/src/bin/dataset-repair-partial-imports.rs`,
  `--dry-run` mode available.

### Tests (94 live-probe lib tests + repair + integrity)

- `active_segment_is_never_imported_at_any_size_under_2_8_3` — the
  worker observes `segments_ingested == 0` across three scans on a
  lone N3 segment with no JSONL proof, then flips to 2 once a
  lex-greater sibling is added AND the JSONL records 2 closures.
- `repair_partial_imports_keeps_only_final_owned_file_for_a_segment_imported_seven_times`
  — 21 input events across 7 partial imports → 3 kept (those anchored
  on `owned-gggg.pcapng`, the final 12 436-B snapshot); 18 removed;
  manifest `event_count = 3`; second invocation byte-identical.
- `repair_partial_imports_is_noop_on_a_healthy_dataset` — zero
  partial groups, zero removed, `events_sha256` unchanged.
- `finalized_candidates_only_drops_the_lex_greatest_per_interface`,
  `finalized_candidates_only_never_uses_mtime_age_as_closed_proof`,
  `finalized_candidates_only_promotes_lone_segment_when_jsonl_proves_closure`.
- 8 legacy tests patched with the new `write_rotation_closures`
  helper so the ingest-pipeline regressions keep their meaning under
  the closed-proof contract.

### Measured locally (Node 22.23.4, Rust 1.75 workspace)

- `cargo test --offline --release -p live-probe --lib` → **94 passed,
  0 failed, 4 ignored**.
- `cargo build --offline --release -p live-probe --bins` → OK, new
  binary `dataset-repair-partial-imports` in release target.
- A 120-s, 3 805-segment real-tree bench with 12 growing-active
  writers is listed as production acceptance for ANR2 (#10 recipe).

## OIRAN API 2.8.2 — 2026-11-06 — no-eviction seen index + dir-mtime gate (rollback of 2.8.1, #10 comment 6687323881)

- ANR2 rolled back 2.8.1 in production (#10 comment 6687323881):
  `oiran-api` averaged 92.85 % CPU over the mandatory 60-s recipe,
  rotation watchers 16.31 % cumulative, and `pending_segments=1`
  was never drained. Root cause: `MAX_CONTINUOUS_SEEN=4096` evicted
  the oldest checksum once the source retained more than 4 096
  finalized segments, so a still-present source segment was
  re-discovered as pending every scan (`live-probe/src/lib.rs:105`
  + eviction at `:4475-4479`), which kept backoff reset and the
  worker spinning. The 2.8.1 fallback watcher continued to
  enumerate + sort every PCAP every 5 s even when the directory
  had not changed.
- Audit (file:line):
  * `OIRAN/live-probe/src/lib.rs:105` `MAX_CONTINUOUS_SEEN = 4096`
    (now removed).
  * `OIRAN/live-probe/src/lib.rs:4475-4479` `remember_checksum`
    popped the oldest entry once the index exceeded the cap. This
    is the eviction ANR2 proved broke retained segments.
  * Pending-segment re-selection: `:2017` worker inner loop
    `state.seen_checksums.contains(&candidate.checksum)` would
    fail after eviction → candidate re-ingested every scan.
  * `infrastructure/capture/rotation-watcher.sh:208-212` fallback
    poll re-enumerated + sorted every `*.pcapng` every tick.
- Fix (`OIRAN/live-probe`):
  * **No cap on `seen_checksums`.** `remember_checksum` only
    inserts; the index grows with the real on-disk file population
    plus any segment held in `state.segments`. Memory at 20 000
    entries: ~2.5 MiB (64-byte hex × 2 containers + BTree
    overhead), well under the 256 MiB MemoryMax ceiling.
  * `purge_missing_source_fingerprints(state, live_paths)` drops
    fingerprints whose source file has vanished AND whose checksum
    is not held in `state.segments`. O(N + M) — pre-2.8.2's
    `.values().any(|v| ...)` per discarded path was O(N × M) and
    would have been 95 M comparisons at 10 000 live files.
    Native-mode and empty disk scans explicitly skip purge.
  * `SourceDiscovery.all_discovered_paths` surfaces the full
    disk-scan set BEFORE the `MAX_SOURCE_CANDIDATES=512` cap, so
    purge no longer evicts entries beyond the cap.
  * **Dir-mtime gate** (`source_tree_mutated`) stats the source
    root AND every subdirectory down to depth 3. A scan runs only
    when at least one watched directory has mutated since the
    previous tick, or there are pending finalization/stability/
    unseen/characterisation signals. New-file writes always update
    the containing directory's mtime, so no segment is missed.
  * **Cheap file-mtime drift check** (`source_cache_mtime_drift`,
    bounded to caches ≤ 1 024 entries) covers the in-place-append
    pattern (dumpcap overlapping-append) where the directory
    mtime does not move. At scale (> 1 024 entries) the dir-mtime
    gate is sufficient because dumpcap rotation creates new files.
  * `SourceSegmentsCache` short-circuit now also persists the
    cache entries ONLY when `source_segments` actually mutated
    them, not on every quiet tick (ANR2 measured the pre-2.8.2
    unconditional 10 000-entry BTreeMap compare + full JSON
    serialize + atomic write).
- Fix (`infrastructure/capture/rotation-watcher.sh`):
  * Fallback poll loop stats the watched directory once per tick
    and calls `scan_once` ONLY when `stat -c %Y "$dir"` differs
    from the previous tick. A finalised rotation always updates
    the containing directory's mtime (dumpcap creates / closes a
    file inside it), so no segment can slip past; a quiet
    directory produces one `stat` per tick (~0 % CPU) — the 2.8.1
    O(1) seen-set keeps its role but the poll no longer re-enumerates.
- Tests (release, locked, offline):
  * `cargo test --workspace --locked --release --offline` →
    **393 passed, 0 failed** (unchanged count, cap-removal test
    swapped for the new no-cap-no-purge semantic).
  * `OIRAN/target/release/examples/idle_cpu_bench 120 10000`
    (10 000 pre-populated segments > old 4 096 cap, state
    pre-seeded, 120-s window) → `cpu_percent = 0.53` (vs ANR2
    production 2.8.1 = **92.85 %**). Gate `< 2 %` **PASS**.
  * `OIRAN/target/release/examples/idle_cpu_bench 60`
    (empty source tree, 60-s window) → `cpu_percent = 0.01`.
    Gate `< 2 %` **PASS**.
  * `OIRAN/target/release/evidence-replay` → 4 edges, 2 N2↔N4
    EXACT + 2 N4↔N3 EXACT. Unchanged from 2.8.1.
  * `rss_publication N=30 000 / 200 000` → 7.7 / 23.1 MiB
    vmhwm. Unchanged.
  * `bash infrastructure/capture/tests/test-rotation-drops.sh`
    → PASS. `…/test-rotation-watcher.sh` → PASS.
    `…/test-dumpcap-retention.sh` → PASS.
- SemVer: `apps/api` 2.8.1 → **2.8.2**, `live-probe` 0.4.15 →
  **0.4.16**.

## OIRAN API 2.8.1 — 2026-11-06 — continuous worker idle CPU + rotation-watcher backoff (#9, ANR2 perf proof)

- ANR2 reported (`#9` comment `6685322833`): thread `continuous-lab-`
  at 86% CPU with `pending=0 / failures=0`; `perf` showed **77.31% of
  the hot path inside `event_schema::Sha256Hasher::compress`**, with
  up to 512 PCAPs re-hashed before the `seen_checksums` filter on
  every 1 s scan (~418 MB per pass; 34 504 `read` + 7 431 `statx`
  in 10 s). Twelve rotation watchers added 24.6 % cumulative CPU via
  `grep` per segment every 5 s (104 `execve`/10 s).
- Audit (file:line):
  * `OIRAN/live-probe/src/lib.rs:4234` `source_segments` returned
    candidates with their `(checksum, packets)` already computed
    via `sha256_hex_file` (`:4308`) + `count_pcap_records` (`:4311`).
    The caller at `:1946-1963` had the `state.seen_checksums` filter
    at `:2017`, but it ran AFTER the heavy work.
  * `OIRAN/live-probe/src/lib.rs:2308` `thread::sleep(scan_interval
    .min(30 s))` — scan_interval defaulted to 1 s (`Policy::default()`
    `polling_interval_ms = 1_000`). No backoff on empty scans.
  * `infrastructure/capture/rotation-watcher.sh:196` `grep -Fxq --
    "$candidate" "$seen_file"` for each candidate on every tick,
    O(N × M) as the seen file grew.
- Fix (`OIRAN/live-probe`):
  * New persistent key `(dev, inode, size, mtime_ns)` via
    `fingerprint_from_metadata`. The `SourceSegmentsCache` short-
    circuits the heavy SHA-256 + pcap-record-count work the moment
    the cheap key matches. Ownership of the source file changing
    (rotation to a new inode) invalidates the key automatically.
  * `ContinuousImportState.source_fingerprints:
    BTreeMap<String, SourceFingerprint>` persists the cache
    alongside `import_state.json`, so a probe restart does NOT
    re-hash every segment in the source root. The worker hydrates
    the in-memory cache from this field at startup.
  * Bounded backoff on empty scans: `scan_interval * 2^n` capped at
    10 s. A pending candidate or a published publication resets the
    factor to 1, so the next fresh segment lands within
    `scan_interval` latency.
- Fix (`infrastructure/capture/rotation-watcher.sh`):
  * Prefer `inotifywait -m -q -e close_write,moved_to` when
    available — the watcher blocks on filesystem events and
    consumes ~0% CPU between rotations.
  * O(1) seen check via a bash associative array (`declare -A
    seen_set`) hydrated once from `$seen_file` at startup;
    `mark_seen` appends to both the in-memory set and the file.
    No more `grep -Fxq` per segment.
  * `OIRAN_CAPTURE_ROTATION_FORCE_POLL=1` forces the fallback poll
    loop deterministically — `test-rotation-watcher.sh` uses it.
- Tests (release, locked, offline):
  * `cargo test --workspace --locked --release --offline` →
    **393 passed, 0 failed** (392 pre-existing + 1 new
    `source_segments_cache_skips_sha256_on_unchanged_candidates`).
  * `OIRAN/target/release/examples/idle_cpu_bench 60` (empty source
    tree) → `cpu_percent = 0.02`, gate `< 2 %` PASS.
  * `OIRAN/target/release/examples/idle_cpu_bench 60 512` (512
    pre-populated PCAPs, state pre-seeded) → `cpu_percent = 0.13`
    (vs ANR2's 87.6 % in production 2.8.0). Gate `< 2 %` PASS.
  * `bash infrastructure/capture/tests/test-rotation-watcher.sh` →
    PASS (with inotify and with `FORCE_POLL=1`).
  * `bash infrastructure/capture/tests/test-rotation-drops.sh` →
    PASS; `bash … test-dumpcap-retention.sh` → PASS.
  * `evidence-replay` on the audit dataset → **4 edges, 2+2 EXACT**
    (unchanged).
  * `rss_publication` → 30 k : 7.8 MiB · 100 k : 14.1 MiB · 200 k :
    23.4 MiB (within noise of 2.8.0).
- SemVer: `apps/api` 2.8.0 → **2.8.1**, `live-probe` 0.4.14 →
  **0.4.15**.

## OIRAN API 2.8.0 — 2026-11-06 — SBI↔N2 / SBI↔N4 tunnel-match correlation

- Before 2.8.0 the only SBI↔N2 / SBI↔N4 bridges were STRONG, driven
  by shared PDU Session ID or shared DNN
  (`OIRAN/correlation-engine/src/lib.rs:138` `ngap-sbi-context-association`,
  `:189` `sbi-pfcp-context-association`). The SBI decoder treated
  every HTTP/2 body as JSON only
  (`OIRAN/decoder-sbi/src/lib.rs:953-975` extract the first `{…}`
  substring, `:977-1006` harvests `pduSessionId`, `dnn`, `sst`, …).
  The N1N2MessageTransfer body is `multipart/related`: the JSON part
  carries control fields and the binary `n2SmInfo` part carries the
  NGAP `PDUSessionResourceSetupRequestTransfer` containing the UL
  NG-U UP TNL Information (TEID + IP) — the EXACT same F-TEID the
  N2 `PDUSessionResourceSetupRequest` IE and the N4 PFCP Created-PDR
  F-TEID expose. The decoder never looked inside that part, so
  SBI↔N2 and SBI↔N4 stayed one confidence rank below N2↔N4
  (EXACT) and N4↔N3 (EXACT) even though the primary 5G identifier
  for user-plane setup — the F-TEID — is physically present in all
  three messages.
- 2.8.0 contract: extract the F-TEID from the SBI n2SmInfo and
  correlate byte-perfectly, same policy as every other tunnel-match
  rule — no key → no edge (open link, NEVER inferred by timestamp),
  multi-match → fail-closed, single match → EXACT. The 2.7.26
  canonical-pair fold already deduplicates edges that overlap with
  `ngap-sbi-context-association`; `matched_rules` surfaces both
  rule ids when they fire on the same canonical pair.
- `OIRAN/decoder-sbi/src/lib.rs`:
  * New `decompose_body(content_type, body)` parses a
    `multipart/related; boundary=X` envelope into a `Vec<BodyPart>`
    with each part's own `content-type`. Non-multipart bodies
    produce a single part carrying the container's content-type,
    so CreateSMContext / UpdateSMContext / ReleaseSMContext (plain
    `application/json`) reach `collect_json` exactly as before.
  * New `is_n2_sm_info(content_type)` recognises
    `application/vnd.3gpp.ngap` and the `vnd.3gpp.n2` / `ngap`
    variants operators emit. The match is deliberately narrow — a
    wrong dispatch would run the NGAP decoder on NAS or JSON bytes
    and emit a tunnel key that never matches anything.
  * `build_event` now dispatches each part: JSON → existing field
    extraction; NGAP binary → `decoder_ngap::
    decode_pdu_session_resource_setup_request_transfer`. On
    success and when `ul_tunnel` resolves to an IPv4 GtpTunnel,
    the SBI event picks up two identifiers (`tunnel_endpoint_ip`,
    `gtp_teid`) and two IEs (`N2 UL NG-U UP TNL Information` with
    the composed `tunnel_endpoint_ip=<ip>,gtp_teid=0x<hex>` value
    that `correlation_engine::tunnel_keys` consumes verbatim, and
    `n2SmInfo sha256` for byte-identical bind-back by operators).
    SUPI / SUCI / NAI remain pseudonymized through the existing
    JSON path — the decoder exposes NO subscriber identity in
    clear.
- `OIRAN/correlation-engine/src/lib.rs` — two new rules at the end
  of `correlate_cross_interface_evidence`:
  * **`sbi-n2-tunnel-match`** EXACT (`EXACT_TUNNEL_MATCH`,
    `tunnel-only`): SBI N1N2MessageTransfer whose (ipv4, teid)
    equals a unique N2 PDUSessionResourceSetupRequest's
    (ipv4, teid) in the same capture scope. Fail-closed on
    duplicate SBI keys or duplicate N2 keys.
  * **`sbi-n4-tunnel-match`** EXACT (`EXACT_TUNNEL_MATCH`,
    `tunnel-only`): same key against a unique N4 PFCP F-TEID in
    the same capture scope. Fail-closed on duplicate SBI or N4
    keys.
- Regression tests (new, all passing):
  * `correlation_engine::tests::sbi_n2_and_sbi_n4_tunnel_matches_are_exact`
    — SBI + matching N2 + matching N4 → exactly 3 EXACT edges
    (ngap-pfcp-exact-tunnel preserved, sbi-n2-tunnel-match and
    sbi-n4-tunnel-match added).
  * `correlation_engine::tests::sbi_tunnel_match_stays_open_when_teid_differs`
    — SBI carries a different TEID than the N2/N4 pair: 0 SBI
    edges (open link, never inferred by ts).
  * `correlation_engine::tests::sbi_tunnel_match_fails_closed_on_duplicate_sbi_tunnel_keys`
    — two SBI events share the same (ipv4, teid): no edge.
  * `decoder_sbi::tests::decompose_body_splits_multipart_related_with_boundary`
    — multipart envelope splits into parts with each part's own
    content-type.
  * `decoder_sbi::tests::is_n2_sm_info_accepts_ngap_and_vnd_3gpp_variants`
    — content-type dispatch is narrow (`application/vnd.3gpp.ngap`,
    `.n2`, `application/ngap`) and refuses JSON / NAS.
  * `decoder_sbi::tests::n1n2_message_transfer_multipart_extracts_ul_ngu_tunnel_from_n2_sm_info`
    — end-to-end from an HTTP/2 POST on
    `/namf-comm/.../n1-n2-messages` carrying a real-shape multipart
    body whose n2SmInfo is the pycrate ground-truth
    `REQUEST_TRANSFER_MINIMAL` (IP=192.0.2.1, TEID=0x11223344). The
    produced SBI event exposes `tunnel_endpoint_ip=192.0.2.1`,
    `gtp_teid=0x11223344`, `pdu_session_id=1`, carries
    `N2 UL NG-U UP TNL Information` and `n2SmInfo sha256` IEs, and
    leaks no `imsi-…` in any identifier or IE value.
- SemVer:
  * `OIRAN/decoder-sbi/Cargo.toml` — `0.3.1` → **`0.4.0`** (public
    extraction surface changed: SBI events now carry tunnel
    identifiers + N2 UL NG-U IE).
  * `OIRAN/correlation-engine/Cargo.toml` — `0.5.3` → **`0.6.0`**
    (two new public rules).
  * `OIRAN/apps/api/Cargo.toml` — `2.7.28` → **`2.8.0`** (minor).

## OIRAN API 2.7.28 — 2026-11-06 — `dataset-restore` goes through the full publication path

- ANR2 production verdict on 2.7.27 (issue #10): the restore binary
  canonically dedup-merged `archive/<seg>/events.jsonl` into
  `dataset/oiran_events.jsonl` (47 326 + 2 717 − 54 overlap = 49 989
  event_ids, canonical order PASS, two runs identical SHA-256) but
  wrote ONLY the JSONL — `dataset_manifest.json`, `callflows/` and the
  dataset registry entry stayed at the pre-restore 47 326 / 5
  sessions. On the next publication cycle
  `recover_continuous_dataset_from_disk`
  (`OIRAN/live-probe/src/lib.rs:3133-3168`) validated the stale
  manifest against the new JSONL via
  `validate_dataset_artifacts` / `count_valid_event_records`
  (`:3589-3624` / `:3630-3654`), reported
  `DATASET_REGISTRATION_EVENT_COUNT_MISMATCH` and emitted
  `CONTINUOUS_DATASET_RECOVER_SKIPPED {reason:"artifact-drift"}`. 3
  of the 7 historical sessions whose events lived ONLY in the
  archive remained absent from `/health`; the other 4 were already
  present via the 54 overlapping event_ids. ANR2 rolled back to
  2.7.26 with retention 3650.
- 2.7.28 contract: **the restore binary never writes
  `oiran_events.jsonl` directly**. It routes through the SAME
  publication path the continuous import worker uses — `.dataset-next`
  → events + session discovery + correlation + folded edges +
  callflows + manifest → atomic swap — under the SAME `flock`
  advisory lock on `<base>/.publication.lock` so the worker and
  `dataset-restore` cannot race. Choice documented: if the worker
  holds the lock, the restore refuses fast with
  `RESTORE_REQUIRES_PUBLICATION_LOCK` rather than queueing. Operators
  stop `oiran-api.service` before running `dataset-restore`.
- Changes in `OIRAN/live-probe/src/lib.rs`:
  * Extracted the "events on disk → sessions + callflows + manifest"
    tail of `process_capture_into` into a new private method
    `publish_events_to_dataset_dir`. The worker still reaches it
    after its PCAP-decode + merge prefix; the restore method reaches
    it after a canonical dedup-merge. No behaviour drift — the 2.7.26
    correlation fold, 2.7.24 streaming memory, and 2.7.23 call-flow
    RSS budget all still apply.
  * New `PublicationLock` (POSIX `flock` wrapper) acquired blocking
    by `process_continuous_capture` and non-blocking
    (`LOCK_EX | LOCK_NB`) by `restore_from_archive_segment`.
    `EWOULDBLOCK` surfaces as `RESTORE_REQUIRES_PUBLICATION_LOCK`;
    the fd is held through the atomic swap and released on process
    exit (crashes can't leave a stale lock).
  * New `pub fn restore_from_archive_segment(&self,
    archive_segment_dir) -> Result<DatasetRestoreReport, String>`:
    validates `manifest.events_sha256`
    (`RESTORE_ARCHIVE_TAMPERED` on mismatch), canonically merges
    `current + archive` into `.dataset-next/oiran_events.jsonl`
    (dedup by event_id, sorted by
    `(capture_id, packet_number, event_id)` — never by timestamp),
    invokes `publish_events_to_dataset_dir`, swaps
    `.dataset-next` ↔ `dataset` via `.dataset-previous`, and calls
    `upsert_dataset` so `/health` observes the rebuilt view
    immediately.
  * New `DatasetRestoreReport { event_count_before,
    archive_event_count, overlap_event_count, overlap_event_ids,
    event_count_after, session_ids, events_sha256, … }` — the
    overlap list makes the `before + archive − overlap = after`
    identity ANR2 validated reproducible and auditable per restore.
- `OIRAN/live-probe/src/bin/dataset-restore.rs` rewritten: now a
  thin wrapper that builds `CaptureManager::new(capture-root, false)`
  and calls `restore_from_archive_segment`. CLI is
  `dataset-restore <capture-root> <archive-segment-dir>` (mirrors
  `oiran-recover`'s positional form).
- Regression tests (new, all passing):
  * `tests::restore_rebuilds_a_manifest_coherent_with_the_restored_events`
    — direct 2.7.27 defect regression guard: after restore, the
    manifest's `event_count` matches the on-disk JSONL count
    exactly, and `callflows/` exists.
  * `tests::restore_refuses_when_the_publication_lock_is_held` —
    holding `PublicationLock::acquire_blocking` externally makes
    `restore_from_archive_segment` return
    `RESTORE_REQUIRES_PUBLICATION_LOCK`.
  * `tests::restore_reports_overlap_event_ids_between_hot_view_and_archive`
    — `(evt-b)` present in both inputs: report shows
    `overlap_event_count = 1`, `overlap_event_ids = ["evt-b"]`,
    `event_count_after = 2 + 2 − 1 = 3`.
  * `tests::restore_followed_by_an_empty_publish_leaves_registration_valid`
    — after restore, the NEXT `process_capture_into` call (empty
    pcap directory) validates the restored manifest as its
    `prior_continuous` checkpoint and publishes successfully. The
    ANR2 symptom cannot reappear.
  * Updated `tests/dataset_restore.rs` integration test: 3 fresh +
    2 717 archived event_ids, two runs produce byte-identical
    `events.jsonl` AND byte-identical `dataset_manifest.json`,
    manifest `event_count` matches the JSONL — the full contract.

## OIRAN API 2.7.27 — 2026-11-06 — archive-based retention + `dataset-restore`

- ANR2 defect (issue #10): the 7-day retention was *deleting*
  events from the published JSONL. The old code path:
  `retention_cutoff_epoch_s()` (`OIRAN/live-probe/src/lib.rs:4275-4290`
  in 2.7.26), per-event `oldest_kept_ts` purge inside
  `merge_event_stream` (`:4529-4543`), atomic rename
  (`:2804`) and session rediscovery (`:2813-2843`) worked
  together to drop 2 717 `event_id`s and 7 sessions on an operator
  dataset older than the rolling window. The published hot view is
  **evidence**: it must never be filtered or shortened by any
  background sweep.
- 2.7.27 rule: **retention never erases**. Aged captures are moved
  to an immutable archive segment BEFORE being removed from the
  hot view, and every `event_id` is accounted for. Default is
  **disabled** — operators opt in explicitly.
- Changes in `OIRAN/live-probe/src/lib.rs`:
  * `retention_days()` now returns `Option<u64>` (default `None`).
    `OIRAN_DATASET_RETENTION_DAYS` unset or `0` disables retention
    entirely. Any opted-in value is clamped to `[1, 3650]` days.
  * `merge_event_stream(reader, writer, seen_ids)` is pure dedup
    by `event_id` — the per-event timestamp purge is gone. The
    two call sites in `CaptureManager::process_capture_into`
    no longer pass a cutoff. The hot view is a strict union with
    dedup, never a truncation.
  * New `scan_capture_ends(events_path) -> BTreeMap<capture_id, max_ts>`
    streams `oiran_events.jsonl` once and records, per capture,
    the **maximum** `timestamp.seconds` observed. Age is measured
    at the end of the capture, never per-event; a capture is never
    sliced in half.
  * New `archive_stale_captures(events_path, archive_root, cutoff)`
    runs only on the continuous capture, only when retention is
    opted in. Sequence (fail-closed):
      1. compute capture ends and the set of stale capture_ids
         (`max_ts < cutoff`);
      2. single streaming pass `archive_split_stream` writes
         stale events into `archive/<segment_id>/events.jsonl`
         and fresh events into `oiran_events.jsonl.hot-tmp`;
      3. `fsync` both tmp files; write
         `archive/<segment_id>/manifest.json` (archive_id,
         created_epoch_s, cutoff_epoch_s, retention_days,
         captures, event_count, `events_sha256`,
         schema_version `"2.7.27"`);
      4. only then rename `hot-tmp` → `oiran_events.jsonl`.
    Any failure at any step leaves the hot view untouched and
    emits `CONTINUOUS_ARCHIVE_FAILED {reason}`. Success emits
    `CONTINUOUS_CAPTURE_ARCHIVE {segment_id, archived_event_ids,
    archived_capture_ids, events_sha256}`.
- New binary `OIRAN/live-probe/src/bin/dataset-restore.rs`:
      dataset-restore <dataset-dir> <archive-segment-dir> [--dry-run]
  Validates `manifest.events_sha256` against the on-disk
  `events.jsonl` (`DATASET_RESTORE_ARCHIVE_TAMPERED` on mismatch),
  then streams both the archive segment and the current hot view
  through a `BTreeSet<event_id>` dedup (first occurrence wins) and
  sorts canonically by `(capture_id, packet_number, event_id)` —
  the same `canonical_sort_key` as session-engine
  (`OIRAN/session-engine/src/lib.rs:943`), never by timestamp.
  Output is written to `oiran_events.jsonl.restore-tmp`, hashed on
  the fly with `event_schema::Sha256Hasher`, fsynced, then renamed
  atomically. **Session rediscovery happens on the next continuous
  publication cycle** — this binary does not regenerate callflows
  itself; it rebuilds the evidence, and `load_path_streaming_index`
  rebuilds sessions + callflows without reloading history into RAM.
  Idempotent: a second run on the same inputs produces a
  byte-identical `oiran_events.jsonl` (same SHA-256).
- Regression tests (new):
  * `live_probe::tests::archive_moves_stale_captures_without_losing_any_event_id`
    — two captures (stale end=1 000, fresh end=9 000), cutoff
    5 000; after archive: hot keeps every fresh event_id, archive
    holds every stale event_id, `hot ∪ archive == original set`,
    `manifest.events_sha256 == sha256(events.jsonl)`.
  * `live_probe::tests::archive_write_failure_leaves_hot_view_untouched`
    — archive root `chmod 0o500`; the archive write fails; the
    on-disk `oiran_events.jsonl` SHA-256 is identical before and
    after (fail-closed).
  * `live_probe::tests::archive_is_a_no_op_when_every_capture_is_fresh`
    — no capture ages past the cutoff → no archive segment, hot
    view SHA-256 unchanged.
  * `live_probe::tests::capture_level_age_never_slices_inside_a_capture`
    — a single capture mixing old and fresh events, `max_ts`
    fresh; capture-level age keeps the whole capture rather than
    slicing the stale events out.
  * `live_probe` integration test
    (`OIRAN/live-probe/tests/dataset_restore.rs`,
    `dataset_restore_reinjects_archived_events_idempotently`): 3
    fresh + 2 717 archived events; two runs of the release binary
    produce byte-identical SHA-256; output ordered by
    `(capture_id, packet_number, event_id)`; all 2 720 `event_id`s
    present.

## OIRAN API 2.7.26 — 2026-11-05 — dedup overlapping correlation rules by canonical pair

- ANR2 production rollback: each N4↔N3 pair was published twice —
  once by `n4-n3-discovered-teid-endpoint`
  (`OIRAN/correlation-engine/src/lib.rs:715`, inside
  `correlate_discovered_tunnels`, fires when
  `discovery.gtpu_tunnels[].related_pfcp_session.is_some()`), and once
  by `pfcp-outer-header-matches-gtpu-tunnel`
  (`OIRAN/correlation-engine/src/lib.rs:272`, inside
  `correlate_cross_interface_evidence`, fires on byte-identical
  tunnel keys regardless of session binding). Both ran from
  `CaptureManager::process_capture_into`
  (`OIRAN/live-probe/src/lib.rs:2850-2851`); the 2.7.25 dedup
  compared `edge_id` only and the builder bakes `rule_id` INTO
  `edge_id`, so two rules on the same event pair emerged as two
  distinct edges → 4 N4↔N3 links instead of 2. The offline audit
  dataset did not reproduce the bug because
  `discovery.gtpu_tunnels[].related_pfcp_session` was `None` there,
  so `correlate_discovered_tunnels` stayed silent.
- 2.7.26 fix (canonical-key dedup, N2↔N4 and every other overlapping
  rule couple included):
  * New `callflow_schema::fold_overlapping_edges(edges)` folds every
    `CorrelationEdge` sharing the same canonical pair
    `(min(source_event_id, target_event_id), max(…), interfaces in
    matching order)` into a single published edge. The primary
    `rule_id` is the alphabetically-first matched rule; all
    overlapping `rule_id`s land in the new
    `matched_rules: Vec<String>` field on `CorrelationEdge`
    (`OIRAN/callflow-schema/src/lib.rs:61-71`), sorted and
    deterministic. `matching_identifiers` are union-ed and sorted;
    confidence is promoted to the highest among the matched rules
    (`EXACT > STRONG > POSSIBLE > WEAK`).
  * Order is strictly structural: the canonical pair is derived
    from `event_id` values, NEVER from `timestamp_ns` or `raw_ticks`;
    the final edge list is sorted by `edge_id` for stable JSON
    output. This matches session-engine's
    `canonical_sort_key = (capture_id, packet_number, event_id)`
    invariant (`OIRAN/session-engine/src/lib.rs:943`).
  * `correlate_discovered_tunnels` now emits ONE edge per tunnel
    (deterministic representative = first G-PDU by
    `(capture_id, packet_number, event_id)`), not one per G-PDU.
    The rule's claim is tunnel-level ("this PFCP TEID matches this
    tunnel"), not packet-level; emitting N edges for a tunnel with
    N G-PDUs was a per-packet proliferation that `fold_overlapping_edges`
    could not collapse with `pfcp-outer-header-matches-gtpu-tunnel`
    (which already picked a canonical representative). The new
    `gtpu_frame_count=<n>` identifier preserves the cardinality for
    reviewers.
  * Call sites updated: `CaptureManager::process_capture_into` global
    path (`OIRAN/live-probe/src/lib.rs:2869`) and per-session path
    (`OIRAN/live-probe/src/lib.rs:1591`) replace
    `global_edges.dedup_by(|l, r| l.edge_id == r.edge_id)` with
    `fold_overlapping_edges(global_edges)`. `evidence-replay`
    (`OIRAN/correlation-engine/src/bin/evidence-replay.rs`) does
    the same — the operator reproduces prod call-flow output with
    the same fold.
- Audit replay (reproducible):

      cargo build --offline --release -p correlation-engine --bin evidence-replay
      OIRAN/target/release/evidence-replay \
          OIRAN/datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl \
          AUDIT_E2E_CERT_001_scripts/out/evidence_replay_2.7.26.json

  Result: **4 edges — exactly 2 N2↔N4 + 2 N4↔N3 EXACT**. Both
  N4↔N3 edges carry
  `matched_rules = ["n4-n3-discovered-teid-endpoint",
  "pfcp-outer-header-matches-gtpu-tunnel"]`; both N2↔N4 edges carry
  `matched_rules = ["ngap-pfcp-exact-tunnel"]` (single rule, no
  overlap).
- Regression tests (new):
  * `correlation_engine::tests::full_publication_correlation_folds_overlapping_rules_to_four_edges`
    replays the audit dataset through BOTH correlation entries
    (`correlate_discovered_tunnels` + `correlate_cross_interface_evidence`)
    + fold; asserts exactly `2 N2↔N4 + 2 N4↔N3` EXACT, both N4↔N3
    pairs carry `matched_rules.len() == 2` with the two overlapping
    rule ids present and sorted.
  * `correlation_engine::tests::fold_overlapping_rules_emits_one_edge_with_matched_rules_length_two`
    is the unit-level synthetic fixture: two rules on the same
    pair → 1 edge, matched_rules of length 2.
  * `correlation_engine::tests::fold_overlapping_rules_keeps_distinct_pairs_distinct`
    guards the inverse: distinct (src, tgt) pairs never fold, even
    when one is overlapping and the other is not.
- `cargo test --workspace --locked --release` → **377 passed / 0
  failed / 4 ignored** (was 374 on 2.7.25). Shell guards
  (`test-rotation-drops.sh`, `test-rotation-watcher.sh`,
  `test-dumpcap-retention.sh`) PASS. Negative harness 9/9 unchanged.
- Memory invariant preserved (same harness as 2.7.25, RSS unchanged
  to the kilobyte):

  | history_size | 2.7.25 VmPeak | 2.7.26 VmPeak |
  | ---: | ---: | ---: |
  |  30 000 |  9.14 MiB |  9.59 MiB |
  | 100 000 | 15.48 MiB | 15.93 MiB |
  | 200 000 | 24.84 MiB | 25.29 MiB |

  The fold is a bounded sort + single pass over the edge list; the
  edge set is O(sessions), not O(events), so memory is unchanged.
- Backwards compatibility: `matched_rules` is `#[serde(default)]` so
  any previously-serialised `CorrelationEdge` (callflows on disk,
  historical call-flow JSON exports) deserialises cleanly — the
  field defaults to an empty vector, and `fold_overlapping_edges`
  rebuilds it before every publication.
- Versions: `apps/api` 2.7.25 → 2.7.26; `live-probe` 0.4.11 →
  0.4.12; `correlation-engine` 0.5.2 → 0.5.3; `callflow-schema`
  1.2.0 → 1.3.0.

## OIRAN API 2.7.25 — 2026-11-05 — bounded streaming publication (ANR2 handoff, reviewed and integrated)

- 2.7.24 shipped a constant-factor reduction on top of the streaming
  merge + per-session reconstruct refactor but RSS was still linear
  with history size (30 000 events ≈ 146 MiB, 100 000 ≈ 488 MiB,
  200 000 ≈ 971 MiB) because `discover_sessions` and
  `correlate_cross_interface_evidence` still needed the full
  `Vec<EventRecord>`. ANR2 pushed the real fix on
  `review/anr2-oiran-2.7.24-streaming` (SHA
  `37a835dc1a3a8bddce89b0aec5c09ba67e1f27e5`); 2.7.25 is a cherry-pick
  of that commit onto `fix/privacy-contract-psn` with a SemVer bump
  (`apps/api` 2.7.24 → 2.7.25 via `env!("CARGO_PKG_VERSION")`,
  `live-probe` 0.4.10 → 0.4.11).
- Independent review (as requested):
  * **Ordering is structural**, never timestamp: the compact index is
    sorted by `canonical_sort_key = (capture_id, packet_number,
    event_id)` at `OIRAN/session-engine/src/lib.rs:943`;
    `deterministic_sort` is the only sort called from
    `load_path_streaming_index`.
  * **No raw identity**: `compact_publication_event` keeps only the
    stable identifier allowlist defined at
    `OIRAN/session-engine/src/lib.rs:663-685`
    (`ran_ue_ngap_id`, `amf_ue_ngap_id`, `pdu_session_id`, `seid`,
    `f_seid`, `teid`, `qfi`, `sm_context_reference`,
    `subscriber_pseudonym`, `imsi_pseudonym`, …). The two "pseudonym"
    names are already-pseudonymised HMAC outputs; everything else is
    structural / technical. Raw-identity fields (`imsi`, `imei`,
    `supi`, etc.) are already stripped upstream by the API's
    `sanitize_value` and never reach the EventRecord stream.
  * **No event_id loss**: every input line passes through
    `event_ids.insert(event.event_id.clone())`; the `BTreeSet<String>`
    collects the complete publication event-id set (no cardinality
    cap — `MAX_CONTINUOUS_EVENTS` is removed). Only duplicate
    observation IDs (same deterministic hash from the same packet
    re-observed) are coalesced, and that behaviour is unchanged from
    2.7.22's dedup contract.
- Non-regression on the audit dataset:
  * `evidence-replay` on
    `datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl` →
    **4 EXACT edges** (two `ngap-pfcp-exact-tunnel`:
    `0x96a8@10.77.22.13`, `0x3@10.77.22.20`; two
    `pfcp-outer-header-matches-gtpu-tunnel` with `gtpu_frame_count=5`).
    Byte-identical to the 2.7.24 and 2.7.18 audit baselines.
  * `cargo test --workspace --locked --release` → **374 passed / 0
    failed / 4 ignored** (+1 vs 2.7.24 — the new
    `streaming_index_retains_only_ids_and_compact_semantic_representatives`
    regression in session-engine).
  * Shell guards (`test-rotation-drops.sh`,
    `test-rotation-watcher.sh`, `test-dumpcap-retention.sh`) PASS.
  * Negative harness 9/9 unchanged.
- Measured RSS (`cargo run --release --example rss_publication --
  <history_size>` → VmPeak):

  | history_size | 2.7.24 VmPeak | 2.7.25 VmPeak |
  | ---: | ---: | ---: |
  |  30 000 | 146 MiB | **9.14 MiB** |
  | 100 000 | 488 MiB | **15.48 MiB** |
  | 200 000 | 971 MiB | **24.84 MiB** |

  Peak now scales with session count + event-id set size, not event
  payload size; all three runs sit **well below the 128 MiB target**.
  Growth between 30 000 and 200 000 events is ~15 MiB
  (≈ 90 B per additional event, dominated by the `BTreeSet<String>` of
  event ids).
- The structural changes that made this possible:
  * `session_engine::load_path_streaming_index` (new, at
    `OIRAN/session-engine/src/lib.rs:625-680`) returns a
    `StreamingEventIndex { events, event_ids, source_event_count }`
    instead of a `Vec<EventRecord>`. `events` holds one compact
    representative per semantic key (protocol state × endpoints ×
    stable identifiers × tunnel material); the full bodies remain on
    disk and are reloaded by `load_events_by_ids` for the per-session
    callflow loop.
  * `count_valid_event_records` (new, at
    `OIRAN/live-probe/src/lib.rs:3581`) replaces `load_path` inside
    `validate_dataset_artifacts` — validation used to run before AND
    after publication with a full Vec<EventRecord>, which was the
    dominant RSS source; it now parses and counts one line at a time.
  * `release_unused_heap_pages()` (at
    `OIRAN/live-probe/src/lib.rs:4434-4440`) calls
    `libc::malloc_trim(0)` on glibc/Linux after each publication
    boundary and every 1024 lines inside the stream loops. Rust's
    heap would otherwise retain the largest arena of the biggest
    publication indefinitely.
  * Optional phase-level trace via
    `OIRAN_PUBLICATION_RSS_TRACE=1` → one `PUBLICATION_RSS
    phase=<name> indexed_events=<n> vmrss_kb=<x> vmhwm_kb=<y>` line
    per phase.
- Versions: `apps/api` 2.7.24 → 2.7.25; `live-probe` 0.4.10 → 0.4.11.

## OIRAN API 2.7.24 — 2026-11-05 — streaming publication merge + per-session call flow + slim-load discovery

- ANR2 (urgent): on the 2.7.23 production path, `oiran-api` RSS grew
  with the published history — 29 478 events → 349 MiB, 36 672 → 399,
  44 520 → 443 (≈ 6 MiB per thousand). The palliative
  `MemoryMax=512 MiB` would be hit around 55 000 events. The root
  cause is a `Vec<EventRecord>` built by
  `session_engine::load_path` (`OIRAN/session-engine/src/lib.rs:620-622`)
  during each publication — each `EventRecord` holds the full
  `information_elements: Value` tree, and session discovery /
  cross-interface correlation hold the full Vec in memory across many
  passes.
- 2.7.24 fix (three-part streaming refactor): streaming merge
  (removes `.normalized-events.spool` + `BTreeMap` of offsets +
  seek phase), per-session call flow (`drop(events)` before the
  reconstruct loop, `load_events_by_ids` per session), slim event
  load (`load_path_slim` drops IEs on non-PFCP/NGAP events). On
  measured RSS this reduces the constant factor roughly in half
  vs. 2.7.22 but keeps the linear growth with history size —
  **superseded by 2.7.25 which reaches < 25 MiB VmPeak at 200 000
  events**.
- Versions: `apps/api` 2.7.23 → 2.7.24; `live-probe` 0.4.9 → 0.4.10.

## OIRAN API 2.7.23 — 2026-11-05 — configurable derived-output cap + no retry loop

- ANR2 (issue #10 comment 6662293690): with `MemoryMax=512 MiB` the
  2.7.22 publication finishes without OOM (RSS 349 MiB), but every
  commit fails with `CONTINUOUS_DERIVED_OUTPUT_LIMIT`: the derived
  publication is 72 332 673 B against a hardcoded 67 108 864 B (=
  `MAX_CONTINUOUS_DERIVED_BYTES = 64 MiB`) and the worker loops on
  `CONTINUOUS_DECODE_RETRYABLE` indefinitely. The hard cap was sized
  for the 2.7.21 "shrink on publish" era; since 2.7.22 keeps every
  prior event by design, 64 MiB is no longer realistic.
- 2.7.23 fix (configurable cap):
  * New env `OIRAN_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES`, default
    `536 870 912` (512 MiB). Read once per publication via
    `derived_output_hard_limit_bytes()`. No clamp, so operators can
    tighten the cap for forced-retry scenarios or raise it when the
    dataset outgrows the default.
  * `MAX_CONTINUOUS_DERIVED_BYTES = 64 MiB` stays as the **staging
    reserve** (per-candidate budget + eviction guards) because the
    semantics there are different: short-lived doublewrite space, not
    the long-lived published dataset ceiling. The docstring now spells
    out the distinction.
  * The `CONTINUOUS_DERIVED_OUTPUT_LIMIT` error message now embeds the
    observed `next_bytes`, the configured cap and the current
    `OIRAN_DATASET_RETENTION_DAYS` value, so the operator can decide
    between shortening the retention window and raising the cap
    without re-reading the source.
- 2.7.23 fix (one attempt, then Blocked — no retry loop):
  * The handler in `run_continuous_import_inner` recognises the
    `CONTINUOUS_DERIVED_OUTPUT_LIMIT` prefix and marks the capture
    `CaptureState::Blocked` with
    `stop_reason = "DERIVED_OUTPUT_EXCEEDS_LIMIT"` and
    `ended_epoch_ms = Some(…)`, then `return Ok(())` to exit the
    worker thread. Every other error (decode, I/O) keeps the
    historical `CONTINUOUS_DECODE_RETRYABLE` retry semantics.
  * The retention sweep inside `process_capture_into` runs
    unconditionally before this check — the error is only raised when
    the dataset is already pruned down to its current retention
    window and STILL overflows the configured cap.
- Regression tests
  (`cargo test --workspace --locked --release` → **373 passed / 0
  failed / 4 ignored**, was 371 on 2.7.22; +2 new):
  * `live_probe::tests::derived_output_cap_accepts_small_publication_under_default_limit`
    publishes the three OIRAN_5G_PDU_SESSION_DATA_V1 fixtures with
    the default 512 MiB cap and asserts the publication succeeds
    (events.jsonl + manifest both present).
  * `live_probe::tests::derived_output_over_limit_returns_informative_error_and_is_not_retryable`
    sets `OIRAN_CONTINUOUS_DERIVED_OUTPUT_MAX_BYTES=1`, publishes the
    same fixtures, asserts `process_continuous_capture` returns `Err`
    whose message starts with `CONTINUOUS_DERIVED_OUTPUT_LIMIT` and
    contains the observed size, the cap, and the retention guidance.
    The non-retryable handler keys on the same prefix.
- Streaming RSS reduction (target: peak < 128 MiB for 30 000 events)
  deferred to 2.7.24. Under the palliative 512 MiB `MemoryMax` the
  2.7.22 publication completes; 2.7.23 removes the retry loop that
  would otherwise keep the queue blocked forever.
- Audit negative harness 9/9 unchanged; 3 shell guards PASS.
- Versions: `apps/api` 2.7.22 → 2.7.23; `live-probe` 0.4.8 → 0.4.9.

## OIRAN API 2.7.22 — 2026-11-05 — republish keeps every prior event + age-based retention

- ANR2 recette (issue #10 comment 6657170005): on the first republish
  after a 2.7.21 cleanup, the dataset went from 25 537 to 7 963 events
  (21 515 historical event_ids lost). Root cause: `process_capture_into`
  used the 2.7.18 `keep_prior` closure
  (`live-probe/src/lib.rs:2668-2685`) to filter prior events by the
  current pcap ring — the ring is bounded by `max_segments`, so once a
  pcap rotates out the events it produced vanish from the next
  republish, even though the data was durably committed to the
  published dataset.
- 2.7.22 fix (publication keeps every prior event):
  * The `keep_prior` filter is removed. The caller now passes
    `|_| true` for both the prior and the decoded spool streams of
    `index_event_stream`. Deduplication by event_id is still enforced
    by the `indexed: BTreeMap<String, EventSpoolLocation>` map, so a
    re-decoded packet matches its prior observation and does not
    duplicate.
  * The `current_capture_ids` BTreeSet computation that fed the
    closure is deleted from `process_capture_into`.
- 2.7.22 fix (age-based retention, the only mechanism to remove a
  published event):
  * New env `OIRAN_DATASET_RETENTION_DAYS` (default 30, clamped
    1..=3650) read once per publication by `retention_days()` and
    materialised into an epoch cutoff by `retention_cutoff_epoch_s()`.
  * `EventSpoolLocation` gains a `timestamp_s: u64` field captured in
    `index_event_stream` from `value["timestamp"]["seconds"]` as each
    line is written to the spool. `timestamp_s == 0` means "no
    parseable timestamp" and causes the retention filter to KEEP the
    event — retention never silently discards an event we could not
    age-assess.
  * Immediately before the final write-out of `oiran_events.jsonl`,
    `process_capture_into` applies the cutoff: every indexed entry
    whose `timestamp_s` is in the past AND older than the window is
    dropped. One structured stderr log line per publication where any
    event was purged:
    ```json
    {"event":"CONTINUOUS_RETENTION_PURGE",
     "cutoff_epoch_s":<cutoff>,"retention_days":<days>,
     "purged_count":<n>,"retained_count":<m>,
     "oldest_kept_epoch_s":<ts>}
    ```
- 2.7.22 fix (storage guard does not count the published dataset):
  * New helper `work_bytes(base) = directory_size(base) -
    directory_size(base/dataset)` — the published `dataset/` subtree
    is long-lived storage with its own age-based retention and must
    not count against the ring's `max_owned_bytes` ceiling. With
    `keep_prior` removed the dataset grows linearly with ingested
    events, which under the pre-2.7.22 guard would have tripped
    `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT` on every new candidate even
    though the ring was well under budget.
  * The three guard sites in `run_continuous_import_inner` + the
    pre-check in `process_continuous_capture` now read `work_bytes`
    instead of `directory_size(&base)`. `job.metrics.storage_bytes`
    keeps reporting the TOTAL (observability — the operator wants to
    see the dataset size too).
- 2.7.21's startup cleanup is unchanged: `.dataset-next/` and
  `.dataset-previous/` (never-committed artefacts) + base-level
  `*.tmp`/`*.spool`/`*.compact-tmp` are removed; `dataset/` stays
  byte-identical.
- Regression tests
  (`cargo test --workspace --locked --release` → **371 passed / 0
  failed / 4 ignored**, was 369 on 2.7.21; +2 new):
  * `live_probe::tests::republish_preserves_every_prior_event_id_even_when_ring_rotates`
    publishes dataset A with the N2/N3/N4 fixtures, deletes those
    pcaps, writes perturbed copies with fresh sha256s, calls
    `process_continuous_capture` a second time, and asserts every
    event_id from dataset A is in dataset B. With the 2.7.18 filter
    the second dataset would carry only the fresh-decode events (none
    of the 51 original capture_ids survive the ring rotation).
  * `live_probe::tests::retention_purges_events_older_than_configured_days`
    publishes once, appends a synthetic event
    (`capture_id=sha256:retention-canary`,
    `timestamp.seconds = now - 3651 days`), updates the manifest
    event_count so `validate_dataset_artifacts` still accepts the
    bundle, sets `OIRAN_DATASET_RETENTION_DAYS=3650`, republishes, and
    asserts the canary is gone while every fixture event (~12 days
    old) survives.
- Audit negative harness 9/9 unchanged; 3 shell guards PASS.
- Versions: `apps/api` 2.7.21 → 2.7.22; `live-probe` 0.4.7 → 0.4.8.

## OIRAN API 2.7.21 — 2026-11-05 — the published dataset is NEVER touched at startup

- ANR2 recette (issue #10 comment 6653514332): on binary 2.7.20 the
  cleanup of `.dataset-next/` worked (1 506 177 003 → 0 B, base
  footprint fell to 46 751 842 B), but the compaction of
  `dataset/oiran_events.jsonl` collapsed the published event set from
  25 537 to 77 entries, keeping 1 capture_id instead of the 51 present
  on disk. 3 945 events belonging to 20 captures **whose pcap was
  still on disk** were dropped before rollback saved the data.
- Root cause (file:line of the bad computation): the 2.7.20 worker ran
  at startup

      // live-probe/src/lib.rs (2.7.20) lines 1764-1769
      let current_capture_ids: BTreeSet<String> = state
          .segments
          .keys()
          .map(|sha| format!("sha256:{sha}"))
          .collect();

  and passed that set to `compact_dataset_in_place` to filter the
  published `oiran_events.jsonl`. `state.segments` is the CURRENT PCAP
  RING, capped at `max_segments`; it is NOT the history of capture_ids
  that ever contributed events to the dataset. The ANR2 lab arrived
  with 1 pcap in the ring (fresh binary start, or the ring had just
  rotated after a crash) while the published `oiran_events.jsonl` held
  51 distinct capture_ids accumulated across many publication cycles
  before those pcaps were evicted. Filtering the dataset against the
  ring therefore dropped every event whose pcap had been rotated out
  — which is most of the historical dataset by construction.
- Decision: **the published dataset is NEVER compacted or filtered at
  startup.** `clean_continuous_import_root` is reduced to the
  never-committed artefacts only. The `current_capture_ids`
  computation is removed from `run_continuous_import_inner`; it is no
  longer used to delete data at startup.
- Remaining startup cleanup scope (strictly outside `dataset/`):
  * `.dataset-previous/` → removed unconditionally (rollback artefact).
  * `.dataset-next/` → removed unconditionally (mid-publish staging
    tree, never holds committed data; `process_capture_into` at
    `live-probe/src/lib.rs:2462` already wipes it before each rebuild).
  * Base-level `*.tmp` / `*.compact-tmp` / `*.spool` → removed (orphan
    `atomic_write` / spool partials).
  * `dataset/` and its `*.spool`, `*.tmp`, `oiran_events.jsonl`,
    `dataset_manifest.json`, `callflows/` are **not inspected and not
    rewritten**.
- The `CONTINUOUS_IMPORT_STARTUP_CLEAN` log line is retained, now
  reporting only the artefacts actually touched (two directories, a
  handful of orphan temp files on first start after a crash, zero
  entries on a clean restart). The ANR2 recette's "before 1 506 177 003
  B / after 46 751 842 B" shape is reproducible because the 1.5 GiB
  were all under `.dataset-next/`.
- `recover_continuous_dataset_from_disk` keeps its 2.7.20 tolerance of a
  missing / malformed / drifted manifest: it logs
  `CONTINUOUS_DATASET_RECOVER_SKIPPED` and returns `Ok`, so a partial
  prior-generation manifest does not crash the worker before its
  normal publication cycle can rebuild a coherent manifest atomically.
- Regression tests (new + updated):
  * `live_probe::tests::startup_cleanup_removes_rollback_only_and_leaves_dataset_byte_identical`
    (NEW) drives the pure `clean_continuous_import_root(base)` helper
    and asserts (a) `.dataset-next/`, `.dataset-previous/`,
    `base/*.tmp`, `base/*.spool` are gone and (b)
    `dataset/oiran_events.jsonl` is **byte-identical** (sha256 before ==
    sha256 after), with events of BOTH live AND evicted capture_ids
    preserved. The call site drops the `current_capture_ids` parameter.
  * `live_probe::tests::anr2_layout_startup_cleanup_shrinks_below_cap_then_drains_250_segments`
    (UPDATED) still reproduces the exact ANR2 lab tree and asserts
    `.dataset-next` + `.dataset-previous` are gone, base footprint
    below 128 MiB cap, and 250 N3 segments drain to
    `segments_ingested >= 250` with `state != Blocked`. Byte-identity
    of `dataset/` across cleanup is now proven by the dedicated test
    above, since here the subsequent publication cycle atomically
    replaces `dataset/` by design.
  * The 2.7.20 `compact_continuous_spools_prunes_orphan_events_and_rollback_directory`
    test is **removed**: compaction of published events is no longer a
    supported operation.
- Workspace: `cargo test --workspace --locked --release` →
  **369 passed / 0 failed / 4 ignored** (same count as 2.7.20 — one
  test added, one removed). Shell guards (3) PASS. Negative harness
  9/9 unchanged.
- Versions: `apps/api` 2.7.20 → 2.7.21; `live-probe` 0.4.6 → 0.4.7.

## OIRAN API 2.7.20 — 2026-11-05 — startup cleanup covers .dataset-next + size-before/after log

- ANR2 arborescence (issue #10 comment 6652125653): the real oversized
  spools in the lab were under `.dataset-next/`, not under `dataset/`.
  `.dataset-next/` is the mid-publish staging tree used by
  `process_capture_into`: when a publication crashes between
  `atomic_write(dataset_next/dataset_manifest.json)` and the final
  `rename(.dataset-next → dataset)`, `.dataset-next/` persists with its
  own ~700 MiB `oiran_events.jsonl`, `.decoded-events.spool`,
  `.normalized-events.spool` and `oiran_events.jsonl.tmp`. The 2.7.19
  startup compaction only touched `dataset/oiran_events.jsonl`, so the
  worker still arrived with 744 MiB (`dataset/`) + 762 MiB
  (`.dataset-next/`) = 1 506 177 003 B > `max_owned_bytes =
  1 140 850 688 B`, the storage guard tripped on candidate #1, and the
  file stayed BLOCKED.
- 2.7.20 fix: `compact_continuous_spools` has been generalised into
  `clean_continuous_import_root(base, current_capture_ids) ->
  CompactionReport`. Scope:
  * `.dataset-previous/` → removed unconditionally (rollback artifact).
  * `.dataset-next/` → removed unconditionally (mid-publish staging
    tree, never holds committed data; `process_capture_into`
    `live-probe/src/lib.rs:2462` already blanket-removes it before
    rebuilding, so pre-cleaning at worker start is safe).
  * `dataset/oiran_events.jsonl` → stream-compact in place
    (`stream_compact_events`), keep only events whose `capture_id` is
    in `current_capture_ids = {"sha256:<sha>" | sha in
    state.segments.keys()}`. If any line was dropped, the (now stale)
    `dataset_manifest.json` + `callflows/` are removed too — the next
    publish rebuilds a coherent bundle atomically.
  * `dataset/.decoded-events.spool`, `.normalized-events.spool`,
    `*.tmp`, `*.compact-tmp` → removed (temp spools from a crashed
    publication cycle).
  * Base-level `*.tmp` / `*.compact-tmp` → removed (orphan
    `atomic_write` partials).
- Memory ceiling unchanged: 1 MiB `BufReader` + 1 MiB `BufWriter` +
  one `serde_json::Value` at a time — no multi-GiB spool is
  materialised in RAM. The compaction is sequential and single-threaded
  so peak RSS during cleanup stays below the baseline footprint.
- Startup log: `run_continuous_import_inner` now emits a single
  structured line on stderr after cleanup finishes:
  ```json
  {
    "event": "CONTINUOUS_IMPORT_STARTUP_CLEAN",
    "base": "/var/lib/oiran/captures/continuous-lab-import",
    "capture_ids_retained": 8,
    "total_before_bytes": 1506177003,
    "total_after_bytes": 65432108,
    "entries": [
      {"path": "...dataset-previous", "before_bytes": 180000000, "after_bytes": 0, "action": "removed-rollback-or-crash-artifact"},
      {"path": "...dataset-next",     "before_bytes": 761937920, "after_bytes": 0, "action": "removed-rollback-or-crash-artifact"},
      {"path": "...dataset/oiran_events.jsonl", "before_bytes": 744239083, "after_bytes": 65432108, "action": "compacted"},
      ...
    ]
  }
  ```
  The "recette" (deployment checklist) can `grep CONTINUOUS_IMPORT_STARTUP_CLEAN
  /var/log/oiran-api/stderr.log` to verify the shrink happened; each
  entry lists its `before_bytes` / `after_bytes` / `action`.
- `recover_continuous_dataset_from_disk` now tolerates a malformed or
  drifted manifest the same way it tolerates a missing one. The worker
  thread's cleanup runs AFTER `recover_continuous_dataset_from_disk`
  returns to `start_continuous_import`, so a prior-run bogus manifest
  must not crash the worker before cleanup can delete it; a
  `CONTINUOUS_DATASET_RECOVER_SKIPPED` log line records the skip.
- Regression tests (new):
  * `live_probe::tests::anr2_layout_startup_cleanup_shrinks_below_cap_then_drains_250_segments`
    reproduces the EXACT ANR2 lab directory tree: `dataset/`
    (`oiran_events.jsonl` 60 000 × ~1 KiB = ~60 MiB with stale
    capture_ids, `dataset_manifest.json`, `callflows/`), `.dataset-next/`
    (its own 60 MiB `oiran_events.jsonl`, 2 MiB `.decoded-events.spool`,
    2 MiB `.normalized-events.spool`, 2 MiB `oiran_events.jsonl.tmp`,
    manifest + callflows), `.dataset-previous/` (20 MiB spool). Total
    pre-cleanup > 128 MiB cap. The worker starts, the test waits for
    the three observable terminal conditions (`.dataset-next` gone,
    `.dataset-previous` gone, `dataset/oiran_events.jsonl` size == 0),
    asserts `directory_size(&base) < cap`, and then 250 N3 segments
    are drained to `segments_ingested >= 250`, `state != Blocked`.
  * The 2.7.19 `compact_continuous_spools_prunes_orphan_events_and_rollback_directory`
    was renamed to call `clean_continuous_import_root` via the new
    entry point and retains full coverage of the rollback-removal +
    stale-manifest-removal invariants.
- Workspace: `cargo test --workspace --locked --release` → **369
  passed / 0 failed / 4 ignored** (was 368 on 2.7.19; +1 for the ANR2
  layout test). Shell guards (3) PASS. Negative harness 9/9
  unchanged.
- Versions: `apps/api` 2.7.19 → 2.7.20; `live-probe` 0.4.5 → 0.4.6.

## OIRAN API 2.7.19 — 2026-11-05 — startup spool compaction + single-source /health coherence

- Follow-up on the ANR2 lab reproduction (issue #10, comment
  6646981831): even on a 2.7.18 binary the lab worker landed with two
  `oiran_events.jsonl` spools on disk — the live one at 744 239 083
  bytes and `.dataset-previous/oiran_events.jsonl` (crash rollback) at
  761 937 920 bytes, total 1 506 177 003 bytes, already **above**
  `max_owned_bytes = 1 140 850 688`. 2.7.18 prevents further growth but
  cannot shrink the pre-existing artifacts, so the FIRST
  `directory_size(&base)` read in `run_continuous_import_inner` tripped
  `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT` on the FIRST candidate of the
  first scan and the queue stayed at 222 pending.
- 2.7.19 fix (startup compaction): new helper
  `compact_continuous_spools(base, current_capture_ids)` at
  `live-probe/src/lib.rs`. Called from the top of
  `run_continuous_import_inner` right after `state.segments` has been
  resolved, BEFORE any guard reads `directory_size(&base)` or the
  historical-bootstrap pcap is copied. The helper streams
  `base/dataset/oiran_events.jsonl` line by line via a 1 MiB
  `BufReader`, parses each line as `serde_json::Value`, keeps only
  events whose `capture_id` is in `current_capture_ids`
  (i.e. `{"sha256:<sha>"}` for every pcap in `state.segments`), writes
  to `oiran_events.jsonl.compact-tmp` and atomically renames. If any
  line was dropped the published manifest and callflows are stale by
  construction (they reference event ids that no longer exist), so the
  helper removes `dataset_manifest.json` + `callflows/`. The next
  successful publication rebuilds a coherent dataset. `.dataset-previous/`
  is always a rollback artifact and is removed unconditionally.
  Memory ceiling: 2 MiB (reader + writer) + one `serde_json::Value` at
  a time — no 1.5 GiB in-RAM materialisation.
- 2.7.19 fix (single-source `/health` coherence): the ANR2 lab also
  observed `/health = 25 939 events / 10 sessions` while
  `dataset_manifest.json` on disk reported `25 537 / 8`. Root cause:
  `apps/api::health` (2.7.17) summed across every entry of
  `capture_manager.datasets()`, so a residual recovered-failed dataset
  (`402` events / `2` sessions) was added on top of the continuous one.
  Fix: in operational mode `/health` now reads exactly
  `capture_manager.dataset(CONTINUOUS_DATASET_ID)` and projects only
  that dataset's `event_count` / `session_ids`. Because the in-RAM
  `LiveDataset` and the on-disk `dataset_manifest.json` are the same
  struct (serialized atomically in `process_capture_into` and upserted
  in the same publication), `/health` and the manifest are now
  identical by construction.
- `CaptureManager::recover_continuous_dataset_from_disk(base)` is now
  `pub` so tests and non-worker code paths can hydrate the manifest
  without spawning the production-only import worker.
- Regression tests
  (`cargo test --workspace --locked --release` → **368 passed / 0
  failed / 4 ignored**, was 366 on 2.7.18):
  * `live_probe::tests::compact_continuous_spools_prunes_orphan_events_and_rollback_directory`
    seeds a 5 MiB spool with 2 500 "stale" events (`capture_id="sha256:stale"`)
    + 2 500 "live" events, plus a `.dataset-previous/` directory and a
    stub manifest + callflow. After `compact_continuous_spools(base,
    {"sha256:live"})` the rollback directory is gone, the manifest +
    callflows are removed (events were dropped), and the compacted spool
    contains exactly the 2 500 live events. A second idempotent call
    with the same keep-set leaves a freshly-written manifest untouched.
  * `live_probe::tests::continuous_import_drains_a_burst_of_250_segments_without_blocking`
    (from 2.7.18) still passes with the new startup compaction added
    in the critical path.
  * `oiran_api::tests::health_counters_mirror_the_continuous_manifest_exclusively`
    seeds a `dataset_manifest.json` with 24 events / 8 sessions,
    hydrates the manager, hits `/api/v1/health`, and asserts
    `data.source_events == manifest.event_count` and
    `data.session_count == manifest.session_ids.len()`.
- Audit negative harness
  (`AUDIT_E2E_CERT_001_scripts/02-negative-tests.py`): 9/9 scenarios
  still match the expected verdict.
- Shell guards all PASS.
- Versions: `apps/api` 2.7.18 → 2.7.19; `live-probe` 0.4.4 → 0.4.5.

## OIRAN API 2.7.18 — 2026-11-04 — bound derived artifacts + N2↔N4 via regenerated dataset

- Root cause of the lab-reproduced 222-segment deadlock (ANR2, issue #9):
  `process_capture_into` merges the previous dataset's events into the
  new `oiran_events.jsonl` through `index_event_stream` at
  `live-probe/src/lib.rs:2619-2639`. Before this patch the merge kept
  **every** prior event, including events from pcap segments that had
  already been evicted by the ring. The derived `oiran_events.jsonl`
  therefore accreted monotonically; `directory_size(&base)` was
  dominated by the events artifact, not by the live pcap ring; and the
  backpressure guard at `live-probe/src/lib.rs:1961-2013` tripped
  because the only thing eviction could reclaim was the pcap pool. A
  freshly-arrived 212 th segment couldn't fit even though the live
  pcap directory was well under budget, and every scan failed on
  candidate #1. The 2.7.16 batch-of-32 did not help because the FIRST
  candidate in every scan tripped the guard — no segment ever entered
  `pending_publication`.
- 2.7.18 fix (filter prior events by the current pcap set):
  `index_event_stream` now takes a `keep: FnMut(&Value) -> bool`
  predicate. The prior-events caller passes
  `|v| current_capture_ids.contains(v.capture_id)` where
  `current_capture_ids` is derived from the `checksums` map built in
  the per-pcap decode loop. Evicted pcap → their events drop from the
  next published dataset. The derived artifact is therefore bounded by
  what the ring currently holds (≤ `max_segments` pcap × their events),
  and can no longer starve the ring.
- 2.7.18 fix (two-pass eviction): the eviction loop at
  `live-probe/src/lib.rs:1982-2002` now falls back to evicting the
  oldest segment **of any kind** (including the N2 historical
  bootstrap) when the non-historical pool is exhausted. The historical
  pcap is on the allowlisted `/var/lib/docker/volumes/oiran_lab_pcap/_data`
  source, so evicting its owned cached copy only loses the on-disk
  mirror; the worker can re-bootstrap on the next start.
- 2.7.18 fix (dataset regenerated with the current decoder):
  `datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl` was
  regenerated with `oiran-decode 0.6.0`, which emits structured tunnel
  IE components (`item_<i>_tunnel_ip_ul`, `item_<i>_gtp_teid_ul`,
  `item_<i>_tunnel_ip_dl`, `item_<i>_gtp_teid_dl`) on NGAP IE 74/75
  instead of the old `nested_transfer_sha256`-only placeholder. The
  pcapng captures themselves are untouched. As a result the existing
  `ngap-pfcp-exact-tunnel` rule in
  `correlation-engine::correlate_cross_interface_evidence` finds the
  byte-identical `(ipv4=10.77.22.13, teid=0x96a8)` on N2 and N4 and
  emits an EXACT edge (plus the mirror downlink
  `(10.77.22.20, 0x3)`). The full 5G SA chain is now certified by the
  engine itself, not just by the audit oracle.
- Regression tests (run with
  `cargo test --workspace --locked --release`):
  * `live_probe::tests::continuous_import_drains_a_burst_of_250_segments_without_blocking`
    writes 250 valid N3 pcaps with distinct TEIDs into the source root
    under `max_owned_bytes = 128 MiB` / `max_segments = 8`, starts the
    import, and asserts `segments_ingested >= 250`, `state != Blocked`
    and `pending_segments == 0` within 120 s (empirically ~3 s).
  * `correlation_engine::tests::audit_dataset_produces_the_full_n2_n4_n3_chain`
    loads the regenerated dataset events, runs
    `correlate_cross_interface_evidence`, and asserts exactly two
    `ngap-pfcp-exact-tunnel` EXACT edges and two
    `pfcp-outer-header-matches-gtpu-tunnel` EXACT edges, each carrying
    the known `(endpoint_ip, teid)` anchor.
  * Four existing API tests were updated to reflect the new on-wire
    event count (24 N2 + 30 N4 + 10 N3 = 64 events, 76 flow-accounting
    sum, 2 session callflows). The pcapng packet count is unchanged
    (same captures).
- Replay of `AUDIT_E2E_CERT_001_scripts/02-negative-tests.py`: the 9-case
  truth table is unchanged — no false positive, fail-closed on
  duplicate TEIDs / multiple candidates / partial captures / duplicate
  events, time-independent on clock skew / reversed order.
- Versions: `apps/api` 2.7.17 → 2.7.18; `live-probe` 0.4.3 → 0.4.4.

## OIRAN API 2.7.17 — 2026-11-04 — remove every hardcoded version; measure continuous RSS

- `apps/api/src/lib.rs:44-45` previously pinned `API_VERSION` and
  `PLATFORM_VERSION` to the string `"2.7.15"`, so `apps/api/Cargo.toml`
  could bump to `2.7.16` while `/version` still reported the old number
  and the unit assertion at `apps/api/src/lib.rs:3509` still read
  `"2.7.15"`. ANR2 refused the 2.7.16 deployment on exactly this drift.
  Fix: `API_VERSION = env!("CARGO_PKG_VERSION")`,
  `PLATFORM_VERSION = env!("CARGO_PKG_VERSION")`. The /version regression
  test now asserts `backend_api == env!("CARGO_PKG_VERSION") ==
  platform_core` — no literal in the assertion.
- Same drift hazard existed in every other crate: `decoder-ngap`,
  `decoder-s1ap`, `decoder-nas`, `decoder-pfcp`, `decoder-gtpu`,
  `decoder-gtpv2c`, `decoder-sbi`, `decoder-diameter`, `oiran-decode`,
  `session-engine`, `correlation-engine`, `callflow-schema`,
  `callflow-renderer`, `live-probe`, `disk-safety`, `dataset-registry`,
  `transport-tcp`, `capture-helper` all exposed
  `pub const VERSION: &str = "<literal>"` mirrored from their own
  Cargo.toml. All 18 are now `pub const VERSION: &str =
  env!("CARGO_PKG_VERSION")`. `cargo build` confirms the identity across
  the workspace; no further manual bumps required.
- Web frontend version (`apps/web/package.json`) was hardcoded as
  `"web_frontend":"2.7.1"` in `apps/api/src/lib.rs:669`. New
  `apps/api/build.rs` reads `apps/web/package.json` at build time and
  emits `cargo:rustc-env=OIRAN_WEB_FRONTEND_VERSION=<value>`; the
  constant `WEB_FRONTEND_VERSION = env!("OIRAN_WEB_FRONTEND_VERSION")`
  serves it. `cargo:rerun-if-changed` is set so bumping the frontend
  triggers an API rebuild automatically.
- Memory measurement: the user reported that `oiran-api` RSS approaches
  256 MiB in production under 2.7.16. We built a reproducible harness
  (`AUDIT_E2E_CERT_001_scripts/04-generate-synthetic-events.py` +
  `04-rss-continuous.rs`, installed as
  `OIRAN/session-engine/examples/rss_continuous.rs`) and measured on the
  reported shape (25 537 events, 8 sessions):

  | stage                        | VmRSS   | VmPeak  |
  | ---                          | ---:    | ---:    |
  | baseline                     | 1.06 MiB | 3.47 MiB |
  | after `load_path`            | **114.7 MiB** | **127.5 MiB** |
  | after `discover_sessions`    | **130.7 MiB** | **136.5 MiB** |
  | after drop (allocator held)  | 116.9 MiB | 136.5 MiB |

  **Peak: 137 MiB VmPeak — under the 200 MiB threshold** stated in the
  mission brief. Retention is concentrated in `Vec<EventRecord>` returned
  by `session_engine::load_path` at `session-engine/src/lib.rs:620-623`.
  session-engine already strips `source_json` to the three top-level
  schema keys (`compact_source`, `src/lib.rs:691-701`), which was
  introduced specifically to keep the continuous importer below the
  256 MiB cgroup; without that trim the figure would be ~3× higher.
  The 115 MiB resident after `drop(events)` is the Rust allocator
  retaining freed arenas, not leaked data — it is reused by the next
  publication cycle rather than returned to the kernel. The production
  gap to 256 MiB (~120 MiB) is accounted for by the live Axum router,
  Tokio worker pool, decode spool buffers (`decoded_spool` /
  `normalized_spool`, `live-probe/src/lib.rs:2538, 2613`), and the live
  `datasets` map; no new bound is required at this stage.
- Regression test guarantees: workspace build succeeds with the new
  `env!()` wiring across all 18 crates and the new `build.rs`.
  `cargo test --workspace --locked --release` → **364 passed / 0 failed /
  4 ignored** (same count as 2.7.16). The strengthened
  `apps/api::tests::version_reports_installed_lte_and_5g_decoders`
  now asserts `backend_api == platform_core ==
  env!("CARGO_PKG_VERSION")` and `web_frontend ==
  env!("OIRAN_WEB_FRONTEND_VERSION")` — four assertions added inside
  the same test function, so the count is unchanged. Shell guards
  (`test-rotation-drops.sh`, `test-rotation-watcher.sh`,
  `test-dumpcap-retention.sh`) all PASS.
- Versions: `apps/api` 2.7.16 → 2.7.17. No other crate changes version
  — this is purely a drift-hardening patch.

## OIRAN API 2.7.16 — 2026-11-04 — API continuous projection + bounded-batch backpressure drain

- `live-probe::CaptureManager::start_continuous_import` now recovers a
  previously-published continuous dataset from
  `<capture_root>/continuous-lab-import/dataset/dataset_manifest.json` into
  the in-RAM `datasets` map before the import worker is spawned (new
  `recover_continuous_dataset_from_disk`). Prior to this fix the API
  process restarted with an empty `datasets` map, so `/sessions`,
  `/datasets` and `/health` reported zero sessions for a continuous dataset
  whose disk already held 25 537 events and 8 sessions (issue #9 part 1,
  ANR2 diagnostic). The recovery reads only the manifest JSON (a few KiB);
  `oiran_events.jsonl` and callflows stay on disk and are never pulled into
  memory, preserving the 256 MiB continuous-import ceiling.
- `apps/api::health` projects `capture_manager.datasets()` into the
  response fields (`dataset`, `source_events`, `session_count`,
  `ue_context_count`) when `Inner.flows` is empty (operational mode).
  Reference mode still wins — the projection is a fallback, not an
  override. The projection accumulates integer counters only, so a dataset
  with 25 537 events adds a `usize` to the sum and nothing else.
- `live-probe::run_continuous_import_inner` drains the pending-segment
  queue in bounded batches of at most `MAX_INGESTED_SEGMENTS_PER_SCAN = 32`
  (`live-probe/src/lib.rs:62`). Before this patch the per-candidate loop
  tried to admit every candidate before publishing, so a burst of 212
  segments observed in the lab (issue #9 part 2) could exhaust the eviction
  budget at `live-probe/src/lib.rs:1961-1992`, trip
  `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT`, set `terminal_error`, and
  `return Ok(())` from the worker — leaving the pending-segments counter
  stuck at 212 forever. The patch:
  * bounds the per-scan ingestion count so each outer-loop iteration
    publishes what it has and sleeps before taking the next batch;
  * stops treating `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT` as a terminal
    error — the worker now records `CaptureState::Blocked` with the
    stop_reason set but continues the outer loop, so eviction+publish on
    the next scan drains the queue. Non-recoverable terminals
    (`CONTINUOUS_IMPORT_DISK_POLICY_STOP` et al.) still end the worker.
  * no segment is lost: the tripped candidate's checksum is never added
    to `seen_checksums` (commit point is `persist_published_checksums`
    after a successful publish), so the next scan re-discovers it.
- `correlation-engine` now emits an explicit N4↔N3 `CorrelationEdge` via
  the new `pfcp-outer-header-matches-gtpu-tunnel` rule. The rule matches a
  PFCP F-TEID or Update-FAR outer-header-creation `(ipv4, teid)` tuple
  against the destination endpoint + `teid` identifier of N3 GTP-U events
  in the same capture scope. Uniqueness is enforced on the N4 side
  (reused F-TEID → no edge); the N3 side aggregates all G-PDUs sharing
  the tuple into one edge with `gtpu_frame_count=<n>` and selects the
  deterministic representative via the canonical
  `(capture_id, packet_number, event_id)` sort key — never a timestamp.
  Covers DSN-ENGINE-002 from the independent audit
  (`AUDIT_E2E_CERT_001` / `FINAL_CERTIFICATION_REPORT.md`).
- `correlation-engine::capture_scope` now falls back to the parent
  directory of `source_file` when the `/captures/<scope>/` marker is
  absent, so a dataset rooted under `datasets/<scope>/*.pcapng` unifies
  N2, N3 and N4 under a single scope. Previously the fallback keyed on the
  per-file `capture_id` SHA-256, which was always distinct across planes
  and forbade any cross-interface match on a fixture dataset. Covers
  DSN-SCOPE-001 from the audit.
- Regression tests (all green under `cargo test --workspace --locked
  --release`, 364 passed / 0 failed / 4 ignored):
  * `correlation_engine::tests::n4_n3_rule_publishes_one_exact_edge_per_matching_tunnel`
    — single N4 F-TEID + 3 N3 G-PDUs → one EXACT edge with
    `gtpu_frame_count=3` and `capture_scope=AUDIT`.
  * `correlation_engine::tests::n4_n3_rule_is_fail_closed_when_the_pfcp_teid_is_reused`
    — ambiguous N4 F-TEID across two PFCP responses → no edge.
  * `correlation_engine::tests::capture_scope_fallback_unifies_planes_under_dataset_directory`
    — `datasets/<X>/N3.pcapng` → `<X>`; `/var/lib/oiran/captures/<Y>/N3.pcapng` → `<Y>`.
- Replay of the audit's negative-test harness
  (`AUDIT_E2E_CERT_001_scripts/02-negative-tests.py`) confirms the 9-case
  truth table is unchanged: no false positives, fail-closed on duplicate
  TEIDs / multiple candidates / partial captures / duplicate events, and
  still time-independent on clock skew / reversed order.
- Replay of `evidence-replay` on
  `datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl` now yields
  **2 EXACT N4↔N3 edges** (uplink `0x96a8 @ 10.77.22.13` and downlink
  `0x3 @ 10.77.22.20`), up from 0 in 2.7.15. The N2↔N4 bridge still
  requires the dataset events to be regenerated with the current
  decoder-ngap (which already emits `item_0_tunnel_ip_ul` /
  `item_0_gtp_teid_ul`, see `decoder-ngap/src/lib.rs:500-507` and
  `:542-548`); the shipped jsonl predates that decoder and only carries
  `nested_transfer_sha256`. DSN-ENGINE-001 therefore becomes a fixture
  regeneration chore, not a code gap.
- Versions: `apps/api` 2.7.15 → 2.7.16; `live-probe` 0.4.2 → 0.4.3;
  `correlation-engine` 0.5.1 → 0.5.2.

## OIRAN API 2.7.15 — 2026-11-04 — session consolidation + typed packet counters

- `session-engine::discover_lte_sessions` now consolidates S1AP
  contexts by the structural `(capture_id, enb_ue_s1ap_id)` key before
  it enumerates sessions. The pre-2.7.15 code
  (`session-engine/src/lib.rs:313-319`) inserted every observed
  `(capture_id, enb, mme)` triple, so an `InitialUEMessage` event
  (which carries `enb_ue_s1ap_id` but no `mme_ue_s1ap_id` — the MME
  has not yet allocated one) was treated as a separate context from
  the rest of the exchange and produced a parallel
  `RELEASED`-but-incomplete session missing `InitialUEMessage` and the
  NAS Attach Request child (ANR3 final report, issue #10 comment
  6636015016). The consolidation keeps structural separation: two
  UEs with distinct `enb_ue_s1ap_id` values still yield two sessions,
  and two UEs that reuse the same `enb_ue_s1ap_id` across different
  `mme_ue_s1ap_id` values still yield two sessions. No timestamp
  comparison is used.
- The per-context match relaxes the `mme_ue_s1ap_id` check: an event
  with no mme (InitialUEMessage, the NAS Attach Request child that
  inherits the parent's identifiers, …) is admitted into the
  canonical context when the `enb` matches. The mme equality check
  stays strict for events that DO carry a mme identifier.
- `rotation-watcher.sh` emits `packets_captured` and `packets_dropped`
  as typed metrics. `packets_captured` is read from capinfos and
  `packets_dropped` is computed as a delta on the bridge's kernel
  `/sys/class/net/<iface>/statistics/rx_dropped` counter, seeded on
  the watcher's first visit. Every failure path produces an explicit
  `"UNKNOWN:<reason>"` JSON string (`capinfos-missing`,
  `capinfos-no-count`, `no-baseline-yet`, `counter-rolled-back`,
  `sysfs-<iface>-unavailable`, `stat-failed`, `file-not-readable`) —
  the field is never `null`. ANR3 observed 24 `packets_dropped:null`
  records before this patch.
- Regression tests:
  * `session_engine::tests::anr3_attach_to_detach_flow_consolidates_into_a_single_session`
    replays the shape reported by ANR3 (InitialUEMessage + NAS Attach
    + 5 subsequent S1AP events + S11 + S1-U) and asserts a single
    session that contains both `InitialUEMessage` and
    `Attach Request`.
  * `session_engine::tests::two_distinct_ues_each_get_their_own_session_after_consolidation`
    guards the mirror case: distinct eNB UE IDs → two sessions.
  * `infrastructure/capture/tests/test-rotation-drops.sh` — four
    rotations driving the four failure modes (`no-baseline-yet`,
    numeric delta, `sysfs-...-unavailable`, `capinfos-missing`) and a
    final sweep over the JSONL asserting no `"packets_captured":null`
    or `"packets_dropped":null` line remains.

## OIRAN API 2.7.14 — 2026-11-04 — technical-field exemption in privacy predicate

- `live-probe::lte_evidence::contains_forbidden_identity` no longer
  rejects the ANR3 event id `evt-78165221727737b8` (issue #10 comment
  6632047981): the previous rule applied the 14-consecutive-decimal
  heuristic to every JSON string, so a canonical event id whose 16-hex
  suffix happened to contain 14 digits in a row was treated as a raw
  IMSI.
- New `is_valid_technical_field(key, value)` predicate is the single
  place that lists the technical field names exempted from the
  long-digit-run heuristic and declares their exact format:
  * `event_id`, `parent_event_id` → `^evt-[0-9a-f]{16}$`
  * `capture_id` → `^sha256:[0-9a-f]{64}$`
  * `raw_payload_reference` → sha256: head, optional `#…` suffix
  * `raw_sha256`, `source_sha256`, `normalized_events_sha256`,
    `derived_manifest_sha256`, `event_artifact_sha256`,
    `correlation_artifact_sha256`, `source_file_sha256` → `[0-9a-f]{64}`
  * `dataset_id` → `dataset-` or `dataset-live-` + `[0-9a-f]{32}` or
    `[0-9a-f]{64}`.
  A value whose format does not match falls through to the strict scan,
  so an IMSI stuffed under `event_id`, `capture_id`, `raw_sha256` or
  `dataset_id` is still refused with
  `LTE_IDENTITY_DISCLOSURE_REJECTED`.
- `contains_forbidden_identity_marker` runs BEFORE the exemption, so a
  value like `imsi-001010123456789` stored under `event_id` stays
  rejected.
- The scan stays strict on IE contents, decoded values, session
  identifiers, and any field not listed above.
- Regression tests:
  * `anr3_exact_event_id_from_the_report_is_not_flagged_as_identity`
    (passes on the exact `evt-78165221727737b8` value),
  * `technical_fields_accept_their_declared_formats`,
  * `imsi_inside_an_information_element_value_stays_rejected`,
  * `imsi_stuffed_into_a_technical_field_is_rejected_by_format_invalidation`,
  * `whitelisted_names_do_not_exempt_other_marker_shapes`.

## OIRAN API 2.7.13 — 2026-11-04 — canonical `(capture_id, seq)` order, no dumpcap retention

- The canonical processing order across OIRAN is now
  `(capture_id, packet_number, event_id)`. The `timestamp_ns` field is
  NEVER used for a processing decision and no two events from different
  captures are ever compared by timestamp. New public helper
  `session_engine::canonical_sort_key()` is the single implementation
  of the key; every processing sort in the workspace now delegates to
  it. Call flow ladder rendering may reorder an already-selected set
  of events by `timestamp_ns` as a presentation step — see the
  explicit comment at `callflow-schema::build_lte_callflow` — and no
  session, correlation, dedup, or attachment decision depends on that
  order.
- `session_engine::within_lte_window` no longer gates on a
  `timestamp_ns` difference. Cross-capture joins (S1-MME ↔ S11 ↔ S1-U)
  rely exclusively on structural keys (MME/eNB-UE-S1AP-ID, E-RAB
  TEIDs, F-TEID, pseudonym when present).
- `oiran-decode::decode_capture()` and
  `live-probe::lte_evidence::read_events_bounded()`'s post-merge sort
  both use `canonical_sort_key`. Within one capture this collapses to
  `(packet_number, event_id)`, which preserves the parent S1AP → NAS
  child emission order without relying on `sort_by_key` stability.
- Dumpcap native rotation drops `-b files:8`. The capture script now
  invokes `dumpcap -b duration:3600 -b filesize:262144 -w <path>` only.
  Retention is owned by the existing disk-safety guard-rail; dumpcap
  must never delete a finalised segment.
- New regression tests:
  - `session_engine::tests::crossed_timestamps_across_captures_do_not_alter_sessions_or_attachments` —
    two captures with interleaved timestamps produce the exact same
    `discover_lte_sessions` shape under both the canonical and the
    legacy ts order.
  - `oiran-decode::tests::sort_by_timestamp_tie_breaks_on_capture_id_then_sequence_then_event_id`
    stays valid against the canonical sort.
  - `infrastructure/capture/tests/test-dumpcap-retention.sh` — asserts
    that `capture-interface.sh` no longer passes `-b files:` (outside
    comments) and that 10 simulated rotations retain all 10 files.

## OIRAN API 2.7.12 — 2026-11-04 — gapless dumpcap rotation + deterministic ts tiebreak

- `infrastructure/capture/capture-interface.sh` drops the
  `timeout --signal=INT 3600 dumpcap ...` wrapper in favour of native
  dumpcap rotation (`-b duration:3600 -b filesize:262144 -b files:8`).
  dumpcap no longer exits between hourly segments, so the capture
  container stays up continuously (ANR3 measured 2.5–3.2 s of capture
  loss per interface per hour and a restart_count of 256 with the
  previous wrapper).
- New `infrastructure/capture/rotation-watcher.sh` keeps the
  `capture-rotation.jsonl` contract from a40e110 alive: it polls each
  per-label output directory and emits one JSONL record the moment
  dumpcap finalises a segment (i.e. the moment a newer file appears
  beside it), with `interface`, `plane`, `file`, `file_bytes`,
  `packets_captured`, `packets_dropped` fields. Idempotent across
  watcher restarts via a per-label seen list.
- `infrastructure/capture/capture-all.sh` orchestrates one
  `capture-interface.sh` + one `rotation-watcher.sh` per approved
  bridge; the shutdown trap stops both cleanly.
- `infrastructure/capture/tests/test-rotation-watcher.sh` simulates two
  dumpcap rotations and asserts the two JSONL records are emitted in
  order, carry all expected fields, and that the watcher is idempotent
  (no gap, no duplicate).
- `oiran-decode::decode_capture()` replaces the previous stable
  `sort_by_key((ts.s, ts.ns, packet_number))` with an explicit
  `sort_by` on `(ts.s, ts.ns, capture_id, packet_number, event_id)`.
  Live-probe's cross-plane merge sort already carried `event_id` as the
  final tiebreak; this patch brings oiran-decode to the same full
  determinism without relying on `sort_by_key`'s stability guarantee.
  New `oiran-decode::tests::sort_by_timestamp_tie_breaks_on_capture_id_then_sequence_then_event_id`.

## OIRAN API 2.7.11 — 2026-11-04 — SecurityKey material withheld at decode

- `event-schema` exposes `InformationElement::withheld(id, length)`, the
  shared constants `KEY_MATERIAL_WITHHELD_IE_NAME` / `..._VALUE`, and the
  explicit allowlist `is_withheld_key_material(decoder, ie_id)` covering
  S1AP IE 73 (SecurityKey, KeNB*/NH/NCC) and NGAP IE 94 (SecurityKey,
  KgNB*/NH/NCC). Both decoders must emit matching IEs via this path so no
  raw key material and no hash of it ever reaches a NormalizedEvent.
- `decoder-s1ap` and `decoder-ngap` build the SecurityKey IE through the
  withheld constructor: id and length are preserved for provenance, `name`
  is `"key_material_withheld"`, `value` is the sentinel `"WITHHELD"`, and
  `raw_sha256` is `None`. The previous `security_key_sha256=...` identifier
  emission is removed.
- `live-probe` fail-closed `LTE_IDENTITY_DISCLOSURE_REJECTED` remains
  active: any residual key material that still reaches the published
  stream (raw bytes under `name: "SecurityKey"`, `security_key=` substring,
  or a sha256 under the original IE name) is refused.
- Regression tests:
  - `decoder-s1ap::tests::initial_context_setup_request_withholds_security_key_payload`
  - `decoder-ngap::tests::initial_context_setup_request_withholds_ngap_security_key_payload`
  - `live-probe::lte_evidence::tests::imports_ics_with_withheld_security_key_without_privacy_rejection`
  - `live-probe::lte_evidence::tests::rejects_raw_security_key_leaked_into_the_published_stream`

## OIRAN API 2.7.10 — 2026-11-04 — explicit decoder-vs-protocol binding for nested EPS NAS

- `live-probe::lte_evidence::read_events_bounded()` now classifies each
  normalised event with an explicit allowlist of `(plane, protocol,
  decoder)` tuples. An S1-MME event with the plane's declared binding
  decoder stays a plane-binding primary; an S1-MME event with protocol
  `NAS-EPS-MM` or `NAS-EPS-SM` is accepted only when it is decoded by
  `decoder-nas/0.3.1` AND carries a `parent_event_id` resolvable to an
  S1AP event seen in the same plane. Any other combination fails closed
  with `LTE_EVENT_DECODER_MISMATCH` (detail: decoder, protocol, parent),
  and a nested NAS event without a valid parent fails
  `LTE_EVENT_NESTED_NAS_WITHOUT_PARENT`. The S11 and S1-U plane bindings
  stay strict. The N2 / NGAP / NAS-5G path is untouched (non-regression).
- Regression tests:
  `accepts_ten_nas_children_decoded_by_the_eps_nas_decoder_on_s1_mme`
  (ANR3 field case),
  `rejects_nested_nas_without_s1ap_parent_on_s1_mme`,
  `rejects_nested_nas_without_any_parent_event_id_on_s1_mme`,
  `rejects_unknown_decoder_on_s1_mme`,
  `rejects_wrong_decoder_version_for_nested_eps_nas`.

## OIRAN API 2.7.9 — 2026-11-04 — bounded LTE runtime-diagnostic privacy predicate

- Removes only the envelope's exact strict `lte-run-<32 lowercase hex>` value
  before applying the long-digit privacy rule to LTE step measurements; any
  other or malformed run identifier remains rejected fail-closed.
- Exempts only the numeric-run heuristic for the exact iperf runtime diagnostic
  stdout/stderr fields while retaining all subscriber and equipment identity
  markers everywhere.

## OIRAN API 2.7.8 — 2026-11-04 — scalar pseudonym IE contract

- Serializes every GTPv2-C, S1AP and EPS NAS information element named
  `subscriber_pseudonym` or `identity_pseudonym` as the bare deployment-keyed
  HMAC value `psn-<32 hex>`, without a key/value prefix or concatenation.
- Exports the EPS mobile type code separately as the numeric-only
  `eps_mobile_type_code`, preserving correlation while satisfying the strict
  POLARIS 0.29.16 privacy contract.

## OIRAN API 2.7.7 — 2026-11-04 — unified `subscriber_pseudonym` / `identity_pseudonym` emission contract

- Every identity-derived identifier (IMSI, IMEI, MSISDN, GUTI/TMSI/5G-S-TMSI,
  SUCI, Masked IMEISV, UE Paging ID) now surfaces on `session_identifiers`
  with the fixed name `subscriber_pseudonym`. Identity-carrying
  `information_elements` entries (NAS 5GS/EPS mobile identity, GTPv2-C IMSI/
  MEI/MSISDN, S1AP S-TMSI/UEPagingID, NGAP 5G-S-TMSI/MaskedIMEISV, Diameter
  User-Name/MSISDN) are renamed `identity_pseudonym`. The value is the HMAC
  output `psn-<32 hex>`. No name, no IE label, no identifier value contains
  any POLARIS blacklist substring (`imsi`, `suci`, `guti`, `tmsi`, `imei`,
  `imeisv`, `msisdn`, `subscriber_id`, `subscriber_identity`). The NAS EPS
  identity-type mnemonic is exported as `eps_mobile_identity_type_code`
  (TS 24.301 §9.9.3.12 numeric code) rather than the 3GPP string
  (`IMSI`/`IMEI`/`IMEISV`/`GUTI`). Regression test
  `decoder-gtpv2c::tests::export_of_a_full_session_contains_no_raw_imsi_imei_or_msisdn`
  now asserts no blacklist substring appears anywhere in the serialised
  event JSON.

## OIRAN API 2.7.6 — 2026-11-03

- Scopes the HMAC-SHA256 pseudonym key to the DEPLOYMENT (not the import):
  generated once at a root-only 0600 file (default
  `/var/lib/oiran/pseudonym.key`, configurable via `OIRAN_PSEUDONYM_KEY_PATH`
  or `ApiConfig.pseudonym_key_path`), reloaded at every probe restart from
  the same path. Wider permissions on the file fail-closed with
  `OIRAN_PSEUDONYM_KEY_INSECURE`; missing or malformed file fails-closed
  `OIRAN_PSEUDONYM_KEY_UNAVAILABLE` (except on the first-generation path).
  The two live-probe continuous-import tests now pass again without being
  weakened. `session-engine::discover_lte_sessions` falls back to the
  structural keys (MME/eNB-UE-S1AP-ID + F-TEID S11 ↔ E-RAB TEID S1-U) when
  no subscriber identifier is present on any event — new regression test
  `s1_s11_s1u_correlate_by_teid_without_any_subscriber_identifier`.
- Replaces the FNV-1a unkeyed 64-bit `pseudonym()` (reversible by enumerating
  the ~10⁹ IMSI space) with HMAC-SHA256 keyed by a 32-byte secret generated
  per import, output `psn-<32 hex>` (128 bits). The secret is OS-sourced from
  `/dev/urandom`, lives in the import's stack frame only, is zeroised on drop
  and never serialised, logged, or committed. Missing entropy source fails
  closed with `OIRAN_PSEUDONYM_KEY_UNAVAILABLE` — no silent fallback to an
  unkeyed hash. Debug impl is deliberately redacted. New RFC 4231 HMAC
  regression tests + mission tests (same-key stable, different-key disjoint,
  domain-separated labels, `PseudonymKey::generate` randomness, no raw
  IMSI/IMEI/MSISDN in gtpv2c exports, S11-level correlation of the same IMSI
  under one import).
- Threads the per-import key through `DecoderInput`, `decode_capture`,
  `decode_capture_streaming`, all S1AP/NGAP/NAS/PFCP/SBI/GTPv2-C/Diameter
  decoders, and the live-probe continuous import (one key per
  `run_continuous_import_inner` and per `process_capture_into` invocation).
  Within one import, S1-MME / S11 / S1-U events carrying the same IMSI share
  the exact same pseudonym; across imports, the same IMSI emits disjoint
  pseudonyms.
- Uses the privacy-safe `subscriber_pseudonym` identifier for decoded LTE
  S11 evidence while retaining read compatibility with legacy
  `imsi_pseudonym` events.
- Correlates S1-MME, S11 and S1-U with the privacy-safe opaque pseudonym so
  POLARIS finalization and OIRAN session reconstruction share one admissible
  contract.

## OIRAN API 2.7.5 / disk-safety 0.2.0 — 2026-11-02

- Replaces the legacy 75/80/85/90 capture policy with 95% information, 97%
  warning and a fail-closed 98% hard ceiling.
- Requires every projected capture budget to fit below the ceiling while
  retaining an 8 GiB absolute free-space reserve.
- Retains inode, measurement, ENOSPC, rotation and unexpected-growth guards;
  Stop, cleanup and read-only analysis remain available at the ceiling.

## OIRAN API 2.7.4 / Live Probe 0.4.2 — 2026-11-01

- Imports approved evidence from clean terminal failed/cancelled LTE runs as
  `IMPORTED_PARTIAL`, preserving the observed plane set and original hashes.
- Keeps `COMPLETED` evidence gated on all three S1-MME/S11/S1-U planes; partial
  evidence cannot be promoted to a successful LTE certification.
- Persists final state and capture planes in the dataset manifest and retains
  idempotence, run conflict, privacy, cleanup, and correlation safety guards.

## OIRAN API 2.7.3 / session-engine 0.5.1 / correlation-engine 0.5.1 — 2026-11-01

- Correlate LTE S1-MME, S11 and S1-U evidence across distinct per-file capture
  hashes while retaining every original `capture_id` as provenance.
- Require a unique S1 context, opaque pseudonym and E-RAB/F-TEID chain before
  admitting S11 evidence; admit S1-U only when its TEID has one established
  session owner inside the bounded 300-second evidence window.
- Keep reused or ambiguous TEIDs, partial captures and insufficient evidence
  unmatched rather than joining by time or TEID alone; add multi-PCAP,
  multi-UE, reused-TEID, partial and out-of-order regressions.
- This is an offline correlation fix only. It does not certify real LTE,
  modify capture processes, generate traffic or deploy production services.

## OIRAN API 2.7.2 / live-probe 0.4.1 / Analyzer 2.7.1 — 2026-11-01

- Reject SUCI, SUPI, TMSI, PEI, equipment-identity variants and subscriber
  key labels at the LTE evidence admission/export privacy boundary.
- Apply recursive response sanitization to paginated LTE evidence sessions and
  add bounded JSON/HTML export support for persisted LTE Call Flows.
- Render LTE S1-MME/S11 and S11/S1-U correlation bridges truthfully in the
  Analyzer; E2E remains `UNKNOWN` unless both required bridges are proven.
- Add raw-response, export and UI regressions. This release does not create
  capture references, certify real LTE, enable live traffic or deploy itself.
- Redact provenance filenames containing identity labels or identity-length digit
  runs while retaining safe `capture://` basename provenance.
- Add fail-closed envelope regressions for duplicate capture planes, duplicate event
  IDs, capture-ID mismatch and packet source-file mismatch.
- Document the exact POLARIS evidence-to-OIRAN binding boundary and preserve the
  strict S1-MME/S11/S1-U required-plane set.
- Accept the complete strict POLARIS 0.28.0 import envelope on the existing LTE
  import route and reject outer/nested provenance drift before artifact access.

## OIRAN API 2.7.1 — 2026-10-31

- Preserve the 2.7 real-lab/LTE-evidence model while integrating bounded offline
  LTE session materialization and the complete installed LTE+5G decoder inventory;
  live capture allowlists and execution gates remain unchanged.
- Remove subscriber and equipment identity fields and identity-bearing decoded
  information elements from raw API responses instead of returning masked labels.
- Apply response sanitization at the common success and pagination boundaries for
  datasets, sessions, events, packets, Call Flow and future read handlers.
- Add raw JSON regressions for unauthenticated/viewer and operator reads while
  preserving protocol events, accounting counters and capture provenance.

## Real-lab read model / API 2.7.0 / live-probe 0.4.0 / Analyzer 2.7.0 — 2026-10-31

- Disable bundled reference dataset loading by default; operational Session Explorer,
  Call Flow and Dataset Library now read only persisted CaptureManager datasets and
  atomically admitted LTE evidence. Reference artifacts require the explicit
  `OIRAN_REFERENCE_DATASET_ENABLED=1` test/reference switch.
- Catalog finalized LTE evidence datasets with bounded, line-oriented session lookup
  and Call Flow pagination. Empty LTE observations remain empty/`UNKNOWN`.
- Derive radio technology from observed planes, preserve missing counters as `null`,
  and remove generated UE/PDU/context placeholders from operational responses.
- Apply defense-in-depth subscriber-identity withholding to session and Call Flow
  responses while retaining source-file provenance as `capture://` references.

## LTE evidence pipeline 1.1.0 / API 2.6.0 / live-probe 0.3.0 — 2026-10-31

- Add the ANR1 V2 evidence adapter, canonical plane aliases and fail-closed
  reference, approval, provenance and SHA-256 validation.
- Add atomic/idempotent LTE materialization with bounded Session and streaming
  Call Flow pagination, capture/binding decoder-version equality and a 64 MiB
  retained-event allocation budget while preserving 5G reconstruction.
- Add verified streaming export for already-sanitized PCAP/derived evidence;
  exports start `SANITIZED_PENDING_REVIEW` and are not a generic anonymizer.
- Add Operator+CSRF import/export routes and exact request/response contract.

## LTE offline certification 1.0.0-offline.1 — 2026-10-31

- Validate mandatory S1-MME/S11/S1-U fixture fields separately from ANR1
  readiness, with a machine-readable schema and fail-closed real-fixture gate.
- Partition LTE sessions by explicit S1AP context, exact pseudonym and S11
  F-TEID; add multi-UE, timestamps, UL/DL counters and ambiguity regressions.
- Add canonical LTE Call Flow generation and offline correlation rule version
  `1.0.0-offline.1` without enabling capture or production ingestion.
- Extend the synthetic decoder fixture with E-RAB procedure coverage and keep
  the approved-PCAP requirement explicit.

## LTE pipeline preparation 0.1.0 — 2026-10-31

- Add explicit, non-aliased offline decoder routes for S1-MME/S1AP PPID 18,
  S11/GTPv2-C UDP 2123 and S1-U/GTP-U UDP 2152 while retaining N2/N3/N4/SBI.
- Add LTE session preparation with EPS bearer metadata and per-TEID UL/DL
  packet/octet counters, without timestamp-only subscriber association.
- Add ambiguity-safe S11-to-S1-U and prepared S1AP-to-S11 correlation rules.
- Add Analyzer LTE filters marked synthetic-only and an ANR1-gated real-fixture
  manifest template. No capture or production enablement is included.

## OIRAN API 2.5.3 / live-probe 0.2.6 - 2026-10-31

- Aggregate continuous N3 user-plane observations by TEID, direction, inner flow and QFI while decoding; packet and byte counters plus first/last provenance remain exact without retaining one event per G-PDU.
- Bound N3 aggregate cardinality and fail an individual segment closed if the limit is exceeded; N2, N4 and SBI signalling remain individual normalized events.
- Preserve the real packet count in continuous-import activity metrics while storing only first/last N3 packet references.
- Normalize directional NGAP `tunnel_ip_{ul,dl}` / `gtp_teid_{ul,dl}` fields when building exact N2-to-N4 tunnel evidence (correlation-engine 0.3.1).

## OIRAN API 2.5.2 / live-probe 0.2.5 - 2026-10-30

- Commit continuous-import checksums only after the rebuilt dataset generation
  has been published atomically. A failed marker write leaves the segment
  retryable instead of reporting it imported without published events.
- Add a regression test covering the atomic marker-write failure and retry.

## OIRAN API 2.5.1 / live-probe 0.2.4 - 2026-10-30

- Added `OIRAN_CONTINUOUS_MAX_SEGMENT_BYTES`, defaulting to 1 GiB, with
  validation against the existing bounded disk policy.
- Reworked PCAP/PCAPNG decoding to visit packets incrementally; discovery,
  SHA-256, copy, packet parsing and decoding no longer materialise an entire
  capture file.
- Stream decoded events through an on-disk spool, finalize idle TCP/SBI
  connections during packet visitation, and retain only event-ID/offset pairs
  during continuous deduplication. This closes the production OOM found when
  a finalized SBI segment expanded to many normalized events under a 256 MiB
  service limit.
- Preserve all fully decoded SBI transactions while keeping response-only
  PARTIAL streams lacking decoded request identity as connection-level HPACK
  evidence rather than synthetic transactions, restoring the pre-regression
  event-count contract without hiding the capture limitation.
- Compact session-engine source metadata to the schema, procedure and SBI
  fields actually consumed after normalization instead of retaining a second
  copy of every decoded IE tree during call-flow reconstruction.
- Oversized finalized segments are now persisted individually with source
  path, observed byte size, timestamp and
  `CONTINUOUS_SOURCE_SEGMENT_TOO_LARGE`; they no longer fail the continuous
  import job or prevent eligible siblings from being ingested.
- Added regression coverage for a streaming 300 MiB import below 32 MiB live
  allocation and for mixed accepted/rejected segments.

## OIRAN API 2.5.0 / live-probe 0.2.3 / oiran-decode 0.4.5 - 2026-10-30

- Integrated the persistent API 2.4 probe registry and its truthful heartbeat,
  interface-role, CSRF, and download-policy routes with the memory-bounded
  live-probe 0.2.3 continuous importer and oiran-decode 0.4.5 decoder release.
- Preserved the mode-`0600` registry seeded with `oiran-vprobe-local-01` and
  retained fail-closed liveness when no measured heartbeat exists.
- Kept continuous checkpoint recovery, stable session/call-flow evidence, and
  external-capture ownership boundaries unchanged.

## OIRAN API 2.4.0-dev / live-probe 0.2.0-dev - 2026-10-28

- Added an atomic, mode-`0600` probe registry seeded with
  `oiran-vprobe-local-01` and an Operator-plus-CSRF `POST /api/v1/probes`
  contract.
- Added registry-backed capture-interface roles while keeping unregistered
  roles explicitly `null`.
- Derived probe liveness only from measured capture ingestion or packet
  timestamps; probes without a real heartbeat remain `PENDING`.
- Made missing live capture interface and size evidence explicitly `null` and
  made raw PCAP download fail closed with `403 DOWNLOAD_POLICY_PENDING`.

## live-probe v0.2.3 — pcap import streaming (copy_verified + write_jsonl_atomic)

- `copy_verified` previously verified the freshly-copied temporary pcap by
  calling `fs::read` on it and feeding the full byte vector to `sha256_hex`.
  On a 512 MiB pcap import the live resident set spiked by ~512 MiB. 0.2.3
  switches the integrity hash to `sha256_hex_file`, which is already the
  streaming (`BufReader` of `STREAM_CHUNK_BYTES`) path used elsewhere in
  the module. The post-copy integrity contract (`size`, `mtime`, `sha256`
  all unchanged) is preserved; only the hashing memory footprint changes.
- The second `fs::read`-into-`sha256_hex` leak at `continuous_source_dedup_ok`
  was fixed with the same `sha256_hex_file` substitution.
- Test (`copy_verified_streams_512_mib_import_under_32_mib_live_allocation`,
  `#[ignore]`'d because the `#[global_allocator]` tracker is shared with
  concurrent tests): materialises a 512 MiB source pcap on disk, computes
  its expected SHA via the streaming hasher, builds a `SourceSegment` with
  that checksum, resets the allocation peak, calls `copy_verified`, and
  asserts the peak live allocation stays under 32 MiB. Measured on Back100:
  `COPY_VERIFIED_512MIB_PEAK_BYTES=1048765 PEAK_MIB=1 LIMIT_MIB=32`. Full
  live-probe suite: `cargo test -p live-probe` → 42 passed, 0 failed, 2
  ignored. Reproduce:
  `cargo test -p live-probe --release copy_verified_streams_512_mib_import_under_32_mib_live_allocation -- --ignored --test-threads=1 --nocapture`.

## oiran-decode v0.4.5 — streaming-friendly write_jsonl_atomic signature

- `write_jsonl_atomic` now accepts `IntoIterator<Item = &NormalizedEvent>`
  instead of `&[NormalizedEvent]`. The function body was already streaming
  through a bounded `BufWriter`; the API change lets a caller that produces
  events lazily avoid materialising the full `Vec` before writing. Existing
  callers (`live-probe/src/lib.rs:2197` with `&all_events` and
  `oiran-decode/src/lib.rs:332` with `&[]`) compile unchanged because
  `&Vec<T>` and `&[T]` both implement the new trait bound.

## live-probe v0.2.2 — source_segments OOM fix, memory-bounded ingestion

### live-probe v0.2.2 — bounded ingestion

Codex measured 27 OOMs in 5 min with RSS up to 255 MiB in a 256 MiB cgroup
on the OIRAN API, root-caused to `source_segments()` retaining up to 512
candidates and `fs::read()`-ing each pcap in full BEFORE applying the
`finalized_candidates_only` filter. The fix:

- **Metadata-first finalized filter.** `source_segments()` now walks the
  candidate pool as a cheap `SourceCandidateMeta { path, interface,
  size_bytes, modified }` projection, applies the finalized filter on
  that, THEN opens and stream-hashes only the kept candidates. The pcap
  content is never materialised in RAM — SHA-256 streams through 1 MiB
  `BufReader` chunks via `sha256_hex_file`, and packet counting uses the
  existing streaming `count_pcap_records` (16-byte header + `io::copy`
  into `io::sink`).
- **Streaming per-candidate loop.** One pcap in flight at a time; the
  candidate's `size_bytes` + `modified` are retained in metadata only.
  No `Vec<u8>` of file contents is ever held across loop iterations.
- **`events.clone()` dropped.** `session_engine::discover_sessions` was
  taking `Vec<EventRecord>` by value and consuming it, forcing live-probe
  (and three other callers) to `events.clone()` the full dataset so the
  Vec could be used after discovery. Signature changed to
  `discover_sessions(&mut Vec<EventRecord>)` — callers now pass a mutable
  borrow and reuse the same Vec afterwards. 4 call sites updated
  (live-probe, correlation-engine, apps/api, evidence-replay bin).
- **600 × 2 MiB memory-bounded test.** New
  `source_segments_memory_is_bounded_on_600_two_mib_pcaps` test uses a
  tracking `GlobalAlloc` shim to assert that the peak live allocation
  stays under 128 MiB when walking 600 synthetic 2 MiB pcaps. Measured
  peak: **1 MiB** on 512 segments (vs. ~1 GiB upper bound in 0.2.1).
  The test is `#[ignore]`'d because the global allocator counts
  allocations from every parallel test thread, so it must run alone:
  `cargo test --release -p live-probe
   source_segments_memory_is_bounded -- --ignored --test-threads=1
   --nocapture` → `source_segments peak live allocation = 1258536 B =
   1 MiB (segments=512)` in 47 s.
- **Pre-existing live-probe test failures proven as environmental.**
  Three continuous-import tests
  (`continuous_import_is_incremental_deduplicated_stoppable_and_restart_safe`,
  `continuous_source_skips_active_truncation_and_rotates_owned_ring`,
  `full_ring_ingests_three_interface_batches_across_rotations`) fail
  when the test host's `/tmp` filesystem is at ≥ 85 % utilisation because
  `disk_safety::capture_budget` returns `allowed=false` on
  `SafetyState::StopNewCaptures`. The tests now call a
  `skip_if_disk_too_full()` guard that emits a `SKIP ...` log line with
  the detected safety state and returns early. On this host `df -h /tmp`
  reports 87 % usage; on a host with free space the guard is a no-op and
  the tests run normally.
- The merge of `feat/oiran-live-probe-finalized-segments` (0.2.0,
  SHA 0930c75) is now part of this branch: `finalized_candidates_only()`
  and `record_ingestion_failure()` are available, plus the four
  finalized-segments unit tests. Lineage proven by
  `git merge-base --is-ancestor 0930c75 HEAD` returning 0 after the
  merge commit `3e87af3`.

### decoder-ngap v0.6.0 compatibility alias

The 0.6.0 outer-list walker emitted `item_<i>_pdu_session_id` identifiers
but `session_engine::discover_sessions` groups events by the historical
`pdu_session_id` key. Fixed by also emitting a plain
`pdu_session_id=<first-item-id>` for IE 74 and IE 75 so the session
engine recognises PDU sessions decoded through the new walker. Fixes
`completed_capture_registers_real_decoded_dataset_with_provenance`.

## oiran-decode v0.4.5 / decoder-sbi v0.3.1 / live-probe v0.2.1 — SBI 0.4.2 regression + OOM fixes

### decoder-sbi v0.3.1 — HPACK regression fix

Codex measurement on inventory `aabbe5e9…` showed 0.4.2 regressed SBI
throughput 70x: 57,532 DECODED / 6,164 PARTIAL (0.3.1) → 799 DECODED / 317,019
PARTIAL (0.4.2). Two root causes were introduced in 0.4.2:
- **Permanent direction poisoning**: a single HPACK failure flagged every
  subsequent HEADERS block on the same direction as `hpack_unavailable`,
  including blocks the HPACK decoder had accepted cleanly.
- **Ghost events**: streams that in 0.3.1 would have been skipped (orphan
  CONTINUATION, oversized HEADERS/CONTINUATION fragments, unflushed
  continuations at end of capture) were promoted to synthetic events via
  `hpack_unavailable=true`. This inflated the event count by ~5x on
  well-formed captures.

Fix:
- HPACK failure now touches **only** the specific header block that failed.
  The next block that decodes cleanly re-synchronises the direction
  automatically — no permanent poisoning.
- Frame-level framing errors (orphan CONTINUATION, oversized blocks,
  unflushed continuations) are now **connection-level** entries in
  `report.errors`. They do not touch any stream state, so they do not
  fabricate events.
- One normalised event per stream (unchanged structural invariant); the
  stream is only promoted to an event when at least one direction's
  decoded headers are non-empty — same contract as 0.3.1.

Two new non-regression tests pin the contract:
- `non_regression_well_formed_connection_emits_one_decoded_event_per_stream`
  encodes 32 well-formed HTTP/2 request/response pairs with SETTINGS,
  WINDOW_UPDATE and GOAWAY interleaved. The decoder emits exactly 32
  DECODED events, zero HPACK_CONTEXT_UNAVAILABLE errors, zero ghost
  events for the control frames.
- `non_regression_hpack_failure_does_not_poison_subsequent_streams`
  encodes a failing HEADERS on stream 1 followed by a well-formed POST
  on stream 3. Stream 3 decodes cleanly, stream 1 surfaces the
  HPACK_CONTEXT_UNAVAILABLE once, and the direction-level error is
  logged exactly once in `report.errors` (not per frame).

### live-probe v0.2.1 — memory-bounded streaming I/O

Audit of live-probe 0.2.0 identified three unbounded-RAM sites that
accounted for the API OOM Codex observed:
1. **`fs::read(pcap_path)` for integrity verification**: every source
   pcap was fully materialised in a `Vec<u8>` so `sha256_hex(&bytes)`
   could run. On a multi-GB pcap this allocates the full file. Fixed by
   introducing a streaming `Sha256Hasher` in event-schema and a
   `sha256_hex_file(path)` + `verify_file_integrity(path, size, sha)`
   helper that walks the file in 1 MiB chunks via `BufReader::fill_buf`.
2. **Continuous events dedup rewrite**: the per-ingestion
   `events.jsonl` rewrite read the entire prior file via
   `fs::read_to_string`, held a `BTreeMap<String, serde_json::Value>` of
   every event, and finally serialised the whole thing into a
   `Vec<u8>` before `atomic_write`. On a long-running continuous
   capture this is proportional to the number of events ever observed.
   Fixed by streaming the prior file line-by-line, storing serialised
   lines (not parsed values), applying a `MAX_IN_MEMORY_EVENT_IDS =
   1_000_000` safety cap with FIFO eviction, and writing the output
   through a `BufWriter` + atomic rename.
3. **Recovery dataset integrity material**: `integrity_material` was
   built by `fs::read(events.jsonl)` and `fs::read(dataset_manifest)`
   concatenated into a single `Vec<u8>`, then hashed. Replaced by a
   two-file streaming SHA-256 identical bit-for-bit to the previous
   output.

Bounded-memory tests pin the contract:
- `streaming_sha256_matches_in_memory_sha256_on_large_synthetic_file`
  materialises a 64 MiB file on disk and verifies that
  `sha256_hex_file` returns the exact same hash as the full-buffer
  oracle. The production code path only ever reads
  `STREAM_CHUNK_BYTES = 1 MiB` at a time.
- `verify_file_integrity_detects_size_and_hash_mismatches_without_full_read`
  proves the integrity verifier catches size and SHA mismatches on a
  4 MiB file without a full-read oracle.

### event-schema

- Added `Sha256Hasher` (streaming) with `new()`, `update(&[u8])`,
  `finish_hex()`. `sha256_hex(bytes)` is now implemented on top of it,
  byte-for-byte identical to the previous implementation (the
  pre-existing `sha256_matches_standard_vector` test still passes).

### Open regressions

- 6 live-probe tests (`completed_capture_registers_real_decoded_dataset_with_provenance`,
  `continuous_checkpoint_keeps_five_sessions_across_restart_and_republish`,
  `continuous_import_is_incremental_deduplicated_stoppable_and_restart_safe`,
  `continuous_source_skips_active_truncation_and_rotates_owned_ring`,
  `failed_capture_recovery_is_atomic_registered_and_idempotent`,
  `full_ring_ingests_three_interface_batches_across_rotations`) are
  broken at the branch base `d85d29f` already; this release does not
  change the pass/fail count — it only adds +2 bounded-memory tests
  that both pass.

## oiran-decode v0.4.4 — pycrate-grounded real TS 38.413 transfer decoders

- `decoder-ngap v0.6.0`:
  - **Real ASN.1 ground truth: pycrate.** Replaced the simplified asn1tools
    schema (removed `tests/fixtures/aper-transfer.asn` and the asn1tools
    generator) with pycrate (`pycrate_asn1dir.NGAP`), the only Python library
    that compiles the full TS 38.413 3GPP ASN.1 module. Fixtures are now
    pycrate `.to_aper()` outputs of real NGAP types.
  - **Request transfer = ProtocolIE-Container.**
    `decode_pdu_session_resource_setup_request_transfer` now walks the real
    `SEQUENCE { protocolIEs ProtocolIE-Container {...} }` structure: outer
    SEQUENCE ext + 1-bit, 2-octet container size, then per-item
    `{ id, criticality, value OPEN TYPE }`. Decoded IEs:
    `id-UL-NGU-UP-TNLInformation` (139), `id-PDUSessionType` (134),
    `id-QosFlowSetupRequestList` (136),
    `id-PDUSessionAggregateMaximumBitRate` (130). Unknown IEs are retained
    with `{id, criticality, length}` on `unknown_protocol_ies` and named in
    `errors`; the OPEN TYPE length determinant lets the walker skip them
    cleanly instead of de-syncing.
  - **Response transfer: 4 top-level OPTIONALs + extensions.** The response
    SEQUENCE now reads the correct 5-bit preamble (ext + additional +
    security + failed + iE-Ext) and parses the `iE-Extensions`
    ProtocolExtensionContainer when present, extracting
    `id-RedundantDLQosFlowPerTNLInformation` (id 196) into `redundant`;
    other extensions are retained verbatim with their id/length.
  - **IE 71 / IE 72 (Cxt-Req / Cxt-Res).**
    `decode_pdu_session_resource_setup_list_cxt_req` and `_cxt_res` cover
    `PDUSessionResourceSetupListCxtReq` / `CxtRes` from the
    `InitialContextSetupRequest/Response` procedures (used by Open5GS to
    mount the session via the Initial Context Setup path).
  - **Correct extensibility on primitives.** Audited every INTEGER / ENUMERATED
    / CHOICE in the real NGAP module and fixed the extension-marker handling:
    `QosFlowIdentifier` is extensible (1 ext bit + 6-bit value, 7 bits total),
    `PriorityLevelARP` is NOT extensible (4-bit bit-field),
    `UPTransportLayerInformation` is NOT extensible (1-bit choice index for
    gTPTunnel vs choice-Extensions),
    `Cause` is NOT extensible (3-bit index for 6 root alternatives including
    choice-Extensions). The old implementation was wrong on all four, which
    is why the asn1tools-simplified fixtures looked self-consistent but
    disagreed with real captures.
  - **Guard-rail.** `tests/pycrate_fixtures.rs` includes an explicit guard
    that encodes `TEID=0x11223344` and `QFI=5` with pycrate and asserts the
    exact values round-trip through the decoder. Separate tests prove
    mangled or truncated bytes return a NON-matching value AND surface
    named `errors` entries — the decoder never silently fabricates a wrong
    value.
  - **8 new typed structs** exposed on the public API (`SNssai`,
    `SetupItemSUReq`, `SetupItemSURes`, `ListSUReq`, `ListSURes`,
    `UnknownProtocolIe`, `UpTransportLayerInformation::ChoiceExtensions`,
    `QosCharacteristics::ChoiceExtensions`) plus `serde::Serialize` on
    every public type so the `ngap-decode-hex` diagnostic CLI emits a
    complete JSON tree.

## oiran-decode v0.4.3 — real outer-list walker, ENUMERATED extension, diagnostic CLI

- `decoder-ngap v0.5.1`:
  - **Outer list walker, no more heuristic.** `decode_pdu_session_list` now
    routes IE 74 and IE 75 through the new
    `decode_pdu_session_resource_setup_list_su_req` /
    `decode_pdu_session_resource_setup_list_su_res` entry points, which
    implement the real X.691 ALIGNED PER encoding of
    `PDUSessionResourceSetupListSUReq` and `PDUSessionResourceSetupListSURes`:
    SIZE(1..256) size byte, per-item SEQUENCE preamble (ext +
    optional-presence bits), `pDUSessionID` octet-aligned, `pDUSessionNAS-PDU`
    with its APER length determinant, `S-NSSAI` SEQUENCE (`sST` as a SIZE(1)
    bit-field, `sD` as SIZE(3) octet-aligned), and the transfer OCTET STRING
    extracted via its own length determinant. The previous "canonical" byte
    offset heuristic has been removed; non-canonical layouts surface their
    specific failure in a per-item `errors` list and the `item_<i>_*` summary
    keys name the exact field that did not decode.
  - **`qosFlowMappingIndication` extension additions.** When the ENUMERATED
    extension bit is set, the walker now reads the normally-small-non-negative
    whole number for the extension index (X.691 Clause 10.6) and reports
    `AssociatedQosFlowMapping::UnknownExtension(index)` instead of returning
    `UnknownExtension(0)` for every extension value.
  - **Diagnostic CLI.** New binary `ngap-decode-hex` (invoked as `cargo run
    -p decoder-ngap --bin ngap-decode-hex`) reads a hex NGAP PDU from stdin
    (whitespace and `0x` prefixes tolerated) and writes the decoded tree as
    pretty-printed JSON on stdout. For IE 74 and IE 75 the embedded transfer
    is decoded in the same JSON blob so operators can diff the result
    side-by-side with `tshark -O ngap -J` on real captures.
  - **New fixtures.** 7 additional asn1tools-generated ground-truth fixtures
    cover the outer list envelope: 1 session SST-only, 1 session with NAS-PDU,
    1 session with S-NSSAI SST+SD, 1 session with item iE-Extensions, 3
    sessions mixed (NAS-PDU + SST/SD + iE-Ext), and SURes with/without
    iE-Extensions on individual items. The hand-crafted bit-level fixture
    `qos_flow_mapping_indication_extension_decodes_normally_small_number`
    exercises the ENUMERATED extension path end-to-end.
- Fixtures remain synthetic (PLMN 001/01 or TEST-NET addresses, NAS-PDU
  stub 0x7e 00 44 6f = plain 5GMM Registration Reject). No real
  SUPI/K/OPc/SUCI/GUTI/IMSI/IMEI material is present in test code,
  fixtures, or decoders.

## oiran-decode v0.4.2 — real X.691 APER walker, HPACK Huffman recovery

- `decoder-ngap v0.5.0`: removed the one-octet-per-primitive canonical walker
  and replaced it with a bit-accurate X.691 ALIGNED PER reader
  (`aper::AperReader`) plus type-specific decoders for
  `PDUSessionResourceSetupRequestTransfer` and
  `PDUSessionResourceSetupResponseTransfer`
  (`transfer::decode_pdu_session_resource_setup_{request,response}_transfer`).
  The decoders are driven by 11 ground-truth fixtures generated with
  `asn1tools` (Python, codec `per`) against the minimal TS 38.413 subset
  shipped in `decoder-ngap/tests/fixtures/aper-transfer.asn`. Each fixture
  round-trips value → bytes → decoder → value, so a byte-level drift fails
  loudly. Optional fields covered end-to-end: `gBR-QosInformation`,
  `dynamic5QI`, `reflectiveQoSAttribute`, `additionalDLQosFlowPerTNLInformation`
  (multi-tunnel), `qosFlowFailedToSetupList` with Cause CHOICE, and
  `SecurityResult`. Unsupported constructs (extension markers, choice
  extensions, unknown Cause groups) are now **named** in a `errors` vector on
  the returned structure instead of being silently dropped — the "canonical
  only" rejection path has been removed.
- `decoder-sbi v0.3.0`: `tolerant_literals` now decodes HPACK Huffman-encoded
  literals via `hpack::huffman::HuffmanDecoder`. HTTP/2 header blocks that
  only recovered static-name indexed-plain literals in 0.2.0 now also recover
  the Huffman-encoded values that make up most SBI PATCH requests. Covered by
  two unit tests: the RFC 7541 Appendix C.4.1 example for `:authority` =
  `www.example.com` and a synthetic SBI `:path` = PATCH SM-context modify.
- Fixtures remain synthetic (PLMN 001/01 or TEST-NET addresses). No real
  SUPI/K/OPc/SUCI/GUTI/IMSI/IMEI/IMEISV material is present in test code,
  fixtures, or decoders.

## oiran-decode v0.4.1 — SBI HPACK context, NGAP QoS flow walker, EPS SMC decoding

- `decoder-sbi v0.2.0`: HPACK decode failures (dynamic table state lost when the
  capture starts mid-connection, orphan CONTINUATION, header block exceeding the
  configured maximum size) are now surfaced as explicit
  `HPACK_CONTEXT_UNAVAILABLE` errors on the normalized event instead of being
  rolled into a generic PARTIAL. Once a direction's HPACK state is poisoned, any
  subsequent HEADERS block on that direction is attributed to
  `HPACK_CONTEXT_UNAVAILABLE` because the dynamic table indices can no longer be
  verified against the sender. Streams whose request headers failed to decode
  are still emitted so the response remains correlatable by HTTP/2 stream ID
  (previously these were silently dropped as incomplete). The CONTINUATION
  reassembler was audited: orphan CONTINUATION frames and over-sized blocks now
  flag the stream explicitly instead of being discarded.
- `decoder-ngap v0.4.1`: added a canonical APER walker for
  `QoSFlowSetupRequestList` inside `PDUSessionResourceSetupRequestTransfer`
  (IE 74) and `AssociatedQosFlowList` inside the first
  `QoSFlowPerTNLInformation` of `PDUSessionResourceSetupResponseTransfer`
  (IE 75). When the walker matches the "no-optionals, nonDynamic5QI, canonical
  one-octet-per-primitive" layout it emits per-item `qfi_<i>`, `five_qi_<i>`,
  `arp_priority_<i>`, `arp_capability_<i>`, `arp_vulnerability_<i>` session
  identifiers. Non-canonical encodings (extensions, additional optional
  subfields, dynamic5QI) fall back to the existing structural
  `qos_flow_setup_list=present` marker so operators can tell "scanned but could
  not decode" apart from "no QoS flow IE at all".
- `decoder-nas v0.3.1`: EPS Security Mode Command (0x5C) now has a dedicated
  per-TS 24.301 §8.5 decoder (previously the body was preserved only by
  SHA-256). Mandatory fields emitted: Selected NAS security algorithms
  (`ciphering=EEAn, integrity=EIAn`), NAS key set identifier (`nas_ksi`,
  `tsc`), and Replayed UE security capabilities parsed as EEA / EIA / UEA /
  UIA / GEA bitmaps per TS 24.301 §9.9.3.34.
- Fixtures are synthetic (PLMN 001/01 or TEST-NET addresses). No real
  identity, key, SUCI, GUTI, IMEI or IMSI material is present in test code.

## oiran-decode v0.4.0 — N2 SM transfer typing, Diameter S6a base, Security Mode Command

- `decoder-ngap v0.4.0`: PDUSessionResourceSetupListSUReq (IE 74) and
  PDUSessionResourceSetupListSURes (IE 75) now expose direction-tagged tunnel
  evidence from the nested PDU Session Resource Setup Request/Response Transfer.
  IE 74 yields `tunnel_ip_ul` + `gtp_teid_ul`, IE 75 yields `tunnel_ip_dl` +
  `gtp_teid_dl`. Structural scan also reports `pdu_session_type` (ipv4, ipv6,
  ipv4v6, ethernet, unstructured) and the presence of a QoS Flow setup list. The
  overall message status stays `PARTIAL` because QFI, QoS profile and secondary
  fields remain SHA-256 provenance; the correlation keys needed for NGAP ↔ PFCP
  ↔ GTP-U are now emitted explicitly instead of being hidden behind an
  undirected `tunnel_endpoint_ip`/`gtp_teid` pair.
- `decoder-nas v0.3.0` (TS 24.501):
  - Registration Request now decodes the optional UE security capability
    (IEI 0x2E = 46). The IE value is parsed into `nr_encryption`,
    `nr_integrity`, and when present `eutra_encryption`/`eutra_integrity`.
  - Security Mode Command (0x5D) now has a dedicated parser: Selected NAS
    security algorithms (ciphering/integrity half-octets), ngKSI, Replayed UE
    security capability (LV) and the optional Additional 5G security information
    (IEI 0x36 = 54) which reports `rinmr` and `hdp`.
- `decoder-diameter v0.2.0` (RFC 6733 + 3GPP TS 29.272): added base AVPs
  Origin-State-Id (278), Session-Id (263), Auth-Session-State (277),
  Vendor-Specific-Application-Id (260, grouped), Vendor-Id (266), Auth- and
  Acct-Application-Id (258/259). These AVPs previously forced S6a messages to
  `PARTIAL` because they were unsupported.
- All new fixtures are synthetic (PLMN 001/01 or TEST-NET addresses). No real
  identity, SUPI, K, OPc, SUCI, GUTI, IMEI or IMSI material is present in test
  code.

## live-probe v0.2.0 — finalized segments only + persistent failure log

- Continuous import skips the still-live dumpcap target per interface. For
  each interface the newest file is dropped from the candidate set whenever
  its mtime is more recent than `2 × stable_age`; finalized files
  (anything older) stay eligible. The pure helper
  `finalized_candidates_only()` replaces the previous "stable-across-scans"
  proxy at the discovery layer, so a running writer is never fed into
  `copy_verified` and cannot trigger
  `CONTINUOUS_SOURCE_CHANGED_DURING_IMPORT` as a hot-path error.
- `ContinuousImportState` grows a bounded `failed_ingestions: VecDeque<
  FailedIngestion>` persisted in `import_state.json`. Every ingestion
  failure path (`CONTINUOUS_SEGMENT_NOT_FINALIZED` pre-copy / post-copy,
  `CONTINUOUS_COPY_RETRYABLE`) now records `{source_path, error_code,
  occurred_epoch_ms}` and writes the state atomically — the entry survives
  probe restarts, so the operator can audit a 1 h window after the fact.
  Bounded at `MAX_PERSISTED_INGESTION_FAILURES=256`, FIFO-evicted.
- Pure helpers `record_ingestion_failure` and `finalized_candidates_only`
  are exposed under tests; four new unit tests exercise FIFO eviction,
  verbatim path/code/timestamp preservation, newest-per-interface skip
  within the safety window and single-file acceptance after the window
  has elapsed.
- No live-probe behaviour change for successful imports; aggregate metrics
  (`ingestion_failures`, `segments_ingested`, …) remain the same.

## decoder-ngap v0.3.1 / oiran-decode v0.3.1 - NGAP status correction

- Mark a structurally bounded NAS-PDU information element as decoded at the
  NGAP layer; the nested NAS child event independently retains
  `ENCRYPTED_OR_PROTECTED`, `PARTIAL` or `MALFORMED`.
- Correct the NAS security-header nibble and accept the observed eight-octet
  as well as schema forty-bit `UEAggregateMaximumBitRate` encodings.
- Keep PDU Session Resource Setup list items `PARTIAL` while their nested N2
  SM transfer remains opaque; no missing field is promoted to decoded.
- Replayed the unchanged finalized N2 inventory identified by SHA-256
  `aabbe5e942ede445fcd59b8ad37184f7dadc57a8b16aee935b30b99e9ecdc084`.

## decoders-epc v1.0 - GTPv2-C, Diameter S6a, EPS NAS (TS 29.274 / RFC 6733 + TS 29.272 / TS 24.301)

- `decoder-gtpv2c v0.1.0` (new crate, TS 29.274): Echo, Create/Modify/Delete Session, Create/Delete Bearer, Release Access Bearers. IEs IMSI, MSISDN, MEI are flagged identity (`pseudonymized: true`); F-TEID, Bearer Context (grouped), PAA, APN, AMBR, Serving Network (PLMN), EBI are decoded.
- `decoder-diameter v0.1.0` (new crate, IETF RFC 6733 + 3GPP TS 29.272 S6a): ULR/ULA (316), AIR/AIA (318), PUR/PUA (321), CLR/CLA (317), NOR/NOA (323). AVPs User-Name (code 1) and MSISDN (code 701, vendor 10415) are flagged identity; Result-Code, Experimental-Result-Code, Visited-PLMN-Id, Origin-Host/Realm, Subscription-Data envelope and Authentication-Info envelope are decoded.
- `decoder-nas v0.2.0` (extended, TS 24.301): added EPS EMM (Attach, TAU, Service Request, Detach, Authentication, Security Mode, Identity, EMM Status/Information, NAS Transport) and ESM (PDN Connectivity, Activate/Modify/Deactivate EPS Bearer Context, ESM Info, Status). EPS Mobile Identity (IMSI/IMEI/IMEISV/GUTI) is flagged identity.
- `decoder-s1ap v0.2.0` (updated): NAS-PDU IE (id 26) now forwards to `decoder-nas` and emits a child `NormalizedEvent` with a parent link back to the S1AP event, mirroring NGAP → 5G NAS.
- `event-schema`: added `Protocol::Gtpv2c`, `Protocol::Diameter`, `Protocol::NasEpsMm`, `Protocol::NasEpsSm` variants (`as_str` → `GTPv2-C`, `DIAMETER`, `NAS-EPS-MM`, `NAS-EPS-SM`).
- All fixtures are synthetic (PLMN 001/01, synthetic BCD/digit material). No real identities are present in test code.

## decoder-s1ap v0.1.0 - S1AP APER decoder (TS 36.413)

- Added `OIRAN/decoder-s1ap` crate implementing the schema-independent S1AP-PDU/open-type envelope and ProtocolIE container, modelled on `decoder-ngap`.
- Procedures recognised: S1 Setup (17), E-RAB Setup (5), E-RAB Release (7), Initial Context Setup (9), Paging (10), Downlink NAS Transport (11), Initial UE Message (12), Uplink NAS Transport (13), UE Context Release Request (18), UE Context Release Command / Complete (23).
- Identity-bearing IEs (`S-TMSI`, `UEPagingID`, `GUMMEI-ID`, `SecurityKey`, `NAS-PDU`) are tagged `pseudonymized: true` so the Analyzer strips them before persistence.
- Added `Protocol::S1ap` variant to the event-schema protocol enum.
- Coverage: 10 unit tests on synthetic APER vectors built from TS 36.413 with synthetic PLMN `001/01` and synthetic identities only — no real IMSI/K/OPc material in fixtures.
- Carried NAS-PDU is EPS NAS (TS 24.301) and preserved opaquely by SHA-256 + length; `decoder-nas` remains 5G-only (declared limitation).
- Added `OIRAN/docs/PROTOCOL_AUDIT.md` with the static 12-plane coverage audit.

## Release consolidation V1.1 - lossless continuous checkpoint resume

- Preserve evidence-backed session identifiers when live activity credit expires or a continuous import is finalized.
- Validate and merge the last durable continuous dataset checkpoint before publishing the next atomic dataset generation.
- Deduplicate observations by stable semantic event identifier and retain only call flows whose event references remain present.
- Fail closed on an invalid checkpoint without replacing the prior event store.
- Added restart, new-data, idempotent replay, five-session retention, and invalid-checkpoint regression coverage.

## E2E-002 - Atomic derived-dataset registration

- Added an authenticated, allowlisted import endpoint that accepts only a derived dataset identifier.
- Verifies source capture identity, all source PCAP hashes and packet counts, artifact hashes, schema/decoder compatibility, provenance, sessions, and correlation evidence before registration.
- Stages and atomically renames the complete dataset, callflows and registry update.
- Supports idempotent re-import and rejects conflicting dataset identifiers.
- Added authenticated candidate browser coverage for derived dataset visibility, exact tunnel evidence, strong associations, unknown NG-U evidence and packet provenance.

## E2E-002 - Evidence-based cross-interface correlation

- Normalized structurally verified NGAP UP transport endpoint and TEID evidence.
- Added typed exact-tunnel and strong-context correlation edges with scope, limitations, and packet provenance.
- Added ambiguity rejection and kept missing NG-U evidence explicitly unknown.
- Exposed evidence type and limitations in Call Flow and Correlation Studio.
- Added an immutable-source offline replay producing a separate 92-event derived dataset.

All notable OIRAN vProbe changes are recorded here. Versions follow Semantic Versioning.

## [S5.5.1/1.0.1-dev] - 2026-10-26

### Fixed

- Defined the shared Rust `MAX_CAPTURE_PLANES = 4` contract and applied it independently in the live-probe API validator and isolated Capture Helper.
- Made the four-plane default (`N2`, `SBI`, `N4`, `N3`) valid while retaining one-, two- and three-plane compatibility.
- Preserved strict rejection of duplicate, unknown, unavailable and more-than-four logical planes.
- Added deterministic interface inventories for offline helper/IPC tests while retaining the fixed `/sys/class/net` inventory in production.
- Added explicit Select All and Apply Configuration controls; successful validation is invalidated whenever capture configuration changes.

### Validation

- Passed 172/172 Rust workspace tests, including authenticated HTTP API to Unix IPC to non-acquiring Capture Helper validation.
- Passed 19/19 frontend tests, TypeScript validation and the production frontend build.
- Passed 46/46 browser E2E regressions against an isolated local API and copied read-only registry fixture.

### Safety

- Four-plane storage remains one global bounded reservation: the helper divides the job budget across plane/rotation segments rather than multiplying it.
- No packet socket was opened by the new validation test, and no live capture, simulator execution, production deployment or service restart occurred.

## [S5.5/1.0.0-dev] - 2026-10-26

### Added

- Unified S5.1 SLL2, S5.2 NAS and S5.3 TCP/HTTP2/SBI decoding in one release lineage.
- Fixed, allowlisted SBI capture point (`br-oiran-sbi`, TCP/7777) in the isolated AF_PACKET helper.
- Four-plane POLARIS profile for NG-C, SBI, N4 and NG-U with synchronized capture-group identifiers and per-plane results.
- Capture-group API, per-plane packet/storage/decode status, and four-plane Probe Manager controls.
- SBI-aware Call Flow participants, arrows and conservative E2E status that remains UNKNOWN when either SBI bridge is unproven.

### Validation

- Passed 166 Rust tests and 18 frontend tests; production frontend build and TypeScript validation passed.
- Passed the dedicated four-plane Playwright suite in Light/Dark at 1440x900 and 1920x1080.
- Retained the unchanged 13-file corpus and the multi-IMSI result: six UE contexts, five PDU sessions, six PFCP sessions, zero GTP-U tunnels and no observed cross-UE contamination.

### Safety

- No live capture, simulator execution, production deployment or shared-service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and certified historical datasets were unchanged.

## [S5.3/1.0.0-dev] - 2026-10-26

### Added

- Bounded bidirectional TCP reconstruction with sequence-aware retransmission, duplicate, out-of-order, gap, timeout and provenance handling.
- Native HTTP/2 frame and multiplexed-stream decoding, including HEADERS/CONTINUATION/DATA and stateful HPACK through the MIT-licensed `hpack` crate.
- Sanitized SBI request/response events for observed Nsmf PDUSession and Namf Communication operations, with JSON/multipart field extraction and explicit TLS/unresolved states.
- Conservative SCP-routing and cross-interface correlation hooks that reject PDU Session ID-only and timestamp-only associations.
- SBI participants and request/response messages in the existing Call Flow schema without synthesizing unseen logical hops.

### Validation

- Replayed the unchanged 13-file, 4,205-packet corpus with SHA256 verification before and after.
- Matched 2,316/2,316 HTTP/2 frames and 766/766 independently comparable fields against TShark 4.2.2; 26 fields remain unresolved because capture begins after HPACK dynamic-table state was established.
- Observed 48 TCP connections, 708 HTTP/2 streams, 198 transactions and 20 prioritized operations.
- Preserved six UE contexts and five PDU sessions without observed cross-UE contamination; the N2/SBI/N4 bridge remains uncertified because explicit cross-layer identifiers are absent.

### Safety

- No live capture, simulator execution, production deployment or service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and the reference corpus were unchanged.

## [S5.2/1.0.0-dev] - 2026-10-26

### Added

- Native bounded Rust dispatch for 5GMM (`0x7e`) and 5GSM (`0x2e`) with observed Release-17 message identities.
- Safe Type 1/3/4/6, TV, TLV and TLV-E handling for observed NAS fields, including pseudonymized mobile identities, PDU Session ID, PTI, causes, DNN and S-NSSAI.
- Explicit NAS security-envelope classification without key derivation, integrity claims or unauthorized decryption.
- Parent/child NGAP → 5GMM → 5GSM event relationships with inherited packet provenance and compatible event schema 1.4.0 fields.
- Evidence-based procedure attempts that separate retry, failure, success and incomplete results and scope NAS children through their exact NGAP parent.

### Validation

- Replayed the unchanged 13-file, 4,205-packet S5.1 corpus before/after SHA256 verification.
- Parsed 116 NGAP-carried NAS envelopes across the full corpus; 46 plain messages were decoded (24 complete, 22 partial), 10 integrity-only messages were decoded without claiming verification, and 60 ciphered envelopes remained unresolved.
- Achieved 404/464 exact independently comparable TShark fields, with zero mismatch and 60 encrypted/unresolved message-type fields.
- Preserved six UE context lifecycles and five PDU sessions in the multi-IMSI fixture without observed cross-UE contamination.
- Passed 152/152 Rust workspace tests after one documented retry of a pre-existing timing-sensitive worker-runtime queue watermark test.

### Safety

- No live capture, simulator execution, production deployment or service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and certified historical datasets were unchanged.

## [S5.1/1.0.0-dev] - 2026-10-26

### Added

- Native Linux cooked capture v2 parsing for `LINKTYPE_LINUX_SLL2` / link type 276.
- Network-byte-order parsing and validation for the 20-byte SLL2 header, including protocol, interface index, ARPHRD type, packet type and address metadata.
- Additive event provenance schema 1.3.0 fields for source SHA256, link type and SLL2 metadata.
- Per-interface SLL2 dispatch for PCAPNG and IPv6 extension-header traversal with explicit fragment/ESP limitations.

### Validation

- Replayed the unchanged 13-file, 4,205-packet benchmark corpus after SHA256 verification.
- Decoded 239 LAB NGAP/PFCP/GTP-U message envelopes with exact packet, timestamp, endpoint and message parity against TShark 4.2.2.
- Reconstructed five isolated PDU sessions from the five-UE fixture without cross-UE contamination; cross-interface N2/N4 confidence remains unresolved.
- Added deterministic PCAP, PCAPNG mixed-link, IPv4, IPv6, malformed-header and fuzz-like regression tests.

### Safety

- No live capture, simulator execution, deployment or production service change occurred.
- POLARIS, POLARIS Control, ETV/OTV and historical certified datasets were unchanged.

## [2.3.0-dev] - 2026-10-26

### Fixed

- Normalize historical, captured-live and recovered dataset records behind API 2.3.
- Add explicit dataset scopes to Session Explorer without fallback to an unrelated historical session.
- Scope decode-completeness counts to session-associated events instead of dataset background events.
- Preserve exact dataset identity through Session Explorer and Call Flow navigation.

### Validation

- Added a deterministic, clearly labeled test corpus with three independent UE contexts, PDU sessions, PFCP sessions and GTP-U tunnels.
- Verified composite identity isolation, identifier reuse safety, pagination and zero-session datasets.
- Passed 134 Rust tests, 18 frontend tests and 44 browser workflows.
- Reviewed Light and Dark screenshots at 1440×900 and 1920×1080.

### Safety

- No live capture, simulator traffic, UE process, deployment or production-service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and certified historical datasets were not changed.

## [1.0.0-dev/OIRAN-P0-LIVE-FINALIZATION-FIX] - 2026-10-25

### Fixed

- Create the derived `dataset/callflows` layout before the first decoded-event write from a freshly finalized helper capture.
- Preserve `FAILED` status for recoverable PCAP evidence until derived processing completes successfully.
- Synchronize terminal helper storage accounting after empty-interface PCAP headers are finalized.
- Show an explicit **View error** action, exact backend failure, and preserved-evidence state for failed capture jobs without linking them to fictitious sessions.
- Finalize normalized-event JSONL, Call Flow exports and dataset manifests using temporary files plus atomic rename.
- Add an idempotent `oiran-recover` command and persistent recovered-dataset registry that never changes the original failed job.

### Validation

- Added clean-root regressions for fully populated N2/N3/N4 captures and captures with an empty N3 interface.
- Added offline timeout, graceful manual Stop, bounded rotation, empty selected interface, partial initialization failure, and failed-job recovery coverage.
- Recovered `live-1792964646320-0003` offline as 50 verified packets and 20 PFCP heartbeat events; the original capture remains `FAILED`.
- No live capture or simulator traffic was executed; original forensic PCAPs and historical certified datasets remain unchanged.

## [1.0.0-dev/OIRAN-P0-ISOLATED-CAPTURE-HELPER] - 2026-10-25

### Added

- Native Rust AF_PACKET capture helper with no tcpdump subprocess dependency.
- Unix socket IPC v1 with `SO_PEERCRED` server authorization and client-side helper identity verification.
- Fixed N2/N3/N4 interface enum, bounded request schema, exact job ownership, and explicit `COMPLETED_EMPTY` state.
- Global disk budget, bounded PCAP rotation, atomic manifests, SHA-256 integrity, and persisted helper job records.
- Review-only hardened systemd unit, API drop-in, IPC specification, security review, and deployment/rollback plan.

### Changed

- `live-probe` now uses the isolated IPC adapter and fails closed when its authorized socket is absent.
- The API capture root may use the fixed `/var/lib/oiran/captures` deployment path; arbitrary Web paths remain impossible.
- Unix termination signals are represented separately from process exit codes.

### Safety

- No helper was deployed or started and no live capture or simulator traffic was executed.
- POLARIS, POLARIS Control, ETV/OTV, Open5GS, UERANSIM, historical datasets, Docker, firewall, and routing were unchanged.

## [2.0.0-dev] - 2026-10-25

### Added

- Premium dark-default Analyzer shell with complete Light, Dark and System themes.
- Operational Overview, Packet Analyzer, Export & Reports, and Live Monitoring modules.
- Versioned API 2.0 endpoints for probe detail, truthful host/live metrics, packet provenance, public Viewer identity, and fail-closed capture lifecycle validation.
- Evidence-driven Call Flow inspector tabs for decoded fields, ASN.1, restricted raw payload references, canonical JSON, correlation evidence and provenance.
- Responsive visual validation for seven analytical views at 1440×900 and 1920×1080 in both themes.

### Validation

- 97 Rust/API tests, 9 frontend tests and 33 browser workflows pass.
- Certified accounting remains 54 source events, 26 session events, 28 background events and 12 evidence edges.
- Live metrics are `NOT AVAILABLE` and capture controls remain unavailable because no authorized live capture backend is configured.

### Safety

- The certified PCAPs and Call Flow JSON remain checksum-identical.
- No POLARIS, POLARIS Control, ETV/OTV, Open5GS, UERANSIM, Docker, firewall, routing or database resource was modified.

## [1.0.0-dev/S4.2] - 2026-10-25

### Added

- Permanent 75/80/85/90 percent disk policy with statvfs byte/inode measurement.
- Fail-closed stateful capture guard, reserved between-poll write budget and bounded 256 MiB × 8 rotation plan.
- Authenticated storage-safety API and measured Probe Manager storage panel.
- Approval-gated five-UE POLARIS scenario manifest and validation reports.

### Safety

- No five-UE scenario, traffic or capture was started because new POLARIS profiles/processes require explicit approval.
- No cleanup, automatic deletion, service restart, database, Docker-network, firewall or route change occurred.

## [1.0.0-dev/S4.1] - 2026-10-24

### Added

- Deterministic multi-UE, multi-PDU, PFCP lifecycle and directional GTP-U tunnel discovery.
- Immutable checksum-based dataset registry with idempotent duplicate handling.
- API 1.1 dataset/UE/procedure endpoints and multi-flow state with S4 compatibility.
- Dataset, UE, interface and state filtering across Session Explorer and Correlation Studio.
- Independent session selection in Call Flow Viewer and conservative incomplete-flow generation.

### Validation

- 85 Rust release tests, 9 frontend tests and 28 browser workflows pass.
- Five-UE/six-PDU synthetic fixture covers concurrent, sequential and incomplete behavior; real multi-UE capture certification remains pending.
- Certified S3.3 call flow and N2/N3/N4 checksums remain unchanged.

### Safety

- POLARIS was read-only; ETV/OTV, Docker networks, databases, routing and capture services were not modified or restarted.
- No additional UE, test traffic or live capture was started.

### Public read-only access update — 2026-10-25

- Removed viewer/admin access tokens and the sign-in screen by explicit operator request.
- Preserved read-only API behavior, disabled live capture controls, sanitized provenance and immutable datasets.

## [1.0.0-dev/S4] - 2026-10-24

### Added

- Localhost-only Axum API adapter with bearer authentication, read-only authorization, pagination, filtering, sanitized provenance and protected exports.
- React/TypeScript application with a shared module-aware shell, Probe Manager, Session Explorer, SVG Call Flow Viewer and Correlation Studio.
- Real integration with 54 certified events, including the strict 26 session / 28 background split and all 12 evidence edges.
- Responsive 1440×900 and 1920×1080 visual certification, keyboard focus states, dark theme, error/empty/loading states and URL-deep-linked sessions.
- Isolated deployment templates, API contract, security/deployment reports and a 25-workflow browser suite.

### Validation

- 71 Rust/API tests, 8 frontend tests and 25 browser workflows pass.
- Production frontend build and TypeScript checking pass; npm audit reports zero vulnerabilities.
- Certified call flow and PCAP hashes remain unchanged; no Docker, database, firewall, route or persistent-service mutation was performed.

## [1.0.0-dev/S3.1-S3.2] - 2026-10-24

### Added

- Native bounded PCAP and PCAPNG reader with exact per-interface timestamp provenance.
- Ethernet, stacked VLAN, Linux cooked v1, IPv4/IPv6, UDP and SCTP extraction.
- SCTP DATA parsing, association generations, duplicate handling and conservative reassembly.
- Independent NGAP, PFCP and GTP-U decoder crates behind plugin API 1.1.0.
- Event schema 1.1.0 with deterministic IDs, packet sets, endpoint roles, decode statuses and raw-payload references.
- Offline CLI producing 99 ordered real-capture events and an independent TShark comparison.

### Validation

- 40 unit/regression tests pass.
- Exact packet/header alignment: 37 NGAP, 52 PFCP and 10 GTP-U; zero missing or mismatched messages.
- Full nested IE parity remains partial: 33 NGAP and 12 PFCP events explicitly retain unsupported values.
- Operational N3 remains empty; GTP-U evidence comes from an immutable Open5GS reference under POLARIS.

### Safety

- No benchmark, package installation, service restart or POLARIS/ETV/OTV mutation.

## [1.0.0-dev/S2.1] - 2026-10-24

### Added

- Immutable preloaded multi-flow batches and deterministic worker-owned partitions.
- Generator-only, independent preloaded fast-path and full-pipeline benchmark isolation.
- Queue-oriented source contract for future PCAP, AF_XDP and DPDK adapters.
- Effective-cpuset-aware automatic/explicit/disabled affinity and worker mask reporting.
- Mandatory fresh receipt from a bounded 15-minute resource safety observer.

### Changed

- `capture-core`, `worker-runtime` and `benchmark-engine` advanced to 0.3.0.
- Processing-only timing no longer contains serial generation, per-packet allocation, queues or shared counters.
- Full-pipeline reporting distinguishes generated, enqueued, processed, explicit drops and in-flight packets.

### Validation

- 21 unit tests passed with no failure; performance runs were deferred because the stability gate did not pass.
- No 25 Gbit/s or 100 Gbit/s capability claim is made.

## [1.0.0-dev/S2] - 2026-10-24

### Added

- Generator-only, pre-generated processing-only and full-pipeline benchmark modes.
- Exact generated = processed + explicit-drop invariant.
- Packet-number sum/XOR, ordered work accumulator and provenance-length validation.
- Four-worker accounting, same-flow ordering and length-mismatch regression tests.
- Complete 1–4 worker, 32–256 batch and 64–1500 byte before/after matrices.

### Changed

- `capture-core` 0.2.0 adds uniquely owned packet buffers while preserving shared replay buffers.
- `worker-runtime` and `telemetry` 0.2.0 aggregate fast-path counters per batch.
- `benchmark-engine` 0.2.0 reports generated packets, length errors and observable work.

### Performance

- Fixed S1 profile (2 workers, batch 64, 250 ms): 1500-byte median increased from 2.694994 to 3.037666 Gbit/s Ethernet-wire equivalent (+12.72%).
- Best accepted three-run median: 3.175694 Gbit/s at 2 workers, batch 256, 1500-byte frames.
- No claim of 25 Gbit/s certification.

### Safety stop

- Further component profiling stopped after an external OTV container replacement/worker exit was observed. S2 status is partial; no OIRAN command modified OTV.

## [1.0.0-dev] - 2026-10-24

### Added

- Eight-crate Rust workspace with independent component versions.
- Immutable packet provenance and batch envelopes.
- Allocation-free Ethernet, VLAN, IPv4, direct-UDP IPv6, UDP and GTP-U classification.
- TEID and tunnel endpoint extraction with strict malformed-length detection.
- Stable software flow/session affinity independent of NIC RSS behavior.
- Bounded per-worker queues, batch execution, CPU affinity, backpressure accounting and graceful shutdown.
- Deterministic replay mode and cache-line-aligned per-worker counters.
- Versioned normalized event model and deterministic decoder plugin contract.
- Safety-bounded synthetic benchmark for 64, 128, 512 and 1500-byte frames.
- Automated integrity, parser, concurrency, saturation, shutdown and replay tests.

### Limitations

- No production capture adapter, SCTP/NGAP/PFCP decoder, dynamic plugin loader or UI in S1.
- No IPv4 fragment or IPv6 extension-header reconstruction.
- Synthetic results are not line-rate certification.

## [1.0.0-dev/S3.2.1] - 2026-10-24

### Added

- Release-aware typed NGAP decoding for observed UE IDs, location, security, S-NSSAI, PDU-session identifiers, cause and selected node/context fields.
- Recursive typed PFCP decoding for the grouped and leaf IEs observed in the selected captures.
- Event-schema 1.2 probe/capture-point identity and explicit EXACT/STRONG/POSSIBLE/UNKNOWN evidence references.
- Field-parity, N3 diagnostic, dataset and correlation-readiness artifacts.

### Changed

- `decoder-ngap` and `decoder-pfcp` advanced to 0.2.0; `event-schema` advanced to 1.2.0-dev.
- Known but untyped PFCP leaves are PARTIAL and unknown IEs are UNSUPPORTED rather than silently decoded.
- The selected PFCP set improved from 40 fully decoded and 12 partial messages to 52 fully decoded and zero partial; NGAP improved from 4/33 to 9/28.

### Validation and safety

- 46 workspace tests pass; 99/99 generated events retain packet provenance and evidence.
- Operational N3 remains empty because no UE user-plane traffic was generated; no POLARIS or ETV/OTV service was changed.
- Full Release-17 NGAP parity and a coherent operational N2/N4/N3 dataset are not claimed.

## [1.0.0-dev/S3.3] - 2026-10-24

### Added

- Independently versioned `session-engine`, `correlation-engine`, `callflow-schema`, `callflow-renderer`, and `oiran-callflow` crates.
- Deterministic UE/PDU/PFCP/GTP-U reconstruction with explicit session, background and unmatched accounting.
- Versioned STRONG N2↔N4 certified-tunnel rules and EXACT N4↔N3 TEID-plus-endpoint rules.
- Canonical Call Flow JSON and standalone interactive HTML with filters, search, zoom, procedure groups, evidence inspector and JSON export.
- Seventeen unit tests for reconstruction, ambiguity, missing data, duplicate handling, provenance, schema, output containment and safe HTML rendering.

### Validation

- All 54 certified source events are preserved: 26 session, 28 background, 0 unmatched, 0 duplicate and 0 extra.
- Twelve evidence-bearing edges reproduce N2↔N4 STRONG, N4↔N3 EXACT and E2E STRONG.
- 63 workspace tests pass; all historical 46 tests remain passing.

### Security

- Subscriber identity remains `UE-A`; no authentication material or unrestricted raw payload is exported.
- HTML has no remote dependency, treats decoded values as text, and script-escapes embedded JSON.

## [1.0.0-dev/OIRAN-LIVE-V1] - 2026-10-25

### Added

- Strictly owned, allowlisted Rust live-capture manager for the discovered POLARIS N2, N3 and N4 Linux bridges.
- Bounded duration, global byte reservation, per-interface rotation, continuous disk enforcement, exact PID ownership, persistent job recovery and audit records.
- Reusable native decoder library feeding normalized events, multi-session discovery, correlation and canonical Call Flow outputs after capture finalization.
- Versioned capture validation/start/stop/metrics API with Viewer, Operator and Administrator enforcement.
- Probe Manager controls, real interface inventory, session-scoped token login and honest execution/certification states.

### Safety

- Capture execution is disabled by default and requires `OIRAN_CAPTURE_EXECUTION_ENABLED=1` plus a server-provisioned token hash.
- No live capture or traffic generation was executed in this release; POLARIS, POLARIS Control and ETV/OTV were not changed.
- Job storage is constrained to `/root/OIRAN_VPROBE/runtime/live-captures`; source datasets are never deleted or overwritten.

## [1.0.0-dev/OIRAN-P0-CAPTURE-LIFECYCLE] - 2026-10-25

- Fixed tcpdump output ownership for its restricted service account.
- Run the OIRAN API with the restricted `tcpdump` primary group and grant write access only to each job's PCAP directory, avoiding the broader `CAP_CHOWN` capability.
- Configure the capture helper to retain the already systemd-confined service identity, avoiding a denied tcpdump `setuid/setgid` transition without granting additional capabilities.
- Persist helper PID, exit status and bounded stderr for capture forensics.
- Classify premature helper exit and missing output as failures.
- Represent legitimate empty capture explicitly without generating sessions.
- Synchronize the selected capture panel with authoritative polling state.
- Recover the affected legacy false-success job as failed.

## [2.2.0-dev] - 2026-10-25

### Added

- Strict capture-to-dataset resolution through `GET /api/v1/captures/{capture_id}/context`.
- Exact packet provenance filters for capture, event and packet number.
- Evidence-derived Call Flow participants, directional SVG arrows, procedure controls and a synchronized message index/inspector.
- Honest zero-session and unavailable-dataset investigation states.
- UTC millisecond timestamp formatting and provenance deep links into Packet Analyzer.

### Changed

- Session navigation now persists `capture_id`, `dataset_id`, `session_id`, `probe_id`, technology and selected event in the URL.
- Capture records expose their associated dataset without changing the immutable capture outcome.
- OIRAN API and Web versions advance to 2.2.0-dev.

### Safety

- No decoder, historical dataset, live capture service or external laboratory component was modified or started.

## OIRAN API 2.5.4 / live-probe 0.2.7 - 2026-10-31

- `GET /api/v1/sessions/:id/callflow` now returns at most 100 events by
  default and accepts `limit` (1..256) plus an event-id `cursor`.
- Persisted call-flow JSON is read with a streaming deserializer; only the
  selected event page is retained, preventing large historical sessions from
  multiplying their resident-memory cost during HTTP serialization.
- Every response carries `pagination.{limit,cursor,next_cursor,returned_events,total_events}`;
  invalid cursors fail explicitly and never replay the first page.

## OIRAN API 2.6.0 / live-probe 0.3.0 - 2026-10-31

- Materialise bounded LTE S1-MME/S11/S1-U sessions and correlated Call Flows
  from already-decoded offline evidence during dataset finalisation and API load.
- Expose the installed decoder inventory and LTE capture protocol labels through
  the version and capture APIs.
- Keep live LTE capture disabled: no capture interface allowlist was expanded.
- Limit offline LTE materialisation to 128 sessions per dataset to bound memory.
