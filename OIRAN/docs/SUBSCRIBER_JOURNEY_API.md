# API Parcours abonné 2.13.0

Toutes les routes sont relatives à `/api/v1`. Elles n'exposent que des pseudonymes au rôle viewer.

- `GET /subscribers` liste les abonnés observés et le nombre de sessions associé.
- `GET /subscribers/{subscriber_pseudonym}/journey` renvoie `contexts`, `sessions` et `links`. Les sessions sont ordonnées par `(capture_id, packet_number, event_id)`, jamais par timestamp.
- `GET /subscribers/{subscriber_pseudonym}/tmsi` renvoie la chaîne des identités temporaires pseudonymisées, avec les références canoniques d'attribution et de présentation.

Une arête de parcours est `EXACT` uniquement si `subscriber_pseudonym` est égal, ou si le même `temporary_identity_pseudonym` est observé dans une attribution antérieure puis une présentation. L'IMEI est informatif. L'heure, la cellule et l'IP sont exclues des règles. Sans attribution capturée, l'état est `OUVERT` et la raison est `attribution non capturée`.

Les valeurs en clair restent exclusivement servies par les routes operator `/identities` de 2.12.0. Le Parcours ne lit ni ne modifie le coffre.
