# Scénarios SIPp — POLARIS IMS-lite

Préparation uniquement : aucune commande ci-dessous ne doit être exécutée sans les accords Sadok listés dans `SOP_VOIX_SIP_IMS_LITE.md` §2. Au relevé du 20/11/2026, l'image SIPp épinglée n'est pas présente localement ; son téléchargement est donc un prérequis explicite.

Les identités et le secret Digest ne sont jamais versionnés. Les fichiers CSV restent hors dépôt, mode `0600`, avec une première ligne `SEQUENTIAL` :

- `register.csv` : `[field0]=AoR`, `[field1]=utilisateur Digest`, `[field2]=secret Digest` ;
- `uas.csv` : même format pour l'UAS ;
- `uac.csv` : `[field0]=AoR appelant`, `[field1]=AoR appelé`, `[field2]=chemin du fichier PCMU brut`.

Préparer un fichier média PCMU local de 30 s, hors dépôt : `head -c 240000 /dev/zero > "$LOCAL_PROOF/pcmu-30s.raw" && chmod 600 "$LOCAL_PROOF/pcmu-30s.raw"`.

## Variables communes

```sh
export SIPP_IMAGE='ctaloi/sipp@sha256:c459f2340443ddcc159227efc798217dbdaad0dbe88b76b78b1a876aa271986a'
export SCENARIOS="$PWD/docs/voix"
export LOCAL_PROOF='/chemin/local/0600/hors-depot'
export PROXY_IP='10.77.24.20'
export DN_IP='10.77.24.30'
export UE_CONTAINER='<conteneur-UE-autorise-et-demarre>'
export IMS_IFACE='<interface-portant-10.47.0.0/16>'
export IMS_IP='<adresse-10.47.x.x>'
```

Après établissement autorisé de la PDU `ims`, détecter `IMS_IFACE` et `IMS_IP` dans le conteneur UE, puis ajouter la route hôte `/32` vers Kamailio par cette interface :

```sh
export IMS_IFACE="$(docker exec "$UE_CONTAINER" sh -lc "ip -o -4 addr show | awk '\$4 ~ /^10\\.47\\./ {print \$2; exit}'")"
export IMS_IP="$(docker exec "$UE_CONTAINER" sh -lc "ip -o -4 addr show dev '$IMS_IFACE' | awk 'NR==1 {sub(/\\/.*/,\"\",\$4); print \$4}'")"
docker exec "$UE_CONTAINER" ip route replace "$PROXY_IP/32" dev "$IMS_IFACE"
```

Ne jamais supposer `uesimtun0` : avec la session `internet` initiale, l'interface IMS attendue est généralement `uesimtun1`.

## V1 — REGISTER Digest

```sh
docker run --rm --network "container:$UE_CONTAINER" --cap-drop ALL \
  --security-opt no-new-privileges:true --read-only --tmpfs /tmp:size=16m \
  -v "$SCENARIOS:/scenarios:ro" -v "$LOCAL_PROOF:/run/local:ro" "$SIPP_IMAGE" \
  "$PROXY_IP:5060" -sf /scenarios/register.xml -inf /run/local/register.csv \
  -i "$IMS_IP" -p 5062 -m 1 -trace_err -trace_msg -nostdin
```

Attendu : REGISTER, 401, REGISTER avec Digest, 200.

## V2 — appel UE vers UAS DN, RTP PCMU avec écho

Terminal UAS DN :

```sh
docker run --rm --network container:polaris-dn-sender --cap-drop ALL \
  --security-opt no-new-privileges:true --read-only --tmpfs /tmp:size=16m \
  -v "$SCENARIOS:/scenarios:ro" -v "$LOCAL_PROOF:/run/local:ro" "$SIPP_IMAGE" \
  "$PROXY_IP:5060" -sf /scenarios/uas_echo.xml -inf /run/local/uas.csv \
  -i "$DN_IP" -p 5064 -mi "$DN_IP" -mp 6000 -rtp_echo -m 1 \
  -set reply_code 200 -set reply_reason OK -set call_ms 30000 -trace_err -trace_msg -nostdin
```

Terminal UAC UE :

```sh
docker run --rm --network "container:$UE_CONTAINER" --cap-drop ALL \
  --security-opt no-new-privileges:true --read-only --tmpfs /tmp:size=16m \
  -v "$SCENARIOS:/scenarios:ro" -v "$LOCAL_PROOF:/run/local:ro" "$SIPP_IMAGE" \
  "$PROXY_IP:5060" -sf /scenarios/uac_invite_rtp.xml -inf /run/local/uac.csv \
  -i "$IMS_IP" -p 5062 -mi "$IMS_IP" -mp 6000 -d 30000 -m 1 \
  -trace_err -trace_msg -nostdin
```

## V3 — qualité RTP

Rejouer V2 pendant 60 s (`call_ms=60000`, `-d 60000`) après l'ajout **autorisé** du `netem` décrit dans la SOP §6, puis retirer obligatoirement ce `netem`. Le fichier PCMU brut doit contenir au moins 60 s, soit 480000 octets à 8 kHz mono.

## V4 — échecs SIP

Utilisateur inconnu (404) : placer un AoR non enregistré dans `[field1]` de `uac.csv`, puis exécuter la commande UAC V2 sans lancer l'UAS.

Occupé (486) : lancer l'UAS V2 avec `-set reply_code 486 -set reply_reason 'Busy Here' -set call_ms 0`, puis lancer l'UAC V2.

Timeout (408) : enregistrer le futur appelé depuis le DN sur un port sans listener persistant :

```sh
docker run --rm --network container:polaris-dn-sender --cap-drop ALL \
  --security-opt no-new-privileges:true --read-only --tmpfs /tmp:size=16m \
  -v "$SCENARIOS:/scenarios:ro" -v "$LOCAL_PROOF:/run/local:ro" "$SIPP_IMAGE" \
  "$PROXY_IP:5060" -sf /scenarios/register.xml -inf /run/local/timeout.csv \
  -i "$DN_IP" -p 5099 -m 1 -trace_err -trace_msg -nostdin
```

Après la fin de ce conteneur, placer cet AoR dans `[field1]` de `uac.csv`, puis exécuter la commande UAC V2 avec `-recv_timeout 40000`. Kamailio doit produire le 408 après expiration de sa transaction.

Pour chaque test, conserver les traces SIPp hors dépôt, recomptabiliser SIP/RTP avec `tshark` comme indiqué dans la SOP §7 et ne publier que les pseudonymes.
