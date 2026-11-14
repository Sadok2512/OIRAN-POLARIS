#!/bin/sh
set -eu
: "${SIP_AOR:?missing SIP_AOR}"
: "${SIP_PROXY:?missing SIP_PROXY}"
: "${SIP_IFACE:=uesimtun0}"
for _ in $(seq 1 30); do
  local_ip=$(ip -4 -o addr show dev "$SIP_IFACE" 2>/dev/null | awk 'NR==1{sub(/\/.*/,"",$4);print $4}')
  [ -n "${local_ip:-}" ] && break
  sleep 1
done
[ -n "${local_ip:-}" ] || { echo IMS_TUN_NOT_READY >&2; exit 2; }
ip route replace "$SIP_PROXY/32" dev "$SIP_IFACE"
password=$(sed -n 's/^#!define IMS_LITE_DIGEST_PASSWORD "\([^"]*\)"$/\1/p' /run/secrets/ims-lite-auth.cfg | head -n1)
[ -n "$password" ] || { echo IMS_DIGEST_SECRET_UNAVAILABLE >&2; exit 3; }
cfg=/tmp/baresip
mkdir -p "$cfg" && chmod 700 "$cfg"
cat >"$cfg/config" <<EOF
sip_listen ${local_ip}:5060
module_path /usr/lib/baresip/modules
module stdio.so
module account.so
module contact.so
module g711.so
module ausine.so
module aubridge.so
module_app ctrl_tcp.so
ctrl_tcp_listen 127.0.0.1:4444
audio_source ausine,440
audio_player aubridge,polaris
EOF
umask 077
cat >"$cfg/accounts" <<EOF
<sip:${SIP_AOR}@ims-lite.audit>;auth_user=ue;auth_pass=${password};regint=60;answermode=auto;outbound="sip:${SIP_PROXY};lr"
EOF
exec baresip -4 -n "$SIP_IFACE" -f "$cfg"
