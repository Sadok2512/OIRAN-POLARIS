#!/usr/bin/env bash
set -euo pipefail

container=polaris-lte-sgi-dn
network=oiran-lab-sgi
expected_ip=10.77.16.30
expected_image=sha256:e60eb72bf7619fd049f6bbbc45cf06927eb73ed7c613446678644f6742af31f3
pgw_u=10.77.16.15
ue_prefix=10.45.0.0/16
probe_ip=10.45.0.1

read -r pid running network_count observed_ip image_id < <(
  /usr/bin/docker inspect --format \
    '{{.State.Pid}} {{.State.Running}} {{len .NetworkSettings.Networks}} {{(index .NetworkSettings.Networks "oiran-lab-sgi").IPAddress}} {{.Image}}' \
    "$container"
)

if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]] \
  || [[ "$running" != true ]] \
  || [[ "$network_count" != 1 ]] \
  || [[ "$observed_ip" != "$expected_ip" ]] \
  || [[ "$image_id" != "$expected_image" ]]; then
  echo "LTE_SGI_DN_RUNTIME_IDENTITY_MISMATCH" >&2
  exit 1
fi

/usr/bin/nsenter --target "$pid" --net -- \
  /usr/sbin/ip route replace "$ue_prefix" via "$pgw_u" dev sgi_lte src "$expected_ip"

route=$(/usr/bin/nsenter --target "$pid" --net -- \
  /usr/sbin/ip -4 route get "$probe_ip")
if [[ "$route" != *"via $pgw_u"* ]] \
  || [[ "$route" != *"dev sgi_lte"* ]] \
  || [[ "$route" != *"src $expected_ip"* ]]; then
  echo "LTE_SGI_DN_RETURN_ROUTE_MISSING" >&2
  exit 1
fi

printf '%s\n' "LTE_SGI_DN_ROUTE_READY"
