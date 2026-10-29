#!/usr/bin/env bash
set -euo pipefail

container=polaris-dn-sender
expected_ip=10.77.24.30
upf_ip=10.77.24.13
ue_prefix=10.46.0.0/16

read -r pid running observed_ip < <(
  /usr/bin/docker inspect --format '{{.State.Pid}} {{.State.Running}} {{(index .NetworkSettings.Networks "oiran-lab-n6").IPAddress}}' "$container"
)

if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]] || [[ "$running" != true ]] || [[ "$observed_ip" != "$expected_ip" ]]; then
  echo "DL_SENDER_RUNTIME_IDENTITY_MISMATCH" >&2
  exit 1
fi

/usr/bin/nsenter --target "$pid" --net -- \
  /usr/sbin/ip route replace "$ue_prefix" via "$upf_ip" src "$expected_ip"

route=$(/usr/bin/nsenter --target "$pid" --net -- /usr/sbin/ip -4 route get 10.46.0.1)
if [[ "$route" != *"via $upf_ip"* ]] || [[ "$route" != *"src $expected_ip"* ]]; then
  echo "DL_SENDER_UE_ROUTE_MISSING" >&2
  exit 1
fi

printf '%s\n' "DL_SENDER_ROUTE_READY"
