#!/usr/bin/env bash
set -euo pipefail

out_dir=${1:-/captures}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
rotation_log=${OIRAN_CAPTURE_ROTATION_LOG:-/results/capture-rotation.jsonl}

declare -a specs=(
  'br-oiran-s1m|s1mme|sctp port 36412'
  'br-oiran-s1u|s1u|udp port 2152'
  'br-oiran-s11|s11|udp port 2123 and host 10.77.12.10 and host 10.77.12.12'
  'br-oiran-s11|s5c|udp port 2123 and host 10.77.12.12 and host 10.77.12.14'
  'br-oiran-s5u|s5u|udp port 2152'
  'br-oiran-s6a|s6a|port 3868'
  'br-oiran-sxab|sxab|udp port 8805'
  'br-oiran-n2|n2|sctp port 38412'
  'br-oiran-n3|n3|udp port 2152'
  'br-oiran-n4|n4|udp port 8805'
  'br-oiran-n6|n6|net 10.46.0.0/16'
  'br-oiran-sbi|sbi|tcp port 7777'
)

log_rotation() {
  local iface=$1 label=$2 exit_code=$3 stderr_file=$4
  local captured dropped timestamp
  timestamp=$(date -u +%FT%T.%NZ)
  captured=$(sed -n 's/.*Packets captured: \([0-9][0-9]*\).*/\1/p' "$stderr_file" | tail -1)
  dropped=$(sed -n "s/.*interface '$iface': [0-9][0-9]*\/\([0-9][0-9]*\).*/\1/p" "$stderr_file" | tail -1)
  captured=${captured:-null}; dropped=${dropped:-null}
  install -d -m 0750 "$(dirname -- "$rotation_log")"
  {
    flock 9
    printf '{"timestamp":"%s","interface":"%s","plane":"%s","exit_code":%d,"packets_captured":%s,"packets_dropped":%s}\n' \
      "$timestamp" "$iface" "$label" "$exit_code" "$captured" "$dropped" >&9
  } 9>>"$rotation_log"
}

capture_one() {
  local iface=$1 label=$2 filter=$3 tmp rc
  tmp=$(mktemp "/tmp/oiran-capture-${label}.XXXXXX")
  set +e
  "$script_dir/capture-interface.sh" "$iface" "$label" "$filter" "$out_dir" \
    2> >(tee "$tmp" >&2)
  rc=$?
  set -e
  log_rotation "$iface" "$label" "$rc" "$tmp"
  rm -f -- "$tmp"
  return "$rc"
}

pids=()
for spec in "${specs[@]}"; do
  IFS='|' read -r iface label filter <<<"$spec"
  if ip link show dev "$iface" >/dev/null 2>&1; then
    capture_one "$iface" "$label" "$filter" &
    pids+=("$!")
  fi
done
if ((${#pids[@]} == 0)); then
  echo 'No approved OIRAN bridges found; refusing empty capture.' >&2
  exit 66
fi
trap 'kill -INT "${pids[@]}" 2>/dev/null || true; wait || true' INT TERM EXIT
result=0
for pid in "${pids[@]}"; do
  wait "$pid" || result=$?
done
exit "$result"
