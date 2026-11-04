#!/usr/bin/env bash
set -euo pipefail

# 2.7.12: dumpcap is driven by its native `-b duration:<s>` rotation (see
# capture-interface.sh). Because the dumpcap process never exits between
# segments, we no longer get an exit-code / stderr-summary per rotation.
# For each approved bridge we therefore start two companions:
#   * one `capture-interface.sh` running dumpcap for the lifetime of the
#     container (the only process that writes pcapng files);
#   * one `rotation-watcher.sh` that polls the per-label output directory
#     and emits one `capture-rotation.jsonl` record the moment dumpcap
#     closes a segment (i.e. the moment a newer file appears next to it).
# If capture-interface.sh ever exits early (invalid interface, dumpcap
# not installed, …), the orchestrator still exits with that status so
# the regression is externally visible.

out_dir=${1:-/captures}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
rotation_log=${OIRAN_CAPTURE_ROTATION_LOG:-/results/capture-rotation.jsonl}
export OIRAN_CAPTURE_ROTATION_LOG="$rotation_log"

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

install -d -m 0750 "$(dirname -- "$rotation_log")"

capture_pids=()
watcher_pids=()

start_pair() {
  local iface=$1 label=$2 filter=$3
  "$script_dir/capture-interface.sh" "$iface" "$label" "$filter" "$out_dir" &
  capture_pids+=("$!")
  "$script_dir/rotation-watcher.sh" "$iface" "$label" "$out_dir/$label" &
  watcher_pids+=("$!")
}

for spec in "${specs[@]}"; do
  IFS='|' read -r iface label filter <<<"$spec"
  if ip link show dev "$iface" >/dev/null 2>&1; then
    start_pair "$iface" "$label" "$filter"
  fi
done
if ((${#capture_pids[@]} == 0)); then
  echo 'No approved OIRAN bridges found; refusing empty capture.' >&2
  exit 66
fi

cleanup() {
  kill -INT "${capture_pids[@]}" "${watcher_pids[@]}" 2>/dev/null || true
  wait || true
}
trap cleanup INT TERM EXIT

result=0
# We only block on the dumpcap workers. Watchers exit when the trap sends
# them SIGINT during shutdown; a watcher outliving its dumpcap would be a
# bug surfaced by the shutdown path.
for pid in "${capture_pids[@]}"; do
  wait "$pid" || result=$?
done
exit "$result"
