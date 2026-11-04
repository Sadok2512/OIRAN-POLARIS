#!/usr/bin/env bash
set -euo pipefail

# 2.7.12 (NS-20261104-CLAUDE-OIRAN-GAPLESS-CAPTURE-2712): emit one JSONL
# record each time dumpcap finalises a rotation segment. The caller runs
# dumpcap with `-b duration:<s>` so the process never exits — the only
# externally visible signal of a rotation is the appearance of a newer
# file in the output directory. We poll the directory on a bounded
# interval and declare "file N is closed" the moment "file N+1" exists.
#
# Arguments:
#   $1  interface (br-oiran-*)
#   $2  plane label (used for the `plane` JSONL field)
#   $3  per-label output directory (one dumpcap writes here)
#
# Environment:
#   OIRAN_CAPTURE_ROTATION_LOG        JSONL output path. Default
#                                     /results/capture-rotation.jsonl.
#   OIRAN_CAPTURE_ROTATION_POLL_S     polling period in seconds. Default 5.
#   OIRAN_CAPTURE_ROTATION_SEEN       rolling-list file path. Default
#                                     "<dir>/.rotations-seen" inside the
#                                     label directory, so a watcher
#                                     restart does not re-emit already
#                                     logged segments.
#   CAPINFOS                          override for the capinfos binary
#                                     (tests inject a stub).

iface=${1:?interface required}
plane=${2:?plane label required}
dir=${3:?per-label output directory required}

rotation_log=${OIRAN_CAPTURE_ROTATION_LOG:-/results/capture-rotation.jsonl}
poll_s=${OIRAN_CAPTURE_ROTATION_POLL_S:-5}
seen_file=${OIRAN_CAPTURE_ROTATION_SEEN:-$dir/.rotations-seen}
capinfos_bin=${CAPINFOS:-capinfos}

case "$poll_s" in ''|*[!0-9]*) echo "REFUSED: invalid poll interval: $poll_s" >&2; exit 65 ;; esac

mkdir -p "$dir"
touch "$seen_file"
install -d -m 0750 "$(dirname -- "$rotation_log")"
touch "$rotation_log"

json_escape() {
  # Minimal JSON string escape for file paths.
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '%s' "$s"
}

emit_rotation() {
  local file=$1
  local timestamp pkts drops size
  timestamp=$(date -u +%FT%T.%NZ)
  pkts=null
  drops=null
  if command -v "$capinfos_bin" >/dev/null 2>&1; then
    local count
    count=$("$capinfos_bin" -c -M "$file" 2>/dev/null |
      awk -F: '/[Nn]umber of packets/ {gsub(/[^0-9]/,"",$2); print $2; exit}')
    if [[ -n ${count:-} ]]; then
      pkts=$count
    fi
  fi
  if [[ -r $file ]]; then
    size=$(stat -c '%s' "$file" 2>/dev/null || echo null)
  else
    size=null
  fi
  {
    flock 9
    printf '{"timestamp":"%s","interface":"%s","plane":"%s","file":"%s","file_bytes":%s,"packets_captured":%s,"packets_dropped":%s}\n' \
      "$timestamp" "$(json_escape "$iface")" "$(json_escape "$plane")" \
      "$(json_escape "$file")" "$size" "$pkts" "$drops" >&9
  } 9>>"$rotation_log"
}

# Main loop — exits when stopped by the orchestrator. Idempotent: a
# segment path is emitted at most once across watcher restarts.
scan_once() {
  shopt -s nullglob
  local -a files=()
  local f
  for f in "$dir"/*.pcapng; do
    files+=("$f")
  done
  shopt -u nullglob
  if [[ ${#files[@]} -lt 2 ]]; then
    return 0
  fi
  # Dumpcap inserts a monotonically increasing index so alphabetical
  # sort matches rotation order; `sort` makes the behaviour explicit.
  IFS=$'\n' read -r -d '' -a sorted < <(printf '%s\n' "${files[@]}" | LC_ALL=C sort && printf '\0')
  local last_idx=$(( ${#sorted[@]} - 1 ))
  local idx
  for (( idx = 0; idx < last_idx; idx++ )); do
    local candidate=${sorted[idx]}
    if ! grep -Fxq -- "$candidate" "$seen_file" 2>/dev/null; then
      emit_rotation "$candidate"
      printf '%s\n' "$candidate" >> "$seen_file"
    fi
  done
}

if [[ ${OIRAN_CAPTURE_ROTATION_ONESHOT:-0} == 1 ]]; then
  scan_once
  exit 0
fi

while :; do
  scan_once
  sleep "$poll_s"
done
