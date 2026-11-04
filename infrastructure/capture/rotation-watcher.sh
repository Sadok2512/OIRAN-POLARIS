#!/usr/bin/env bash
set -euo pipefail

# 2.7.12 (NS-20261104-CLAUDE-OIRAN-GAPLESS-CAPTURE-2712): emit one JSONL
# record each time dumpcap finalises a rotation segment. The caller runs
# dumpcap with `-b duration:<s>` so the process never exits — the only
# externally visible signal of a rotation is the appearance of a newer
# file in the output directory. We poll the directory on a bounded
# interval and declare "file N is closed" the moment "file N+1" exists.
#
# 2.7.15 (NS-20261104-CLAUDE-OIRAN-FINAL-2715): `packets_captured` and
# `packets_dropped` MUST now be chiffrés or explicitly `"UNKNOWN:<reason>"`
# — never `null`. packets_captured is read from capinfos. packets_dropped
# is read as a delta on the kernel RX-drop counter of the bridge, seeded
# on the watcher's first visit. Every failure path emits an explicit
# UNKNOWN reason so the JSONL consumer never has to guess.
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
#   OIRAN_IFACE_STATS_ROOT            sysfs root. Default /sys/class/net.
#                                     Tests inject a fake tree here.
#   OIRAN_IFACE_DROP_CACHE            per-interface baseline file. Default
#                                     "<dir>/.iface-drops" inside the
#                                     label directory.
#   CAPINFOS                          override for the capinfos binary
#                                     (tests inject a stub).

iface=${1:?interface required}
plane=${2:?plane label required}
dir=${3:?per-label output directory required}

rotation_log=${OIRAN_CAPTURE_ROTATION_LOG:-/results/capture-rotation.jsonl}
poll_s=${OIRAN_CAPTURE_ROTATION_POLL_S:-5}
seen_file=${OIRAN_CAPTURE_ROTATION_SEEN:-$dir/.rotations-seen}
drop_cache=${OIRAN_IFACE_DROP_CACHE:-$dir/.iface-drops}
sysfs_root=${OIRAN_IFACE_STATS_ROOT:-/sys/class/net}
capinfos_bin=${CAPINFOS:-capinfos}

case "$poll_s" in ''|*[!0-9]*) echo "REFUSED: invalid poll interval: $poll_s" >&2; exit 65 ;; esac

mkdir -p "$dir"
touch "$seen_file"
touch "$drop_cache"
install -d -m 0750 "$(dirname -- "$rotation_log")"
touch "$rotation_log"

json_escape() {
  # Minimal JSON string escape for file paths.
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '%s' "$s"
}

# Returns the current kernel RX-drop counter for `$iface`, or empty
# string on failure. Stderr output is swallowed; the caller observes
# success through a non-empty print.
read_iface_rx_dropped() {
  local path="$sysfs_root/$iface/statistics/rx_dropped"
  if [[ -r $path ]]; then
    local value
    value=$(cat "$path" 2>/dev/null || true)
    case "$value" in
      ''|*[!0-9]*) return 0 ;;
      *) printf '%s' "$value" ;;
    esac
  fi
}

# Reads the previous cached RX-drop value for `$iface` from the per-label
# cache file. Empty string means no baseline yet.
cached_iface_rx_dropped() {
  awk -F= -v iface="$iface" '$1 == iface {print $2}' "$drop_cache" 2>/dev/null | tail -1
}

update_cached_iface_rx_dropped() {
  local value=$1 tmp
  tmp=$(mktemp "${drop_cache}.XXXXXX")
  awk -F= -v iface="$iface" '$1 != iface {print}' "$drop_cache" >"$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$iface" "$value" >>"$tmp"
  mv -- "$tmp" "$drop_cache"
}

# Formats a known numeric value as a JSON number, or an explicit
# "UNKNOWN:<reason>" as a JSON string. Never returns `null`.
format_metric() {
  local value=$1 reason=$2
  if [[ -n $value ]]; then
    printf '%s' "$value"
  else
    printf '"UNKNOWN:%s"' "$(json_escape "$reason")"
  fi
}

emit_rotation() {
  local file=$1
  local timestamp size size_reason captured captured_reason dropped dropped_reason
  timestamp=$(date -u +%FT%T.%NZ)

  # File size (bytes on disk) — still useful for operator triage.
  if [[ -r $file ]]; then
    size=$(stat -c '%s' "$file" 2>/dev/null || true)
    case "$size" in ''|*[!0-9]*) size=''; size_reason='stat-failed' ;; *) size_reason='' ;; esac
  else
    size=''
    size_reason='file-not-readable'
  fi

  # packets_captured via capinfos.
  captured=''
  captured_reason=''
  if command -v "$capinfos_bin" >/dev/null 2>&1; then
    local count
    count=$("$capinfos_bin" -c -M "$file" 2>/dev/null |
      awk -F: '/[Nn]umber of packets/ {gsub(/[^0-9]/,"",$2); print $2; exit}')
    if [[ -n ${count:-} ]]; then
      captured=$count
    else
      captured_reason='capinfos-no-count'
    fi
  else
    captured_reason='capinfos-missing'
  fi

  # packets_dropped from the bridge's kernel RX-drop counter (delta).
  dropped=''
  dropped_reason=''
  local current prev
  current=$(read_iface_rx_dropped)
  if [[ -n $current ]]; then
    prev=$(cached_iface_rx_dropped)
    if [[ -n $prev ]]; then
      case "$prev" in
        ''|*[!0-9]*) prev='' ;;
      esac
    fi
    if [[ -n $prev ]]; then
      if (( current >= prev )); then
        dropped=$(( current - prev ))
      else
        dropped_reason='counter-rolled-back'
      fi
    else
      dropped_reason='no-baseline-yet'
    fi
    update_cached_iface_rx_dropped "$current"
  else
    dropped_reason="sysfs-$iface-unavailable"
  fi

  local size_field captured_field dropped_field
  size_field=$(format_metric "$size" "$size_reason")
  captured_field=$(format_metric "$captured" "$captured_reason")
  dropped_field=$(format_metric "$dropped" "$dropped_reason")

  {
    flock 9
    printf '{"timestamp":"%s","interface":"%s","plane":"%s","file":"%s","file_bytes":%s,"packets_captured":%s,"packets_dropped":%s}\n' \
      "$timestamp" "$(json_escape "$iface")" "$(json_escape "$plane")" \
      "$(json_escape "$file")" "$size_field" "$captured_field" "$dropped_field" >&9
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
