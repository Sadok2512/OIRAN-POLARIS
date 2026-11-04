#!/usr/bin/env bash
set -euo pipefail

# 2.7.12: dumpcap is driven by its NATIVE rotation (`-b duration:<s>`) so the
# process never exits between hourly segments. The previous
# `timeout --signal=INT 3600 dumpcap ...` wrapper killed dumpcap at each
# rotation, which in turn exited the capture container (2.5-3.2 s without
# capture per interface per hour; restart_count 256 observed by ANR3).
#
# Native dumpcap rotation:
#   -b duration:<s>   close the current file and open a new one every <s>
#                     seconds, without stopping the process.
#   -b filesize:<k>   secondary cap (KiB) that forces earlier rotation when
#                     a bursty interface overruns the duration budget.
#   -b files:<n>      retention ring per label (oldest files pruned by
#                     dumpcap itself).
#
# Output naming: dumpcap inserts "_NNNNN_YYYYMMDDHHMMSS" between the
# supplied prefix and the suffix, so each finalised segment keeps a UTC
# timestamp and a monotonic sequence index.

iface=${1:?interface required}
label=${2:?label required}
filter=${3:?BPF filter required}
out_dir=${4:-/captures}

case "$iface" in
  br-oiran-*) ;;
  *) echo "REFUSED: interface is outside OIRAN allowlist: $iface" >&2; exit 64 ;;
esac
ip link show dev "$iface" >/dev/null
mkdir -p "$out_dir/$label"
stamp=$(date -u +%Y%m%dT%H%M%SZ)

command -v dumpcap >/dev/null 2>&1 || {
  echo 'REFUSED: dumpcap is required; no legacy capture fallback is allowed' >&2
  exit 69
}

duration=${OIRAN_CAPTURE_DURATION_S:-3600}
filesize_kib=${OIRAN_CAPTURE_FILESIZE_KIB:-262144}
ring_files=${OIRAN_CAPTURE_RING_FILES:-8}

case "$duration" in ''|*[!0-9]*) echo "REFUSED: invalid duration: $duration" >&2; exit 65 ;; esac
case "$filesize_kib" in ''|*[!0-9]*) echo "REFUSED: invalid filesize: $filesize_kib" >&2; exit 65 ;; esac
case "$ring_files" in ''|*[!0-9]*) echo "REFUSED: invalid ring size: $ring_files" >&2; exit 65 ;; esac

exec dumpcap -q -i "$iface" -f "$filter" \
  -b duration:"$duration" \
  -b filesize:"$filesize_kib" \
  -b files:"$ring_files" \
  -w "$out_dir/$label/${label}_${stamp}.pcapng"
