#!/usr/bin/env bash
set -euo pipefail

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
exec timeout --preserve-status --signal=INT 3600 dumpcap -q -i "$iface" -f "$filter" \
  -b filesize:262144 -b files:8 -w "$out_dir/$label/${label}_${stamp}.pcapng"
