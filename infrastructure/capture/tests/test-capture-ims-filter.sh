#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
capture_script="$repo_root/infrastructure/capture/capture-all.sh"
expected="'br-oiran-n6|n6|(net 10.46.0.0/16 or net 10.47.0.0/16 or (host 10.77.24.20 and udp port 5060))'"

[[ -r "$capture_script" ]]
[[ $(grep -Fxc "  $expected" "$capture_script") -eq 1 ]]

echo 'PASS: N6 capture includes internet, IMS, and Kamailio SIP filters'
