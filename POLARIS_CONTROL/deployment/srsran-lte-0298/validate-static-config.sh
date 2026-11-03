#!/usr/bin/env bash
set -euo pipefail

enb=${1:-/root/POLARIS/config/srsran/enb.conf}
ue=${2:-/root/POLARIS/runtime/srsran/ue.conf}
rr=${3:-/root/POLARIS/config/srsran/rr.conf}

grep -Eq 'device_name[[:space:]]*=[[:space:]]*zmq' "$enb"
grep -Eq 'tx_port=tcp://\*:2000.*rx_port=tcp://10\.77\.17\.21:2001.*base_srate=5\.76e6' "$enb"
grep -Eq 'device_name[[:space:]]*=[[:space:]]*zmq' "$ue"
grep -Eq 'tx_port=tcp://\*:2001.*rx_port=tcp://10\.77\.17\.20:2000.*base_srate=5\.76e6' "$ue"
grep -Eq 'dl_earfcn[[:space:]]*=[[:space:]]*3350' "$ue"
if ! grep -Eq 'n_prb[[:space:]]*=[[:space:]]*25' "$enb" "$rr"; then
  echo 'ZMQ_CONFIG=FAIL n_prb=25 absent' >&2
  exit 1
fi
echo 'ZMQ_CONFIG=PASS ports=2000/2001 base_srate=5.76e6 n_prb=25 earfcn=3350'
