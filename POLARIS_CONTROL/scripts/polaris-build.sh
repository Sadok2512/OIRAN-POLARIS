#!/usr/bin/env bash
# POLARIS Control 0.36.15 — lance une build/test HORS du cgroup surveillé
# par le garde CPU (system.slice) : polaris-build.slice, poids CPU minimal,
# quota 200 %, nice 19, ionice idle. Le trafic du lab garde la priorité et
# la PSI de system.slice n'est pas gonflée par la build.
#   usage : scripts/polaris-build.sh cargo test --release --locked -j 2
set -euo pipefail
[ "$#" -ge 1 ] || { echo "usage: $0 <commande…>" >&2; exit 2; }
if command -v systemd-run >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
  exec systemd-run --quiet --scope --collect --slice=polaris-build.slice \
    -p CPUWeight=1 -p CPUQuota=200% -p IOWeight=1 \
    nice -n 19 ionice -c3 "$@"
fi
echo '{"event":"POLARIS_BUILD_NO_SLICE","reason":"systemd-run absent ou non-root : build en nice/ionice seulement, PSI system.slice non isolée"}' >&2
exec nice -n 19 ionice -c3 "$@"
