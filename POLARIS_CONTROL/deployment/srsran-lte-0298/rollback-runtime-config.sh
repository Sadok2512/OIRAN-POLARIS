#!/usr/bin/env bash
set -euo pipefail

backup_root="${1:?backup directory required}"
install -m 0600 "$backup_root/ue.conf" /root/POLARIS/runtime/srsran/ue.conf
install -m 0600 "$backup_root/enb.conf" /root/POLARIS/config/srsran/enb.conf
if test -e "$backup_root/override.absent"; then
  rm -f /root/POLARIS/compose/docker-compose.polaris-0.29.8.yml
else
  install -m 0644 "$backup_root/docker-compose.polaris-0.29.8.yml" \
    /root/POLARIS/compose/docker-compose.polaris-0.29.8.yml
fi
