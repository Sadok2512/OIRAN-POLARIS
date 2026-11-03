#!/usr/bin/env bash
set -euo pipefail

source_dir="$(cd "$(dirname "$0")" && pwd)"
backup_root="${1:?backup directory required}"
install -d -m 0700 "$backup_root"

ue=/root/POLARIS/runtime/srsran/ue.conf
enb=/root/POLARIS/config/srsran/enb.conf
override=/root/POLARIS/compose/docker-compose.polaris-0.29.8.yml

install -m 0600 "$ue" "$backup_root/ue.conf"
install -m 0600 "$enb" "$backup_root/enb.conf"
if test -e "$override"; then
  install -m 0600 "$override" "$backup_root/docker-compose.polaris-0.29.8.yml"
else
  : >"$backup_root/override.absent"
  chmod 0600 "$backup_root/override.absent"
fi

rewrite_log_section() {
  input=$1
  fragment=$2
  temporary="${input}.0298.$$"
  awk -v fragment="$fragment" '
    BEGIN { in_log=0; inserted=0 }
    /^\[log\][[:space:]]*$/ {
      while ((getline line < fragment) > 0) print line
      close(fragment)
      in_log=1; inserted=1; next
    }
    /^\[/ && in_log { in_log=0 }
    !in_log { print }
    END {
      if (!inserted) {
        print ""
        while ((getline line < fragment) > 0) print line
        close(fragment)
      }
    }
  ' "$input" >"$temporary"
  chmod 0600 "$temporary"
  chown --reference="$input" "$temporary"
  mv -f "$temporary" "$input"
}

rewrite_log_section "$ue" "$source_dir/ue-log.conf.fragment"
rewrite_log_section "$enb" "$source_dir/enb-log.conf.fragment"
install -m 0644 "$source_dir/docker-compose.polaris-0.29.8.yml" "$override"

sha256sum "$ue" "$enb" "$override" >"$backup_root/installed.sha256"
chmod 0600 "$backup_root/installed.sha256"
