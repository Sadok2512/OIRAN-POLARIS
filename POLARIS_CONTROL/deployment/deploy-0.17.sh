#!/usr/bin/env bash
set -euo pipefail

mode=dry-run
rollback_dir=
case "${1:-}" in
  "") ;;
  --execute) mode=execute ;;
  --rollback) mode=rollback; rollback_dir=${2:?backup directory required} ;;
  --copy-test) mode=copy-test ;;
  *) echo "usage: $0 [--execute|--rollback BACKUP|--copy-test]" >&2; exit 64 ;;
esac

API_DST=${POLARIS_API_DST:-/root/POLARIS_CONTROL/target/release/polaris-control-api}
FRONT_DST=${POLARIS_FRONT_DST:-/opt/oiran-polaris-preview/public/simulator}
CONFIG_DIR=${POLARIS_CONFIG_DIR:-/root/POLARIS_CONTROL/config}
STATE_DIR=${POLARIS_STATE_DIR:-/var/lib/polaris-control}
BACKUP_ROOT=${POLARIS_BACKUP_ROOT:-/var/backups/polaris-control}
SERVICE=${POLARIS_SERVICE:-polaris-control.service}
API_BASE=${POLARIS_API_BASE:-http://127.0.0.1:49153}
PREVIEW_BASE=${POLARIS_PREVIEW_BASE:-http://127.0.0.1:8020}
MONGO_CONTAINER=${POLARIS_MONGO_CONTAINER:-oiran-lab-mongodb-1}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
IPERF_SRC=${POLARIS_IPERF_ARTIFACT:-$SCRIPT_DIR/../release/iperf3-3.21}
IPERF_DST=${POLARIS_IPERF_DST:-/opt/polaris-control/libexec}
IPERF_DROPIN=/etc/systemd/system/polaris-control.service.d/20-iperf3.conf
IPERF_SHA=7548a6e3e7cf33d92595b7e68abea87da011a28d1ff10f043e1caf6bbcf1d3ed
LIBIPERF_SHA=c38136e9bb1ca2fb09c23245d4fd9abc1dad34f3042a29067d5d8b16e76a35b9

say() { printf '[%s] %s\n' "$mode" "$*"; }
run() { if [[ $mode == dry-run ]]; then printf '+ '; printf '%q ' "$@"; printf '\n'; else "$@"; fi; }
require_file() { [[ -f $1 ]] || { echo "missing file: $1" >&2; exit 66; }; }
verify_sha() { printf '%s  %s\n' "$2" "$1" | sha256sum -c -; }
check_disk() {
  local used
  used=$(df -P / | awk 'NR == 2 {gsub(/%/, "", $5); print $5}')
  [[ $used =~ ^[0-9]+$ && $used -lt 90 ]] || {
    echo "disk safety gate failed: root usage=${used:-unknown}%" >&2
    exit 75
  }
}

restore_copy() {
  local backup=$1
  install -m 0755 "$backup/api" "$API_DST"
  install -d -m 0755 "$(dirname "$FRONT_DST")"
  cp -a "$backup/frontend" "${FRONT_DST}.restore"
  mv -T "$FRONT_DST" "${FRONT_DST}.failed"
  mv -T "${FRONT_DST}.restore" "$FRONT_DST"
}

if [[ $mode == copy-test ]]; then
  root=$(mktemp -d /tmp/polaris-deploy-copy-test.XXXXXX)
  trap 'rm -rf "$root"' EXIT
  API_DST=$root/prod/api; FRONT_DST=$root/prod/frontend
  CONFIG_DIR=$root/prod/config; STATE_DIR=$root/prod/state
  mkdir -p "$FRONT_DST" "$CONFIG_DIR" "$STATE_DIR" "$root/candidate/frontend" "$root/backup"
  printf old-api >"$API_DST"; printf old-front >"$FRONT_DST/index.html"
  printf old-config >"$CONFIG_DIR/settings"; printf old-state >"$STATE_DIR/registry"
  cp "$API_DST" "$root/backup/api"; cp -a "$FRONT_DST" "$root/backup/frontend"
  cp -a "$CONFIG_DIR" "$root/backup/config"; cp -a "$STATE_DIR" "$root/backup/state"
  printf new-api >"$root/candidate/api"; printf new-front >"$root/candidate/frontend/index.html"
  install -m 0755 "$root/candidate/api" "$API_DST"
  cp -a "$root/candidate/frontend/." "$FRONT_DST/"
  printf new-config >"$CONFIG_DIR/settings"; printf new-state >"$STATE_DIR/registry"
  restore_copy "$root/backup"
  rm -rf -- "$CONFIG_DIR" "$STATE_DIR"
  cp -a "$root/backup/config" "$CONFIG_DIR"; cp -a "$root/backup/state" "$STATE_DIR"
  cmp "$API_DST" "$root/backup/api"
  cmp "$FRONT_DST/index.html" "$root/backup/frontend/index.html"
  cmp "$CONFIG_DIR/settings" "$root/backup/config/settings"
  cmp "$STATE_DIR/registry" "$root/backup/state/registry"
  verify_sha "$IPERF_SRC/iperf3" "$IPERF_SHA"
  verify_sha "$IPERF_SRC/lib/libiperf.so.0.0.0" "$LIBIPERF_SHA"
  echo 'COPY_ROLLBACK_TEST=PASS'
  exit 0
fi

if [[ $mode == rollback ]]; then
  [[ -d $rollback_dir ]] || { echo "backup not found" >&2; exit 66; }
  say "restore API, frontend, configuration and state from $rollback_dir"
  run install -m 0755 "$rollback_dir/api/polaris-control-api" "$API_DST"
  run tar -C / -xpf "$rollback_dir/config.tar"
  if [[ -f $rollback_dir/iperf-dropin-was-absent ]]; then
    run rm -f -- "$IPERF_DROPIN"
  fi
  run tar -C / -xpf "$rollback_dir/state.tar"
  run mv -T "$FRONT_DST" "${FRONT_DST}.failed-$(date -u +%Y%m%dT%H%M%SZ)"
  run tar -C / -xpf "$rollback_dir/frontend.tar"
  run systemctl restart "$SERVICE"
  run curl --fail --silent --show-error "$API_BASE/api/v1/system/health"
  exit 0
fi

CANDIDATE_API=${POLARIS_CANDIDATE_API:-/path/to/polaris-control-api-0.17.0}
CANDIDATE_FRONTEND=${POLARIS_CANDIDATE_FRONTEND:-/path/to/simulator-0.17.0-dist}
say "verify candidates and pinned iperf3 runtime"
if [[ $mode == execute ]]; then require_file "$CANDIDATE_API"; [[ -f $CANDIDATE_FRONTEND/index.html ]]; fi
run verify_sha "$IPERF_SRC/iperf3" "$IPERF_SHA"
run verify_sha "$IPERF_SRC/lib/libiperf.so.0.0.0" "$LIBIPERF_SHA"
run df -P /
if [[ $mode == execute ]]; then check_disk; else say 'require root filesystem usage below 90%'; fi

stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup=$BACKUP_ROOT/0.17.0-$stamp
say "backup destination: $backup"
run install -d -m 0700 "$backup/api"
run cp -a "$API_DST" "$backup/api/polaris-control-api"
if [[ $mode == execute && ! -e $IPERF_DROPIN ]]; then
  : >"$backup/iperf-dropin-was-absent"
elif [[ $mode == dry-run ]]; then
  say "record whether $IPERF_DROPIN existed before maintenance"
fi
run tar -C / -cpf "$backup/config.tar" "${CONFIG_DIR#/}" etc/systemd/system/polaris-control.service etc/systemd/system/polaris-control.service.d
run tar -C / -cpf "$backup/state.tar" "${STATE_DIR#/}"
run tar -C / -cpf "$backup/frontend.tar" "${FRONT_DST#/}"
if [[ $mode == dry-run ]]; then
  say "docker exec $MONGO_CONTAINER mongodump --db open5gs --archive > $backup/open5gs.archive"
else
  docker exec "$MONGO_CONTAINER" mongodump --db open5gs --archive >"$backup/open5gs.archive"
  sha256sum "$backup"/* "$backup"/api/* >"$backup/SHA256SUMS"
fi

say 'install candidate API, frontend and iperf3 atomically'
run install -m 0755 "$CANDIDATE_API" "${API_DST}.new"
run mv -T "${API_DST}.new" "$API_DST"
run install -d -m 0755 "${FRONT_DST}.new"
run cp -a "$CANDIDATE_FRONTEND/." "${FRONT_DST}.new/"
run mv -T "$FRONT_DST" "${FRONT_DST}.previous-$stamp"
run mv -T "${FRONT_DST}.new" "$FRONT_DST"
run install -d -m 0755 "$IPERF_DST/lib"
run install -m 0755 "$IPERF_SRC/iperf3" "$IPERF_DST/iperf3"
run install -m 0644 "$IPERF_SRC/lib/libiperf.so.0.0.0" "$IPERF_DST/lib/libiperf.so.0.0.0"
run ln -sfn libiperf.so.0.0.0 "$IPERF_DST/lib/libiperf.so.0"
run install -d -m 0755 /etc/systemd/system/polaris-control.service.d
run install -m 0644 "$SCRIPT_DIR/systemd/polaris-control-iperf3.conf" "$IPERF_DROPIN"
run verify_sha "$IPERF_DST/iperf3" "$IPERF_SHA"
run verify_sha "$IPERF_DST/lib/libiperf.so.0.0.0" "$LIBIPERF_SHA"
run systemctl daemon-reload

say 'restart POLARIS only and run smoke tests; rollback automatically on failure'
if [[ $mode == execute ]]; then
  if ! systemctl restart "$SERVICE" \
    || ! curl --fail --silent --show-error "$API_BASE/api/v1/system/health" >/dev/null \
    || ! curl --fail --silent --show-error "$PREVIEW_BASE/simulator/" >/dev/null; then
    "$0" --rollback "$backup"
    exit 1
  fi
else
  run systemctl restart "$SERVICE"
  run curl --fail --silent --show-error "$API_BASE/api/v1/system/health"
  run curl --fail --silent --show-error "$PREVIEW_BASE/simulator/"
fi
say "DEPLOYMENT=PASS backup=$backup"
