#!/usr/bin/env bash
set -euo pipefail

mode=dry-run
rollback_dir=
test_mongo=
case "${1:-}" in
  "") ;;
  --execute) mode=execute ;;
  --rollback) mode=rollback; rollback_dir=${2:?backup directory required} ;;
  --copy-test) mode=copy-test ;;
  --isolated-test) mode=isolated-test; test_mongo=${2:?isolated MongoDB container required} ;;
  *) echo "usage: $0 [--execute|--rollback BACKUP|--copy-test|--isolated-test CONTAINER]" >&2; exit 64 ;;
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
CANDIDATE_API=${POLARIS_CANDIDATE_API:-/root/POLARIS_API_017_BUILD/POLARIS_CONTROL/target/release/polaris-control-api}
CANDIDATE_API_SHA=${POLARIS_CANDIDATE_API_SHA:-4129155dcd96a6f6edae9d75baa407a40b7573658aaf3ac7c426eada7e6eb92c}
CANDIDATE_FRONTEND=${POLARIS_CANDIDATE_FRONTEND:-/root/OIRAN_POLARIS_SIM_091/apps/simulator-control/dist}

say() { printf '[%s] %s\n' "$mode" "$*"; }
run() { if [[ $mode == dry-run ]]; then printf '+ '; printf '%q ' "$@"; printf '\n'; else "$@"; fi; }
require_file() { [[ -f $1 ]] || { echo "missing file: $1" >&2; exit 66; }; }
verify_sha() { printf '%s  %s\n' "$2" "$1" | sha256sum -c -; }
check_disk() {
  local used_pct
  used_pct=$(df -B1 -P / | awk 'NR == 2 && $2 > 0 {printf "%.2f", ($3 * 100) / $2}')
  [[ $used_pct =~ ^[0-9]+([.][0-9]+)?$ ]] \
    && awk -v used="$used_pct" 'BEGIN {exit !(used < 85.0)}' || {
    echo "disk safety gate failed: root usage=${used_pct:-unknown}%" >&2
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

mongo_state_sha() {
  docker exec "$1" mongosh --quiet open5gs --eval \
    'print(EJSON.stringify(db.subscribers.find({}).sort({_id:1}).toArray()))' \
    | sha256sum | awk '{print $1}'
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

if [[ $mode == isolated-test ]]; then
  root=$(mktemp -d /tmp/polaris-deploy-isolated.XXXXXX)
  api_pid= web_pid=
  cleanup_isolated() {
    local rc=$?
    if ((rc != 0)); then
      [[ ! -f $root/api.log ]] || { echo '--- isolated API log ---' >&2; tail -80 "$root/api.log" >&2; }
      [[ ! -f $root/web.log ]] || { echo '--- isolated web log ---' >&2; tail -20 "$root/web.log" >&2; }
    fi
    [[ -z $api_pid ]] || kill "$api_pid" 2>/dev/null || true
    [[ -z $web_pid ]] || kill "$web_pid" 2>/dev/null || true
    wait "$api_pid" "$web_pid" 2>/dev/null || true
    rm -rf -- "$root"
    return "$rc"
  }
  trap cleanup_isolated EXIT
  require_file "$CANDIDATE_API"
  verify_sha "$CANDIDATE_API" "$CANDIDATE_API_SHA"
  verify_sha "$IPERF_SRC/iperf3" "$IPERF_SHA"
  verify_sha "$IPERF_SRC/lib/libiperf.so.0.0.0" "$LIBIPERF_SHA"

  API_DST=$root/prod/api; FRONT_DST=$root/prod/frontend
  CONFIG_DIR=$root/prod/config; STATE_DIR=$root/prod/state
  IPERF_DST=$root/prod/libexec
  backup=$root/backup
  mkdir -p "$FRONT_DST" "$CONFIG_DIR" "$STATE_DIR" "$backup" "$root/candidate/frontend"
  printf old-api >"$API_DST"; printf old-front >"$FRONT_DST/index.html"
  printf old-config >"$CONFIG_DIR/settings"; printf old-state >"$STATE_DIR/registry"
  printf candidate-front >"$root/candidate/frontend/index.html"

  cp "$API_DST" "$backup/api"; cp -a "$FRONT_DST" "$backup/frontend"
  cp -a "$CONFIG_DIR" "$backup/config"; cp -a "$STATE_DIR" "$backup/state"
  docker exec "$test_mongo" mongodump --quiet --db open5gs --archive >"$backup/open5gs.archive"
  mongo_before=$(mongo_state_sha "$test_mongo")

  install -m 0755 "$CANDIDATE_API" "$API_DST"
  cp -a "$root/candidate/frontend/." "$FRONT_DST/"
  install -d -m 0755 "$IPERF_DST/lib"
  install -m 0755 "$IPERF_SRC/iperf3" "$IPERF_DST/iperf3"
  install -m 0644 "$IPERF_SRC/lib/libiperf.so.0.0.0" "$IPERF_DST/lib/libiperf.so.0.0.0"
  verify_sha "$API_DST" "$CANDIDATE_API_SHA"
  verify_sha "$IPERF_DST/iperf3" "$IPERF_SHA"

  printf '{"ue_count":0,"gnb_count":1,"updated_at_epoch_s":0,"updated_by":"ISOLATED_TEST"}\n' >"$STATE_DIR/configuration.json"
  POLARIS_BIND=127.0.0.1:49217 \
  POLARIS_CONFIGURATION_PATH=$STATE_DIR/configuration.json \
  POLARIS_JOB_STATE_PATH=$STATE_DIR/jobs.json \
  POLARIS_UE_JOB_STATE_PATH=$STATE_DIR/ue-jobs.json \
  POLARIS_CPU_DECISION_PATH=$STATE_DIR/cpu-decisions.json \
  POLARIS_POLICY_PATH=$STATE_DIR/policy.json \
  POLARIS_UE_PROFILE_REGISTRY_PATH=$STATE_DIR/ue-profile-registry.json \
  POLARIS_UE_PROFILE_ROOT=$STATE_DIR/ue-profiles \
  POLARIS_SCENARIO_CATALOG_PATH=$STATE_DIR/scenario-definitions.json \
  POLARIS_SUBSCRIBER_PLAN_PATH=$STATE_DIR/subscriber-plan.json \
  POLARIS_OPEN5GS_MONGODB_CONTAINER=$test_mongo \
  POLARIS_SUBSCRIBER_BACKUP_ROOT=$STATE_DIR/subscriber-backups \
  POLARIS_WEB_DIR=$FRONT_DST POLARIS_STORAGE_PATH=$root \
  POLARIS_AUDIT_PATH=$STATE_DIR/audit.jsonl \
  POLARIS_SERVED_SNSSAIS=1/010203 POLARIS_SERVED_DNNS=internet,ims \
    "$API_DST" >"$root/api.log" 2>&1 &
  api_pid=$!
  python3 -m http.server 18020 --bind 127.0.0.1 --directory "$FRONT_DST" \
    >"$root/web.log" 2>&1 &
  web_pid=$!
  for _ in $(seq 1 30); do
    curl --fail --silent http://127.0.0.1:49217/api/v1/system/health >/dev/null && break
    sleep 1
  done
  curl --fail --silent http://127.0.0.1:49217/api/v1/system/health >/dev/null
  for _ in $(seq 1 30); do
    curl --fail --silent http://127.0.0.1:18020/ >/dev/null && break
    sleep 1
  done
  curl --fail --silent http://127.0.0.1:18020/ >/dev/null

  docker exec "$test_mongo" mongosh --quiet open5gs --eval '
db.subscribers.insertOne({schema_version:NumberInt(1),imsi:"777770000000000",slice:[],security:{k:"00",opc:"00"},polaris:{owned:true,slot:"ISOLATED-ROLLBACK-MARKER"}});
print(JSON.stringify({mutated:true}));' >/dev/null

  install -m 0755 "$backup/api" "$API_DST"
  cp -a "$backup/frontend/." "$FRONT_DST/"
  cp -a "$backup/config/." "$CONFIG_DIR/"
  cp -a "$backup/state/." "$STATE_DIR/"
  docker exec -i "$test_mongo" mongorestore --quiet --drop --archive <"$backup/open5gs.archive"
  mongo_after=$(mongo_state_sha "$test_mongo")
  [[ $mongo_after == "$mongo_before" ]]
  cmp "$API_DST" "$backup/api"
  cmp "$FRONT_DST/index.html" "$backup/frontend/index.html"
  cmp "$CONFIG_DIR/settings" "$backup/config/settings"
  cmp "$STATE_DIR/registry" "$backup/state/registry"
  echo "ISOLATED_DEPLOY_SMOKE=PASS MONGO_RESTORE=PASS MONGO_STATE_SHA=$mongo_after"
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

say "verify candidates and pinned iperf3 runtime"
if [[ $mode == execute ]]; then
  require_file "$CANDIDATE_API"
  [[ -f $CANDIDATE_FRONTEND/index.html ]]
  verify_sha "$CANDIDATE_API" "$CANDIDATE_API_SHA"
else
  run verify_sha "$CANDIDATE_API" "$CANDIDATE_API_SHA"
fi
run verify_sha "$IPERF_SRC/iperf3" "$IPERF_SHA"
run verify_sha "$IPERF_SRC/lib/libiperf.so.0.0.0" "$LIBIPERF_SHA"
run df -P /
if [[ $mode == execute ]]; then check_disk; else say 'require root filesystem usage below 85%'; fi

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
