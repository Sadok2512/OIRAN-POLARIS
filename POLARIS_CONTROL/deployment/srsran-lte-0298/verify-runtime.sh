#!/usr/bin/env bash
set -euo pipefail

for service in srsenb srsue; do
  container_id="$(docker compose --project-name oiran-lab --profile lte \
    --env-file /root/POLARIS/compose/versions.env \
    -f /root/POLARIS/compose/docker-compose.oiran-lab.yml \
    -f /root/POLARIS/compose/docker-compose.polaris-0.29.8.yml \
    ps -q "$service")"
  test -n "$container_id"
  docker inspect --format '{{json .HostConfig.Ulimits}} {{.HostConfig.NanoCpus}} {{.HostConfig.CpusetCpus}}' "$container_id"
  docker exec "$container_id" /bin/sh -ec '
    grep -E "^(VmLck|CapEff|Threads):" /proc/1/status
    locked_kib=$(awk "/^VmLck:/ {print \$2}" /proc/1/status)
    test "${locked_kib:-0}" -gt 0
    ps -eLo pid,tid,cls,rtprio,pri,comm | tee /tmp/thread-classes
    grep -Eq "[[:space:]](FF|RR)[[:space:]]" /tmp/thread-classes
  '
done
