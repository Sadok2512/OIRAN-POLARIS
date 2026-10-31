#!/usr/bin/env bash
# Read-only preflight for LTE-SRSUE-TEST-01. This script intentionally has no
# docker start/stop/compose-up code and never reads subscriber identity values.
set -euo pipefail

lab_root=${POLARIS_LAB_ROOT:-/root/POLARIS}
max_disk_percent=${LTE_MAX_DISK_PERCENT:-85}
required_dumpcaps=${LTE_REQUIRED_DUMPCAPS:-12}
min_memory_bytes=${LTE_MIN_MEMORY_BYTES:-4294967296}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    printf '{"status":"BLOCKED","error":"TOOL_UNAVAILABLE","tool":"%s"}\n' "$1"
    exit 2
  }
}

for tool in awk df docker jq pgrep sha256sum stat; do
  need "$tool"
done

enb_conf="$lab_root/config/srsran/enb.conf"
rr_conf="$lab_root/config/srsran/rr.conf"
ue_conf="$lab_root/runtime/srsran/ue.conf"
mme_conf="$lab_root/config/open5gs/mme.yaml"
smf_conf="$lab_root/config/open5gs/smf-lte.yaml"

for path in "$enb_conf" "$rr_conf" "$ue_conf" "$mme_conf" "$smf_conf"; do
  if [[ ! -r "$path" ]]; then
    jq -n --arg path "$path" '{status:"BLOCKED",error:"CONFIG_UNREADABLE",path:$path}'
    exit 3
  fi
done

read -r disk_size disk_used disk_avail < <(df -B1 --output=size,used,avail / | awk 'NR==2 {print $1,$2,$3}')
disk_percent=$(awk -v used="$disk_used" -v avail="$disk_avail" 'BEGIN {printf "%.4f", (used*100)/(used+avail)}')
disk_ok=$(awk -v used="$disk_used" -v avail="$disk_avail" -v max="$max_disk_percent" 'BEGIN {print ((used*100)/(used+avail) < max) ? "true" : "false"}')
memory_available=$(awk '/MemAvailable:/ {print $2*1024}' /proc/meminfo)
if [[ "$memory_available" -ge "$min_memory_bytes" ]]; then memory_ok=true; else memory_ok=false; fi
dumpcap_count=$(pgrep -x dumpcap 2>/dev/null | wc -l)
if [[ "$dumpcap_count" -eq "$required_dumpcaps" ]]; then dumpcap_ok=true; else dumpcap_ok=false; fi

mode=$(stat -c '%a' "$ue_conf")
owner=$(stat -c '%U:%G' "$ue_conf")
if [[ "$mode" == "600" && "$owner" == "root:root" ]]; then config_permissions_ok=true; else config_permissions_ok=false; fi

enb_mcc=$(awk -F= '/^[[:space:]]*mcc[[:space:]]*=/{gsub(/[[:space:]\047\042]/,"",$2); print $2; exit}' "$enb_conf")
enb_mnc=$(awk -F= '/^[[:space:]]*mnc[[:space:]]*=/{gsub(/[[:space:]\047\042]/,"",$2); print $2; exit}' "$enb_conf")
enb_mme=$(awk -F= '/^[[:space:]]*mme_addr[[:space:]]*=/{gsub(/[[:space:]\047\042]/,"",$2); print $2; exit}' "$enb_conf")
enb_tac_hex=$(awk 'match($0,/tac[[:space:]]*=[[:space:]]*(0x[0-9A-Fa-f]+)/,m){print m[1]; exit}' "$rr_conf")
ue_apn=$(awk -F= '/^[[:space:]]*apn[[:space:]]*=/{gsub(/[[:space:]\047\042]/,"",$2); print $2; exit}' "$ue_conf")

mme_plmn_ok=false
mme_tac_ok=false
mme_endpoint_ok=false
apn_ok=false
rg_mcc="mcc: ['\"]?$enb_mcc"
rg_mnc="mnc: ['\"]?$enb_mnc"
grep -Eq "$rg_mcc" "$mme_conf" && grep -Eq "$rg_mnc" "$mme_conf" && mme_plmn_ok=true
[[ "$enb_tac_hex" == "0x0064" ]] && grep -Eq 'tac:[[:space:]]*100' "$mme_conf" && mme_tac_ok=true
grep -Eq "address:[[:space:]]*$enb_mme,[[:space:]]*port:[[:space:]]*36412" "$mme_conf" && mme_endpoint_ok=true
grep -Eq "dnn:[[:space:]]*$ue_apn([,}])" "$smf_conf" && apn_ok=true

core_ok=true
core_json='[]'
for service in mme sgwc sgwu hss pgwc pgwu pcrf; do
  name="oiran-lab-${service}-1"
  state=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || printf 'missing')
  health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}not_available{{end}}' "$name" 2>/dev/null || printf 'missing')
  if [[ "$state" != "running" || "$health" != "healthy" ]]; then core_ok=false; fi
  core_json=$(jq -c --arg name "$name" --arg state "$state" --arg health "$health" '. + [{container:$name,state:$state,health:$health}]' <<<"$core_json")
done

srs_running=$(docker ps --format '{{.Names}}' | grep -Ec '^oiran-lab-srs(enb|ue)-1$' || true)
if [[ "$srs_running" -eq 0 ]]; then srs_stopped=true; else srs_stopped=false; fi

config_sha=$(sha256sum "$enb_conf" "$rr_conf" "$ue_conf" | sha256sum | awk '{print $1}')

status=READY
for gate in "$disk_ok" "$memory_ok" "$dumpcap_ok" "$config_permissions_ok" "$mme_plmn_ok" "$mme_tac_ok" "$mme_endpoint_ok" "$apn_ok" "$core_ok" "$srs_stopped"; do
  [[ "$gate" == true ]] || status=BLOCKED
done

jq -n \
  --arg status "$status" \
  --arg observed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg profile_id 'LTE-SRSUE-TEST-01' \
  --argjson disk_size "$disk_size" \
  --argjson disk_used "$disk_used" \
  --argjson disk_avail "$disk_avail" \
  --arg disk_percent "$disk_percent" \
  --argjson disk_ok "$disk_ok" \
  --argjson memory_available "$memory_available" \
  --argjson memory_minimum "$min_memory_bytes" \
  --argjson memory_ok "$memory_ok" \
  --argjson dumpcap_count "$dumpcap_count" \
  --argjson dumpcap_ok "$dumpcap_ok" \
  --argjson config_permissions_ok "$config_permissions_ok" \
  --argjson plmn_ok "$mme_plmn_ok" \
  --argjson tac_ok "$mme_tac_ok" \
  --argjson mme_endpoint_ok "$mme_endpoint_ok" \
  --argjson apn_ok "$apn_ok" \
  --argjson core "$core_json" \
  --argjson core_ok "$core_ok" \
  --argjson srs_stopped "$srs_stopped" \
  --arg config_sha256 "$config_sha" \
  '{schema_version:"polaris.lte-preflight.v1",status:$status,observed_at:$observed_at,profile_id:$profile_id,resources:{disk:{size_bytes:$disk_size,used_bytes:$disk_used,available_bytes:$disk_avail,used_percent:($disk_percent|tonumber),strictly_below_85:$disk_ok},memory:{available_bytes:$memory_available,minimum_bytes:$memory_minimum,pass:$memory_ok}},captures:{dumpcap_count:$dumpcap_count,expected:12,pass:$dumpcap_ok},configuration:{permissions_pass:$config_permissions_ok,plmn_pass:$plmn_ok,tac_pass:$tac_ok,mme_endpoint_pass:$mme_endpoint_ok,apn_pass:$apn_ok,aggregate_sha256:$config_sha256},epc:{pass:$core_ok,containers:$core},runtime:{srsran_stopped:$srs_stopped},subscriber_material_exposed:false}'

[[ "$status" == READY ]]
