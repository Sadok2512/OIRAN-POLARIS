#!/usr/bin/env bash
# Read-only 15-minute safety observer. It writes only a small receipt in this workspace.
set -u

workspace=/root/OIRAN_VPROBE
receipt=${1:-$workspace/S2_1_SAFETY_RECEIPT.env}
window_seconds=${S2_1_WINDOW_SECONDS:-900}
sample_seconds=${S2_1_SAMPLE_SECONDS:-5}

if (( window_seconds < 900 )); then
  echo "REFUSED: observation window must be at least 900 seconds" >&2
  exit 2
fi
case "$receipt" in "$workspace"/*) ;; *) echo "REFUSED: receipt must remain inside $workspace" >&2; exit 2;; esac
if pgrep -fa '[b]enchmark-engine' >/dev/null; then
  echo "FAIL: benchmark-engine is already running" >&2
  exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "FAIL: Docker health cannot be verified" >&2
  exit 1
fi

start_epoch=$(date +%s)
end_epoch=$((start_epoch + window_seconds))
initial_state=$(docker ps --no-trunc --format '{{.ID}}|{{.Names}}' | sort)
if ! grep -Eiq 'etv|otv' <<<"$initial_state"; then
  echo "FAIL: ETV/OTV containers were not identifiable" >&2
  exit 1
fi
if ! grep -Eiq 'oiran-lab-capture|polaris' <<<"$initial_state"; then
  echo "FAIL: POLARIS capture service was not identifiable" >&2
  exit 1
fi

failures=0
samples=0
read -r _ cpu_user cpu_nice cpu_system cpu_idle cpu_iowait cpu_irq cpu_softirq cpu_steal _ </proc/stat
previous_total=$((cpu_user + cpu_nice + cpu_system + cpu_idle + cpu_iowait + cpu_irq + cpu_softirq + cpu_steal))
previous_steal=$cpu_steal
previous_throttled=$(awk '/^nr_throttled /{print $2}' /sys/fs/cgroup/cpu.stat 2>/dev/null || echo 0)
while (( $(date +%s) < end_epoch )); do
  current_state=$(docker ps --no-trunc --format '{{.ID}}|{{.Names}}' | sort)
  [[ "$current_state" == "$initial_state" ]] || failures=$((failures + 1))
  grep -Eiq 'etv|otv' <<<"$current_state" || failures=$((failures + 1))
  grep -Eiq 'oiran-lab-capture|polaris' <<<"$current_state" || failures=$((failures + 1))
  unhealthy=$(docker inspect $(docker ps -q) --format '{{.Name}}|{{.State.Status}}|{{.State.OOMKilled}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null | awk -F'|' '$2!="running" || $3=="true" || ($4!="" && $4!="healthy"){n++} END{print n+0}')
  (( unhealthy == 0 )) || failures=$((failures + 1))
  otv_burst=$(docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}' 2>/dev/null | awk -F'|' 'tolower($1)~/etv|otv/{gsub(/%/,"",$2); if($2>=200)n++} END{print n+0}')
  (( otv_burst == 0 )) || failures=$((failures + 1))
  pgrep -fa '[b]enchmark-engine' >/dev/null && failures=$((failures + 1))
  mem_kib=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
  (( mem_kib >= 8 * 1024 * 1024 )) || failures=$((failures + 1))
  cpu_psi=$(awk '/^some /{for(i=1;i<=NF;i++)if($i~/^avg10=/){split($i,a,"=");print a[2]}}' /proc/pressure/cpu)
  mem_full=$(awk '/^full /{for(i=1;i<=NF;i++)if($i~/^avg10=/){split($i,a,"=");print a[2]}}' /proc/pressure/memory)
  awk -v v="${cpu_psi:-100}" 'BEGIN{exit !(v < 2.0)}' || failures=$((failures + 1))
  awk -v v="${mem_full:-100}" 'BEGIN{exit !(v == 0.0)}' || failures=$((failures + 1))
  read -r _ cpu_user cpu_nice cpu_system cpu_idle cpu_iowait cpu_irq cpu_softirq cpu_steal _ </proc/stat
  current_total=$((cpu_user + cpu_nice + cpu_system + cpu_idle + cpu_iowait + cpu_irq + cpu_softirq + cpu_steal))
  total_delta=$((current_total - previous_total))
  steal_delta=$((cpu_steal - previous_steal))
  awk -v s="$steal_delta" -v t="$total_delta" 'BEGIN{exit !(t>0 && (100*s/t)<1.0)}' || failures=$((failures + 1))
  previous_total=$current_total
  previous_steal=$cpu_steal
  current_throttled=$(awk '/^nr_throttled /{print $2}' /sys/fs/cgroup/cpu.stat 2>/dev/null || echo 0)
  (( current_throttled == previous_throttled )) || failures=$((failures + 1))
  previous_throttled=$current_throttled
  samples=$((samples + 1))
  sleep "$sample_seconds"
done

if (( failures != 0 )); then
  echo "FAIL: $failures threshold/lifecycle violations across $samples samples" >&2
  exit 1
fi
issued=$(date +%s)
expires=$((issued + 300))
umask 077
{
  echo 'STATUS=PASS'
  echo "OBSERVED_SECONDS=$window_seconds"
  echo "ISSUED_EPOCH_SECONDS=$issued"
  echo "EXPIRES_EPOCH_SECONDS=$expires"
  echo "SAMPLES=$samples"
} >"$receipt"
echo "PASS: safety receipt valid for five minutes: $receipt"
