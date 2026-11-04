#!/usr/bin/env bash
set -euo pipefail

# 2.7.15 regression: `packets_dropped` and `packets_captured` in the
# rotation JSONL must NEVER be `null`. ANR3 observed 24 records with
# `packets_dropped:null` across two hourly rotations on the real P4
# import (issue #10 comment 6636015016). The watcher must emit either
# a chiffré integer OR an explicit `"UNKNOWN:<reason>"` string.

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
watcher="$here/../rotation-watcher.sh"
tmp=$(mktemp -d /tmp/oiran-capture-drops-test.XXXXXX)
trap 'rm -rf -- "$tmp"' EXIT

label_dir="$tmp/s1mme"
mkdir -p "$label_dir"
rotation_log="$tmp/capture-rotation.jsonl"
seen_file="$label_dir/.rotations-seen"
drop_cache="$label_dir/.iface-drops"
sysfs_root="$tmp/sysfs"
iface="br-oiran-s1m"

stub_capinfos="$tmp/capinfos-stub"
cat >"$stub_capinfos" <<'CAPINFOS_STUB'
#!/usr/bin/env bash
set -euo pipefail
file=${@: -1}
size=$(stat -c '%s' "$file" 2>/dev/null || echo 0)
printf 'Number of packets: %d\n' "$((size))"
CAPINFOS_STUB
chmod +x "$stub_capinfos"

export CAPINFOS="$stub_capinfos"
export OIRAN_CAPTURE_ROTATION_LOG="$rotation_log"
export OIRAN_CAPTURE_ROTATION_ONESHOT=1
export OIRAN_CAPTURE_ROTATION_SEEN="$seen_file"
export OIRAN_IFACE_DROP_CACHE="$drop_cache"
export OIRAN_IFACE_STATS_ROOT="$sysfs_root"

mkdir -p "$sysfs_root/$iface/statistics"
printf '%s' 0 > "$sysfs_root/$iface/statistics/rx_dropped"

# Rotation 1: finalise file1 by creating a newer file2. The first
# rotation seeds the baseline, so `packets_dropped` is the explicit
# "UNKNOWN:no-baseline-yet" rather than `null`.
file1="$label_dir/s1mme_00001_20261104T120000.pcapng"
file2="$label_dir/s1mme_00002_20261104T130000.pcapng"
printf 'rotation-1' > "$file1"
printf 'rotation-2' > "$file2"
"$watcher" "$iface" s1mme "$label_dir"
record1=$(sed -n 1p "$rotation_log")
if ! grep -qF '"packets_dropped":"UNKNOWN:no-baseline-yet"' <<<"$record1"; then
  echo "FAIL: first rotation must expose 'UNKNOWN:no-baseline-yet' drops, got: $record1" >&2
  exit 1
fi
if ! grep -qF '"packets_captured":10' <<<"$record1"; then
  echo "FAIL: first rotation must expose numeric packets_captured, got: $record1" >&2
  exit 1
fi

# Rotation 2: 7 packets dropped since the baseline. Delta must show as
# an integer, never as null.
printf '%s' 7 > "$sysfs_root/$iface/statistics/rx_dropped"
file3="$label_dir/s1mme_00003_20261104T140000.pcapng"
printf 'rotation-3-' > "$file3"
"$watcher" "$iface" s1mme "$label_dir"
record2=$(sed -n 2p "$rotation_log")
if ! grep -qF '"packets_dropped":7' <<<"$record2"; then
  echo "FAIL: second rotation must expose delta=7 drops, got: $record2" >&2
  exit 1
fi
if ! grep -qF '"packets_captured":10' <<<"$record2"; then
  echo "FAIL: second rotation must expose numeric packets_captured, got: $record2" >&2
  exit 1
fi

# Rotation 3: sysfs disappears (simulates a host restriction). The
# watcher must fall back to an explicit UNKNOWN reason naming the
# interface, never null.
rm -rf "$sysfs_root"
printf '%s' 21 > /dev/null  # no-op, counter now unavailable.
file4="$label_dir/s1mme_00004_20261104T150000.pcapng"
printf 'rotation-4-sample' > "$file4"
"$watcher" "$iface" s1mme "$label_dir"
record3=$(sed -n 3p "$rotation_log")
if ! grep -qF "\"packets_dropped\":\"UNKNOWN:sysfs-$iface-unavailable\"" <<<"$record3"; then
  echo "FAIL: third rotation must expose UNKNOWN sysfs reason, got: $record3" >&2
  exit 1
fi

# Rotation 4: capinfos missing. packets_captured must fall back to
# UNKNOWN:capinfos-missing, never null.
export CAPINFOS="/nonexistent-capinfos-$$"
file5="$label_dir/s1mme_00005_20261104T160000.pcapng"
printf 'rotation-5-longer-sample' > "$file5"
"$watcher" "$iface" s1mme "$label_dir"
record4=$(sed -n 4p "$rotation_log")
if ! grep -qF '"packets_captured":"UNKNOWN:capinfos-missing"' <<<"$record4"; then
  echo "FAIL: fourth rotation must expose UNKNOWN capinfos reason, got: $record4" >&2
  exit 1
fi

# Global invariant: no record contains the literal `null` for either
# captured or dropped. The regex is anchored to the JSON keys so a
# future field named foo_null stays allowed.
if grep -E '"(packets_captured|packets_dropped)":null' "$rotation_log"; then
  echo "FAIL: at least one record still emits null for the packet counters" >&2
  exit 1
fi

echo 'PASS: packets_dropped is never null; capinfos and sysfs failures surface as explicit UNKNOWN reasons.'
