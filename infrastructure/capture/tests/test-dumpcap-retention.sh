#!/usr/bin/env bash
set -euo pipefail

# 2.7.13 regression: dumpcap no longer owns retention. The previous
# `-b files:8` ring silently dropped older segments once the 8-file
# window was reached. The capture script must not pass that flag any
# more, and the rotation workflow must keep every segment on disk so
# the disk-safety guard-rail is the single authority on deletion.
#
# This test enforces the invariant by:
#   1. asserting that `capture-interface.sh` does not pass `-b files:`
#      to dumpcap and that the previous `OIRAN_CAPTURE_RING_FILES`
#      knob has been retired (no code path can resurrect it);
#   2. simulating ten rotations by creating ten pcapng files side by
#      side in the per-label directory and asserting that all ten
#      files remain accessible after the rotation watcher has emitted
#      its JSONL records.
#
# dumpcap itself is not invoked (no root, no live bridge); the point
# is to prove that the OIRAN components around dumpcap neither
# instruct dumpcap to prune nor prune the files themselves.

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
capture_script="$here/../capture-interface.sh"
watcher="$here/../rotation-watcher.sh"

tmp=$(mktemp -d /tmp/oiran-capture-retention-test.XXXXXX)
trap 'rm -rf -- "$tmp"' EXIT

# 1. No `-b files:` on the dumpcap command line, no residual ring knob.
# Comments are allowed to mention the retired flag so operators can
# cross-reference the behaviour change; what matters is that the
# non-comment portion of the script never writes `-b files:` to the
# dumpcap argv.
if grep -vE '^\s*#' "$capture_script" | grep -q -- '-b files:'; then
  echo "FAIL: capture-interface.sh still passes '-b files:' to dumpcap" >&2
  exit 1
fi
if grep -vE '^\s*#' "$capture_script" | grep -q 'OIRAN_CAPTURE_RING_FILES'; then
  echo "FAIL: capture-interface.sh still references OIRAN_CAPTURE_RING_FILES outside comments" >&2
  exit 1
fi

# 2. Simulate 10 rotations and assert every file remains.
label_dir="$tmp/s1mme"
mkdir -p "$label_dir"
rotation_log="$tmp/capture-rotation.jsonl"
seen_file="$label_dir/.rotations-seen"

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

for i in $(seq -w 1 10); do
  file="$label_dir/s1mme_000${i}_20261104T${i}0000.pcapng"
  printf 'rotation-%s-synthetic' "$i" > "$file"
  "$watcher" br-oiran-s1m s1mme "$label_dir"
done
# Create one extra "open" segment so the last rotation is finalised.
tail_file="$label_dir/s1mme_00011_20261104T110000.pcapng"
printf 'open-segment' > "$tail_file"
"$watcher" br-oiran-s1m s1mme "$label_dir"

retained=$(find "$label_dir" -maxdepth 1 -type f -name '*.pcapng' | wc -l)
if [[ $retained -ne 11 ]]; then
  echo "FAIL: expected 11 files on disk after 10 rotations, found $retained" >&2
  ls -la "$label_dir" >&2
  exit 1
fi

records=$(wc -l <"$rotation_log")
if [[ $records -ne 10 ]]; then
  echo "FAIL: expected 10 JSONL records (one per finalised rotation), got $records" >&2
  cat "$rotation_log" >&2
  exit 1
fi

for i in $(seq -w 1 10); do
  file="$label_dir/s1mme_000${i}_20261104T${i}0000.pcapng"
  if [[ ! -f $file ]]; then
    echo "FAIL: segment $file disappeared after rotation" >&2
    exit 1
  fi
done

echo 'PASS: 10 rotations retained all 10 segments; dumpcap does not own retention.'
