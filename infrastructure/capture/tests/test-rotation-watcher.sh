#!/usr/bin/env bash
set -euo pipefail

# 2.7.12 regression test: two simulated dumpcap rotations must produce two
# `capture-rotation.jsonl` records WITHOUT GAP, i.e. nothing in between is
# dropped and the segment order is preserved. The watcher runs in
# oneshot mode (OIRAN_CAPTURE_ROTATION_ONESHOT=1) so the test does not
# sleep.

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
watcher="$here/../rotation-watcher.sh"
tmp=$(mktemp -d /tmp/oiran-capture-rotation-test.XXXXXX)
trap 'rm -rf -- "$tmp"' EXIT

label_dir="$tmp/s1mme"
mkdir -p "$label_dir"
rotation_log="$tmp/capture-rotation.jsonl"
seen_file="$label_dir/.rotations-seen"

# Stub capinfos so the test does not need wireshark-tools. The watcher
# picks it up through the CAPINFOS environment variable.
stub_capinfos="$tmp/capinfos-stub"
cat >"$stub_capinfos" <<'CAPINFOS_STUB'
#!/usr/bin/env bash
# Deterministic packet count derived from the file size so the test can
# compare values without a real pcapng.
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

# Rotation 1: the very first file is NOT yet finalised (dumpcap is still
# writing to it), the watcher must emit nothing.
file1="$label_dir/s1mme_00001_20261104T120000.pcapng"
printf 'r1-r1-r1-r1-r1-r1' > "$file1"
"$watcher" br-oiran-s1m s1mme "$label_dir"
if [[ -s $rotation_log ]]; then
  echo "FAIL: watcher emitted a record for the open segment" >&2
  cat "$rotation_log" >&2
  exit 1
fi

# Simulate rotation 1: dumpcap closes file1 and opens file2.
file2="$label_dir/s1mme_00002_20261104T130000.pcapng"
printf 'r2-r2-r2-r2-r2-r2-r2' > "$file2"
"$watcher" br-oiran-s1m s1mme "$label_dir"
records1=$(wc -l <"$rotation_log")
if [[ $records1 -ne 1 ]]; then
  echo "FAIL: expected 1 record after first rotation, got $records1" >&2
  cat "$rotation_log" >&2
  exit 1
fi

# Simulate rotation 2: dumpcap closes file2 and opens file3.
file3="$label_dir/s1mme_00003_20261104T140000.pcapng"
printf 'r3-r3-r3-r3-r3-r3-r3-r3' > "$file3"
"$watcher" br-oiran-s1m s1mme "$label_dir"
records2=$(wc -l <"$rotation_log")
if [[ $records2 -ne 2 ]]; then
  echo "FAIL: expected 2 records after second rotation, got $records2" >&2
  cat "$rotation_log" >&2
  exit 1
fi

# Content invariants: records cover file1 then file2 in that exact order
# (no gap, no reordering) and carry the fixed fields.
line1=$(sed -n 1p "$rotation_log")
line2=$(sed -n 2p "$rotation_log")
for expected in \
    "\"interface\":\"br-oiran-s1m\"" \
    "\"plane\":\"s1mme\"" \
    "\"packets_captured\":"; do
  if ! grep -qF "$expected" <<<"$line1"; then
    echo "FAIL: first record missing $expected: $line1" >&2
    exit 1
  fi
  if ! grep -qF "$expected" <<<"$line2"; then
    echo "FAIL: second record missing $expected: $line2" >&2
    exit 1
  fi
done
if ! grep -qF "\"file\":\"$file1\"" <<<"$line1"; then
  echo "FAIL: first record does not reference file1: $line1" >&2
  exit 1
fi
if ! grep -qF "\"file\":\"$file2\"" <<<"$line2"; then
  echo "FAIL: second record does not reference file2: $line2" >&2
  exit 1
fi

# Running the watcher a fourth time without any new finalisation must NOT
# produce a duplicate record — segments are idempotent.
"$watcher" br-oiran-s1m s1mme "$label_dir"
records_final=$(wc -l <"$rotation_log")
if [[ $records_final -ne 2 ]]; then
  echo "FAIL: watcher re-emitted a finalised segment (got $records_final records)" >&2
  cat "$rotation_log" >&2
  exit 1
fi

echo 'PASS: 2 rotations observed with no gap, no duplicates.'
