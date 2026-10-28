#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 OPEN5GS_READ_ONLY_EXPORT CONFIGURED_PROFILE_COUNT" >&2
  exit 64
fi

readonly export_path=$1
readonly profile_count=$2
readonly binary=/opt/polaris-control/bin/polaris-provisioning-attest
readonly registry=/var/lib/polaris-control/ue-profile-registry.json
readonly profile_root=/var/lib/polaris-control/ue-profiles
readonly output=/var/lib/polaris-control/ue-provisioning-attestation.json

for path in "$binary" "$export_path" "$registry"; do
  [[ -f "$path" ]] || { echo "required file unavailable: $path" >&2; exit 66; }
done

# Phase one is deliberately read-only. It validates the newly bound slot against an
# independently produced Open5GS export and prints digests/identifiers only.
"$binary" \
  --open5gs-records "$export_path" \
  --profile-registry "$registry" \
  --profile-root "$profile_root" \
  --count "$profile_count"

# The operator must explicitly opt in to the atomic mode-0600 replacement.
if [[ ${POLARIS_ATTESTATION_WRITE:-0} != 1 ]]; then
  echo "dry-run verified; set POLARIS_ATTESTATION_WRITE=1 for the reviewed atomic write" >&2
  exit 0
fi

"$binary" \
  --open5gs-records "$export_path" \
  --profile-registry "$registry" \
  --profile-root "$profile_root" \
  --count "$profile_count" \
  --output "$output" \
  --write

sha256sum "$output"
