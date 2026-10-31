#!/usr/bin/env bash
# Fail-closed identity gate. It does not rewrite PCAP files. A successful scan
# is only one input to an independent anonymization review.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  printf 'usage: %s SANITIZED_CANDIDATE.pcapng\n' "$0" >&2
  exit 64
fi

pcap=$1
decoder=${OIRAN_TSHARK_PATH:-tshark}

[[ -r "$pcap" ]] || { printf 'BLOCKED|PCAP_UNREADABLE\n'; exit 2; }
command -v "$decoder" >/dev/null 2>&1 || { printf 'BLOCKED|DECODER_UNAVAILABLE\n'; exit 3; }

# Field names are verified at runtime. If a required field is absent from the
# installed decoder, the release gate blocks instead of silently weakening.
fields=$($decoder -G fields)
required=(e212.imsi nas_eps.emm.m_tmsi nas_eps.emm.guti gsm_a.imei)
for field in "${required[@]}"; do
  grep -Fq $'\t'"$field"$'\t' <<<"$fields" || {
    printf 'BLOCKED|IDENTITY_FIELD_UNSUPPORTED|%s\n' "$field"
    exit 4
  }
done

display_filter='e212.imsi || nas_eps.emm.m_tmsi || nas_eps.emm.guti || gsm_a.imei'
matches=$($decoder -n -r "$pcap" -Y "$display_filter" -T fields -e frame.number 2>/dev/null | sed '/^$/d' | head -n 1)
if [[ -n "$matches" ]]; then
  printf 'BLOCKED|SUBSCRIBER_IDENTITY_PRESENT|frame=%s\n' "$matches"
  exit 5
fi

printf 'PASS|NO_DECODED_SUBSCRIBER_IDENTITY|sha256=%s\n' "$(sha256sum "$pcap" | awk '{print $1}')"
