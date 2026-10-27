#!/bin/bash
set -euo pipefail
umask 077

readonly container="oiran-lab-mongodb-1"
readonly source_env="/root/POLARIS/secrets/subscriber.env"
readonly source_profile="/root/POLARIS/runtime/ueransim/ue.yaml"
readonly state_root="/var/lib/polaris-control/subscriber-secrets"
readonly plan="$state_root/v3.2.plan"
readonly profile_root="/var/lib/polaris-control/ue-profiles"
stage=""
mongo_script=""

fail() { printf 'PROVISIONING_FAILED=%s\n' "$1" >&2; exit 1; }
cleanup() {
  if [[ -n "$mongo_script" && "$mongo_script" == /var/lib/polaris-control/subscriber-provision.*.js ]]; then
    : > "$mongo_script"
    rm -f -- "$mongo_script"
  fi
  if [[ -n "$stage" && "$stage" == /var/lib/polaris-control/ue-profiles.stage.* && -d "$stage" ]]; then
    find "$stage" -maxdepth 1 -type f -name 'ue-*.yaml' -delete
    rmdir -- "$stage"
  fi
}
trap cleanup EXIT
secret_value() {
  local name="$1"
  local value
  value=$(sed -n "s/^${name}=//p" "$source_env")
  [[ "$value" =~ ^[0-9A-Fa-f]+$ ]] || fail "INVALID_EXISTING_SECRET_SOURCE"
  printf '%s' "$value"
}

[[ $(id -u) -eq 0 ]] || fail "ROOT_REQUIRED"
[[ -r "$source_env" && -r "$source_profile" ]] || fail "EXISTING_PROFILE_UNAVAILABLE"
docker inspect --format '{{.State.Health.Status}}' "$container" | grep -qx healthy || fail "MONGODB_NOT_HEALTHY"
install -d -m 0700 "$state_root" "$profile_root"

if [[ ! -f "$plan" ]]; then
  existing_imsi=$(secret_value SYNTHETIC_IMSI)
  existing_key=$(secret_value SYNTHETIC_K)
  existing_opc=$(secret_value SYNTHETIC_OPC)
  existing_imei=$(secret_value SYNTHETIC_IMEI)
  existing_imeisv=$(secret_value SYNTHETIC_IMEISV)
  [[ ${#existing_imsi} -eq 15 && ${#existing_key} -eq 32 && ${#existing_opc} -eq 32 ]] || fail "EXISTING_SECRET_SHAPE_INVALID"
  {
    printf 'UE-01|%s|%s|%s|%s|%s\n' "$existing_imsi" "$existing_key" "$existing_opc" "$existing_imei" "$existing_imeisv"
    for index in $(seq 2 10); do
      imsi=$(printf '%015d' "$((10#$existing_imsi + index - 1))")
      imei=$(printf '%015d' "$((10#$existing_imei + index - 1))")
      imeisv=$(printf '%016d' "$((10#$existing_imeisv + index - 1))")
      printf 'UE-%02d|%s|%s|%s|%s|%s\n' "$index" "$imsi" "$(openssl rand -hex 16)" "$(openssl rand -hex 16)" "$imei" "$imeisv"
    done
  } > "$plan"
  chmod 0600 "$plan"
fi

[[ $(wc -l < "$plan") -eq 10 ]] || fail "SECRET_PLAN_COUNT_INVALID"
awk -F'|' 'NF != 6 || $1 !~ /^UE-[0-9][0-9]$/ || $2 !~ /^[0-9]{15}$/ || $3 !~ /^[0-9a-fA-F]{32}$/ || $4 !~ /^[0-9a-fA-F]{32}$/ {exit 1}' "$plan" || fail "SECRET_PLAN_INVALID"
[[ $(cut -d'|' -f2 "$plan" | sort -u | wc -l) -eq 10 ]] || fail "DUPLICATE_SUBSCRIBER_IDENTITY"
[[ $(cut -d'|' -f3 "$plan" | sort -u | wc -l) -eq 10 ]] || fail "DUPLICATE_AUTHENTICATION_KEY"
[[ $(cut -d'|' -f4 "$plan" | sort -u | wc -l) -eq 10 ]] || fail "DUPLICATE_OPC"

stage=$(mktemp -d /var/lib/polaris-control/ue-profiles.stage.XXXXXX)
chmod 0700 "$stage"
while IFS='|' read -r ue_id imsi key opc imei imeisv; do
  profile_number=${ue_id#UE-}
  output="$stage/ue-${profile_number}.yaml"
  sed -E \
    -e "s/^supi:.*/supi: 'imsi-${imsi}'/" \
    -e "s/^key:.*/key: '${key}'/" \
    -e "s/^op:.*/op: '${opc}'/" \
    -e "s/^imei:.*/imei: '${imei}'/" \
    -e "s/^imeiSv:.*/imeiSv: '${imeisv}'/" \
    "$source_profile" > "$output"
  chmod 0600 "$output"
done < "$plan"

mongo_script=$(mktemp /var/lib/polaris-control/subscriber-provision.XXXXXX.js)
chmod 0600 "$mongo_script"
{
  printf 'const requested = [\n'
  while IFS='|' read -r ue_id imsi key opc _imei _imeisv; do
    printf '{imsi:"%s",security:{k:"%s",op:null,opc:"%s",amf:"8000"}},\n' "$imsi" "$key" "$opc"
  done < "$plan"
  cat <<'JAVASCRIPT'
];
function compatible(doc, desired) {
  return doc && doc.security && doc.security.k === desired.security.k &&
    doc.security.opc === desired.security.opc && doc.security.amf === "8000" &&
    Array.isArray(doc.slice) && doc.slice.some(s => s.sst === 1 && s.sd === "010203" &&
      Array.isArray(s.session) && s.session.some(x => x.name === "internet"));
}
const totalBefore = db.subscribers.countDocuments({});
if (totalBefore < 1 || totalBefore > 10) throw new Error("UNEXPECTED_SUBSCRIBER_INVENTORY");
const existing = db.subscribers.find({imsi: {$in: requested.map(x => x.imsi)}}).toArray();
for (const doc of existing) {
  const desired = requested.find(x => x.imsi === doc.imsi);
  if (!compatible(doc, desired)) throw new Error("EXISTING_SUBSCRIBER_MISMATCH");
}
const missing = requested.filter(x => !existing.some(d => d.imsi === x.imsi));
const inserted = [];
try {
  for (const desired of missing) {
    const result = db.subscribers.insertOne({
      schema_version: NumberInt(1), imsi: desired.imsi, msisdn: [], imeisv: [], mme_host: [], mm_realm: [], purge_flag: [],
      slice: [{sst: NumberInt(1), sd: "010203", default_indicator: true, session: [{name: "internet", type: NumberInt(3), qos: {index: NumberInt(9), arp: {priority_level: NumberInt(8), pre_emption_capability: NumberInt(1), pre_emption_vulnerability: NumberInt(2)}}, ambr: {downlink: {value: NumberInt(1000000000), unit: NumberInt(0)}, uplink: {value: NumberInt(1000000000), unit: NumberInt(0)}}, pcc_rule: [], _id: new ObjectId()}], _id: new ObjectId()}],
      security: desired.security,
      ambr: {downlink: {value: NumberInt(1000000000), unit: NumberInt(0)}, uplink: {value: NumberInt(1000000000), unit: NumberInt(0)}},
      access_restriction_data: NumberInt(32), network_access_mode: NumberInt(0), subscriber_status: NumberInt(0), operator_determined_barring: NumberInt(0), subscribed_rau_tau_timer: NumberInt(12), __v: NumberInt(0)
    });
    if (!result.acknowledged) throw new Error("INSERT_NOT_ACKNOWLEDGED");
    inserted.push(desired.imsi);
  }
} catch (error) {
  if (inserted.length) db.subscribers.deleteMany({imsi: {$in: inserted}});
  throw error;
}
const finalDocs = db.subscribers.find({imsi: {$in: requested.map(x => x.imsi)}}).toArray();
if (db.subscribers.countDocuments({}) !== 10 || finalDocs.length !== 10 || !finalDocs.every(d => compatible(d, requested.find(x => x.imsi === d.imsi)))) {
  if (inserted.length) db.subscribers.deleteMany({imsi: {$in: inserted}});
  throw new Error("POST_PROVISION_VALIDATION_FAILED");
}
print(JSON.stringify({before: totalBefore, created: inserted.length, total: finalDocs.length, compatible: finalDocs.length, duplicates: 0}));
JAVASCRIPT
} > "$mongo_script"

result=$(docker exec -i "$container" mongosh --quiet open5gs --file /dev/stdin < "$mongo_script") || fail "DATABASE_PROVISIONING_FAILED"
printf '%s' "$result" | tail -1 | jq -e '.total == 10 and .compatible == 10 and .duplicates == 0' >/dev/null || fail "DATABASE_VALIDATION_FAILED"

for profile in "$stage"/*.yaml; do
  install -m 0600 "$profile" "$profile_root/$(basename "$profile")"
done

printf '%s' "$result" | tail -1 | jq '{before,created,total,compatible,duplicates}'
printf 'PROFILES_READY=%s\n' "$(find "$profile_root" -maxdepth 1 -type f -name 'ue-*.yaml' | wc -l)"
printf 'EXECUTION_STARTED=FALSE\n'
