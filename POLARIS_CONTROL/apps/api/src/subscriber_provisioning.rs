use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_BULK_ROWS: usize = 100_000;
pub const WRITE_BATCH_ROWS: usize = 5_000;
pub const GENERATE_MAX_COUNT: usize = 1_000;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SubscriberAmbr {
    pub uplink: u64,
    pub downlink: u64,
}

/// Write-only request. Deliberately does not implement Debug or Serialize.
#[derive(Clone, Deserialize)]
pub struct SubscriberMutation {
    pub imsi: String,
    pub k: String,
    pub opc: String,
    pub sst: u8,
    pub sd: Option<String>,
    pub dnns: Vec<String>,
    pub ambr: SubscriberAmbr,
}

/// Internal secret-bearing representation. Never serialize or log this type.
#[derive(Clone)]
pub struct SubscriberRecord {
    pub imsi: String,
    pub k: String,
    pub opc: String,
    pub slot: String,
    pub plmn_mcc: String,
    pub plmn_mnc: String,
    pub sst: u8,
    pub sd: Option<String>,
    pub dnns: Vec<String>,
    pub ambr: SubscriberAmbr,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct SanitizedSubscriber {
    pub slot: String,
    pub state: String,
    pub plmn: SanitizedPlmn,
    pub snssai: SanitizedSnssai,
    pub dnns: Vec<String>,
    pub ambr: SubscriberAmbr,
    pub subscriber_identity: &'static str,
    pub authentication_material: &'static str,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct SanitizedPlmn {
    pub mcc: String,
    pub mnc: String,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct SanitizedSnssai {
    pub sst: u8,
    pub sd: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProvisionResult {
    pub row: usize,
    pub ok: bool,
    pub slot: Option<String>,
    pub error: Option<String>,
}

/// Write-only partial update for `PUT /subscribers/:slot`. Fields set to
/// `Some` are overwritten; a `None` on `k`/`opc` preserves the stored
/// authentication material (no accidental zeroing). All fields are serde
/// `default`-ed so an operator may send a minimal body (for example only
/// `{"ambr": {...}}`).
#[derive(Clone, Deserialize, Default)]
#[serde(default)]
pub struct SubscriberUpdate {
    pub sst: Option<u8>,
    pub sd: Option<Option<String>>,
    pub dnns: Option<Vec<String>>,
    pub ambr: Option<SubscriberAmbr>,
    pub k: Option<String>,
    pub opc: Option<String>,
}

pub trait SubscriberBackend: Send + Sync {
    fn list(&self) -> Result<Vec<SanitizedSubscriber>, String>;
    fn lookup_many(
        &self,
        identities: &[String],
    ) -> Result<BTreeMap<String, SubscriberRecord>, String>;
    fn provision_batch(
        &self,
        rows: Vec<(usize, SubscriberMutation)>,
    ) -> Result<Vec<ProvisionResult>, String>;
    fn fetch_slot(&self, slot: &str) -> Result<Option<SanitizedSubscriber>, String>;
    /// Apply a partial update to the subscriber identified by `slot`. The
    /// backend performs the IMSI/K/OPc confidentiality by never returning
    /// them in `SanitizedSubscriber`.
    fn apply_update(
        &self,
        slot: &str,
        update: SubscriberUpdate,
    ) -> Result<SanitizedSubscriber, String>;
    /// Returns the lexicographically sorted list of taken IMSIs. Used by
    /// `allocate_next_imsis()` to pick the next free MSIN. The MongoDB
    /// implementation issues a projection over `_id` only, so the IMSI
    /// digits are the only identity bytes that leave Mongo for this flow.
    fn taken_imsis(&self) -> Result<BTreeSet<String>, String>;
}

#[derive(Clone)]
pub struct MongoSubscriberBackend {
    container: String,
    backup_root: PathBuf,
    plmn_mcc: String,
    plmn_mnc: String,
}

impl MongoSubscriberBackend {
    pub fn from_env() -> Result<Self, String> {
        let backend = Self {
            container: std::env::var("POLARIS_OPEN5GS_MONGODB_CONTAINER")
                .unwrap_or_else(|_| "oiran-lab-mongodb-1".into()),
            backup_root: std::env::var("POLARIS_SUBSCRIBER_BACKUP_ROOT")
                .unwrap_or_else(|_| "/var/lib/polaris-control/subscriber-backups".into())
                .into(),
            plmn_mcc: std::env::var("POLARIS_PLMN_MCC").unwrap_or_else(|_| "001".into()),
            plmn_mnc: std::env::var("POLARIS_PLMN_MNC").unwrap_or_else(|_| "01".into()),
        };
        validate_plmn(&backend.plmn_mcc, &backend.plmn_mnc)?;
        Ok(backend)
    }

    fn mongosh(&self, script: &[u8]) -> Result<Value, String> {
        let mut child = Command::new("/usr/bin/docker")
            .args([
                "exec",
                "-i",
                self.container.as_str(),
                "mongosh",
                "--quiet",
                "open5gs",
                "--file",
                "/dev/stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "OPEN5GS_DATABASE_UNAVAILABLE")?;
        child
            .stdin
            .take()
            .ok_or("OPEN5GS_DATABASE_UNAVAILABLE")?
            .write_all(script)
            .map_err(|_| "OPEN5GS_DATABASE_UNAVAILABLE")?;
        let output = child
            .wait_with_output()
            .map_err(|_| "OPEN5GS_DATABASE_UNAVAILABLE")?;
        if !output.status.success() {
            #[cfg(test)]
            {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let class = [
                    "SyntaxError",
                    "TypeError",
                    "MongoServerError",
                    "ReferenceError",
                ]
                .into_iter()
                .find(|candidate| stderr.contains(candidate))
                .unwrap_or("UNCLASSIFIED");
                eprintln!(
                    "MONGOSH_FAILURE_EXIT={:?} ERROR_CLASS={class}",
                    output.status.code()
                );
            }
            return Err("OPEN5GS_DATABASE_OPERATION_FAILED".into());
        }
        let line = String::from_utf8(output.stdout)
            .map_err(|_| "OPEN5GS_DATABASE_RESPONSE_INVALID")?
            .lines()
            .last()
            .ok_or("OPEN5GS_DATABASE_RESPONSE_INVALID")?
            .to_string();
        serde_json::from_str(&line).map_err(|_| "OPEN5GS_DATABASE_RESPONSE_INVALID".into())
    }

    fn backup(&self) -> Result<PathBuf, String> {
        fs::create_dir_all(&self.backup_root).map_err(|_| "SUBSCRIBER_BACKUP_FAILED")?;
        fs::set_permissions(&self.backup_root, fs::Permissions::from_mode(0o700))
            .map_err(|_| "SUBSCRIBER_BACKUP_FAILED")?;
        let name = format!(
            "open5gs-subscribers-{}-{}.archive",
            epoch_millis(),
            random_suffix()
        );
        let path = self.backup_root.join(name);
        let output = Command::new("/usr/bin/docker")
            .args([
                "exec",
                self.container.as_str(),
                "mongodump",
                "--quiet",
                "--db",
                "open5gs",
                "--collection",
                "subscribers",
                "--archive",
            ])
            .stderr(Stdio::null())
            .output()
            .map_err(|_| "SUBSCRIBER_BACKUP_FAILED")?;
        if !output.status.success() || output.stdout.is_empty() {
            return Err("SUBSCRIBER_BACKUP_FAILED".into());
        }
        private_write(&path, &output.stdout)?;
        Ok(path)
    }

    fn decode_record(&self, value: &Value) -> Result<SubscriberRecord, String> {
        let imsi = value["imsi"].as_str().ok_or("OPEN5GS_SUBSCRIBER_INVALID")?;
        let k = value
            .pointer("/security/k")
            .and_then(Value::as_str)
            .ok_or("OPEN5GS_SUBSCRIBER_INVALID")?;
        let opc = value
            .pointer("/security/opc")
            .and_then(Value::as_str)
            .ok_or("OPEN5GS_SUBSCRIBER_INVALID")?;
        let marker = value.get("polaris").ok_or("SUBSCRIBER_NOT_PROVISIONED")?;
        if marker["owned"].as_bool() != Some(true) {
            return Err("SUBSCRIBER_NOT_PROVISIONED".into());
        }
        let slice = value["slice"]
            .as_array()
            .and_then(|v| v.first())
            .ok_or("OPEN5GS_SUBSCRIBER_INVALID")?;
        let sessions = slice["session"]
            .as_array()
            .ok_or("OPEN5GS_SUBSCRIBER_INVALID")?;
        let dnns = sessions
            .iter()
            .filter_map(|s| s["name"].as_str().map(str::to_string))
            .collect::<Vec<_>>();
        let record = SubscriberRecord {
            imsi: imsi.to_string(),
            k: k.to_string(),
            opc: opc.to_string(),
            slot: marker["slot"]
                .as_str()
                .ok_or("OPEN5GS_SUBSCRIBER_INVALID")?
                .to_string(),
            plmn_mcc: marker["plmn_mcc"]
                .as_str()
                .unwrap_or(&self.plmn_mcc)
                .to_string(),
            plmn_mnc: marker["plmn_mnc"]
                .as_str()
                .unwrap_or(&self.plmn_mnc)
                .to_string(),
            sst: slice["sst"]
                .as_u64()
                .and_then(|v| u8::try_from(v).ok())
                .ok_or("OPEN5GS_SUBSCRIBER_INVALID")?,
            sd: slice["sd"].as_str().map(str::to_string),
            dnns,
            ambr: SubscriberAmbr {
                uplink: value
                    .pointer("/ambr/uplink/value")
                    .and_then(json_u64)
                    .ok_or("OPEN5GS_SUBSCRIBER_INVALID")?,
                downlink: value
                    .pointer("/ambr/downlink/value")
                    .and_then(json_u64)
                    .ok_or("OPEN5GS_SUBSCRIBER_INVALID")?,
            },
        };
        validate_record(&record)?;
        Ok(record)
    }
}

impl SubscriberBackend for MongoSubscriberBackend {
    fn list(&self) -> Result<Vec<SanitizedSubscriber>, String> {
        let value = self.mongosh(br#"print(JSON.stringify(db.subscribers.find({"polaris.owned":true},{imsi:1,security:1,slice:1,ambr:1,polaris:1}).toArray()))"#)?;
        value
            .as_array()
            .ok_or("OPEN5GS_DATABASE_RESPONSE_INVALID")?
            .iter()
            .map(|v| self.decode_record(v).map(|r| sanitize(&r)))
            .collect()
    }

    fn lookup_many(
        &self,
        identities: &[String],
    ) -> Result<BTreeMap<String, SubscriberRecord>, String> {
        if identities.is_empty() {
            return Ok(BTreeMap::new());
        }
        let requested =
            serde_json::to_string(identities).map_err(|_| "SUBSCRIBER_REQUEST_INVALID")?;
        let script = format!("const ids={requested};print(JSON.stringify(db.subscribers.find({{imsi:{{$in:ids}},\"polaris.owned\":true}}).toArray()))");
        let value = self.mongosh(script.as_bytes())?;
        let mut records = BTreeMap::new();
        for item in value
            .as_array()
            .ok_or("OPEN5GS_DATABASE_RESPONSE_INVALID")?
        {
            let record = self.decode_record(item)?;
            records.insert(record.imsi.clone(), record);
        }
        Ok(records)
    }

    fn provision_batch(
        &self,
        rows: Vec<(usize, SubscriberMutation)>,
    ) -> Result<Vec<ProvisionResult>, String> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        self.backup()?;
        let requested = rows.iter().map(|(row, input)| {
            let slot = slot_for(&input.imsi);
            json!({"row":row,"imsi":input.imsi,"k":input.k,"opc":input.opc,"sst":input.sst,"sd":input.sd,"dnns":input.dnns,"ambr":input.ambr,"slot":slot})
        }).collect::<Vec<_>>();
        let payload =
            serde_json::to_string(&requested).map_err(|_| "SUBSCRIBER_REQUEST_INVALID")?;
        let mcc = serde_json::to_string(&self.plmn_mcc).unwrap();
        let mnc = serde_json::to_string(&self.plmn_mnc).unwrap();
        let script = format!(
            r#"
const requested={payload}; const mcc={mcc}; const mnc={mnc}; const results=[];
const template=db.subscribers.findOne({{}},{{mme_realm:1}});
const mmeRealm=template&&typeof template.mme_realm==="string"?template.mme_realm:"";
for (const x of requested) {{
  const existing=db.subscribers.findOne({{imsi:x.imsi}});
  if (existing) {{ results.push({{row:x.row,ok:false,error:existing.polaris&&existing.polaris.owned===true?"SUBSCRIBER_ALREADY_EXISTS":"SUBSCRIBER_NOT_POLARIS_OWNED"}}); continue; }}
  const dl=NumberLong(String(x.ambr.downlink)); const ul=NumberLong(String(x.ambr.uplink));
  const sessions=x.dnns.map(name=>({{name,type:NumberInt(3),qos:{{index:NumberInt(9),arp:{{priority_level:NumberInt(8),pre_emption_capability:NumberInt(1),pre_emption_vulnerability:NumberInt(2)}}}},ambr:{{downlink:{{value:dl,unit:NumberInt(0)}},uplink:{{value:ul,unit:NumberInt(0)}}}},pcc_rule:[],_id:new ObjectId()}}));
  const doc={{schema_version:NumberInt(1),imsi:x.imsi,msisdn:[],imeisv:[],mme_host:[],mm_realm:[],mme_realm:mmeRealm,mme_timestamp:NumberLong(0),purge_flag:[],slice:[{{sst:NumberInt(x.sst),sd:x.sd,default_indicator:true,session:sessions,_id:new ObjectId()}}],security:{{k:x.k,op:null,opc:x.opc,amf:"8000"}},ambr:{{downlink:{{value:dl,unit:NumberInt(0)}},uplink:{{value:ul,unit:NumberInt(0)}}}},access_restriction_data:NumberInt(32),network_access_mode:NumberInt(0),subscriber_status:NumberInt(0),operator_determined_barring:NumberInt(0),subscribed_rau_tau_timer:NumberInt(12),polaris:{{owned:true,slot:x.slot,plmn_mcc:mcc,plmn_mnc:mnc}},__v:NumberInt(0)}};
  try {{ db.subscribers.insertOne(doc); results.push({{row:x.row,ok:true,slot:x.slot}}); }} catch (_) {{ results.push({{row:x.row,ok:false,error:"SUBSCRIBER_WRITE_FAILED"}}); }}
}}
print(JSON.stringify(results));
"#
        );
        let value = self.mongosh(script.as_bytes())?;
        serde_json::from_value(value).map_err(|_| "OPEN5GS_DATABASE_RESPONSE_INVALID".into())
    }

    fn fetch_slot(&self, slot: &str) -> Result<Option<SanitizedSubscriber>, String> {
        let slot_json = serde_json::to_string(slot).map_err(|_| "SUBSCRIBER_REQUEST_INVALID")?;
        let script = format!(
            "const r=db.subscribers.findOne({{\"polaris.slot\":{slot_json},\"polaris.owned\":true}});print(JSON.stringify(r))"
        );
        let value = self.mongosh(script.as_bytes())?;
        if value.is_null() {
            return Ok(None);
        }
        self.decode_record(&value).map(|record| Some(sanitize(&record)))
    }

    fn apply_update(
        &self,
        slot: &str,
        update: SubscriberUpdate,
    ) -> Result<SanitizedSubscriber, String> {
        self.backup()?;
        let script = self.apply_update_script(slot, &update);
        let value = self.mongosh(&script)?;
        if value.is_null() {
            return Err("SUBSCRIBER_NOT_FOUND".into());
        }
        self.decode_record(&value).map(|record| sanitize(&record))
    }

    fn taken_imsis(&self) -> Result<BTreeSet<String>, String> {
        let value = self.mongosh(br#"print(JSON.stringify(db.subscribers.find({},{imsi:1,_id:0}).toArray()))"#)?;
        let array = value
            .as_array()
            .ok_or("OPEN5GS_DATABASE_RESPONSE_INVALID")?;
        let mut taken = BTreeSet::new();
        for item in array {
            if let Some(imsi) = item.get("imsi").and_then(Value::as_str) {
                taken.insert(imsi.to_string());
            }
        }
        Ok(taken)
    }
}

impl MongoSubscriberBackend {
    /// Build the mongosh script that applies `update` to the record identified
    /// by `slot`. The script emits real BSON types (`NumberLong` for AMBR
    /// values, `NumberInt` for the AMBR unit and for integer schema fields) by
    /// calling the mongosh constructors directly — it never injects EJSON
    /// literals like `{"$numberLong":"N"}`, which mongosh would store as a
    /// plain sub-document instead of a BSON long and which was the root cause
    /// of the 0.17.0+ AMBR data corruption that broke Open5GS UDM reads.
    fn apply_update_script(&self, slot: &str, update: &SubscriberUpdate) -> Vec<u8> {
        let slot_json = serde_json::to_string(slot).unwrap_or_else(|_| "\"\"".into());

        // Scalar / string field writes: emitted as `setFields["<path>"] = <expr>;`
        // where <expr> is a typed mongosh expression (NumberInt / quoted string).
        let mut scalar_sets: Vec<String> = Vec::new();
        if let Some(sst) = update.sst {
            scalar_sets.push(format!("setFields[\"slice.0.sst\"] = NumberInt({sst});"));
        }
        if let Some(sd) = &update.sd {
            match sd {
                Some(value) => {
                    let s = serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into());
                    scalar_sets.push(format!("setFields[\"slice.0.sd\"] = {s};"));
                }
                None => scalar_sets.push("setFields[\"slice.0.sd\"] = null;".into()),
            }
        }
        if let Some(k) = &update.k {
            let s = serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into());
            scalar_sets.push(format!("setFields[\"security.k\"] = {s};"));
        }
        if let Some(opc) = &update.opc {
            let s = serde_json::to_string(opc).unwrap_or_else(|_| "\"\"".into());
            scalar_sets.push(format!("setFields[\"security.opc\"] = {s};"));
        }
        let scalar_block = scalar_sets.join(" ");

        // AMBR + DNN carry typed sub-documents and need the fetch/merge path.
        let ambr_js = if let Some(ambr) = &update.ambr {
            format!(
                "{{dl: NumberLong(\"{}\"), ul: NumberLong(\"{}\")}}",
                ambr.downlink, ambr.uplink
            )
        } else {
            "null".into()
        };
        let dnns_js = if let Some(dnns) = &update.dnns {
            let items: Vec<String> = dnns
                .iter()
                .map(|name| serde_json::to_string(name).unwrap_or_else(|_| "\"\"".into()))
                .collect();
            format!("[{}]", items.join(", "))
        } else {
            "null".into()
        };

        let script = format!(
            r#"
const slotKey = {slot_json};
const current = db.subscribers.findOne({{"polaris.slot": slotKey, "polaris.owned": true}});
if (!current) {{ print("null"); }} else {{
  const nextAmbr = {ambr_js};
  const nextDnns = {dnns_js};
  const setFields = {{}};
  {scalar_block}
  function parseLong(v) {{
    if (v === null || v === undefined) return NumberLong("1000000000");
    if (typeof v === "object" && v !== null && v.$numberLong !== undefined) {{ return NumberLong(v.$numberLong); }}
    try {{ return NumberLong(String(v)); }} catch (_) {{ return NumberLong("1000000000"); }}
  }}
  function sessionAmbrOf(a) {{
    return {{
      downlink: {{ value: a.dl, unit: NumberInt(0) }},
      uplink:   {{ value: a.ul, unit: NumberInt(0) }}
    }};
  }}
  if (nextAmbr !== null) {{
    setFields["ambr.uplink.value"]   = nextAmbr.ul;
    setFields["ambr.uplink.unit"]    = NumberInt(0);
    setFields["ambr.downlink.value"] = nextAmbr.dl;
    setFields["ambr.downlink.unit"]  = NumberInt(0);
  }}
  const existingSessions = (current.slice && current.slice[0] && Array.isArray(current.slice[0].session))
    ? current.slice[0].session : [];
  if (nextDnns !== null) {{
    const fallbackAmbr = {{
      dl: parseLong(current.ambr && current.ambr.downlink && current.ambr.downlink.value),
      ul: parseLong(current.ambr && current.ambr.uplink   && current.ambr.uplink.value)
    }};
    const effectiveAmbr = nextAmbr !== null ? nextAmbr : fallbackAmbr;
    setFields["slice.0.session"] = nextDnns.map((name, i) => ({{
      name: name,
      type: NumberInt(3),
      qos: {{ index: NumberInt(9),
              arp: {{ priority_level: NumberInt(8),
                      pre_emption_capability: NumberInt(1),
                      pre_emption_vulnerability: NumberInt(2) }} }},
      ambr: sessionAmbrOf(effectiveAmbr),
      pcc_rule: [],
      _id: (existingSessions[i] && existingSessions[i]._id) ? existingSessions[i]._id : new ObjectId()
    }}));
  }} else if (nextAmbr !== null) {{
    setFields["slice.0.session"] = existingSessions.map(function(s) {{
      return Object.assign({{}}, s, {{ ambr: sessionAmbrOf(nextAmbr) }});
    }});
  }}
  if (Object.keys(setFields).length > 0) {{
    db.subscribers.updateOne({{"polaris.slot": slotKey, "polaris.owned": true}}, {{"$set": setFields}});
  }}
  print(JSON.stringify(db.subscribers.findOne({{"polaris.slot": slotKey, "polaris.owned": true}})));
}}
"#
        );
        script.into_bytes()
    }
}

#[derive(Clone, Default)]
pub struct MemorySubscriberBackend {
    records: Arc<Mutex<BTreeMap<String, SubscriberRecord>>>,
    backups: Arc<Mutex<usize>>,
}

impl MemorySubscriberBackend {
    #[cfg(test)]
    pub fn backup_count(&self) -> usize {
        *self.backups.lock().unwrap()
    }
}

impl SubscriberBackend for MemorySubscriberBackend {
    fn list(&self) -> Result<Vec<SanitizedSubscriber>, String> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .values()
            .map(sanitize)
            .collect())
    }
    fn lookup_many(
        &self,
        identities: &[String],
    ) -> Result<BTreeMap<String, SubscriberRecord>, String> {
        let records = self.records.lock().unwrap();
        Ok(identities
            .iter()
            .filter_map(|id| records.get(id).cloned().map(|r| (id.clone(), r)))
            .collect())
    }
    fn provision_batch(
        &self,
        rows: Vec<(usize, SubscriberMutation)>,
    ) -> Result<Vec<ProvisionResult>, String> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        *self.backups.lock().unwrap() += 1;
        let mut records = self.records.lock().unwrap();
        Ok(rows
            .into_iter()
            .map(|(row, input)| {
                if records.contains_key(&input.imsi) {
                    return ProvisionResult {
                        row,
                        ok: false,
                        slot: None,
                        error: Some("SUBSCRIBER_ALREADY_EXISTS".into()),
                    };
                }
                let record = record_from_mutation(input, "001", "01");
                let slot = record.slot.clone();
                records.insert(record.imsi.clone(), record);
                ProvisionResult {
                    row,
                    ok: true,
                    slot: Some(slot),
                    error: None,
                }
            })
            .collect())
    }
    fn fetch_slot(&self, slot: &str) -> Result<Option<SanitizedSubscriber>, String> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .values()
            .find(|record| record.slot == slot)
            .map(sanitize))
    }
    fn apply_update(
        &self,
        slot: &str,
        update: SubscriberUpdate,
    ) -> Result<SanitizedSubscriber, String> {
        *self.backups.lock().unwrap() += 1;
        let mut records = self.records.lock().unwrap();
        let imsi = records
            .iter()
            .find(|(_, record)| record.slot == slot)
            .map(|(imsi, _)| imsi.clone())
            .ok_or("SUBSCRIBER_NOT_FOUND")?;
        let record = records.get_mut(&imsi).expect("record exists");
        apply_update_in_place(record, update)?;
        Ok(sanitize(record))
    }
    fn taken_imsis(&self) -> Result<BTreeSet<String>, String> {
        Ok(self.records.lock().unwrap().keys().cloned().collect())
    }
}

pub fn validate_mutation(input: &SubscriberMutation) -> Result<(), String> {
    if input.imsi.len() != 15 || !input.imsi.chars().all(|c| c.is_ascii_digit()) {
        return Err("IMSI_INVALID".into());
    }
    if [input.k.as_str(), input.opc.as_str()]
        .iter()
        .any(|v| v.len() != 32 || !v.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("AUTHENTICATION_MATERIAL_INVALID".into());
    }
    if input.sst == 0
        || input
            .sd
            .as_ref()
            .is_some_and(|v| v.len() != 6 || !v.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err("SNSSAI_INVALID".into());
    }
    let dnns = input.dnns.iter().cloned().collect::<BTreeSet<_>>();
    if dnns.is_empty()
        || dnns.len() != input.dnns.len()
        || dnns
            .iter()
            .any(|d| !matches!(d.as_str(), "internet" | "ims"))
    {
        return Err("DNN_INVALID".into());
    }
    if input.ambr.uplink == 0 || input.ambr.downlink == 0 {
        return Err("AMBR_INVALID".into());
    }
    Ok(())
}

/// Accepts the two operator-facing IMSI forms while keeping the Open5GS
/// storage representation canonical (15 decimal digits, no SUPI prefix).
pub fn normalize_imsi(value: &str) -> Result<String, String> {
    let digits = value.strip_prefix("imsi-").unwrap_or(value);
    if digits.len() == 15 && digits.chars().all(|c| c.is_ascii_digit()) {
        Ok(digits.to_string())
    } else {
        Err("IMSI_INVALID".into())
    }
}

pub fn sanitize(record: &SubscriberRecord) -> SanitizedSubscriber {
    SanitizedSubscriber {
        slot: record.slot.clone(),
        state: "PROVISIONED".into(),
        plmn: SanitizedPlmn {
            mcc: record.plmn_mcc.clone(),
            mnc: record.plmn_mnc.clone(),
        },
        snssai: SanitizedSnssai {
            sst: record.sst,
            sd: record.sd.clone(),
        },
        dnns: record.dnns.clone(),
        ambr: record.ambr.clone(),
        subscriber_identity: "PROTECTED",
        authentication_material: "PROTECTED",
    }
}

fn record_from_mutation(input: SubscriberMutation, mcc: &str, mnc: &str) -> SubscriberRecord {
    SubscriberRecord {
        slot: slot_for(&input.imsi),
        imsi: input.imsi,
        k: input.k,
        opc: input.opc,
        plmn_mcc: mcc.into(),
        plmn_mnc: mnc.into(),
        sst: input.sst,
        sd: input.sd,
        dnns: input.dnns,
        ambr: input.ambr,
    }
}

fn validate_record(record: &SubscriberRecord) -> Result<(), String> {
    validate_mutation(&SubscriberMutation {
        imsi: record.imsi.clone(),
        k: record.k.clone(),
        opc: record.opc.clone(),
        sst: record.sst,
        sd: record.sd.clone(),
        dnns: record.dnns.clone(),
        ambr: record.ambr.clone(),
    })
}
fn validate_plmn(mcc: &str, mnc: &str) -> Result<(), String> {
    if mcc.len() == 3
        && matches!(mnc.len(), 2 | 3)
        && mcc.chars().chain(mnc.chars()).all(|c| c.is_ascii_digit())
    {
        Ok(())
    } else {
        Err("PLMN_INVALID".into())
    }
}
fn json_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| {
            value
                .get("$numberLong")
                .and_then(Value::as_str)
                .and_then(|number| number.parse().ok())
        })
        .or_else(|| {
            let high = value.get("high")?.as_i64()?;
            let low = value.get("low")?.as_i64()?;
            (high >= 0).then(|| ((high as u64) << 32) | u64::from(low as u32))
        })
}
fn slot_for(imsi: &str) -> String {
    let digest = format!("{:x}", Sha256::digest(imsi.as_bytes()));
    format!("SUB-{}", &digest[..12])
}
fn epoch_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
fn random_suffix() -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("{}-{}", epoch_millis(), std::process::id()).as_bytes())
    )[..12]
        .to_string()
}
/// Generate 16 cryptographically random bytes, hex-encoded (32 chars). Used
/// for both K and OPc when `POST /subscribers/generate` is called or when a
/// CSV row omits them. Returns `AUTHENTICATION_KEY_GENERATION_FAILED` if the
/// OS CSPRNG is unavailable, so the operator does not get a zero-filled key.
pub fn generate_authentication_key() -> Result<String, String> {
    let mut buffer = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut buffer)
        .map_err(|_| "AUTHENTICATION_KEY_GENERATION_FAILED".to_string())?;
    let mut out = String::with_capacity(32);
    for byte in buffer {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

/// Allocate `count` fresh IMSIs in the fixed MCC=001 / MNC=01 range by picking
/// the lowest MSIN values that are not already taken. MSIN digits 000000000 to
/// 999999999 → 10^9 possible IMSIs. Returns `SUBSCRIBER_IMSI_POOL_EXHAUSTED`
/// if fewer than `count` free slots remain.
pub fn allocate_next_imsis(taken: &BTreeSet<String>, count: usize) -> Result<Vec<String>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > GENERATE_MAX_COUNT {
        return Err("SUBSCRIBER_GENERATE_COUNT_INVALID".into());
    }
    const MAX_MSIN: u64 = 1_000_000_000; // 10 decimal digits
    let mut candidates = Vec::with_capacity(count);
    let mut msin = 0u64;
    while candidates.len() < count {
        if msin >= MAX_MSIN {
            return Err("SUBSCRIBER_IMSI_POOL_EXHAUSTED".into());
        }
        let imsi = format!("00101{msin:010}");
        if !taken.contains(&imsi) {
            candidates.push(imsi);
        }
        msin += 1;
    }
    Ok(candidates)
}

fn apply_update_in_place(
    record: &mut SubscriberRecord,
    update: SubscriberUpdate,
) -> Result<(), String> {
    if let Some(sst) = update.sst {
        record.sst = sst;
    }
    if let Some(sd) = update.sd {
        record.sd = sd;
    }
    if let Some(dnns) = update.dnns {
        record.dnns = dnns;
    }
    if let Some(ambr) = update.ambr {
        record.ambr = ambr;
    }
    if let Some(k) = update.k {
        record.k = k;
    }
    if let Some(opc) = update.opc {
        record.opc = opc;
    }
    validate_record(record)
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "SUBSCRIBER_BACKUP_FAILED")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "SUBSCRIBER_BACKUP_FAILED".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imsi_normalization_accepts_digits_and_supi_prefix_only() {
        assert_eq!(
            normalize_imsi("001010000000201").unwrap(),
            "001010000000201"
        );
        assert_eq!(
            normalize_imsi("imsi-001010000000201").unwrap(),
            "001010000000201"
        );
        assert_eq!(
            normalize_imsi("supi-001010000000201").unwrap_err(),
            "IMSI_INVALID"
        );
    }

    #[test]
    fn one_hundred_thousand_rows_validate_without_secret_serialization() {
        fn rss_kib() -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|document| {
                    document
                        .lines()
                        .find(|line| line.starts_with("VmRSS:"))
                        .and_then(|line| line.split_whitespace().nth(1))
                        .and_then(|value| value.parse().ok())
                })
                .unwrap_or(0)
        }
        let rss_before = rss_kib();
        let started = std::time::Instant::now();
        let rows = (0..MAX_BULK_ROWS)
            .map(|i| SubscriberMutation {
                imsi: format!("00101{i:010}"),
                k: "11".repeat(16),
                opc: "22".repeat(16),
                sst: 1,
                sd: Some("010203".into()),
                dnns: vec!["internet".into()],
                ambr: SubscriberAmbr {
                    uplink: 1_000_000,
                    downlink: 1_000_000,
                },
            })
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), MAX_BULK_ROWS);
        assert!(rows.iter().all(|r| validate_mutation(r).is_ok()));
        assert!(started.elapsed().as_secs() < 10);
        let sanitized = sanitize(&record_from_mutation(rows[0].clone(), "001", "01"));
        let json = serde_json::to_string(&sanitized).unwrap();
        assert!(!json.contains(&rows[0].imsi));
        assert!(!json.contains(&rows[0].k));
        assert!(!json.contains(&rows[0].opc));
        eprintln!(
            "BULK_100K_ELAPSED_MS={} RSS_DELTA_KIB={}",
            started.elapsed().as_millis(),
            rss_kib().saturating_sub(rss_before)
        );
    }
    #[test]
    fn backup_precedes_every_memory_write_batch() {
        let store = MemorySubscriberBackend::default();
        let row = SubscriberMutation {
            imsi: "001010000000001".into(),
            k: "11".repeat(16),
            opc: "22".repeat(16),
            sst: 1,
            sd: Some("010203".into()),
            dnns: vec!["internet".into()],
            ambr: SubscriberAmbr {
                uplink: 1,
                downlink: 1,
            },
        };
        assert_eq!(store.backup_count(), 0);
        assert!(store.provision_batch(vec![(1, row)]).unwrap()[0].ok);
        assert_eq!(store.backup_count(), 1);
    }

    #[test]
    fn generate_authentication_key_is_32_hex_chars_and_random() {
        let a = generate_authentication_key().expect("csprng ok");
        let b = generate_authentication_key().expect("csprng ok");
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "CSPRNG must not return identical keys back to back");
    }

    #[test]
    fn allocate_next_imsis_skips_taken_and_rejects_invalid_count() {
        let mut taken = BTreeSet::new();
        taken.insert("001010000000000".to_string());
        taken.insert("001010000000002".to_string());
        let next = allocate_next_imsis(&taken, 3).expect("ok");
        assert_eq!(
            next,
            vec![
                "001010000000001".to_string(),
                "001010000000003".to_string(),
                "001010000000004".to_string(),
            ]
        );
        assert_eq!(allocate_next_imsis(&taken, 0).unwrap(), Vec::<String>::new());
        assert_eq!(
            allocate_next_imsis(&taken, GENERATE_MAX_COUNT + 1)
                .unwrap_err(),
            "SUBSCRIBER_GENERATE_COUNT_INVALID"
        );
    }

    #[test]
    fn apply_update_updates_only_requested_fields_and_preserves_authentication_material() {
        let store = MemorySubscriberBackend::default();
        let mutation = SubscriberMutation {
            imsi: "001010000000005".into(),
            k: "aa".repeat(16),
            opc: "bb".repeat(16),
            sst: 1,
            sd: Some("010203".into()),
            dnns: vec!["internet".into()],
            ambr: SubscriberAmbr {
                uplink: 100,
                downlink: 200,
            },
        };
        let result = store
            .provision_batch(vec![(1, mutation)])
            .expect("provision");
        assert!(result[0].ok);
        let slot = result[0].slot.clone().unwrap();

        // Update only the slice/DNN/AMBR; K and OPc are left untouched.
        let update = SubscriberUpdate {
            sst: Some(2),
            sd: Some(Some("040506".into())),
            dnns: Some(vec!["ims".into()]),
            ambr: Some(SubscriberAmbr {
                uplink: 500,
                downlink: 600,
            }),
            k: None,
            opc: None,
        };
        let sanitized = store.apply_update(&slot, update).expect("update");
        assert_eq!(sanitized.slot, slot);
        assert_eq!(sanitized.snssai.sst, 2);
        assert_eq!(sanitized.snssai.sd.as_deref(), Some("040506"));
        assert_eq!(sanitized.dnns, vec!["ims".to_string()]);
        assert_eq!(sanitized.ambr.uplink, 500);
        assert_eq!(sanitized.ambr.downlink, 600);
        assert_eq!(sanitized.subscriber_identity, "PROTECTED");
        assert_eq!(sanitized.authentication_material, "PROTECTED");

        // Confidentiality: the JSON representation must never contain the IMSI
        // or the stored K/OPc values.
        let json = serde_json::to_string(&sanitized).unwrap();
        assert!(!json.contains("001010000000005"));
        assert!(!json.contains(&"aa".repeat(16)));
        assert!(!json.contains(&"bb".repeat(16)));
    }

    #[test]
    fn apply_update_can_rewrite_authentication_material() {
        let store = MemorySubscriberBackend::default();
        let mutation = SubscriberMutation {
            imsi: "001010000000006".into(),
            k: "11".repeat(16),
            opc: "22".repeat(16),
            sst: 1,
            sd: None,
            dnns: vec!["internet".into()],
            ambr: SubscriberAmbr {
                uplink: 1,
                downlink: 1,
            },
        };
        let slot = store
            .provision_batch(vec![(1, mutation)])
            .unwrap()
            .remove(0)
            .slot
            .unwrap();
        let update = SubscriberUpdate {
            k: Some("ff".repeat(16)),
            opc: Some("ee".repeat(16)),
            ..SubscriberUpdate::default()
        };
        let sanitized = store.apply_update(&slot, update).expect("update");
        assert_eq!(sanitized.authentication_material, "PROTECTED");
        let lookup = store
            .lookup_many(&["001010000000006".into()])
            .expect("lookup");
        let record = &lookup["001010000000006"];
        assert_eq!(record.k, "ff".repeat(16));
        assert_eq!(record.opc, "ee".repeat(16));
    }

    #[test]
    fn apply_update_on_unknown_slot_fails_closed() {
        let store = MemorySubscriberBackend::default();
        match store.apply_update("SUB-missing", SubscriberUpdate::default()) {
            Ok(_) => panic!("missing slot must not resolve"),
            Err(error) => assert_eq!(error, "SUBSCRIBER_NOT_FOUND"),
        }
    }

    #[test]
    fn fetch_slot_returns_sanitized_record() {
        let store = MemorySubscriberBackend::default();
        let imsi = "001010000000007";
        let slot = store
            .provision_batch(vec![(
                1,
                SubscriberMutation {
                    imsi: imsi.into(),
                    k: "33".repeat(16),
                    opc: "44".repeat(16),
                    sst: 1,
                    sd: Some("010203".into()),
                    dnns: vec!["internet".into()],
                    ambr: SubscriberAmbr {
                        uplink: 1,
                        downlink: 1,
                    },
                },
            )])
            .unwrap()
            .remove(0)
            .slot
            .unwrap();
        let fetched = store.fetch_slot(&slot).unwrap().expect("slot present");
        assert_eq!(fetched.slot, slot);
        assert_eq!(fetched.state, "PROVISIONED");
        assert_eq!(fetched.subscriber_identity, "PROTECTED");
        assert_eq!(fetched.authentication_material, "PROTECTED");
        let json = serde_json::to_string(&fetched).unwrap();
        assert!(!json.contains(imsi));
        assert!(!json.contains(&"33".repeat(16)));
        assert!(!json.contains(&"44".repeat(16)));
        assert!(store.fetch_slot("SUB-missing").unwrap().is_none());
    }

    #[test]
    fn taken_imsis_includes_every_provisioned_record() {
        let store = MemorySubscriberBackend::default();
        for i in 0..5 {
            store
                .provision_batch(vec![(
                    i,
                    SubscriberMutation {
                        imsi: format!("00101{:010}", 100 + i),
                        k: "55".repeat(16),
                        opc: "66".repeat(16),
                        sst: 1,
                        sd: None,
                        dnns: vec!["internet".into()],
                        ambr: SubscriberAmbr {
                            uplink: 1,
                            downlink: 1,
                        },
                    },
                )])
                .unwrap();
        }
        let taken = store.taken_imsis().unwrap();
        assert_eq!(taken.len(), 5);
        for i in 0..5 {
            assert!(taken.contains(&format!("00101{:010}", 100 + i)));
        }
    }

    #[test]
    fn mongo_long_json_forms_decode_without_precision_loss() {
        assert_eq!(json_u64(&json!(42)), Some(42));
        assert_eq!(
            json_u64(&json!({"$numberLong":"4294967297"})),
            Some(4_294_967_297)
        );
        assert_eq!(
            json_u64(&json!({"high":1,"low":1,"unsigned":false})),
            Some(4_294_967_297)
        );
        assert_eq!(json_u64(&json!({"high":-1,"low":1,"unsigned":false})), None);
    }

    /// 0.17.8 (#39) — regression lock: `apply_update_script` MUST emit real
    /// mongosh `NumberLong(...)` / `NumberInt(...)` constructor calls, never
    /// EJSON literals such as `{"$numberLong":"N"}`. The latter is parsed by
    /// mongosh as a plain JS object and stored by MongoDB as a sub-document,
    /// which was the root cause of the UDR "No UE-AMBR" / AMF HTTP 400
    /// `am-data` incident reported against 0.17.0+.
    #[test]
    fn apply_update_script_never_emits_ejson_literals_for_ambr() {
        let backend = MongoSubscriberBackend {
            container: "unused".into(),
            backup_root: PathBuf::from("/tmp/unused"),
            plmn_mcc: "001".into(),
            plmn_mnc: "01".into(),
        };
        let update = SubscriberUpdate {
            ambr: Some(SubscriberAmbr {
                uplink: 500_000_000,
                downlink: 1_500_000_000,
            }),
            dnns: Some(vec!["internet".into(), "ims".into()]),
            sst: Some(1),
            sd: Some(Some("010203".into())),
            k: None,
            opc: None,
        };
        let script = backend.apply_update_script("SUB-regression", &update);
        let script = std::str::from_utf8(&script).expect("script is utf-8");
        // The EJSON injection form that corrupted documents in 0.17.0+ must be
        // completely absent from the emitted script — both the raw key and the
        // dollar-escaped mongosh key.
        assert!(
            !script.contains("$numberLong\":\""),
            "apply_update_script re-emits EJSON literals for AMBR: {script}"
        );
        // The typed mongosh constructor calls MUST appear for both AMBR legs.
        assert!(
            script.contains("NumberLong(\"500000000\")"),
            "uplink AMBR missing NumberLong constructor: {script}"
        );
        assert!(
            script.contains("NumberLong(\"1500000000\")"),
            "downlink AMBR missing NumberLong constructor: {script}"
        );
        // AMBR unit must be a BSON int32.
        assert!(
            script.contains("NumberInt(0)"),
            "ambr.unit missing NumberInt(0): {script}"
        );
        // Session rebuild (DNN change) must carry typed qos.index + arp fields,
        // not strip them (the old `$set` duplicate-key form silently did).
        assert!(
            script.contains("index: NumberInt(9)"),
            "session qos.index not typed as NumberInt: {script}"
        );
        assert!(
            script.contains("priority_level: NumberInt(8)"),
            "session qos.arp.priority_level not typed as NumberInt: {script}"
        );
        // The duplicate `$set` key bug (two `$set` keys in the updateOne
        // argument object, where the second silently clobbered the first) must
        // not reappear — the script now constructs a single `setFields`.
        let update_calls = script.matches("db.subscribers.updateOne").count();
        assert_eq!(update_calls, 1, "expected a single updateOne call: {script}");
    }

    /// 0.17.8 (#39) — mandatory MongoDB integration test. Gated by
    /// `POLARIS_TEST_MONGODB_CONTAINER` (NOT `#[ignore]`): when the env var is
    /// set, the test MUST pass; when unset the test skips with a loud
    /// `SKIPPED_NO_MONGO` marker so an operator can grep for it in CI logs.
    /// Validates that a `PUT /subscribers/:slot` AMBR write produces real BSON
    /// numeric types (`$type = "long"` for value, `"int"` for unit) at every
    /// Open5GS schema path (`ambr.{dl,ul}.{value,unit}`, `slice.0.session.*
    /// .ambr.{dl,ul}.{value,unit}`), not literal `{$numberLong}` sub-documents.
    #[test]
    fn ambr_put_writes_real_bson_long_in_live_mongo() {
        let container = match std::env::var("POLARIS_TEST_MONGODB_CONTAINER") {
            Ok(c) if !c.is_empty() => c,
            _ => {
                eprintln!("SKIPPED_NO_MONGO: POLARIS_TEST_MONGODB_CONTAINER unset");
                return;
            }
        };
        std::env::set_var("POLARIS_OPEN5GS_MONGODB_CONTAINER", &container);
        let root = std::env::temp_dir().join(format!(
            "polaris-ambr-bson-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        std::env::set_var("POLARIS_SUBSCRIBER_BACKUP_ROOT", &root);
        let backend = MongoSubscriberBackend::from_env().expect("from_env");

        // Pick a reserved IMSI slot deterministically keyed on the test name
        // so repeat runs stay isolated from other POLARIS tests.
        let imsi = "001019999999978".to_string();
        let slot = slot_for(&imsi);
        // Scrub prior residue from a previous (possibly aborted) run.
        let cleanup = format!(
            "db.subscribers.deleteMany({{imsi: {}}})",
            serde_json::to_string(&imsi).unwrap()
        );
        let _ = backend.mongosh(cleanup.as_bytes());

        let mutation = SubscriberMutation {
            imsi: imsi.clone(),
            k: "aa".repeat(16),
            opc: "bb".repeat(16),
            sst: 1,
            sd: Some("010203".into()),
            dnns: vec!["internet".into()],
            ambr: SubscriberAmbr {
                uplink: 1_000_000,
                downlink: 2_000_000,
            },
        };
        let provision = backend
            .provision_batch(vec![(0, mutation)])
            .expect("provision_batch");
        assert!(provision[0].ok, "provision failed: {:?}", provision[0].error);

        let update = SubscriberUpdate {
            ambr: Some(SubscriberAmbr {
                uplink: 500_000_000,
                downlink: 1_500_000_000,
            }),
            ..SubscriberUpdate::default()
        };
        let after = backend
            .apply_update(&slot, update)
            .expect("apply_update must succeed on a provisioned slot");
        assert_eq!(after.slot, slot);
        assert_eq!(after.ambr.uplink, 500_000_000);
        assert_eq!(after.ambr.downlink, 1_500_000_000);

        // Authoritative BSON-type probe via `$type` aggregation. Returns a
        // single-row document whose fields are the per-path BSON type names
        // ("long", "int", "double", "object", ...).
        let probe = format!(
            r#"
const r = db.subscribers.aggregate([
  {{"$match": {{"polaris.slot": {slot_json}, "polaris.owned": true}}}},
  {{"$project": {{
    "_id": 0,
    "ambr_dl_value": {{"$type": "$ambr.downlink.value"}},
    "ambr_dl_unit":  {{"$type": "$ambr.downlink.unit"}},
    "ambr_ul_value": {{"$type": "$ambr.uplink.value"}},
    "ambr_ul_unit":  {{"$type": "$ambr.uplink.unit"}},
    "s0_dl_value":   {{"$type": {{"$arrayElemAt": ["$slice.session.ambr.downlink.value", 0]}}}},
    "s0_dl_unit":    {{"$type": {{"$arrayElemAt": ["$slice.session.ambr.downlink.unit",  0]}}}},
    "s0_ul_value":   {{"$type": {{"$arrayElemAt": ["$slice.session.ambr.uplink.value",   0]}}}},
    "s0_ul_unit":    {{"$type": {{"$arrayElemAt": ["$slice.session.ambr.uplink.unit",    0]}}}},
    "ambr_dl_value_num": "$ambr.downlink.value",
    "ambr_ul_value_num": "$ambr.uplink.value",
    "s0_dl_value_num":   {{"$arrayElemAt": ["$slice.session.ambr.downlink.value", 0]}},
    "s0_ul_value_num":   {{"$arrayElemAt": ["$slice.session.ambr.uplink.value",   0]}}
  }}}}
]).toArray();
print(JSON.stringify(r[0] || null));
"#,
            slot_json = serde_json::to_string(&slot).unwrap()
        );
        let probe_value = backend
            .mongosh(probe.as_bytes())
            .expect("mongosh $type probe");
        eprintln!("BSON_TYPES={probe_value}");

        for key in [
            "ambr_dl_value",
            "ambr_ul_value",
            "s0_dl_value",
            "s0_ul_value",
        ] {
            let actual = probe_value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("probe missing {key}: {probe_value}"));
            assert!(
                matches!(actual, "long" | "int"),
                "{key} must be BSON int/long (Open5GS UDR requirement); was {actual}: {probe_value}"
            );
        }
        for key in [
            "ambr_dl_unit",
            "ambr_ul_unit",
            "s0_dl_unit",
            "s0_ul_unit",
        ] {
            let actual = probe_value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("probe missing {key}: {probe_value}"));
            assert!(
                matches!(actual, "int" | "long"),
                "{key} must be BSON int/long; was {actual}: {probe_value}"
            );
        }
        // The value fields must round-trip exactly — not just happen to parse —
        // so we also compare the numeric payload the aggregation extracted.
        assert_eq!(
            json_u64(&probe_value["ambr_dl_value_num"]),
            Some(1_500_000_000)
        );
        assert_eq!(
            json_u64(&probe_value["ambr_ul_value_num"]),
            Some(500_000_000)
        );
        assert_eq!(
            json_u64(&probe_value["s0_dl_value_num"]),
            Some(1_500_000_000)
        );
        assert_eq!(
            json_u64(&probe_value["s0_ul_value_num"]),
            Some(500_000_000)
        );

        // Clean up so repeat runs stay deterministic.
        let _ = backend.mongosh(cleanup.as_bytes());
        let _ = fs::remove_dir_all(&root);
    }
}
