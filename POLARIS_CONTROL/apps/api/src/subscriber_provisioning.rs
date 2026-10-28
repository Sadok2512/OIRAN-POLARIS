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
  const sessions=x.dnns.map(name=>({{name,type:NumberInt(3),qos:{{index:NumberInt(9),arp:{{priority_level:NumberInt(8),pre_emption_capability:NumberInt(1),pre_emption_vulnerability:NumberInt(2)}}}},ambr:{{downlink:{{value:NumberLong(x.ambr.downlink),unit:NumberInt(0)}},uplink:{{value:NumberLong(x.ambr.uplink),unit:NumberInt(0)}}}},pcc_rule:[],_id:new ObjectId()}}));
  const doc={{schema_version:NumberInt(1),imsi:x.imsi,msisdn:[],imeisv:[],mme_host:[],mm_realm:[],mme_realm:mmeRealm,mme_timestamp:NumberLong(0),purge_flag:[],slice:[{{sst:NumberInt(x.sst),sd:x.sd,default_indicator:true,session:sessions,_id:new ObjectId()}}],security:{{k:x.k,op:null,opc:x.opc,amf:"8000"}},ambr:{{downlink:{{value:NumberLong(x.ambr.downlink),unit:NumberInt(0)}},uplink:{{value:NumberLong(x.ambr.uplink),unit:NumberInt(0)}}}},access_restriction_data:NumberInt(32),network_access_mode:NumberInt(0),subscriber_status:NumberInt(0),operator_determined_barring:NumberInt(0),subscribed_rau_tau_timer:NumberInt(12),polaris:{{owned:true,slot:x.slot,plmn_mcc:mcc,plmn_mnc:mnc}},__v:NumberInt(0)}};
  try {{ db.subscribers.insertOne(doc); results.push({{row:x.row,ok:true,slot:x.slot}}); }} catch (_) {{ results.push({{row:x.row,ok:false,error:"SUBSCRIBER_WRITE_FAILED"}}); }}
}}
print(JSON.stringify(results));
"#
        );
        let value = self.mongosh(script.as_bytes())?;
        serde_json::from_value(value).map_err(|_| "OPEN5GS_DATABASE_RESPONSE_INVALID".into())
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
}
