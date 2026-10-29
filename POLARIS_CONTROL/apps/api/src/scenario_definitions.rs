use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u8 = 1;
pub const MAX_STEPS: usize = 256;
pub const MAX_LOOP_COUNT: u32 = 10_000;
pub const MAX_RESOLVED_STEPS: usize = 10_000;
pub const MAX_REPEAT_DEPTH: usize = 2;
pub const MAX_TRAFFIC_BYTES: u64 = 200 * 1024 * 1024;
pub const EXPORT_SCHEMA_VERSION: &str = "polaris.scenario-definition.v2";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScenarioCatalog {
    pub schema_version: u8,
    pub definitions: Vec<ScenarioDefinition>,
}

impl Default for ScenarioCatalog {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            definitions: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScenarioDefinition {
    pub id: String,
    pub name: String,
    pub version: u64,
    #[serde(default = "default_loop_count")]
    pub loop_count: u32,
    pub steps: Vec<ScenarioStep>,
    pub created_at_epoch_s: u64,
    pub updated_at_epoch_s: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScenarioMutation {
    pub id: String,
    pub name: String,
    #[serde(default = "default_loop_count")]
    pub loop_count: u32,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScenarioStep {
    #[serde(rename = "type")]
    pub step_type: String,
    #[serde(default = "default_loop_count")]
    pub loop_count: u32,
    #[serde(default)]
    pub parameters: BTreeMap<String, ParameterSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<ScenarioStep>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ParameterSpec {
    Fixed { fixed: Value },
    Random { random: RandomRange },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RandomRange {
    pub min: i64,
    pub max: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ResolvedStep {
    pub index: usize,
    #[serde(rename = "type")]
    pub step_type: String,
    pub scenario_loop_iteration: u32,
    pub scenario_loop_count: u32,
    pub step_loop_iteration: u32,
    pub step_loop_count: u32,
    pub parameters: BTreeMap<String, Value>,
}

#[derive(Clone)]
pub struct ScenarioDefinitionStore {
    path: PathBuf,
}

impl ScenarioDefinitionStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load(&self) -> Result<ScenarioCatalog, String> {
        let mut catalog = match fs::read(&self.path) {
            Ok(bytes) => {
                // 0.15.2 — Same portable-permissions pattern as the UE
                // profile registry: enforce uid=0 in release builds,
                // tolerate the current process owner under `cfg(test)`,
                // never relax the group/world write bits.
                #[cfg(all(unix, not(test)))]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    let metadata = fs::symlink_metadata(&self.path)
                        .map_err(|_| "SCENARIO_CATALOG_UNREADABLE")?;
                    if !metadata.file_type().is_file()
                        || metadata.uid() != 0
                        || metadata.permissions().mode() & 0o077 != 0
                    {
                        return Err("SCENARIO_CATALOG_PERMISSIONS_UNSAFE".into());
                    }
                }
                #[cfg(all(unix, test))]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    let metadata = fs::symlink_metadata(&self.path)
                        .map_err(|_| "SCENARIO_CATALOG_UNREADABLE")?;
                    if !metadata.file_type().is_file()
                        || metadata.permissions().mode() & 0o022 != 0
                    {
                        return Err("SCENARIO_CATALOG_PERMISSIONS_UNSAFE".into());
                    }
                    let _ = metadata.uid();
                }
                let catalog: ScenarioCatalog = serde_json::from_slice(&bytes)
                    .map_err(|_| "SCENARIO_CATALOG_INVALID".to_string())?;
                validate_catalog(&catalog)?;
                catalog
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ScenarioCatalog::default()
            }
            Err(_) => return Err("SCENARIO_CATALOG_UNREADABLE".into()),
        };
        let changed = seed_templates(&mut catalog)?;
        if changed {
            self.persist(&catalog)?;
        }
        Ok(catalog)
    }

    pub fn persist(&self, catalog: &ScenarioCatalog) -> Result<(), String> {
        validate_catalog(catalog)?;
        atomic_private_write(
            &self.path,
            &serde_json::to_vec_pretty(catalog)
                .map_err(|_| "SCENARIO_CATALOG_INVALID".to_string())?,
        )
    }

    pub fn create(
        &self,
        catalog: &mut ScenarioCatalog,
        input: ScenarioMutation,
    ) -> Result<ScenarioDefinition, String> {
        validate_mutation(&input)?;
        if template_id(&input.id) {
            return Err("TEMPLATE_ID_RESERVED".into());
        }
        if catalog.definitions.iter().any(|item| item.id == input.id) {
            return Err("SCENARIO_DEFINITION_ALREADY_EXISTS".into());
        }
        let now = epoch_seconds();
        let definition = ScenarioDefinition {
            id: input.id,
            name: input.name,
            version: 1,
            loop_count: input.loop_count,
            steps: input.steps,
            created_at_epoch_s: now,
            updated_at_epoch_s: now,
        };
        let original = catalog.clone();
        catalog.definitions.push(definition.clone());
        if let Err(error) = self.persist(catalog) {
            *catalog = original;
            return Err(error);
        }
        Ok(definition)
    }

    pub fn update(
        &self,
        catalog: &mut ScenarioCatalog,
        id: &str,
        input: ScenarioMutation,
    ) -> Result<ScenarioDefinition, String> {
        if input.id != id {
            return Err("SCENARIO_ID_IMMUTABLE".into());
        }
        if template_id(id) {
            return Err("SCENARIO_TEMPLATE_READ_ONLY".into());
        }
        validate_mutation(&input)?;
        let index = catalog
            .definitions
            .iter()
            .position(|item| item.id == id)
            .ok_or("SCENARIO_DEFINITION_NOT_FOUND")?;
        let original = catalog.clone();
        let previous = &original.definitions[index];
        let updated = ScenarioDefinition {
            id: input.id,
            name: input.name,
            version: previous.version.saturating_add(1),
            loop_count: input.loop_count,
            steps: input.steps,
            created_at_epoch_s: previous.created_at_epoch_s,
            updated_at_epoch_s: epoch_seconds(),
        };
        catalog.definitions[index] = updated.clone();
        if let Err(error) = self.persist(catalog) {
            *catalog = original;
            return Err(error);
        }
        Ok(updated)
    }

    pub fn delete(
        &self,
        catalog: &mut ScenarioCatalog,
        id: &str,
    ) -> Result<ScenarioDefinition, String> {
        if template_id(id) {
            return Err("SCENARIO_TEMPLATE_READ_ONLY".into());
        }
        let index = catalog
            .definitions
            .iter()
            .position(|item| item.id == id)
            .ok_or("SCENARIO_DEFINITION_NOT_FOUND")?;
        let original = catalog.clone();
        let deleted = catalog.definitions.remove(index);
        if let Err(error) = self.persist(catalog) {
            *catalog = original;
            return Err(error);
        }
        Ok(deleted)
    }

    pub fn clone_definition(
        &self,
        catalog: &mut ScenarioCatalog,
        source_id: &str,
        target_id: &str,
    ) -> Result<ScenarioDefinition, String> {
        let source = catalog
            .definitions
            .iter()
            .find(|item| item.id == source_id)
            .cloned()
            .ok_or("SCENARIO_DEFINITION_NOT_FOUND")?;
        self.create(
            catalog,
            ScenarioMutation {
                id: target_id.into(),
                name: format!("{} (clone)", source.name),
                loop_count: source.loop_count,
                steps: source.steps,
            },
        )
    }
}

pub fn resolve_steps(definition: &ScenarioDefinition) -> Result<Vec<ResolvedStep>, String> {
    validate_definition(definition)?;
    let mut resolved = Vec::new();
    for scenario_iteration in 1..=definition.loop_count {
        resolve_step_list(
            &definition.steps,
            scenario_iteration,
            definition.loop_count,
            &mut resolved,
        )?;
    }
    Ok(resolved)
}

fn resolve_step_list(
    steps: &[ScenarioStep],
    scenario_iteration: u32,
    scenario_count: u32,
    resolved: &mut Vec<ResolvedStep>,
) -> Result<(), String> {
    for step in steps {
        for step_iteration in 1..=step.loop_count {
            if step.step_type == "repeat" {
                resolve_step_list(&step.steps, scenario_iteration, scenario_count, resolved)?;
                continue;
            }
            let mut parameters = BTreeMap::new();
            for (name, value) in &step.parameters {
                let selected = match value {
                    ParameterSpec::Fixed { fixed } => fixed.clone(),
                    ParameterSpec::Random { random } => {
                        let span = random
                            .max
                            .checked_sub(random.min)
                            .and_then(|value| value.checked_add(1))
                            .ok_or("SCENARIO_RANDOM_RANGE_INVALID")?
                            as u64;
                        let mut bytes = [0_u8; 8];
                        OsRng.fill_bytes(&mut bytes);
                        Value::from(random.min + (u64::from_le_bytes(bytes) % span) as i64)
                    }
                };
                parameters.insert(name.clone(), selected);
            }
            resolved.push(ResolvedStep {
                index: resolved.len(),
                step_type: step.step_type.clone(),
                scenario_loop_iteration: scenario_iteration,
                scenario_loop_count: scenario_count,
                step_loop_iteration: step_iteration,
                step_loop_count: step.loop_count,
                parameters,
            });
        }
    }
    Ok(())
}

pub fn estimate_duration_ms(definition: &ScenarioDefinition) -> Result<u64, String> {
    resolve_steps(definition)?
        .iter()
        .try_fold(0_u64, |total, step| {
            let duration = match step.step_type.as_str() {
                "wait" | "idle" | "voice_call" => resolved_u64(step, "duration_ms", 0)?,
                _ => 0,
            };
            total
                .checked_add(duration)
                .ok_or_else(|| "SCENARIO_DURATION_OVERFLOW".into())
        })
}

fn resolved_u64(step: &ResolvedStep, name: &str, default: u64) -> Result<u64, String> {
    step.parameters
        .get(name)
        .map(|value| {
            value
                .as_u64()
                .ok_or("SCENARIO_PARAMETER_INVALID".to_string())
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn validate_catalog(catalog: &ScenarioCatalog) -> Result<(), String> {
    if catalog.schema_version != SCHEMA_VERSION {
        return Err("SCENARIO_CATALOG_VERSION_UNSUPPORTED".into());
    }
    let mut ids = BTreeSet::new();
    for definition in &catalog.definitions {
        if !ids.insert(definition.id.as_str()) {
            return Err("SCENARIO_DEFINITION_DUPLICATE".into());
        }
        validate_definition(definition)?;
    }
    Ok(())
}

fn validate_definition(definition: &ScenarioDefinition) -> Result<(), String> {
    validate_mutation(&ScenarioMutation {
        id: definition.id.clone(),
        name: definition.name.clone(),
        loop_count: definition.loop_count,
        steps: definition.steps.clone(),
    })
}

fn validate_mutation(input: &ScenarioMutation) -> Result<(), String> {
    if !safe_id(&input.id) || input.name.trim().is_empty() || input.name.len() > 128 {
        return Err("SCENARIO_DEFINITION_INVALID".into());
    }
    if input.steps.is_empty() || input.steps.len() > MAX_STEPS {
        return Err("SCENARIO_STEP_COUNT_INVALID".into());
    }
    if !(1..=MAX_LOOP_COUNT).contains(&input.loop_count) {
        return Err("SCENARIO_LOOP_COUNT_INVALID".into());
    }
    let resolved_step_count = validate_steps(&input.steps, 0)?
        .checked_mul(input.loop_count as usize)
        .ok_or("SCENARIO_RESOLVED_STEP_COUNT_INVALID")?;
    if resolved_step_count > MAX_RESOLVED_STEPS {
        return Err("SCENARIO_RESOLVED_STEP_COUNT_INVALID".into());
    }
    Ok(())
}

fn validate_steps(steps: &[ScenarioStep], depth: usize) -> Result<usize, String> {
    if steps.is_empty() || steps.len() > MAX_STEPS {
        return Err("SCENARIO_STEP_COUNT_INVALID".into());
    }
    let mut resolved = 0_usize;
    for step in steps {
        if !(1..=MAX_LOOP_COUNT).contains(&step.loop_count) {
            return Err("SCENARIO_LOOP_COUNT_INVALID".into());
        }
        let supported = matches!(
            step.step_type.as_str(),
            "ue_start"
                | "ue_stop"
                | "pdu_establish"
                | "pdu_release"
                | "udp_traffic"
                | "wait"
                | "traffic_dl"
                | "traffic_ul"
                | "idle"
                | "detach"
                | "repeat"
                | "ims_register"
                | "voice_call"
        );
        if !supported {
            return Err("SCENARIO_STEP_TYPE_UNSUPPORTED".into());
        }
        if step.step_type == "repeat" {
            if depth >= MAX_REPEAT_DEPTH || !step.parameters.is_empty() {
                return Err("SCENARIO_REPEAT_INVALID".into());
            }
            let nested = validate_steps(&step.steps, depth + 1)?;
            resolved = resolved
                .checked_add(
                    nested
                        .checked_mul(step.loop_count as usize)
                        .ok_or("SCENARIO_RESOLVED_STEP_COUNT_INVALID")?,
                )
                .ok_or("SCENARIO_RESOLVED_STEP_COUNT_INVALID")?;
        } else {
            if !step.steps.is_empty() {
                return Err("SCENARIO_REPEAT_INVALID".into());
            }
            validate_parameters(step)?;
            resolved = resolved
                .checked_add(step.loop_count as usize)
                .ok_or("SCENARIO_RESOLVED_STEP_COUNT_INVALID")?;
        }
        if resolved > MAX_RESOLVED_STEPS {
            return Err("SCENARIO_RESOLVED_STEP_COUNT_INVALID".into());
        }
    }
    Ok(resolved)
}

fn validate_parameters(step: &ScenarioStep) -> Result<(), String> {
    for (name, value) in &step.parameters {
        if !safe_id(name) {
            return Err("SCENARIO_PARAMETER_INVALID".into());
        }
        match value {
            ParameterSpec::Fixed { .. } => {}
            ParameterSpec::Random { random } if random.min <= random.max => {}
            ParameterSpec::Random { .. } => return Err("SCENARIO_RANDOM_RANGE_INVALID".into()),
        }
    }
    if matches!(step.step_type.as_str(), "traffic_dl" | "traffic_ul") {
        let bytes = parameter_max_u64(step, "bytes")?;
        if bytes == 0 || bytes > MAX_TRAFFIC_BYTES {
            return Err("TRAFFIC_BYTES_OUT_OF_RANGE".into());
        }
    }
    if matches!(step.step_type.as_str(), "idle" | "voice_call") {
        parameter_max_u64(step, "duration_ms")?;
    }
    Ok(())
}

fn parameter_max_u64(step: &ScenarioStep, name: &str) -> Result<u64, String> {
    match step
        .parameters
        .get(name)
        .ok_or("SCENARIO_PARAMETER_REQUIRED")?
    {
        ParameterSpec::Fixed { fixed } => fixed
            .as_u64()
            .ok_or_else(|| "SCENARIO_PARAMETER_INVALID".into()),
        ParameterSpec::Random { random } if random.min >= 0 => Ok(random.max as u64),
        ParameterSpec::Random { .. } => Err("SCENARIO_PARAMETER_INVALID".into()),
    }
}

fn template_id(id: &str) -> bool {
    id.starts_with("tpl-")
}

fn fixed(value: impl Into<Value>) -> ParameterSpec {
    ParameterSpec::Fixed {
        fixed: value.into(),
    }
}
fn step(kind: &str, parameters: BTreeMap<String, ParameterSpec>) -> ScenarioStep {
    ScenarioStep {
        step_type: kind.into(),
        loop_count: 1,
        parameters,
        steps: Vec::new(),
    }
}
fn repeat(loop_count: u32, steps: Vec<ScenarioStep>) -> ScenarioStep {
    ScenarioStep {
        step_type: "repeat".into(),
        loop_count,
        parameters: BTreeMap::new(),
        steps,
    }
}

pub fn builtin_templates() -> Vec<ScenarioDefinition> {
    let now = 0;
    let p = |pairs: &[(&str, u64)]| {
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), fixed(*v)))
            .collect()
    };
    let dnn = |name: &str| BTreeMap::from([("dnn".into(), fixed(name))]);
    vec![
        ScenarioDefinition {
            id: "tpl-voice-long".into(),
            name: "Voice long ×100".into(),
            version: 1,
            loop_count: 100,
            steps: vec![
                step("ue_start", BTreeMap::new()),
                step("pdu_establish", dnn("ims")),
                step("ims_register", BTreeMap::new()),
                step("voice_call", p(&[("duration_ms", 600_000)])),
                step("wait", p(&[("duration_ms", 60_000)])),
                step("idle", p(&[("duration_ms", 60_000)])),
                step("ue_stop", BTreeMap::new()),
            ],
            created_at_epoch_s: now,
            updated_at_epoch_s: now,
        },
        ScenarioDefinition {
            id: "tpl-voice-short".into(),
            name: "Voice short".into(),
            version: 1,
            loop_count: 1,
            steps: vec![
                step("ue_start", BTreeMap::new()),
                step("pdu_establish", dnn("ims")),
                step("ims_register", BTreeMap::new()),
                repeat(
                    50,
                    vec![
                        step("voice_call", p(&[("duration_ms", 60_000)])),
                        step("idle", p(&[("duration_ms", 20_000)])),
                    ],
                ),
                step("detach", BTreeMap::new()),
            ],
            created_at_epoch_s: now,
            updated_at_epoch_s: now,
        },
        ScenarioDefinition {
            id: "tpl-small-traffic".into(),
            name: "Small traffic".into(),
            version: 1,
            loop_count: 1,
            steps: vec![
                step("ue_start", BTreeMap::new()),
                step("pdu_establish", dnn("internet")),
                repeat(
                    10,
                    vec![
                        step("traffic_dl", p(&[("bytes", 10 * 1024 * 1024)])),
                        step("wait", p(&[("duration_ms", 20_000)])),
                        step("traffic_ul", p(&[("bytes", 1024 * 1024)])),
                        step("idle", p(&[("duration_ms", 20_000)])),
                    ],
                ),
                step("detach", BTreeMap::new()),
            ],
            created_at_epoch_s: now,
            updated_at_epoch_s: now,
        },
        ScenarioDefinition {
            id: "tpl-high-runner".into(),
            name: "High runner".into(),
            version: 1,
            loop_count: 1,
            steps: vec![
                step("ue_start", BTreeMap::new()),
                step("pdu_establish", dnn("internet")),
                step("traffic_dl", p(&[("bytes", 100 * 1024 * 1024)])),
                step("traffic_ul", p(&[("bytes", 1_310_720)])),
                step("idle", p(&[("duration_ms", 20_000)])),
                step("detach", BTreeMap::new()),
            ],
            created_at_epoch_s: now,
            updated_at_epoch_s: now,
        },
    ]
}

fn seed_templates(catalog: &mut ScenarioCatalog) -> Result<bool, String> {
    let mut changed = false;
    for template in builtin_templates() {
        if !catalog
            .definitions
            .iter()
            .any(|item| item.id == template.id)
        {
            validate_definition(&template)?;
            catalog.definitions.push(template);
            changed = true;
        }
    }
    Ok(changed)
}

const fn default_loop_count() -> u32 {
    1
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "SCENARIO_CATALOG_UNWRITABLE")?;
    }
    let temporary = path.with_extension("json.tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| "SCENARIO_CATALOG_UNWRITABLE")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "SCENARIO_CATALOG_UNWRITABLE")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|_| "SCENARIO_CATALOG_UNWRITABLE")?;
    }
    fs::rename(&temporary, path).map_err(|_| "SCENARIO_CATALOG_UNWRITABLE")?;
    if let Some(parent) = path.parent() {
        OpenOptions::new()
            .read(true)
            .open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "SCENARIO_CATALOG_UNWRITABLE")?;
    }
    Ok(())
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mutation(id: &str) -> ScenarioMutation {
        ScenarioMutation {
            id: id.into(),
            name: "bounded scenario".into(),
            loop_count: 1,
            steps: vec![ScenarioStep {
                step_type: "wait".into(),
                loop_count: 2,
                parameters: BTreeMap::from([(
                    "duration_ms".into(),
                    ParameterSpec::Random {
                        random: RandomRange { min: 10, max: 20 },
                    },
                )]),
                steps: Vec::new(),
            }],
        }
    }

    #[test]
    fn catalog_crud_is_persistent_versioned_and_cloneable() {
        let root = std::env::temp_dir().join(format!("polaris-scenario-{}", epoch_seconds()));
        let _ = fs::remove_dir_all(&root);
        let store = ScenarioDefinitionStore::new(root.join("catalog.json"));
        let mut catalog = store.load().unwrap();
        let created = store.create(&mut catalog, mutation("s1")).unwrap();
        assert_eq!(created.version, 1);
        let mut changed = mutation("s1");
        changed.name = "updated".into();
        assert_eq!(
            store.update(&mut catalog, "s1", changed).unwrap().version,
            2
        );
        assert_eq!(
            store
                .clone_definition(&mut catalog, "s1", "s2")
                .unwrap()
                .version,
            1
        );
        store.delete(&mut catalog, "s1").unwrap();
        let recovered = store.load().unwrap();
        assert_eq!(recovered.definitions.len(), 5);
        assert!(recovered.definitions.iter().any(|item| item.id == "s2"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsupported_steps_and_invalid_random_ranges_are_rejected() {
        let mut unsupported = mutation("bad");
        unsupported.steps[0].step_type = "rrc_idle".into();
        assert_eq!(
            validate_mutation(&unsupported).unwrap_err(),
            "SCENARIO_STEP_TYPE_UNSUPPORTED"
        );
        let mut invalid = mutation("range");
        invalid.steps[0].parameters.insert(
            "duration_ms".into(),
            ParameterSpec::Random {
                random: RandomRange { min: 20, max: 10 },
            },
        );
        assert_eq!(
            validate_mutation(&invalid).unwrap_err(),
            "SCENARIO_RANDOM_RANGE_INVALID"
        );

        let mut oversized = mutation("oversized");
        oversized.steps = (0..2)
            .map(|_| ScenarioStep {
                step_type: "wait".into(),
                loop_count: 6_000,
                parameters: BTreeMap::new(),
                steps: Vec::new(),
            })
            .collect();
        assert_eq!(
            validate_mutation(&oversized).unwrap_err(),
            "SCENARIO_RESOLVED_STEP_COUNT_INVALID"
        );
    }

    #[test]
    fn random_values_are_resolved_and_recordable_per_loop_iteration() {
        let definition = ScenarioDefinition {
            id: "s1".into(),
            name: "test".into(),
            version: 1,
            loop_count: 2,
            steps: mutation("s1").steps,
            created_at_epoch_s: 0,
            updated_at_epoch_s: 0,
        };
        let resolved = resolve_steps(&definition).unwrap();
        assert_eq!(resolved.len(), 4);
        assert_eq!(resolved[0].scenario_loop_iteration, 1);
        assert_eq!(resolved[2].scenario_loop_iteration, 2);
        assert!(resolved.iter().all(|step| {
            step.scenario_loop_count == 2
                && step.step_loop_count == 2
                && (1..=2).contains(&step.step_loop_iteration)
        }));
        assert!(resolved.iter().all(|step| {
            step.parameters["duration_ms"]
                .as_i64()
                .is_some_and(|value| (10..=20).contains(&value))
        }));
    }

    #[test]
    fn omitted_scenario_and_step_loops_default_to_one() {
        let mutation: ScenarioMutation = serde_json::from_value(serde_json::json!({
            "id":"default-loop",
            "name":"Default loop",
            "steps":[{"type":"wait","parameters":{}}]
        }))
        .unwrap();
        assert_eq!(mutation.loop_count, 1);
        assert_eq!(mutation.steps[0].loop_count, 1);
        validate_mutation(&mutation).unwrap();
    }

    #[test]
    fn four_templates_are_seeded_read_only_and_bounded() {
        let templates = builtin_templates();
        assert_eq!(templates.len(), 4);
        assert_eq!(
            templates
                .iter()
                .map(|item| item.id.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "tpl-voice-long",
                "tpl-voice-short",
                "tpl-small-traffic",
                "tpl-high-runner"
            ])
        );
        for template in &templates {
            validate_definition(template).unwrap();
            assert!(resolve_steps(template).unwrap().len() <= MAX_RESOLVED_STEPS);
        }
        let root = std::env::temp_dir().join(format!("polaris-templates-{}", epoch_seconds()));
        let store = ScenarioDefinitionStore::new(root.join("catalog.json"));
        let mut catalog = store.load().unwrap();
        assert_eq!(
            catalog
                .definitions
                .iter()
                .filter(|item| template_id(&item.id))
                .count(),
            4
        );
        assert_eq!(
            store.delete(&mut catalog, "tpl-voice-long").unwrap_err(),
            "SCENARIO_TEMPLATE_READ_ONLY"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repeat_depth_resolved_limit_and_traffic_bound_are_enforced() {
        let leaf = step(
            "idle",
            BTreeMap::from([("duration_ms".into(), fixed(1_u64))]),
        );
        let mut valid = mutation("nested");
        valid.steps = vec![repeat(2, vec![repeat(3, vec![leaf.clone()])])];
        validate_mutation(&valid).unwrap();
        assert_eq!(
            resolve_steps(&ScenarioDefinition {
                id: valid.id.clone(),
                name: valid.name.clone(),
                version: 1,
                loop_count: 1,
                steps: valid.steps.clone(),
                created_at_epoch_s: 0,
                updated_at_epoch_s: 0
            })
            .unwrap()
            .len(),
            6
        );
        let mut too_deep = valid.clone();
        too_deep.steps = vec![repeat(1, vec![repeat(1, vec![repeat(1, vec![leaf])])])];
        assert_eq!(
            validate_mutation(&too_deep).unwrap_err(),
            "SCENARIO_REPEAT_INVALID"
        );
        let mut too_large = mutation("too-large");
        too_large.steps = vec![step(
            "traffic_ul",
            BTreeMap::from([("bytes".into(), fixed(MAX_TRAFFIC_BYTES + 1))]),
        )];
        assert_eq!(
            validate_mutation(&too_large).unwrap_err(),
            "TRAFFIC_BYTES_OUT_OF_RANGE"
        );
    }
}
