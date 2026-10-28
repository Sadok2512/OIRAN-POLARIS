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
    pub steps: Vec<ScenarioStep>,
    pub created_at_epoch_s: u64,
    pub updated_at_epoch_s: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScenarioMutation {
    pub id: String,
    pub name: String,
    pub steps: Vec<ScenarioStep>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScenarioStep {
    #[serde(rename = "type")]
    pub step_type: String,
    pub loop_count: u32,
    #[serde(default)]
    pub parameters: BTreeMap<String, ParameterSpec>,
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
    pub loop_iteration: u32,
    pub loop_count: u32,
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
        match fs::read(&self.path) {
            Ok(bytes) => {
                #[cfg(unix)]
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
                let catalog: ScenarioCatalog = serde_json::from_slice(&bytes)
                    .map_err(|_| "SCENARIO_CATALOG_INVALID".to_string())?;
                validate_catalog(&catalog)?;
                Ok(catalog)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ScenarioCatalog::default())
            }
            Err(_) => Err("SCENARIO_CATALOG_UNREADABLE".into()),
        }
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
        if catalog.definitions.iter().any(|item| item.id == input.id) {
            return Err("SCENARIO_DEFINITION_ALREADY_EXISTS".into());
        }
        let now = epoch_seconds();
        let definition = ScenarioDefinition {
            id: input.id,
            name: input.name,
            version: 1,
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
                steps: source.steps,
            },
        )
    }
}

pub fn resolve_steps(definition: &ScenarioDefinition) -> Result<Vec<ResolvedStep>, String> {
    validate_definition(definition)?;
    let mut resolved = Vec::new();
    for (index, step) in definition.steps.iter().enumerate() {
        for iteration in 1..=step.loop_count {
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
                index,
                step_type: step.step_type.clone(),
                loop_iteration: iteration,
                loop_count: step.loop_count,
                parameters,
            });
        }
    }
    Ok(resolved)
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
    let mut resolved_step_count = 0_usize;
    for step in &input.steps {
        if !matches!(
            step.step_type.as_str(),
            "ue_start" | "ue_stop" | "pdu_establish" | "pdu_release" | "udp_traffic" | "wait"
        ) {
            return Err("SCENARIO_STEP_TYPE_UNSUPPORTED".into());
        }
        if !(1..=MAX_LOOP_COUNT).contains(&step.loop_count) {
            return Err("SCENARIO_LOOP_COUNT_INVALID".into());
        }
        resolved_step_count = resolved_step_count
            .checked_add(step.loop_count as usize)
            .ok_or("SCENARIO_RESOLVED_STEP_COUNT_INVALID")?;
        if resolved_step_count > MAX_RESOLVED_STEPS {
            return Err("SCENARIO_RESOLVED_STEP_COUNT_INVALID".into());
        }
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
    }
    Ok(())
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
            steps: vec![ScenarioStep {
                step_type: "wait".into(),
                loop_count: 2,
                parameters: BTreeMap::from([(
                    "duration_ms".into(),
                    ParameterSpec::Random {
                        random: RandomRange { min: 10, max: 20 },
                    },
                )]),
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
        assert_eq!(recovered.definitions.len(), 1);
        assert_eq!(recovered.definitions[0].id, "s2");
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
            steps: mutation("s1").steps,
            created_at_epoch_s: 0,
            updated_at_epoch_s: 0,
        };
        let resolved = resolve_steps(&definition).unwrap();
        assert_eq!(resolved.len(), 2);
        assert!(resolved.iter().all(|step| {
            step.parameters["duration_ms"]
                .as_i64()
                .is_some_and(|value| (10..=20).contains(&value))
        }));
    }
}
