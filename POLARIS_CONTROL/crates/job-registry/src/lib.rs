use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VERSION: &str = "0.1.0";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobState {
    Prepared,
    MockRunning,
    Stopping,
    Stopped,
    Failed,
    RecoveredOrphan,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Job {
    pub job_id: String,
    pub scenario_id: String,
    pub owner_id: String,
    pub state: JobState,
    pub owned_handles: Vec<String>,
    pub created_at_epoch_s: u64,
    pub error: Option<String>,
}
#[derive(Default)]
pub struct Registry {
    jobs: BTreeMap<String, Job>,
    scenario_index: BTreeMap<String, String>,
}
impl Registry {
    pub fn register(&mut self, job: Job) -> Result<&Job, String> {
        if let Some(id) = self.scenario_index.get(&job.scenario_id) {
            return self.jobs.get(id).ok_or("registry index corrupted".into());
        }
        if job.owned_handles.iter().any(|x| x.is_empty()) {
            return Err("empty ownership handle".into());
        }
        self.scenario_index
            .insert(job.scenario_id.clone(), job.job_id.clone());
        self.jobs.insert(job.job_id.clone(), job);
        Ok(self.jobs.values().next_back().unwrap())
    }
    pub fn get(&self, id: &str) -> Option<&Job> {
        self.jobs.get(id)
    }
    pub fn list(&self) -> Vec<&Job> {
        self.jobs.values().collect()
    }
    pub fn stop_owned(&mut self, id: &str, owner: &str) -> Result<(), String> {
        let j = self.jobs.get_mut(id).ok_or("unknown job")?;
        if j.owner_id != owner {
            return Err("ownership mismatch".into());
        }
        j.state = JobState::Stopped;
        Ok(())
    }
    pub fn recover(&mut self, live_handles: &[String]) {
        for job in self.jobs.values_mut() {
            if matches!(job.state, JobState::MockRunning)
                && !job.owned_handles.iter().all(|h| live_handles.contains(h))
            {
                job.state = JobState::RecoveredOrphan
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn job() -> Job {
        Job {
            job_id: "j1".into(),
            scenario_id: "s1".into(),
            owner_id: "controller".into(),
            state: JobState::MockRunning,
            owned_handles: vec!["mock:j1".into()],
            created_at_epoch_s: 1,
            error: None,
        }
    }
    #[test]
    fn duplicate_start_is_idempotent() {
        let mut r = Registry::default();
        r.register(job()).unwrap();
        assert_eq!(
            r.register(Job {
                job_id: "j2".into(),
                ..job()
            })
            .unwrap()
            .job_id,
            "j1"
        );
        assert_eq!(r.list().len(), 1)
    }
    #[test]
    fn stop_enforces_ownership() {
        let mut r = Registry::default();
        r.register(job()).unwrap();
        assert!(r.stop_owned("j1", "other").is_err());
        r.stop_owned("j1", "controller").unwrap()
    }
    #[test]
    fn recovery_marks_only_owned_missing_handle() {
        let mut r = Registry::default();
        r.register(job()).unwrap();
        r.recover(&[]);
        assert_eq!(r.get("j1").unwrap().state, JobState::RecoveredOrphan)
    }
}
