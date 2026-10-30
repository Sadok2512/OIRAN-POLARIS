use job_registry::{Job, JobState, Registry};
use safety_guard::{evaluate, Policy, Sample};
use scenario_engine::{validate, Scenario};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};
use ueransim_adapter::{
    is_approved_controller_ue, validate_profile_set, LiveLaunchSpec, UeObservation, UeProfileSpec,
};
pub const VERSION: &str = "0.3.0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UeLifecycle {
    Created,
    Configured,
    Starting,
    Registering,
    Registered,
    PduActive,
    Stopping,
    Stopped,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UeJob {
    pub ue_id: String,
    pub pseudonym: String,
    pub profile_name: String,
    pub serving_gnb: String,
    pub lifecycle: UeLifecycle,
    pub process_state: String,
    pub registration_state: String,
    pub pdu_session_state: String,
    #[serde(default)]
    pub ue_ip: Option<String>,
    pub traffic_state: String,
    pub controller_owned: bool,
    pub process_handle: Option<String>,
    #[serde(default)]
    pub operation_id: Option<String>,
    /// 0.19.5 — Epoch second at which `operation_id` was last stamped.
    /// Reset to `None` whenever the lock clears. Used by
    /// `release_stale_locks` to evict leftovers from a Stop that
    /// crashed or raced the API process.
    #[serde(default)]
    pub operation_locked_at_epoch_s: Option<u64>,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub approved_runtime: Option<LiveLaunchSpec>,
    pub started_at_epoch_s: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupResult {
    pub started: Vec<String>,
    pub failed: Vec<(String, String)>,
}

pub struct MultiUeController {
    profiles: BTreeMap<String, UeProfileSpec>,
    jobs: BTreeMap<String, UeJob>,
    max_live_ues: usize,
}

/// 0.19.5 — Default max age for an operation lock. 2 minutes is the
/// outer bound for any single Start / Stop step in the lab; a lock
/// that stayed held past that is attributable to a crashed worker
/// or a race with the API process restart.
pub const MAX_OPERATION_LOCK_SECONDS: u64 = 120;

/// 0.19.5 — Audit record returned by `release_stale_locks`. Lists the
/// UE and the operation_id whose lock was reclaimed so the caller can
/// emit one audit-log line per reclaim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasedLock {
    pub ue_id: String,
    pub operation_id: String,
    pub locked_at_epoch_s: Option<u64>,
}

impl MultiUeController {
    pub fn new(profiles: Vec<UeProfileSpec>, max_live_ues: usize) -> Result<Self, String> {
        validate_profile_set(&profiles)?;
        if max_live_ues == 0 || max_live_ues > 10 {
            return Err("live UE limit must be between 1 and 10".into());
        }
        let profiles = profiles
            .into_iter()
            .map(|profile| (profile.ue_id.clone(), profile))
            .collect();
        Ok(Self {
            profiles,
            jobs: BTreeMap::new(),
            max_live_ues,
        })
    }

    pub fn inventory(&self) -> Vec<UeJob> {
        self.profiles
            .values()
            .map(|profile| {
                self.jobs.get(&profile.ue_id).cloned().unwrap_or(UeJob {
                    ue_id: profile.ue_id.clone(),
                    pseudonym: profile.pseudonym.clone(),
                    profile_name: profile.profile_name.clone(),
                    serving_gnb: profile.serving_gnb.clone(),
                    lifecycle: if profile.configured {
                        UeLifecycle::Configured
                    } else {
                        UeLifecycle::Created
                    },
                    process_state: "STOPPED".into(),
                    registration_state: "NOT_OBSERVED".into(),
                    pdu_session_state: "INACTIVE".into(),
                    ue_ip: None,
                    traffic_state: "IDLE".into(),
                    controller_owned: true,
                    process_handle: None,
                    operation_id: None,
                    operation_locked_at_epoch_s: None,
                    generation: 0,
                    approved_runtime: None,
                    started_at_epoch_s: None,
                    last_error: (!profile.subscription_verified)
                        .then(|| "SUBSCRIBER_PROVISIONING_REQUIRED".into()),
                })
            })
            .collect()
    }

    pub fn profiles(&self) -> Vec<UeProfileSpec> {
        self.profiles.values().cloned().collect()
    }

    /// Replaces one stopped profile. Runtime ownership is deliberately not inferred from profile
    /// data; an active or reserved job must be stopped and reconciled first.
    pub fn upsert_profile(&mut self, profile: UeProfileSpec) -> Result<(), String> {
        let mut profiles = self.profiles.values().cloned().collect::<Vec<_>>();
        if let Some(existing) = profiles.iter_mut().find(|item| item.ue_id == profile.ue_id) {
            if self.jobs.get(&profile.ue_id).is_some_and(|job| {
                job.process_handle.is_some()
                    || !matches!(job.lifecycle, UeLifecycle::Stopped | UeLifecycle::Failed)
            }) {
                return Err("UE_PROFILE_ACTIVE".into());
            }
            *existing = profile.clone();
        } else {
            profiles.push(profile.clone());
        }
        validate_profile_set(&profiles)?;
        self.profiles.insert(profile.ue_id.clone(), profile);
        Ok(())
    }

    /// Adds a persistent catalog batch after one aggregate validation. This does not allocate a
    /// runtime job and therefore cannot start or reserve any UE.
    pub fn add_profiles(&mut self, additions: Vec<UeProfileSpec>) -> Result<(), String> {
        if additions
            .iter()
            .any(|profile| self.profiles.contains_key(&profile.ue_id))
        {
            return Err("UE_PROFILE_ALREADY_EXISTS".into());
        }
        let mut profiles = self.profiles.values().cloned().collect::<Vec<_>>();
        profiles.extend(additions.iter().cloned());
        validate_profile_set(&profiles)?;
        for profile in additions {
            self.profiles.insert(profile.ue_id.clone(), profile);
        }
        Ok(())
    }

    /// Deletes only a stopped profile. A retained terminal job is removed with the profile so it
    /// cannot later be mistaken for a newly-created UE using the same stable ID.
    pub fn delete_profile(&mut self, ue_id: &str) -> Result<UeProfileSpec, String> {
        let profile = self.profiles.get(ue_id).ok_or("UNKNOWN_UE_PROFILE")?;
        if self.jobs.get(ue_id).is_some_and(|job| {
            job.process_handle.is_some()
                || !matches!(job.lifecycle, UeLifecycle::Stopped | UeLifecycle::Failed)
        }) {
            return Err("UE_PROFILE_ACTIVE".into());
        }
        let removed = profile.clone();
        self.profiles.remove(ue_id);
        self.jobs.remove(ue_id);
        Ok(removed)
    }

    pub fn configured_count(&self) -> usize {
        self.profiles
            .values()
            .filter(|profile| profile.configured)
            .count()
    }

    pub fn set_subscription_verified(&mut self, verified: &BTreeSet<String>) {
        for profile in self.profiles.values_mut() {
            profile.subscription_verified = verified.contains(&profile.ue_id);
        }
    }

    pub fn set_profile_subscription_verified(
        &mut self,
        ue_id: &str,
        verified: bool,
    ) -> Result<(), String> {
        let profile = self.profiles.get_mut(ue_id).ok_or("UNKNOWN_UE_PROFILE")?;
        profile.subscription_verified = verified;
        Ok(())
    }

    /// Changes desired configuration only. It never starts or stops a UE process.
    pub fn configure_count(&mut self, count: usize) -> Result<(), String> {
        if count > self.profiles.len() || count > ueransim_adapter::MAX_LIVE_UES {
            return Err("UE_COUNT_OUT_OF_RANGE".into());
        }
        let selected = self
            .profiles
            .keys()
            .take(count)
            .cloned()
            .collect::<BTreeSet<_>>();
        if self.jobs.values().any(|job| {
            !selected.contains(&job.ue_id)
                && matches!(
                    job.lifecycle,
                    UeLifecycle::Starting
                        | UeLifecycle::Registering
                        | UeLifecycle::Registered
                        | UeLifecycle::PduActive
                        | UeLifecycle::Stopping
                )
        }) {
            return Err("ACTIVE_UE_OUTSIDE_REQUESTED_CONFIGURATION".into());
        }
        for profile in self.profiles.values_mut() {
            profile.configured = selected.contains(&profile.ue_id);
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Vec<UeJob> {
        self.jobs.values().cloned().collect()
    }

    /// Restores only known, controller-owned records. Active records are failed closed because
    /// ownership cannot be proven from a serialized handle after a controller restart.
    pub fn recover(&mut self, records: Vec<UeJob>) -> Result<(), String> {
        let mut recovered = BTreeMap::new();
        for mut job in records {
            if !self.profiles.contains_key(&job.ue_id) || !job.controller_owned {
                return Err("INVALID_UE_REGISTRY_RECORD".into());
            }
            if !matches!(job.lifecycle, UeLifecycle::Stopped | UeLifecycle::Failed) {
                job.lifecycle = UeLifecycle::Failed;
                job.process_state = "UNKNOWN".into();
                job.registration_state = "UNKNOWN".into();
                job.pdu_session_state = "UNKNOWN".into();
                job.traffic_state = "STOPPED".into();
                job.process_handle = None;
                job.last_error = Some("CONTROLLER_RESTART_REQUIRES_RECONCILIATION".into());
            }
            recovered.insert(job.ue_id.clone(), job);
        }
        self.jobs = recovered;
        Ok(())
    }

    pub fn start_offline(&mut self, ue_id: &str) -> Result<&UeJob, String> {
        let profile = self.profiles.get(ue_id).ok_or("UNKNOWN_UE_PROFILE")?;
        if !profile.configured || !profile.subscription_verified {
            return Err("SUBSCRIBER_PROVISIONING_REQUIRED".into());
        }
        if let Some(existing) = self.jobs.get(ue_id) {
            if matches!(
                existing.lifecycle,
                UeLifecycle::Starting
                    | UeLifecycle::Registering
                    | UeLifecycle::Registered
                    | UeLifecycle::PduActive
            ) {
                return Ok(self.jobs.get(ue_id).unwrap());
            }
        }
        let active = self
            .jobs
            .values()
            .filter(|job| {
                matches!(
                    job.lifecycle,
                    UeLifecycle::Starting
                        | UeLifecycle::Registering
                        | UeLifecycle::Registered
                        | UeLifecycle::PduActive
                )
            })
            .count();
        if active >= self.max_live_ues {
            return Err("UE_RESOURCE_LIMIT".into());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.jobs.insert(
            ue_id.into(),
            UeJob {
                ue_id: profile.ue_id.clone(),
                pseudonym: profile.pseudonym.clone(),
                profile_name: profile.profile_name.clone(),
                serving_gnb: profile.serving_gnb.clone(),
                lifecycle: UeLifecycle::Starting,
                process_state: "MOCK_RUNNING".into(),
                registration_state: "REGISTERING".into(),
                pdu_session_state: "INACTIVE".into(),
                ue_ip: None,
                traffic_state: "IDLE".into(),
                controller_owned: true,
                process_handle: Some(format!("mock-ue:{ue_id}")),
                operation_id: None,
                operation_locked_at_epoch_s: None,
                generation: 0,
                approved_runtime: None,
                started_at_epoch_s: Some(now),
                last_error: None,
            },
        );
        Ok(self.jobs.get(ue_id).unwrap())
    }

    pub fn observe(
        &mut self,
        ue_id: &str,
        registered: bool,
        pdu_active: bool,
    ) -> Result<&UeJob, String> {
        let job = self.jobs.get_mut(ue_id).ok_or("UE_NOT_STARTED")?;
        job.registration_state = if registered {
            "REGISTERED"
        } else {
            "REGISTERING"
        }
        .into();
        job.pdu_session_state = if pdu_active { "ACTIVE" } else { "INACTIVE" }.into();
        if !pdu_active {
            job.ue_ip = None;
        }
        job.lifecycle = if pdu_active {
            UeLifecycle::PduActive
        } else if registered {
            UeLifecycle::Registered
        } else {
            UeLifecycle::Registering
        };
        Ok(job)
    }

    pub fn record_live_start(
        &mut self,
        ue_id: &str,
        process_handle: &str,
    ) -> Result<&UeJob, String> {
        if !is_approved_controller_ue(ue_id) {
            return Err("PROTECTED_OR_UNAPPROVED_UE".into());
        }
        let profile = self.profiles.get(ue_id).ok_or("UNKNOWN_UE_PROFILE")?;
        if !profile.configured || !profile.subscription_verified {
            return Err("UE_PROFILE_NOT_READY".into());
        }
        let valid_handle = process_handle
            .strip_prefix("container:")
            .is_some_and(|id| id.len() == 64 && id.chars().all(|value| value.is_ascii_hexdigit()));
        if !valid_handle {
            return Err("INVALID_PROCESS_HANDLE".into());
        }
        let active = self
            .jobs
            .values()
            .filter(|job| {
                matches!(
                    job.lifecycle,
                    UeLifecycle::Starting
                        | UeLifecycle::Registering
                        | UeLifecycle::Registered
                        | UeLifecycle::PduActive
                )
            })
            .count();
        if active >= self.max_live_ues {
            return Err("UE_RESOURCE_LIMIT".into());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.jobs.insert(
            ue_id.into(),
            UeJob {
                ue_id: profile.ue_id.clone(),
                pseudonym: profile.pseudonym.clone(),
                profile_name: profile.profile_name.clone(),
                serving_gnb: profile.serving_gnb.clone(),
                lifecycle: UeLifecycle::Starting,
                process_state: "STARTING".into(),
                registration_state: "NOT_OBSERVED".into(),
                pdu_session_state: "INACTIVE".into(),
                ue_ip: None,
                traffic_state: "IDLE".into(),
                controller_owned: true,
                process_handle: Some(process_handle.into()),
                operation_id: None,
                operation_locked_at_epoch_s: None,
                generation: 0,
                approved_runtime: None,
                started_at_epoch_s: Some(now),
                last_error: None,
            },
        );
        Ok(self.jobs.get(ue_id).unwrap())
    }

    /// Reserves a live transition before any external runtime action. The returned record must be
    /// durably persisted before launch is attempted.
    pub fn reserve_live_start(
        &mut self,
        ue_id: &str,
        operation_id: &str,
        approved_runtime: LiveLaunchSpec,
    ) -> Result<&UeJob, String> {
        if !is_approved_controller_ue(ue_id) {
            return Err("PROTECTED_OR_UNAPPROVED_UE".into());
        }
        if operation_id.is_empty() || operation_id.len() > 128 {
            return Err("INVALID_UE_OPERATION_ID".into());
        }
        let profile = self.profiles.get(ue_id).ok_or("UNKNOWN_UE_PROFILE")?;
        if !profile.configured || !profile.subscription_verified {
            return Err("UE_PROFILE_NOT_READY".into());
        }
        // 0.19.5 — Evict an expired lock before enforcing the 409.
        // Matches the Stop-side priority rule: during runtime a lock
        // older than MAX_OPERATION_LOCK_SECONDS is treated as stale
        // (its owning worker thread is gone) and silently reclaimed.
        let now_epoch_s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        if let Some(job) = self.jobs.get_mut(ue_id) {
            if job.operation_id.is_some() {
                let locked_at = job.operation_locked_at_epoch_s.unwrap_or(0);
                if now_epoch_s.saturating_sub(locked_at) >= MAX_OPERATION_LOCK_SECONDS {
                    job.operation_id = None;
                    job.operation_locked_at_epoch_s = None;
                }
            }
        }
        if self
            .jobs
            .get(ue_id)
            .is_some_and(|job| job.operation_id.is_some())
        {
            return Err("UE_OPERATION_IN_PROGRESS".into());
        }
        if self.jobs.get(ue_id).is_some_and(|job| {
            matches!(
                job.lifecycle,
                UeLifecycle::Starting
                    | UeLifecycle::Registering
                    | UeLifecycle::Registered
                    | UeLifecycle::PduActive
            )
        }) {
            return Err("UE_ALREADY_RUNNING".into());
        }
        let active = self
            .jobs
            .values()
            .filter(|job| {
                job.ue_id != ue_id
                    && matches!(
                        job.lifecycle,
                        UeLifecycle::Starting
                            | UeLifecycle::Registering
                            | UeLifecycle::Registered
                            | UeLifecycle::PduActive
                    )
            })
            .count();
        if active >= self.max_live_ues {
            return Err("UE_RESOURCE_LIMIT".into());
        }
        let previous_handle = self
            .jobs
            .get(ue_id)
            .and_then(|job| job.process_handle.clone());
        if approved_runtime.ue_id != ue_id
            || approved_runtime.profile_basename != profile.profile_name
        {
            return Err("LIVE_RUNTIME_APPROVAL_MISMATCH".into());
        }
        let generation = self
            .jobs
            .get(ue_id)
            .map_or(1, |job| job.generation.saturating_add(1));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.jobs.insert(
            ue_id.into(),
            UeJob {
                ue_id: profile.ue_id.clone(),
                pseudonym: profile.pseudonym.clone(),
                profile_name: profile.profile_name.clone(),
                serving_gnb: profile.serving_gnb.clone(),
                lifecycle: UeLifecycle::Starting,
                process_state: "STARTING".into(),
                registration_state: "NOT_OBSERVED".into(),
                pdu_session_state: "INACTIVE".into(),
                ue_ip: None,
                traffic_state: "IDLE".into(),
                controller_owned: true,
                process_handle: previous_handle,
                operation_id: Some(operation_id.into()),
                operation_locked_at_epoch_s: Some(now),
                generation,
                approved_runtime: Some(approved_runtime),
                started_at_epoch_s: Some(now),
                last_error: None,
            },
        );
        Ok(self.jobs.get(ue_id).unwrap())
    }

    pub fn complete_live_start(
        &mut self,
        ue_id: &str,
        operation_id: &str,
        process_handle: &str,
    ) -> Result<&UeJob, String> {
        let valid_handle = process_handle
            .strip_prefix("container:")
            .is_some_and(|id| id.len() == 64 && id.chars().all(|value| value.is_ascii_hexdigit()));
        if !valid_handle {
            return Err("INVALID_PROCESS_HANDLE".into());
        }
        let job = self.jobs.get_mut(ue_id).ok_or("UE_NOT_RESERVED")?;
        if job.operation_id.as_deref() != Some(operation_id) {
            return Err("UE_OPERATION_MISMATCH".into());
        }
        job.process_handle = Some(process_handle.into());
        job.operation_id = None;
        job.operation_locked_at_epoch_s = None;
        job.lifecycle = UeLifecycle::Registering;
        job.process_state = "RUNNING".into();
        Ok(job)
    }

    pub fn attach_live_handle(
        &mut self,
        ue_id: &str,
        operation_id: &str,
        process_handle: &str,
    ) -> Result<&UeJob, String> {
        let valid_handle = process_handle
            .strip_prefix("container:")
            .is_some_and(|id| id.len() == 64 && id.chars().all(|value| value.is_ascii_hexdigit()));
        if !valid_handle {
            return Err("INVALID_PROCESS_HANDLE".into());
        }
        let job = self.jobs.get_mut(ue_id).ok_or("UE_NOT_RESERVED")?;
        if job.operation_id.as_deref() != Some(operation_id) {
            return Err("UE_OPERATION_MISMATCH".into());
        }
        job.process_handle = Some(process_handle.into());
        Ok(job)
    }

    pub fn fail_live_operation(
        &mut self,
        ue_id: &str,
        operation_id: &str,
        error: &str,
        retain_handle: bool,
    ) -> Result<&UeJob, String> {
        let job = self.jobs.get_mut(ue_id).ok_or("UE_NOT_RESERVED")?;
        if job.operation_id.as_deref() != Some(operation_id) {
            return Err("UE_OPERATION_MISMATCH".into());
        }
        job.operation_id = None;
        job.operation_locked_at_epoch_s = None;
        job.lifecycle = UeLifecycle::Failed;
        job.process_state = "UNKNOWN".into();
        job.registration_state = "NOT_OBSERVED".into();
        job.pdu_session_state = "INACTIVE".into();
        job.ue_ip = None;
        if !retain_handle {
            job.process_handle = None;
        }
        job.last_error = Some(error.into());
        Ok(job)
    }

    pub fn mark_cleanup_pending(&mut self, ue_id: &str, error: &str) -> Result<&UeJob, String> {
        let job = self.jobs.get_mut(ue_id).ok_or("UE_NOT_STARTED")?;
        if job.process_handle.is_none() || job.approved_runtime.is_none() {
            return Err("UE_CLEANUP_HANDLE_MISSING".into());
        }
        job.operation_id = None;
        job.operation_locked_at_epoch_s = None;
        job.lifecycle = UeLifecycle::Failed;
        job.process_state = "UNKNOWN".into();
        job.registration_state = "NOT_OBSERVED".into();
        job.pdu_session_state = "INACTIVE".into();
        job.ue_ip = None;
        job.last_error = Some(error.into());
        Ok(job)
    }

    /// 0.19.5 — Test harness only: mutable access to the internal job
    /// table so Stop-resilience tests in the API crate can hand-stamp
    /// an expired `operation_locked_at`. Documented as "do not use in
    /// production code"; the name screams the contract. We can't gate
    /// this on `cfg(test)` because the consumer (polaris-control-api)
    /// builds the simulator-controller crate in `dev` mode, not test
    /// mode — so a `cfg(test)` method is invisible to API tests.
    #[doc(hidden)]
    pub fn jobs_mut_for_tests(&mut self) -> &mut BTreeMap<String, UeJob> {
        &mut self.jobs
    }

    /// 0.19.5 — Release every operation lock that is `None` for a
    /// locked_at or older than `max_age_s`. Called at startup with
    /// `max_age_s = 0` to clear EVERY leftover (no operations are in
    /// progress across an API restart), and periodically with
    /// `MAX_OPERATION_LOCK_SECONDS` during runtime to evict stuck
    /// locks whose owning worker thread died mid-flight.
    pub fn release_stale_locks(
        &mut self,
        now_epoch_s: u64,
        max_age_s: u64,
    ) -> Vec<ReleasedLock> {
        let mut released = Vec::new();
        for job in self.jobs.values_mut() {
            let Some(operation_id) = job.operation_id.clone() else {
                continue;
            };
            let locked_at = job.operation_locked_at_epoch_s;
            let is_stale = match locked_at {
                None => true,
                Some(epoch) => now_epoch_s.saturating_sub(epoch) >= max_age_s,
            };
            if !is_stale {
                continue;
            }
            job.operation_id = None;
            job.operation_locked_at_epoch_s = None;
            released.push(ReleasedLock {
                ue_id: job.ue_id.clone(),
                operation_id,
                locked_at_epoch_s: locked_at,
            });
        }
        released
    }

    /// 0.19.5 — Stop reservation now has priority over an existing lock
    /// if that lock is older than `max_age_s` (treated as expired).
    /// `now_epoch_s` is passed in so the caller controls the clock
    /// source (unit tests pin a fixed value). When the previous lock
    /// is still fresh we return the historical UE_OPERATION_IN_PROGRESS
    /// so Start / Run operators see the honest 409.
    pub fn reserve_live_stop(
        &mut self,
        ue_id: &str,
        operation_id: &str,
        now_epoch_s: u64,
        max_age_s: u64,
    ) -> Result<&UeJob, String> {
        if !is_approved_controller_ue(ue_id) {
            return Err("PROTECTED_OR_UNAPPROVED_UE".into());
        }
        let job = self.jobs.get_mut(ue_id).ok_or("UE_NOT_STARTED")?;
        if job.operation_id.is_some() {
            let locked_at = job.operation_locked_at_epoch_s.unwrap_or(0);
            let age = now_epoch_s.saturating_sub(locked_at);
            if age < max_age_s {
                return Err("UE_OPERATION_IN_PROGRESS".into());
            }
            // Older than max age → treat as expired. Stop steals it.
        }
        if job.process_handle.is_none() {
            return Err("UE_NOT_STARTED".into());
        }
        job.lifecycle = UeLifecycle::Stopping;
        job.operation_id = Some(operation_id.into());
        job.operation_locked_at_epoch_s = Some(now_epoch_s);
        Ok(job)
    }

    pub fn apply_observation(
        &mut self,
        ue_id: &str,
        process_state: &str,
        registration_state: &str,
        pdu_session_state: &str,
        ue_ip: Option<&str>,
    ) -> Result<&UeJob, String> {
        if !matches!(
            process_state,
            "RUNNING" | "STARTING" | "RESTARTING" | "PAUSED" | "STOPPED" | "EXITED" | "UNKNOWN"
        ) || !matches!(registration_state, "REGISTERED" | "NOT_OBSERVED")
            || !matches!(pdu_session_state, "ACTIVE" | "INACTIVE")
            || (pdu_session_state == "ACTIVE"
                && (registration_state != "REGISTERED" || ue_ip.is_none()))
        {
            return Err("INVALID_UE_OBSERVATION".into());
        }
        let job = self.jobs.get_mut(ue_id).ok_or("UE_NOT_STARTED")?;
        job.process_state = process_state.into();
        job.registration_state = registration_state.into();
        job.pdu_session_state = pdu_session_state.into();
        job.ue_ip = ue_ip.map(str::to_string);
        job.lifecycle = if process_state == "UNKNOWN" {
            UeLifecycle::Unknown
        } else if matches!(process_state, "STOPPED" | "EXITED") {
            UeLifecycle::Stopped
        } else if matches!(process_state, "STARTING" | "RESTARTING") {
            UeLifecycle::Starting
        } else if process_state == "PAUSED" {
            UeLifecycle::Unknown
        } else if pdu_session_state == "ACTIVE" {
            UeLifecycle::PduActive
        } else if registration_state == "REGISTERED" {
            UeLifecycle::Registered
        } else {
            UeLifecycle::Registering
        };
        Ok(job)
    }

    pub fn apply_observation_if_current(
        &mut self,
        ue_id: &str,
        expected_handle: &str,
        expected_operation_id: Option<&str>,
        expected_generation: u64,
        observation: &UeObservation,
    ) -> Result<&UeJob, String> {
        let job = self.jobs.get(ue_id).ok_or("UE_NOT_STARTED")?;
        if job.process_handle.as_deref() != Some(expected_handle)
            || job.operation_id.as_deref() != expected_operation_id
            || job.generation != expected_generation
        {
            return Err("STALE_UE_OBSERVATION".into());
        }
        self.apply_observation(
            ue_id,
            &observation.process_state,
            &observation.registration_state,
            &observation.pdu_session_state,
            observation.ue_ip.as_deref(),
        )
    }

    pub fn reconcile<F>(
        &mut self,
        records: Vec<UeJob>,
        mut observe_live_handle: F,
    ) -> Result<(), String>
    where
        F: FnMut(&str, &str, &str) -> Option<UeObservation>,
    {
        let mut reconciled = BTreeMap::new();
        for mut job in records {
            if !self.profiles.contains_key(&job.ue_id) || !job.controller_owned {
                return Err("INVALID_UE_REGISTRY_RECORD".into());
            }
            let observation = job
                .process_handle
                .as_deref()
                .and_then(|handle| observe_live_handle(&job.ue_id, &job.profile_name, handle));
            if let Some(observation) = observation {
                job.process_state = observation.process_state;
                job.registration_state = observation.registration_state;
                job.pdu_session_state = observation.pdu_session_state;
                job.ue_ip = observation.ue_ip;
                job.traffic_state = "IDLE".into();
                job.last_error = None;
                job.operation_id = None;
                job.operation_locked_at_epoch_s = None;
                job.lifecycle = if matches!(job.process_state.as_str(), "EXITED" | "STOPPED") {
                    UeLifecycle::Stopped
                } else if job.process_state != "RUNNING" {
                    UeLifecycle::Unknown
                } else if job.pdu_session_state == "ACTIVE" {
                    UeLifecycle::PduActive
                } else if job.registration_state == "REGISTERED" {
                    UeLifecycle::Registered
                } else {
                    UeLifecycle::Registering
                };
            } else if !matches!(job.lifecycle, UeLifecycle::Stopped | UeLifecycle::Failed) {
                job.lifecycle = UeLifecycle::Failed;
                job.process_state = "UNKNOWN".into();
                job.registration_state = "UNKNOWN".into();
                job.pdu_session_state = "UNKNOWN".into();
                job.ue_ip = None;
                job.traffic_state = "STOPPED".into();
                job.operation_id = None;
                job.operation_locked_at_epoch_s = None;
                job.last_error = Some("CONTROLLER_RESTART_OWNERSHIP_NOT_PROVEN".into());
            }
            reconciled.insert(job.ue_id.clone(), job);
        }
        self.jobs = reconciled;
        Ok(())
    }

    pub fn set_traffic(&mut self, ue_id: &str, state: &str) -> Result<&UeJob, String> {
        if !matches!(
            state,
            "IDLE" | "RUNNING" | "COMPLETED" | "FAILED" | "STOPPED"
        ) {
            return Err("INVALID_TRAFFIC_STATE".into());
        }
        let job = self.jobs.get_mut(ue_id).ok_or("UE_NOT_STARTED")?;
        job.traffic_state = state.into();
        Ok(job)
    }

    pub fn stop_offline(&mut self, ue_id: &str) -> Result<&UeJob, String> {
        let job = self.jobs.get_mut(ue_id).ok_or("UE_NOT_STARTED")?;
        if !job.controller_owned {
            return Err("OWNERSHIP_MISMATCH".into());
        }
        if matches!(job.lifecycle, UeLifecycle::Stopped) {
            return Ok(job);
        }
        job.lifecycle = UeLifecycle::Stopped;
        job.process_state = "STOPPED".into();
        job.registration_state = "DEREGISTERED".into();
        job.pdu_session_state = "INACTIVE".into();
        job.ue_ip = None;
        job.traffic_state = "STOPPED".into();
        job.process_handle = None;
        job.operation_id = None;
        job.operation_locked_at_epoch_s = None;
        job.generation = job.generation.saturating_add(1);
        job.approved_runtime = None;
        Ok(job)
    }

    pub fn start_group_offline(&mut self, ue_ids: &[String]) -> GroupResult {
        let mut unique = BTreeSet::new();
        let mut result = GroupResult {
            started: Vec::new(),
            failed: Vec::new(),
        };
        for ue_id in ue_ids.iter().take(10) {
            if !unique.insert(ue_id.clone()) {
                continue;
            }
            match self.start_offline(ue_id) {
                Ok(_) => result.started.push(ue_id.clone()),
                Err(error) => result.failed.push((ue_id.clone(), error)),
            }
        }
        result
    }

    pub fn stop_group_offline(&mut self, ue_ids: &[String]) -> GroupResult {
        let mut result = GroupResult {
            started: Vec::new(),
            failed: Vec::new(),
        };
        for ue_id in ue_ids.iter().take(10) {
            match self.stop_offline(ue_id) {
                Ok(_) => result.started.push(ue_id.clone()),
                Err(error) => result.failed.push((ue_id.clone(), error)),
            }
        }
        result
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Mock,
    LiveApproved,
}
pub struct Controller {
    pub registry: Registry,
    pub mode: Mode,
    pub owner_id: String,
}
impl Controller {
    pub fn new() -> Self {
        Self {
            registry: Registry::default(),
            mode: Mode::Mock,
            owner_id: "polaris-control".into(),
        }
    }
    pub fn validate_start(
        &self,
        scenario: &Scenario,
        sample: Result<Sample, String>,
    ) -> Result<(), String> {
        validate(scenario)?;
        let disk = evaluate(sample, Policy::default());
        if !disk.writes_allowed {
            return Err(disk.reason);
        };
        traffic_engine::validate(&scenario.traffic, &["10.77.22.1".parse().unwrap()])?;
        Ok(())
    }
    pub fn mock_start(
        &mut self,
        scenario: &Scenario,
        sample: Result<Sample, String>,
    ) -> Result<&Job, String> {
        self.validate_start(scenario, sample)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.registry.register(Job {
            job_id: format!("job-{}", scenario.scenario_id),
            scenario_id: scenario.scenario_id.clone(),
            owner_id: self.owner_id.clone(),
            state: JobState::MockRunning,
            owned_handles: vec![format!("mock:{}", scenario.scenario_id)],
            created_at_epoch_s: now,
            error: None,
        })
    }
    pub fn live_start(&mut self, _: &Scenario) -> Result<(), String> {
        if self.mode != Mode::LiveApproved {
            return Err("LIVE_APPROVAL_REQUIRED".into());
        }
        Err("live UERANSIM executor is not enabled in v1.0.0-dev".into())
    }
    pub fn stop(&mut self, job: &str) -> Result<(), String> {
        self.registry.stop_owned(job, &self.owner_id)
    }
}
impl Default for Controller {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use scenario_engine::{StartMode, State};
    use traffic_engine::{Profile, Protocol};
    fn scenario() -> Scenario {
        Scenario {
            scenario_id: "s1".into(),
            name: "one UE".into(),
            ue_count: 1,
            start_mode: StartMode::Staggered,
            stagger_seconds: 2,
            traffic: Profile {
                protocol: Protocol::Udp,
                destination: "10.77.22.1".parse().unwrap(),
                packet_count: 5,
                packet_size: 64,
                rate_per_second: 1,
                duration_seconds: 5,
            },
            state: State::Validated,
        }
    }
    fn disk() -> Result<Sample, String> {
        Ok(Sample {
            total_bytes: 100 * 1024 * 1024 * 1024,
            available_bytes: 30 * 1024 * 1024 * 1024,
            total_inodes: 1000,
            available_inodes: 900,
        })
    }
    #[test]
    fn mock_lifecycle_is_owned_and_idempotent() {
        let mut c = Controller::new();
        assert_eq!(c.mock_start(&scenario(), disk()).unwrap().job_id, "job-s1");
        assert_eq!(c.mock_start(&scenario(), disk()).unwrap().job_id, "job-s1");
        c.stop("job-s1").unwrap()
    }
    #[test]
    fn live_start_requires_approval() {
        let mut c = Controller::new();
        assert_eq!(
            c.live_start(&scenario()).unwrap_err(),
            "LIVE_APPROVAL_REQUIRED"
        )
    }
    #[test]
    fn resource_failure_blocks_start() {
        let mut c = Controller::new();
        assert!(c.mock_start(&scenario(), Err("fail".into())).is_err())
    }

    fn ready_profiles(count: usize) -> Vec<UeProfileSpec> {
        let mut profiles = ueransim_adapter::planned_profiles();
        profiles.truncate(count);
        profiles.iter_mut().for_each(|profile| {
            profile.configured = true;
            profile.subscription_verified = true;
        });
        profiles
    }

    fn approved_runtime(ue_id: &str) -> LiveLaunchSpec {
        LiveLaunchSpec {
            ue_id: ue_id.into(),
            profile_basename: format!("ue-{}.yaml", &ue_id[3..]),
            container_name: format!("polaris-control-{}", ue_id.to_ascii_lowercase()),
            owner_id: "a".repeat(64),
            profile_sha256: "b".repeat(64),
            script_sha256: "c".repeat(64),
            image_id: format!("sha256:{}", "d".repeat(64)),
            docker_args: Vec::new(),
        }
    }

    #[test]
    fn two_five_and_ten_ues_have_independent_lifecycles() {
        for count in [2, 5, 10] {
            let mut controller = MultiUeController::new(ready_profiles(count), count).unwrap();
            let ids = (1..=count)
                .map(|index| format!("UE-{index:02}"))
                .collect::<Vec<_>>();
            let result = controller.start_group_offline(&ids);
            assert_eq!(result.started.len(), count);
            for id in &ids {
                controller.observe(id, true, true).unwrap();
            }
            controller.set_traffic(&ids[0], "COMPLETED").unwrap();
            let inventory = controller.inventory();
            assert!(inventory
                .iter()
                .all(|job| job.registration_state == "REGISTERED"));
            assert_eq!(inventory[0].traffic_state, "COMPLETED");
            assert_eq!(inventory[0].lifecycle, UeLifecycle::PduActive);
        }
    }

    #[test]
    fn duplicate_start_and_stop_are_idempotent_and_owned() {
        let mut controller = MultiUeController::new(ready_profiles(1), 1).unwrap();
        let first = controller
            .start_offline("UE-01")
            .unwrap()
            .process_handle
            .clone();
        let second = controller
            .start_offline("UE-01")
            .unwrap()
            .process_handle
            .clone();
        assert_eq!(first, second);
        controller.stop_offline("UE-01").unwrap();
        controller.stop_offline("UE-01").unwrap();
        assert_eq!(controller.inventory()[0].lifecycle, UeLifecycle::Stopped);
    }

    #[test]
    fn partial_group_failure_never_stops_successful_ue() {
        let mut profiles = ready_profiles(2);
        profiles[1].subscription_verified = false;
        let mut controller = MultiUeController::new(profiles, 2).unwrap();
        let result = controller.start_group_offline(&["UE-01".into(), "UE-02".into()]);
        assert_eq!(result.started, vec!["UE-01"]);
        assert_eq!(result.failed[0].0, "UE-02");
        assert_eq!(controller.inventory()[0].process_state, "MOCK_RUNNING");
    }

    #[test]
    fn resource_limit_and_unknown_ue_fail_closed() {
        let mut controller = MultiUeController::new(ready_profiles(2), 1).unwrap();
        controller.start_offline("UE-01").unwrap();
        assert_eq!(
            controller.start_offline("UE-02").unwrap_err(),
            "UE_RESOURCE_LIMIT"
        );
        assert_eq!(
            controller.start_offline("UE-99").unwrap_err(),
            "UNKNOWN_UE_PROFILE"
        );
    }

    #[test]
    fn registry_recovery_fails_active_jobs_closed_and_preserves_stopped_jobs() {
        let mut controller = MultiUeController::new(ready_profiles(2), 2).unwrap();
        controller.start_offline("UE-01").unwrap();
        controller.start_offline("UE-02").unwrap();
        controller.stop_offline("UE-02").unwrap();
        let snapshot = controller.snapshot();
        let mut recovered = MultiUeController::new(ready_profiles(2), 2).unwrap();
        recovered.recover(snapshot).unwrap();
        let inventory = recovered.inventory();
        assert_eq!(inventory[0].lifecycle, UeLifecycle::Failed);
        assert_eq!(
            inventory[0].last_error.as_deref(),
            Some("CONTROLLER_RESTART_REQUIRES_RECONCILIATION")
        );
        assert_eq!(inventory[1].lifecycle, UeLifecycle::Stopped);
    }

    #[test]
    fn configuration_supports_zero_one_two_five_and_ten_without_starting_processes() {
        let mut controller = MultiUeController::new(ready_profiles(10), 10).unwrap();
        for count in [0, 1, 2, 5, 10] {
            controller.configure_count(count).unwrap();
            assert_eq!(controller.configured_count(), count);
            assert!(controller
                .inventory()
                .iter()
                .all(|job| job.process_handle.is_none()));
        }
    }

    #[test]
    fn profile_crud_requires_stopped_state_and_removes_terminal_identity() {
        let mut profiles = ready_profiles(2);
        profiles[0].configured = true;
        profiles[1].configured = true;
        let mut controller = MultiUeController::new(profiles.clone(), 10).unwrap();
        let mut added = profiles[1].clone();
        added.ue_id = "UE-03".into();
        added.profile_name = "ue-03.yaml".into();
        added.pseudonym = "UE-PSEUDONYM-03".into();
        controller.upsert_profile(added.clone()).unwrap();
        assert!(controller
            .profiles()
            .iter()
            .any(|item| item.ue_id == "UE-03"));

        controller.start_offline("UE-03").unwrap();
        assert_eq!(
            controller.delete_profile("UE-03").unwrap_err(),
            "UE_PROFILE_ACTIVE"
        );
        controller.stop_offline("UE-03").unwrap();
        controller.delete_profile("UE-03").unwrap();
        assert!(!controller
            .profiles()
            .iter()
            .any(|item| item.ue_id == "UE-03"));
        assert!(!controller
            .snapshot()
            .iter()
            .any(|item| item.ue_id == "UE-03"));

        controller.delete_profile("UE-01").unwrap();
        controller.delete_profile("UE-02").unwrap();
        assert!(controller.profiles().is_empty());
        assert!(controller.inventory().is_empty());
    }

    #[test]
    fn configuration_cannot_drop_an_active_owned_ue() {
        let mut controller = MultiUeController::new(ready_profiles(2), 2).unwrap();
        controller.start_offline("UE-02").unwrap();
        assert_eq!(
            controller.configure_count(1).unwrap_err(),
            "ACTIVE_UE_OUTSIDE_REQUESTED_CONFIGURATION"
        );
    }

    #[test]
    fn exact_owned_runtime_can_be_reconciled_without_fabricating_state() {
        let mut controller = MultiUeController::new(ready_profiles(2), 2).unwrap();
        controller
            .record_live_start("UE-02", &format!("container:{}", "a".repeat(64)))
            .unwrap();
        controller
            .apply_observation(
                "UE-02",
                "RUNNING",
                "REGISTERED",
                "ACTIVE",
                Some("10.46.0.7"),
            )
            .unwrap();
        let snapshot = controller.snapshot();

        let mut recovered = MultiUeController::new(ready_profiles(2), 2).unwrap();
        recovered
            .reconcile(snapshot, |ue_id, _, handle| {
                (ue_id == "UE-02" && handle == format!("container:{}", "a".repeat(64))).then(|| {
                    UeObservation {
                        process_state: "RUNNING".into(),
                        registration_state: "NOT_OBSERVED".into(),
                        pdu_session_state: "INACTIVE".into(),
                        ue_ip: None,
                    }
                })
            })
            .unwrap();
        let job = &recovered.inventory()[1];
        assert_eq!(job.process_state, "RUNNING");
        assert_eq!(job.registration_state, "NOT_OBSERVED");
        assert_eq!(job.pdu_session_state, "INACTIVE");
        assert_eq!(job.ue_ip, None);
        assert_eq!(
            job.process_handle,
            Some(format!("container:{}", "a".repeat(64)))
        );
    }

    #[test]
    fn restart_reconciliation_fails_closed_on_ownership_mismatch() {
        let mut controller = MultiUeController::new(ready_profiles(2), 2).unwrap();
        controller
            .record_live_start("UE-02", &format!("container:{}", "d".repeat(64)))
            .unwrap();
        let snapshot = controller.snapshot();
        let mut recovered = MultiUeController::new(ready_profiles(2), 2).unwrap();
        recovered.reconcile(snapshot, |_, _, _| None).unwrap();
        let job = &recovered.inventory()[1];
        assert_eq!(job.lifecycle, UeLifecycle::Failed);
        assert_eq!(job.process_state, "UNKNOWN");
        assert_eq!(
            job.process_handle,
            Some(format!("container:{}", "d".repeat(64)))
        );
        assert_eq!(
            job.last_error.as_deref(),
            Some("CONTROLLER_RESTART_OWNERSHIP_NOT_PROVEN")
        );
    }

    #[test]
    fn live_start_supports_bounded_profiles_after_api_ownership_authorization() {
        let mut controller = MultiUeController::new(ready_profiles(10), 10).unwrap();
        assert_eq!(
            controller
                .record_live_start("UE-02", "container:short")
                .unwrap_err(),
            "INVALID_PROCESS_HANDLE"
        );
        controller
            .record_live_start("UE-01", &format!("container:{}", "a".repeat(64)))
            .unwrap();
        controller
            .record_live_start("UE-02", &format!("container:{}", "b".repeat(64)))
            .unwrap();
        controller
            .record_live_start("UE-03", &format!("container:{}", "c".repeat(64)))
            .unwrap();
        controller
            .record_live_start("UE-10", &format!("container:{}", "d".repeat(64)))
            .unwrap();
    }

    #[test]
    fn durable_reservation_blocks_racing_start_and_recovers_exited_container_as_stopped() {
        let mut controller = MultiUeController::new(ready_profiles(3), 3).unwrap();
        controller
            .reserve_live_start("UE-02", "operation-a", approved_runtime("UE-02"))
            .unwrap();
        assert_eq!(
            controller
                .reserve_live_start("UE-02", "operation-b", approved_runtime("UE-02"))
                .unwrap_err(),
            "UE_OPERATION_IN_PROGRESS"
        );
        let handle = format!("container:{}", "e".repeat(64));
        controller
            .complete_live_start("UE-02", "operation-a", &handle)
            .unwrap();
        let snapshot = controller.snapshot();
        let mut recovered = MultiUeController::new(ready_profiles(3), 3).unwrap();
        recovered
            .reconcile(snapshot, |_, _, _| {
                Some(UeObservation {
                    process_state: "EXITED".into(),
                    registration_state: "NOT_OBSERVED".into(),
                    pdu_session_state: "INACTIVE".into(),
                    ue_ip: None,
                })
            })
            .unwrap();
        let job = &recovered.inventory()[1];
        assert_eq!(job.lifecycle, UeLifecycle::Stopped);
        assert_eq!(job.process_state, "EXITED");
        assert_eq!(job.process_handle.as_deref(), Some(handle.as_str()));
        recovered
            .reserve_live_start("UE-02", "operation-c", approved_runtime("UE-02"))
            .unwrap();
    }

    #[test]
    fn stale_observation_cannot_resurrect_stopped_generation() {
        let mut controller = MultiUeController::new(ready_profiles(3), 3).unwrap();
        let handle = format!("container:{}", "e".repeat(64));
        controller
            .reserve_live_start("UE-02", "operation-a", approved_runtime("UE-02"))
            .unwrap();
        controller
            .complete_live_start("UE-02", "operation-a", &handle)
            .unwrap();
        let generation = controller.snapshot()[0].generation;
        controller.stop_offline("UE-02").unwrap();
        let observed = UeObservation {
            process_state: "RUNNING".into(),
            registration_state: "REGISTERED".into(),
            pdu_session_state: "ACTIVE".into(),
            ue_ip: Some("10.46.0.5".into()),
        };
        assert_eq!(
            controller
                .apply_observation_if_current("UE-02", &handle, None, generation, &observed)
                .unwrap_err(),
            "STALE_UE_OBSERVATION"
        );
        assert_eq!(controller.inventory()[1].process_state, "STOPPED");
    }

    #[test]
    fn paused_and_restarting_observations_replace_prior_active_state() {
        let mut controller = MultiUeController::new(ready_profiles(3), 3).unwrap();
        let handle = format!("container:{}", "f".repeat(64));
        controller.record_live_start("UE-02", &handle).unwrap();
        controller
            .apply_observation(
                "UE-02",
                "RUNNING",
                "REGISTERED",
                "ACTIVE",
                Some("10.46.0.5"),
            )
            .unwrap();
        for state in ["PAUSED", "RESTARTING"] {
            controller
                .apply_observation("UE-02", state, "NOT_OBSERVED", "INACTIVE", None)
                .unwrap();
            let job = &controller.inventory()[1];
            assert_eq!(job.process_state, state);
            assert_eq!(job.registration_state, "NOT_OBSERVED");
            assert_eq!(job.pdu_session_state, "INACTIVE");
        }
    }

    #[test]
    fn catalog_capacity_is_independent_from_live_capacity() {
        let mut controller = MultiUeController::new(Vec::new(), 10).unwrap();
        let additions = (1..=100)
            .map(|index| UeProfileSpec {
                ue_id: format!("UE-{index:05}"),
                pseudonym: format!("UE {index}"),
                profile_name: format!("ue-{index:05}.yaml"),
                serving_gnb: "GNB-01".into(),
                plmn_mcc: "001".into(),
                plmn_mnc: "01".into(),
                dnn: "internet".into(),
                sst: 1,
                sd: Some("010203".into()),
                configured: true,
                subscription_verified: false,
            })
            .collect();
        controller.add_profiles(additions).unwrap();
        assert_eq!(controller.configured_count(), 100);
        controller.configure_count(10).unwrap();
        assert_eq!(
            controller.configure_count(11).unwrap_err(),
            "UE_COUNT_OUT_OF_RANGE"
        );
        assert!(controller
            .inventory()
            .iter()
            .all(|ue| ue.process_handle.is_none()));
    }

    /// 0.19.5 — Startup scenario: a leftover `operation_id` from a
    /// crashed Stop. `release_stale_locks(_, 0)` must reap every
    /// surviving lock regardless of its age, and return a per-UE
    /// report so the caller can audit each reclaim.
    #[test]
    fn release_stale_locks_at_startup_reaps_every_leftover_lock() {
        let mut controller = MultiUeController::new(ready_profiles(3), 3).unwrap();
        controller
            .reserve_live_start("UE-02", "op-abc", approved_runtime("UE-02"))
            .unwrap();
        // The lock is fresh (locked_at = now); `max_age_s = 0` means
        // ANY surviving lock is treated as stale → reap.
        let released = controller.release_stale_locks(now_epoch_s() + 1, 0);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].ue_id, "UE-02");
        assert_eq!(released[0].operation_id, "op-abc");
        assert!(released[0].locked_at_epoch_s.is_some());
        // After reap, operation_id is None (the registry no longer
        // reports a lock on this UE).
        let job = &controller.inventory()[1];
        assert_eq!(job.ue_id, "UE-02");
        assert!(job.operation_id.is_none());
        assert!(job.operation_locked_at_epoch_s.is_none());
    }

    /// 0.19.5 — Runtime scenario: a lock older than
    /// MAX_OPERATION_LOCK_SECONDS expires. A fresher lock (younger
    /// than max_age) stays untouched.
    #[test]
    fn release_stale_locks_during_runtime_evicts_only_locks_past_max_age() {
        let mut controller = MultiUeController::new(ready_profiles(3), 3).unwrap();
        controller
            .reserve_live_start("UE-02", "op-stale", approved_runtime("UE-02"))
            .unwrap();
        controller
            .complete_live_start(
                "UE-02",
                "op-stale",
                &format!("container:{}", "e".repeat(64)),
            )
            .unwrap();
        controller
            .reserve_live_start("UE-03", "op-fresh", approved_runtime("UE-03"))
            .unwrap();
        // Make UE-02 look stale by rewriting its locked_at timestamp
        // to five minutes ago. Then simulate reserve_live_stop by
        // stamping a new lock on UE-02 directly to exercise the age
        // check in isolation.
        let now = now_epoch_s();
        {
            let job = controller
                .jobs
                .get_mut("UE-02")
                .expect("UE-02 is in the registry");
            job.operation_id = Some("op-stale-2".into());
            job.operation_locked_at_epoch_s = Some(now.saturating_sub(600));
        }
        let released = controller.release_stale_locks(now, MAX_OPERATION_LOCK_SECONDS);
        assert_eq!(released.len(), 1, "only the stale lock is reaped");
        assert_eq!(released[0].ue_id, "UE-02");
        // The fresh UE-03 lock survived the sweep.
        let ue03 = controller.inventory().into_iter().find(|job| job.ue_id == "UE-03").unwrap();
        assert_eq!(ue03.operation_id.as_deref(), Some("op-fresh"));
    }

    /// 0.19.5 — Stop priority: when the current lock is older than
    /// MAX_OPERATION_LOCK_SECONDS, `reserve_live_stop` reclaims it
    /// instead of returning UE_OPERATION_IN_PROGRESS. A FRESH lock
    /// still produces the historical 409.
    #[test]
    fn reserve_live_stop_reclaims_an_expired_lock_but_refuses_a_fresh_one() {
        let mut controller = MultiUeController::new(ready_profiles(3), 3).unwrap();
        controller
            .reserve_live_start("UE-02", "op-ghost", approved_runtime("UE-02"))
            .unwrap();
        controller
            .complete_live_start(
                "UE-02",
                "op-ghost",
                &format!("container:{}", "e".repeat(64)),
            )
            .unwrap();
        // Install a fresh lock on UE-02 (simulate a stuck Stop
        // in-flight) and attempt a competing Stop. Fresh → refused.
        let now = now_epoch_s();
        {
            let job = controller.jobs.get_mut("UE-02").unwrap();
            job.operation_id = Some("op-stuck".into());
            job.operation_locked_at_epoch_s = Some(now);
        }
        let refused = controller.reserve_live_stop(
            "UE-02",
            "op-new",
            now + 1,
            MAX_OPERATION_LOCK_SECONDS,
        );
        assert_eq!(refused.unwrap_err(), "UE_OPERATION_IN_PROGRESS");

        // Age the lock past the max → Stop reclaims it.
        {
            let job = controller.jobs.get_mut("UE-02").unwrap();
            job.operation_locked_at_epoch_s = Some(now.saturating_sub(600));
        }
        let reclaimed = controller
            .reserve_live_stop("UE-02", "op-new", now, MAX_OPERATION_LOCK_SECONDS)
            .expect("expired lock must be reclaimed");
        assert_eq!(reclaimed.operation_id.as_deref(), Some("op-new"));
    }

    fn now_epoch_s() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }
}
