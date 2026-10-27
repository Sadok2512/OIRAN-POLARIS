//! Fail-closed storage policy for OIRAN-owned capture jobs.

use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::path::Path;

pub const VERSION: &str = "0.1.0";
const MIB: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub information_percent: u8,
    pub warning_percent: u8,
    pub stop_percent: u8,
    pub hard_limit_percent: u8,
    pub max_file_bytes: u64,
    pub max_files: u16,
    pub max_job_seconds: u64,
    pub max_concurrent_jobs: u8,
    pub polling_interval_ms: u64,
    pub reserve_bytes: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            information_percent: 75,
            warning_percent: 80,
            stop_percent: 85,
            hard_limit_percent: 90,
            max_file_bytes: 256 * MIB,
            max_files: 8,
            max_job_seconds: 15 * 60,
            max_concurrent_jobs: 1,
            polling_interval_ms: 1_000,
            reserve_bytes: 32 * MIB,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesystemSample {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub total_inodes: u64,
    pub available_inodes: u64,
}

impl FilesystemSample {
    pub fn used_bytes(self) -> Option<u64> {
        self.total_bytes.checked_sub(self.available_bytes)
    }
    pub fn usage_basis_points(self) -> Option<u16> {
        let used = self.used_bytes()?;
        (self.total_bytes > 0)
            .then(|| ((u128::from(used) * 10_000) / u128::from(self.total_bytes)) as u16)
    }
    pub fn usage_percent(self) -> Option<f64> {
        self.usage_basis_points()
            .map(|value| f64::from(value) / 100.0)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SafetyState {
    Normal,
    Information,
    Warning,
    StopNewCaptures,
    DiskHardLimit,
    MeasurementFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub state: SafetyState,
    pub new_capture_allowed: bool,
    pub active_capture_must_finalize: bool,
    pub read_only_analysis_allowed: bool,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureBudget {
    pub allowed: bool,
    pub requested_bytes: u64,
    pub maximum_allowed_bytes: u64,
    pub headroom_to_stop_bytes: u64,
    pub reserved_bytes: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotationPlan {
    pub max_file_bytes: u64,
    pub max_files: u16,
    pub maximum_job_bytes: u64,
    pub max_job_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureGuard {
    policy: Policy,
    active: bool,
    remaining_budget_bytes: u64,
    written_bytes: u64,
    final_reason: Option<String>,
}

impl CaptureGuard {
    pub fn start(
        sample: Result<FilesystemSample, String>,
        requested_bytes: u64,
        policy: Policy,
    ) -> Result<Self, String> {
        let budget = capture_budget(sample, requested_bytes, policy);
        if !budget.allowed {
            return Err(budget.reason);
        }
        Ok(Self {
            policy,
            active: true,
            remaining_budget_bytes: requested_bytes,
            written_bytes: 0,
            final_reason: None,
        })
    }

    pub fn authorize_write(
        &mut self,
        bytes: u64,
        sample: Result<FilesystemSample, String>,
    ) -> Result<(), String> {
        if !self.active {
            return Err("capture guard is finalized".into());
        }
        let decision = assess(sample, self.policy);
        if !decision.new_capture_allowed || bytes > self.remaining_budget_bytes {
            self.active = false;
            self.final_reason = Some(if bytes > self.remaining_budget_bytes {
                "reserved write budget exhausted".into()
            } else {
                decision.reason
            });
            return Err(self.final_reason.clone().unwrap());
        }
        self.remaining_budget_bytes -= bytes;
        self.written_bytes = self.written_bytes.saturating_add(bytes);
        Ok(())
    }

    pub fn interrupt(&mut self, reason: &str) {
        self.active = false;
        self.final_reason = Some(reason.into());
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn written_bytes(&self) -> u64 {
        self.written_bytes
    }

    pub fn final_reason(&self) -> Option<&str> {
        self.final_reason.as_deref()
    }
}

pub fn assess(sample: Result<FilesystemSample, String>, policy: Policy) -> Decision {
    let Ok(sample) = sample else {
        return Decision {
            state: SafetyState::MeasurementFailed,
            new_capture_allowed: false,
            active_capture_must_finalize: true,
            read_only_analysis_allowed: true,
            reason: "filesystem measurement unavailable; capture writes fail closed".into(),
        };
    };
    let Some(basis_points) = sample.usage_basis_points() else {
        return assess(Err("invalid filesystem capacity".into()), policy);
    };
    let percent = |value: u8| u16::from(value) * 100;
    let state = if basis_points >= percent(policy.hard_limit_percent) {
        SafetyState::DiskHardLimit
    } else if basis_points >= percent(policy.stop_percent) {
        SafetyState::StopNewCaptures
    } else if basis_points >= percent(policy.warning_percent) {
        SafetyState::Warning
    } else if basis_points >= percent(policy.information_percent) {
        SafetyState::Information
    } else {
        SafetyState::Normal
    };
    Decision {
        state,
        new_capture_allowed: state < SafetyState::StopNewCaptures,
        active_capture_must_finalize: state >= SafetyState::StopNewCaptures,
        read_only_analysis_allowed: true,
        reason: format!("filesystem usage {:.2}%", f64::from(basis_points) / 100.0),
    }
}

pub fn capture_budget(
    sample: Result<FilesystemSample, String>,
    requested_bytes: u64,
    policy: Policy,
) -> CaptureBudget {
    let decision = assess(sample.clone(), policy);
    let Ok(sample) = sample else {
        return CaptureBudget {
            allowed: false,
            requested_bytes,
            maximum_allowed_bytes: 0,
            headroom_to_stop_bytes: 0,
            reserved_bytes: policy.reserve_bytes,
            reason: decision.reason,
        };
    };
    let used = sample.used_bytes().unwrap_or(sample.total_bytes);
    let stop_used = (u128::from(sample.total_bytes) * u128::from(policy.stop_percent) / 100) as u64;
    let headroom = stop_used.saturating_sub(used);
    let rotation_cap = policy
        .max_file_bytes
        .saturating_mul(u64::from(policy.max_files));
    let maximum = headroom
        .saturating_sub(policy.reserve_bytes)
        .min(rotation_cap);
    let allowed = decision.new_capture_allowed
        && requested_bytes > 0
        && requested_bytes <= maximum
        && sample.available_inodes > u64::from(policy.max_files) + 2;
    CaptureBudget {
        allowed,
        requested_bytes,
        maximum_allowed_bytes: maximum,
        headroom_to_stop_bytes: headroom,
        reserved_bytes: policy.reserve_bytes,
        reason: if allowed {
            "bounded write budget accepted below the 85% stop threshold".into()
        } else {
            "capture rejected: threshold, inode, or reserved-budget requirement not met".into()
        },
    }
}

pub fn rotation_plan(policy: Policy) -> RotationPlan {
    RotationPlan {
        max_file_bytes: policy.max_file_bytes,
        max_files: policy.max_files,
        maximum_job_bytes: policy
            .max_file_bytes
            .saturating_mul(u64::from(policy.max_files)),
        max_job_seconds: policy.max_job_seconds,
    }
}

pub fn measure_path(path: &Path) -> Result<FilesystemSample, String> {
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| "path contains NUL")?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stats` points to writable storage.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: successful statvfs initializes the complete structure.
    let stats = unsafe { stats.assume_init() };
    let block_size = stats.f_frsize as u64;
    Ok(FilesystemSample {
        total_bytes: (stats.f_blocks as u64).saturating_mul(block_size),
        available_bytes: (stats.f_bavail as u64).saturating_mul(block_size),
        total_inodes: stats.f_files as u64,
        available_inodes: stats.f_favail as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(percent: u64) -> Result<FilesystemSample, String> {
        Ok(FilesystemSample {
            total_bytes: 100 * MIB,
            available_bytes: (100 - percent) * MIB,
            total_inodes: 10_000,
            available_inodes: 9_000,
        })
    }

    #[test]
    fn thresholds_are_exact_and_fail_closed() {
        let policy = Policy::default();
        assert_eq!(assess(at(74), policy).state, SafetyState::Normal);
        assert_eq!(assess(at(75), policy).state, SafetyState::Information);
        assert_eq!(assess(at(80), policy).state, SafetyState::Warning);
        assert_eq!(assess(at(85), policy).state, SafetyState::StopNewCaptures);
        assert_eq!(assess(at(90), policy).state, SafetyState::DiskHardLimit);
        let failed = assess(Err("monitor failed".into()), policy);
        assert_eq!(failed.state, SafetyState::MeasurementFailed);
        assert!(!failed.new_capture_allowed);
        assert!(failed.active_capture_must_finalize);
    }

    #[test]
    fn budget_reserves_headroom_between_polls() {
        let policy = Policy {
            reserve_bytes: MIB,
            max_file_bytes: 10 * MIB,
            max_files: 2,
            ..Policy::default()
        };
        assert!(capture_budget(at(70), 10 * MIB, policy).allowed);
        assert!(!capture_budget(at(84), MIB, policy).allowed);
        assert!(!capture_budget(at(70), 21 * MIB, policy).allowed);
    }

    #[test]
    fn inode_exhaustion_rejects_capture() {
        let sample = FilesystemSample {
            total_bytes: 100 * MIB,
            available_bytes: 50 * MIB,
            total_inodes: 100,
            available_inodes: 2,
        };
        assert!(!capture_budget(Ok(sample), MIB, Policy::default()).allowed);
    }

    #[test]
    fn rotation_is_bounded_without_deletion_action() {
        let plan = rotation_plan(Policy::default());
        assert_eq!(plan.max_file_bytes, 256 * MIB);
        assert_eq!(plan.max_files, 8);
        assert_eq!(plan.maximum_job_bytes, 2 * 1024 * MIB);
    }

    #[test]
    fn stop_and_hard_limit_preserve_read_only_analysis() {
        for percent in [85, 90] {
            let decision = assess(at(percent), Policy::default());
            assert!(decision.active_capture_must_finalize);
            assert!(decision.read_only_analysis_allowed);
        }
    }

    #[test]
    fn active_capture_finalizes_at_stop_threshold_and_on_monitor_failure() {
        let policy = Policy {
            reserve_bytes: MIB,
            max_file_bytes: 10 * MIB,
            max_files: 2,
            ..Policy::default()
        };
        let mut guard = CaptureGuard::start(at(70), 10 * MIB, policy).unwrap();
        guard.authorize_write(MIB, at(80)).unwrap();
        assert!(guard.authorize_write(MIB, at(85)).is_err());
        assert!(!guard.is_active());
        let mut guard = CaptureGuard::start(at(70), 10 * MIB, policy).unwrap();
        assert!(guard
            .authorize_write(MIB, Err("statvfs failed".into()))
            .is_err());
        assert_eq!(
            guard.final_reason(),
            Some("filesystem measurement unavailable; capture writes fail closed")
        );
    }

    #[test]
    fn reserved_budget_and_operator_interruption_are_deterministic() {
        let policy = Policy {
            reserve_bytes: MIB,
            max_file_bytes: 10 * MIB,
            max_files: 2,
            ..Policy::default()
        };
        let mut guard = CaptureGuard::start(at(70), 2 * MIB, policy).unwrap();
        guard.authorize_write(MIB, at(70)).unwrap();
        assert!(guard.authorize_write(2 * MIB, at(70)).is_err());
        assert_eq!(guard.written_bytes(), MIB);
        let mut interrupted = CaptureGuard::start(at(70), 2 * MIB, policy).unwrap();
        interrupted.interrupt("operator requested graceful stop");
        assert!(!interrupted.is_active());
        assert!(interrupted.authorize_write(1, at(70)).is_err());
    }
}
