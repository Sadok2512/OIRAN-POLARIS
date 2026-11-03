use serde::{Deserialize, Serialize};
use std::{ffi::CString, path::Path};

pub const VERSION: &str = "0.2.0";
const MIB: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub information: u8,
    pub warning: u8,
    pub stop: u8,
    pub hard: u8,
    pub reserve_bytes: u64,
    pub max_scenario_bytes: u64,
    pub poll_ms: u64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            // Percentage thresholds are retained for wire compatibility only.
            // 0.29.8 does not use them to reject writes.
            information: 100,
            warning: 100,
            stop: 100,
            hard: 100,
            reserve_bytes: 0,
            max_scenario_bytes: 2 * 1024 * MIB,
            poll_ms: 1_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sample {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub total_inodes: u64,
    pub available_inodes: u64,
}
impl Sample {
    pub fn used_bytes(self) -> u64 {
        self.total_bytes.saturating_sub(self.available_bytes)
    }
    pub fn basis_points(self) -> Option<u16> {
        (self.total_bytes > 0).then(|| {
            ((u128::from(self.used_bytes()) * 10_000) / u128::from(self.total_bytes)) as u16
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Normal,
    Information,
    Warning,
    StopNewWrites,
    HardLimit,
    MeasurementFailed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    pub state: State,
    pub writes_allowed: bool,
    pub finalize_owned_writes: bool,
    pub reason: String,
    pub maximum_budget_bytes: u64,
}

pub fn evaluate(sample: Result<Sample, String>, policy: Policy) -> Decision {
    let Ok(sample) = sample else {
        return Decision {
            state: State::MeasurementFailed,
            writes_allowed: false,
            finalize_owned_writes: true,
            reason: "filesystem measurement failed; writes fail closed".into(),
            maximum_budget_bytes: 0,
        };
    };
    let Some(_bp) = sample.basis_points() else {
        return evaluate(Err("invalid filesystem".into()), policy);
    };
    let state = State::Normal;
    let maximum_budget_bytes = sample
        .available_bytes
        .saturating_sub(policy.reserve_bytes)
        .min(policy.max_scenario_bytes);
    let writes_allowed = maximum_budget_bytes > 0 && sample.available_inodes > 0;
    Decision {
        state,
        writes_allowed,
        finalize_owned_writes: !writes_allowed,
        reason: format!(
            "available_bytes={} available_inodes={}",
            sample.available_bytes, sample.available_inodes
        ),
        maximum_budget_bytes,
    }
}

pub fn measure(path: &Path) -> Result<Sample, String> {
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| "invalid path")?;
    let mut raw = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: valid NUL-terminated path and writable output pointer.
    if unsafe { libc::statvfs(path.as_ptr(), raw.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: statvfs returned success.
    let raw = unsafe { raw.assume_init() };
    let block = raw.f_frsize as u64;
    Ok(Sample {
        total_bytes: (raw.f_blocks as u64).saturating_mul(block),
        available_bytes: (raw.f_bavail as u64).saturating_mul(block),
        total_inodes: raw.f_files as u64,
        available_inodes: raw.f_favail as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn at(p: u64) -> Result<Sample, String> {
        Ok(Sample {
            total_bytes: 100 * MIB,
            available_bytes: (100 - p) * MIB,
            total_inodes: 1000,
            available_inodes: 900,
        })
    }
    #[test]
    fn percentages_never_block_writes() {
        let p = Policy {
            reserve_bytes: 0,
            max_scenario_bytes: 100 * MIB,
            ..Policy::default()
        };
        for used_percent in [80, 85, 90, 98, 99] {
            let decision = evaluate(at(used_percent), p);
            assert_eq!(decision.state, State::Normal);
            assert!(decision.writes_allowed);
        }
    }
    #[test]
    fn monitor_failure_is_closed() {
        let d = evaluate(Err("x".into()), Policy::default());
        assert!(!d.writes_allowed);
        assert!(d.finalize_owned_writes)
    }
    #[test]
    fn reserve_caps_budget() {
        let p = Policy {
            reserve_bytes: 2 * MIB,
            max_scenario_bytes: 50 * MIB,
            ..Policy::default()
        };
        assert_eq!(evaluate(at(90), p).maximum_budget_bytes, 8 * MIB)
    }

    #[test]
    fn legacy_thresholds_do_not_block_when_budget_and_reserve_fit() {
        let p = Policy {
            reserve_bytes: MIB,
            max_scenario_bytes: 10 * MIB,
            ..Policy::default()
        };
        for used_percent in [80, 85, 90] {
            let decision = evaluate(at(used_percent), p);
            assert!(decision.writes_allowed, "{used_percent}% must not block");
            assert_eq!(decision.state, State::Normal);
        }
    }

    #[test]
    fn projected_budget_and_absolute_reserve_use_free_bytes_only() {
        let p = Policy {
            reserve_bytes: 2 * MIB,
            max_scenario_bytes: 50 * MIB,
            ..Policy::default()
        };
        let decision = evaluate(at(97), p);
        assert_eq!(decision.state, State::Normal);
        assert!(decision.writes_allowed);
        assert_eq!(decision.maximum_budget_bytes, MIB);
    }

    #[test]
    fn inode_exhaustion_and_measurement_failure_remain_closed() {
        let mut sample = at(50).unwrap();
        sample.available_inodes = 0;
        assert!(!evaluate(Ok(sample), Policy::default()).writes_allowed);
        assert!(!evaluate(Err("ENOSPC".into()), Policy::default()).writes_allowed);
    }
}
