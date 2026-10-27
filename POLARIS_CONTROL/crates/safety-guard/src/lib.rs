use serde::{Deserialize, Serialize};
use std::{ffi::CString, path::Path};

pub const VERSION: &str = "0.1.0";
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
            information: 75,
            warning: 80,
            stop: 85,
            hard: 90,
            reserve_bytes: 32 * MIB,
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
    let Some(bp) = sample.basis_points() else {
        return evaluate(Err("invalid filesystem".into()), policy);
    };
    let t = |value: u8| u16::from(value) * 100;
    let state = if bp >= t(policy.hard) {
        State::HardLimit
    } else if bp >= t(policy.stop) {
        State::StopNewWrites
    } else if bp >= t(policy.warning) {
        State::Warning
    } else if bp >= t(policy.information) {
        State::Information
    } else {
        State::Normal
    };
    let stop_used = (u128::from(sample.total_bytes) * u128::from(policy.stop) / 100) as u64;
    let maximum_budget_bytes = stop_used
        .saturating_sub(sample.used_bytes())
        .saturating_sub(policy.reserve_bytes)
        .min(policy.max_scenario_bytes);
    let writes_allowed =
        state < State::StopNewWrites && maximum_budget_bytes > 0 && sample.available_inodes > 16;
    Decision {
        state,
        writes_allowed,
        finalize_owned_writes: state >= State::StopNewWrites,
        reason: format!("usage {:.2}%", f64::from(bp) / 100.0),
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
    fn exact_thresholds() {
        let p = Policy {
            reserve_bytes: 0,
            max_scenario_bytes: 100 * MIB,
            ..Policy::default()
        };
        assert_eq!(evaluate(at(75), p).state, State::Information);
        assert_eq!(evaluate(at(80), p).state, State::Warning);
        assert_eq!(evaluate(at(85), p).state, State::StopNewWrites);
        assert_eq!(evaluate(at(90), p).state, State::HardLimit)
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
        assert_eq!(evaluate(at(80), p).maximum_budget_bytes, 3 * MIB)
    }
}
