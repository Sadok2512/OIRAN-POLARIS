use serde::Serialize;
use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MIB: u64 = 1024 * 1024;
static DECISION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ScenarioResourceBudget {
    pub id: String,
    pub cpu_cpus: f64,
    pub ram_bytes: u64,
    pub storage_bytes: u64,
    pub target_capacity_cpus: f64,
    pub concurrent_reservations: usize,
}

impl ScenarioResourceBudget {
    pub fn traffic() -> Self {
        Self {
            id: "BOUNDED_UDP_TRAFFIC".into(),
            cpu_cpus: 0.10,
            ram_bytes: 64 * MIB,
            storage_bytes: 0,
            target_capacity_cpus: 1.0,
            concurrent_reservations: 0,
        }
    }

    pub fn ue(additions: usize) -> Self {
        Self {
            id: format!("UE_LIFECYCLE_{additions}"),
            cpu_cpus: 0.75 * additions as f64,
            ram_bytes: 512 * MIB * additions as u64,
            storage_bytes: 0,
            target_capacity_cpus: 0.75 * additions as f64,
            concurrent_reservations: additions.saturating_sub(1),
        }
    }

    pub fn four_plane_capture() -> Self {
        Self {
            id: "OIRAN_FOUR_PLANE_CAPTURE".into(),
            cpu_cpus: 2.0,
            ram_bytes: 512 * MIB,
            storage_bytes: 256 * MIB,
            target_capacity_cpus: 2.0,
            concurrent_reservations: 0,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct HostCpuTelemetry {
    pub valid: bool,
    pub source: &'static str,
    pub observed_at_epoch_ms: u64,
    pub sample_duration_ms: u64,
    pub logical_cpus: usize,
    pub user_percent: Option<f64>,
    pub system_percent: Option<f64>,
    pub usage_percent: Option<f64>,
    pub idle_percent: Option<f64>,
    pub iowait_percent: Option<f64>,
    pub steal_percent: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuPressureTelemetry {
    pub valid: bool,
    pub source: &'static str,
    pub some_avg10: Option<f64>,
    pub some_avg60: Option<f64>,
    pub some_avg300: Option<f64>,
    pub full_avg10: Option<f64>,
    pub full_avg60: Option<f64>,
    pub full_avg300: Option<f64>,
    pub some_stall_delta_usec: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CgroupTelemetry {
    pub valid: bool,
    pub version: &'static str,
    pub source: String,
    pub effective_capacity_cpus: Option<f64>,
    pub effective_cpuset_cpus: Option<usize>,
    pub nr_periods_delta: Option<u64>,
    pub nr_throttled_delta: Option<u64>,
    pub throttled_usec_delta: Option<u64>,
    pub throttled_period_ratio: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuTriggerEvidence {
    pub metric: String,
    pub observed_value: Option<f64>,
    pub threshold: Option<f64>,
    pub comparator: String,
    pub consecutive_samples: usize,
    pub required_samples: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuSafetyEvidence {
    pub decision_id: String,
    pub decision_timestamp_epoch_ms: u64,
    pub state: String,
    pub classification: String,
    pub blocking: bool,
    pub reason: String,
    pub trigger: Option<CpuTriggerEvidence>,
    pub sample_window_ms: u64,
    pub ready: bool,
    pub telemetry_fresh: bool,
    pub telemetry_age_ms: u64,
    pub observed_at_epoch_ms: u64,
    pub valid_samples: usize,
    pub consecutive_breaches: usize,
    pub consecutive_recoveries: usize,
    pub host: HostCpuTelemetry,
    pub pressure: CpuPressureTelemetry,
    pub api_cgroup: CgroupTelemetry,
    pub ue_target_capacity_cpus: f64,
    pub oiran_capture_capacity_cpus: Option<f64>,
    pub available_host_cpus: Option<f64>,
    pub shared_headroom_cpus: f64,
    pub budget: ScenarioResourceBudget,
}

#[derive(Clone, Debug)]
pub struct CpuSafetyPolicy {
    pub sample_interval: Duration,
    pub stale_after: Duration,
    pub minimum_valid_samples: usize,
    pub breach_samples: usize,
    pub recovery_samples: usize,
    pub host_block_percent: f64,
    pub host_recovery_percent: f64,
    pub psi_block_avg10: f64,
    pub psi_recovery_avg10: f64,
    pub throttle_block_ratio: f64,
    pub throttle_recovery_ratio: f64,
    pub shared_headroom_cpus: f64,
}

impl Default for CpuSafetyPolicy {
    fn default() -> Self {
        Self {
            sample_interval: Duration::from_secs(1),
            stale_after: Duration::from_secs(5),
            minimum_valid_samples: 3,
            breach_samples: 3,
            recovery_samples: 3,
            host_block_percent: 90.0,
            host_recovery_percent: 80.0,
            psi_block_avg10: 20.0,
            psi_recovery_avg10: 10.0,
            throttle_block_ratio: 0.20,
            throttle_recovery_ratio: 0.05,
            shared_headroom_cpus: 1.0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CpuCounters {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

impl CpuCounters {
    fn total(self) -> u64 {
        self.user
            .saturating_add(self.nice)
            .saturating_add(self.system)
            .saturating_add(self.idle)
            .saturating_add(self.iowait)
            .saturating_add(self.irq)
            .saturating_add(self.softirq)
            .saturating_add(self.steal)
    }
}

#[derive(Clone, Copy, Debug)]
struct ThrottleCounters {
    nr_periods: u64,
    nr_throttled: u64,
    throttled_usec: u64,
}

#[derive(Clone, Debug)]
struct RawTelemetry {
    host: HostCpuTelemetry,
    pressure: CpuPressureTelemetry,
    api_cgroup: CgroupTelemetry,
    oiran_capture_capacity_cpus: Option<f64>,
}

#[derive(Clone, Debug)]
struct CgroupLocation {
    version: &'static str,
    path: String,
}

pub struct CpuSafetyMonitor {
    policy: CpuSafetyPolicy,
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    previous_cpu: Option<(CpuCounters, Instant)>,
    previous_throttle: Option<ThrottleCounters>,
    previous_pressure_total: Option<u64>,
    latest: Option<RawTelemetry>,
    history: VecDeque<RawTelemetry>,
    blocked_latched: bool,
}

impl Default for CpuSafetyMonitor {
    fn default() -> Self {
        Self::new(CpuSafetyPolicy::default(), "/proc", "/sys/fs/cgroup")
    }
}

impl CpuSafetyMonitor {
    pub fn new(
        policy: CpuSafetyPolicy,
        proc_root: impl Into<PathBuf>,
        cgroup_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            proc_root: proc_root.into(),
            cgroup_root: cgroup_root.into(),
            previous_cpu: None,
            previous_throttle: None,
            previous_pressure_total: None,
            latest: None,
            history: VecDeque::new(),
            blocked_latched: false,
        }
    }

    pub fn sample_interval(&self) -> Duration {
        self.policy.sample_interval
    }

    pub fn refresh(&mut self) {
        let now = Instant::now();
        let epoch_ms = epoch_ms();
        let stat = fs::read_to_string(self.proc_root.join("stat"));
        let counters = stat.as_deref().ok().and_then(parse_cpu_counters);
        let logical_cpus = stat.as_deref().map(logical_cpu_count).unwrap_or(0);
        let host = match (self.previous_cpu, counters) {
            (Some((previous, previous_at)), Some(current)) => host_delta(
                previous,
                current,
                now.duration_since(previous_at),
                logical_cpus,
                epoch_ms,
            ),
            _ => invalid_host(logical_cpus, epoch_ms),
        };
        if let Some(counters) = counters {
            self.previous_cpu = Some((counters, now));
        }

        let pressure_text = fs::read_to_string(self.proc_root.join("pressure/cpu")).ok();
        let (mut pressure, total) = pressure_text
            .as_deref()
            .map(parse_pressure)
            .unwrap_or_else(|| (invalid_pressure(), None));
        pressure.some_stall_delta_usec = self
            .previous_pressure_total
            .zip(total)
            .and_then(|(previous, current)| current.checked_sub(previous));
        if let Some(total) = total {
            self.previous_pressure_total = Some(total);
        }

        let cgroup = self.current_cgroup_location();
        let capacity = cgroup.as_ref().and_then(|location| match location.version {
            "v2" => effective_capacity(&self.cgroup_root, &location.path),
            "v1" => effective_capacity_v1(&self.cgroup_root, &location.path),
            _ => None,
        });
        let current_throttle = cgroup.as_ref().and_then(|location| match location.version {
            "v2" => read_throttle(
                &self
                    .cgroup_root
                    .join(location.path.trim_start_matches('/'))
                    .join("cpu.stat"),
            ),
            "v1" => read_throttle_v1(
                &self
                    .cgroup_root
                    .join("cpu")
                    .join(location.path.trim_start_matches('/'))
                    .join("cpu.stat"),
            ),
            _ => None,
        });
        let throttle_delta =
            self.previous_throttle
                .zip(current_throttle)
                .and_then(|(previous, current)| {
                    Some(ThrottleCounters {
                        nr_periods: current.nr_periods.checked_sub(previous.nr_periods)?,
                        nr_throttled: current.nr_throttled.checked_sub(previous.nr_throttled)?,
                        throttled_usec: current
                            .throttled_usec
                            .checked_sub(previous.throttled_usec)?,
                    })
                });
        if let Some(current) = current_throttle {
            self.previous_throttle = Some(current);
        }
        let api_cgroup = CgroupTelemetry {
            valid: cgroup.is_some() && capacity.is_some() && current_throttle.is_some(),
            version: cgroup.as_ref().map_or("unknown", |value| value.version),
            source: cgroup
                .as_ref()
                .map(|value| value.path.clone())
                .unwrap_or_else(|| "UNKNOWN".into()),
            effective_capacity_cpus: capacity.map(|value| value.0),
            effective_cpuset_cpus: capacity.map(|value| value.1),
            nr_periods_delta: throttle_delta.map(|value| value.nr_periods),
            nr_throttled_delta: throttle_delta.map(|value| value.nr_throttled),
            throttled_usec_delta: throttle_delta.map(|value| value.throttled_usec),
            throttled_period_ratio: throttle_delta.and_then(|value| {
                (value.nr_periods > 0)
                    .then_some(value.nr_throttled as f64 / value.nr_periods as f64)
            }),
        };
        let oiran_capacity = [
            "/system.slice/oiran-api.service",
            "/system.slice/oiran-capture-helper.service",
        ]
        .iter()
        .map(|path| effective_capacity(&self.cgroup_root, path).map(|value| value.0))
        .collect::<Option<Vec<_>>>()
        .map(|values| values.into_iter().sum());

        let telemetry = RawTelemetry {
            host,
            pressure,
            api_cgroup,
            oiran_capture_capacity_cpus: oiran_capacity,
        };
        self.latest = Some(telemetry.clone());
        self.history.push_back(telemetry);
        while self.history.len() > 32 {
            self.history.pop_front();
        }
    }

    pub fn evaluate(&mut self, budget: ScenarioResourceBudget) -> CpuSafetyEvidence {
        let now_ms = epoch_ms();
        let Some(raw) = self.latest.clone() else {
            return unavailable_evidence(
                budget,
                now_ms,
                "BLOCKED_STALE_TELEMETRY",
                "CPU_TELEMETRY_NOT_SAMPLED",
            );
        };
        let age = now_ms.saturating_sub(raw.host.observed_at_epoch_ms);
        let fresh = age <= self.policy.stale_after.as_millis() as u64;
        let mandatory_valid = raw.host.valid && raw.pressure.valid && raw.api_cgroup.valid;
        let available_host_cpus = raw
            .host
            .idle_percent
            .map(|idle| raw.host.logical_cpus as f64 * idle / 100.0);
        let valid_samples = self
            .history
            .iter()
            .rev()
            .take_while(|sample| {
                sample.host.valid
                    && sample.pressure.valid
                    && sample.api_cgroup.valid
                    && now_ms.saturating_sub(sample.host.observed_at_epoch_ms)
                        <= self.policy.stale_after.as_millis() as u64
            })
            .count();
        let current_violation = sample_violation(&raw, &budget, &self.policy);
        let consecutive_breaches = current_violation.as_ref().map_or(0, |current| {
            self.history
                .iter()
                .rev()
                .take_while(|sample| {
                    sample_violation(sample, &budget, &self.policy)
                        .is_some_and(|candidate| candidate.reason == current.reason)
                })
                .count()
        });
        let consecutive_recoveries = self
            .history
            .iter()
            .rev()
            .take_while(|sample| sample_is_recovered(sample, &budget, &self.policy))
            .count();

        let sample_window_ms = raw.host.sample_duration_ms.saturating_mul(
            valid_samples.min(self.policy.breach_samples.max(self.policy.recovery_samples)) as u64,
        );
        let (state, classification, reason, ready, trigger) = if !fresh || !mandatory_valid {
            (
                "BLOCKED_STALE_TELEMETRY",
                "BLOCKED",
                "MANDATORY_CPU_TELEMETRY_INVALID_OR_STALE",
                false,
                Some(trigger(
                    "telemetry_age_ms",
                    Some(age as f64),
                    Some(self.policy.stale_after.as_millis() as f64),
                    ">",
                    1,
                    1,
                )),
            )
        } else if valid_samples < self.policy.minimum_valid_samples {
            (
                "BLOCKED_STALE_TELEMETRY",
                "BLOCKED",
                "CPU_TELEMETRY_WARMING_UP",
                false,
                Some(trigger(
                    "valid_samples",
                    Some(valid_samples as f64),
                    Some(self.policy.minimum_valid_samples as f64),
                    "<",
                    valid_samples,
                    self.policy.minimum_valid_samples,
                )),
            )
        } else if let Some(violation) = current_violation {
            let evidence = Some(trigger(
                violation.metric,
                violation.observed_value,
                violation.threshold,
                violation.comparator,
                consecutive_breaches,
                if violation.requires_sustained {
                    self.policy.breach_samples
                } else {
                    1
                },
            ));
            if !violation.requires_sustained {
                (
                    violation.state,
                    "BLOCKED",
                    violation.reason,
                    false,
                    evidence,
                )
            } else if consecutive_breaches >= self.policy.breach_samples {
                self.blocked_latched = true;
                (
                    violation.state,
                    "BLOCKED",
                    violation.reason,
                    false,
                    evidence,
                )
            } else if self.blocked_latched {
                (
                    "WARNING_BLOCKING",
                    "WARNING_BLOCKING",
                    violation.reason,
                    false,
                    evidence,
                )
            } else {
                (
                    "WARNING_NON_BLOCKING",
                    "WARNING_NON_BLOCKING",
                    violation.reason,
                    true,
                    evidence,
                )
            }
        } else if self.blocked_latched {
            if consecutive_recoveries >= self.policy.recovery_samples {
                self.blocked_latched = false;
                ("READY", "READY", "CPU_SAFETY_CONDITIONS_PASS", true, None)
            } else {
                (
                    "WARNING_BLOCKING",
                    "WARNING_BLOCKING",
                    "CPU_RECOVERY_SAMPLING",
                    false,
                    Some(trigger(
                        "consecutive_recovery_samples",
                        Some(consecutive_recoveries as f64),
                        Some(self.policy.recovery_samples as f64),
                        "<",
                        consecutive_recoveries,
                        self.policy.recovery_samples,
                    )),
                )
            }
        } else if let Some(recovery) = recovery_warning(&raw, &self.policy) {
            (
                "WARNING_NON_BLOCKING",
                "WARNING_NON_BLOCKING",
                recovery.reason,
                true,
                Some(trigger(
                    recovery.metric,
                    recovery.observed_value,
                    recovery.threshold,
                    recovery.comparator,
                    1,
                    self.policy.breach_samples,
                )),
            )
        } else {
            ("READY", "READY", "CPU_SAFETY_CONDITIONS_PASS", true, None)
        };
        CpuSafetyEvidence {
            decision_id: format!(
                "cpu-{now_ms}-{:08}",
                DECISION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ),
            decision_timestamp_epoch_ms: now_ms,
            state: state.into(),
            classification: classification.into(),
            blocking: !ready,
            reason: reason.into(),
            trigger,
            sample_window_ms,
            ready,
            telemetry_fresh: fresh,
            telemetry_age_ms: age,
            observed_at_epoch_ms: raw.host.observed_at_epoch_ms,
            valid_samples,
            consecutive_breaches,
            consecutive_recoveries,
            host: raw.host,
            pressure: raw.pressure,
            api_cgroup: raw.api_cgroup,
            ue_target_capacity_cpus: 0.75,
            oiran_capture_capacity_cpus: raw.oiran_capture_capacity_cpus,
            available_host_cpus,
            shared_headroom_cpus: self.policy.shared_headroom_cpus,
            budget,
        }
    }

    fn current_cgroup_location(&self) -> Option<CgroupLocation> {
        let value = fs::read_to_string(self.proc_root.join("self/cgroup")).ok()?;
        if let Some(path) = value.lines().find_map(|line| line.strip_prefix("0::")) {
            return Some(CgroupLocation {
                version: "v2",
                path: path.into(),
            });
        }
        value.lines().find_map(|line| {
            let mut fields = line.splitn(3, ':');
            let _hierarchy = fields.next()?;
            let controllers = fields.next()?;
            let path = fields.next()?;
            controllers
                .split(',')
                .any(|controller| controller == "cpu")
                .then(|| CgroupLocation {
                    version: "v1",
                    path: path.into(),
                })
        })
    }

    #[cfg(test)]
    fn inject(&mut self, raw: RawTelemetry) {
        self.latest = Some(raw.clone());
        self.history.push_back(raw);
    }
}

#[derive(Clone, Debug)]
struct CpuViolation {
    state: &'static str,
    reason: &'static str,
    metric: &'static str,
    observed_value: Option<f64>,
    threshold: Option<f64>,
    comparator: &'static str,
    requires_sustained: bool,
}

fn violation(
    state: &'static str,
    reason: &'static str,
    metric: &'static str,
    observed_value: Option<f64>,
    threshold: Option<f64>,
    requires_sustained: bool,
) -> CpuViolation {
    CpuViolation {
        state,
        reason,
        metric,
        observed_value,
        threshold,
        comparator: if reason == "TARGET_CGROUP_CAPACITY_BELOW_SCENARIO_BUDGET"
            || reason == "INSUFFICIENT_HOST_CPU_HEADROOM"
        {
            "<"
        } else {
            ">="
        },
        requires_sustained,
    }
}

fn trigger(
    metric: &str,
    observed_value: Option<f64>,
    threshold: Option<f64>,
    comparator: &str,
    consecutive_samples: usize,
    required_samples: usize,
) -> CpuTriggerEvidence {
    CpuTriggerEvidence {
        metric: metric.into(),
        observed_value,
        threshold,
        comparator: comparator.into(),
        consecutive_samples,
        required_samples,
    }
}

fn sample_violation(
    raw: &RawTelemetry,
    budget: &ScenarioResourceBudget,
    policy: &CpuSafetyPolicy,
) -> Option<CpuViolation> {
    if raw.host.logical_cpus == 0 || raw.api_cgroup.effective_capacity_cpus.unwrap_or(0.0) <= 0.0 {
        Some(violation(
            "BLOCKED_UNKNOWN_CAPACITY",
            "CPU_CAPACITY_UNAVAILABLE",
            "effective_cpu_capacity",
            raw.api_cgroup.effective_capacity_cpus,
            Some(f64::EPSILON),
            false,
        ))
    } else if budget.target_capacity_cpus + f64::EPSILON < budget.cpu_cpus {
        Some(violation(
            "BLOCKED_RESOURCE_BUDGET",
            "TARGET_CGROUP_CAPACITY_BELOW_SCENARIO_BUDGET",
            "target_cgroup_capacity_cpus",
            Some(budget.target_capacity_cpus),
            Some(budget.cpu_cpus),
            false,
        ))
    } else if raw.api_cgroup.throttled_period_ratio.unwrap_or(0.0) >= policy.throttle_block_ratio {
        Some(violation(
            "BLOCKED_CGROUP_THROTTLING",
            "POLARIS_CGROUP_SUSTAINED_THROTTLING",
            "api_cgroup_throttled_period_ratio",
            raw.api_cgroup.throttled_period_ratio,
            Some(policy.throttle_block_ratio),
            true,
        ))
    } else if raw.pressure.some_avg10.unwrap_or(100.0) >= policy.psi_block_avg10 {
        Some(violation(
            "BLOCKED_CPU_PRESSURE",
            "HOST_CPU_PSI_SUSTAINED_PRESSURE",
            "cpu_psi_some_avg10",
            raw.pressure.some_avg10,
            Some(policy.psi_block_avg10),
            true,
        ))
    } else if raw.host.usage_percent.unwrap_or(100.0) >= policy.host_block_percent {
        Some(violation(
            "BLOCKED_HOST_CPU",
            "HOST_CPU_SUSTAINED_UTILIZATION",
            "host_cpu_usage_percent",
            raw.host.usage_percent,
            Some(policy.host_block_percent),
            true,
        ))
    } else if raw
        .host
        .idle_percent
        .map(|idle| raw.host.logical_cpus as f64 * idle / 100.0)
        .unwrap_or(0.0)
        < budget.cpu_cpus + policy.shared_headroom_cpus
    {
        Some(violation(
            "BLOCKED_RESOURCE_BUDGET",
            "INSUFFICIENT_HOST_CPU_HEADROOM",
            "available_host_cpus",
            raw.host
                .idle_percent
                .map(|idle| raw.host.logical_cpus as f64 * idle / 100.0),
            Some(budget.cpu_cpus + policy.shared_headroom_cpus),
            false,
        ))
    } else {
        None
    }
}

fn recovery_warning(raw: &RawTelemetry, policy: &CpuSafetyPolicy) -> Option<CpuViolation> {
    if raw.host.usage_percent.unwrap_or(100.0) > policy.host_recovery_percent {
        Some(violation(
            "WARNING_NON_BLOCKING",
            "HOST_CPU_ABOVE_RECOVERY_THRESHOLD",
            "host_cpu_usage_percent",
            raw.host.usage_percent,
            Some(policy.host_recovery_percent),
            true,
        ))
    } else if raw.pressure.some_avg10.unwrap_or(100.0) > policy.psi_recovery_avg10 {
        Some(violation(
            "WARNING_NON_BLOCKING",
            "CPU_PSI_ABOVE_RECOVERY_THRESHOLD",
            "cpu_psi_some_avg10",
            raw.pressure.some_avg10,
            Some(policy.psi_recovery_avg10),
            true,
        ))
    } else if raw.api_cgroup.throttled_period_ratio.unwrap_or(0.0) > policy.throttle_recovery_ratio
    {
        Some(violation(
            "WARNING_NON_BLOCKING",
            "CGROUP_THROTTLING_ABOVE_RECOVERY_THRESHOLD",
            "api_cgroup_throttled_period_ratio",
            raw.api_cgroup.throttled_period_ratio,
            Some(policy.throttle_recovery_ratio),
            true,
        ))
    } else {
        None
    }
}

fn sample_is_recovered(
    raw: &RawTelemetry,
    budget: &ScenarioResourceBudget,
    policy: &CpuSafetyPolicy,
) -> bool {
    sample_violation(raw, budget, policy).is_none()
        && raw.host.usage_percent.unwrap_or(100.0) <= policy.host_recovery_percent
        && raw.pressure.some_avg10.unwrap_or(100.0) <= policy.psi_recovery_avg10
        && raw.api_cgroup.throttled_period_ratio.unwrap_or(0.0) <= policy.throttle_recovery_ratio
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn parse_cpu_counters(value: &str) -> Option<CpuCounters> {
    let mut fields = value.lines().next()?.split_whitespace();
    (fields.next()? == "cpu").then_some(())?;
    let values = fields
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (values.len() >= 8).then_some(CpuCounters {
        user: values[0],
        nice: values[1],
        system: values[2],
        idle: values[3],
        iowait: values[4],
        irq: values[5],
        softirq: values[6],
        steal: values[7],
    })
}

fn logical_cpu_count(value: &str) -> usize {
    value
        .lines()
        .filter(|line| {
            let name = line.split_whitespace().next().unwrap_or_default();
            name.strip_prefix("cpu").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
            })
        })
        .count()
}

fn host_delta(
    previous: CpuCounters,
    current: CpuCounters,
    duration: Duration,
    logical_cpus: usize,
    epoch_ms: u64,
) -> HostCpuTelemetry {
    let Some(total) = current
        .total()
        .checked_sub(previous.total())
        .filter(|value| *value > 0)
    else {
        return invalid_host(logical_cpus, epoch_ms);
    };
    let pct = |current: u64, previous: u64| {
        current
            .checked_sub(previous)
            .map(|delta| delta as f64 * 100.0 / total as f64)
    };
    let idle = pct(current.idle, previous.idle);
    let iowait = pct(current.iowait, previous.iowait);
    HostCpuTelemetry {
        valid: idle.is_some() && iowait.is_some() && logical_cpus > 0,
        source: "/proc/stat",
        observed_at_epoch_ms: epoch_ms,
        sample_duration_ms: duration.as_millis() as u64,
        logical_cpus,
        user_percent: pct(
            current.user.saturating_add(current.nice),
            previous.user.saturating_add(previous.nice),
        ),
        system_percent: pct(
            current
                .system
                .saturating_add(current.irq)
                .saturating_add(current.softirq),
            previous
                .system
                .saturating_add(previous.irq)
                .saturating_add(previous.softirq),
        ),
        usage_percent: idle
            .zip(iowait)
            .map(|(idle, iowait)| (100.0 - idle - iowait).clamp(0.0, 100.0)),
        idle_percent: idle,
        iowait_percent: iowait,
        steal_percent: pct(current.steal, previous.steal),
    }
}

fn invalid_host(logical_cpus: usize, observed_at_epoch_ms: u64) -> HostCpuTelemetry {
    HostCpuTelemetry {
        valid: false,
        source: "/proc/stat",
        observed_at_epoch_ms,
        sample_duration_ms: 0,
        logical_cpus,
        user_percent: None,
        system_percent: None,
        usage_percent: None,
        idle_percent: None,
        iowait_percent: None,
        steal_percent: None,
    }
}

fn parse_pressure(value: &str) -> (CpuPressureTelemetry, Option<u64>) {
    let parse_line = |prefix: &str| -> Option<(f64, f64, f64, u64)> {
        let line = value.lines().find(|line| line.starts_with(prefix))?;
        let field = |name: &str| {
            line.split_whitespace()
                .find_map(|item| item.strip_prefix(name))
        };
        Some((
            field("avg10=")?.parse().ok()?,
            field("avg60=")?.parse().ok()?,
            field("avg300=")?.parse().ok()?,
            field("total=")?.parse().ok()?,
        ))
    };
    let some = parse_line("some ");
    let full = parse_line("full ");
    (
        CpuPressureTelemetry {
            valid: some.is_some(),
            source: "/proc/pressure/cpu",
            some_avg10: some.map(|v| v.0),
            some_avg60: some.map(|v| v.1),
            some_avg300: some.map(|v| v.2),
            full_avg10: full.map(|v| v.0),
            full_avg60: full.map(|v| v.1),
            full_avg300: full.map(|v| v.2),
            some_stall_delta_usec: None,
        },
        some.map(|v| v.3),
    )
}

fn invalid_pressure() -> CpuPressureTelemetry {
    CpuPressureTelemetry {
        valid: false,
        source: "/proc/pressure/cpu",
        some_avg10: None,
        some_avg60: None,
        some_avg300: None,
        full_avg10: None,
        full_avg60: None,
        full_avg300: None,
        some_stall_delta_usec: None,
    }
}

fn parse_cpu_set(value: &str) -> Option<usize> {
    let mut count = 0usize;
    for item in value.trim().split(',').filter(|item| !item.is_empty()) {
        if let Some((start, end)) = item.split_once('-') {
            let start: usize = start.parse().ok()?;
            let end: usize = end.parse().ok()?;
            count = count.checked_add(end.checked_sub(start)?.checked_add(1)?)?;
        } else {
            item.parse::<usize>().ok()?;
            count = count.checked_add(1)?;
        }
    }
    (count > 0).then_some(count)
}

fn quota_capacity(value: &str) -> Option<Option<f64>> {
    let mut fields = value.split_whitespace();
    let quota = fields.next()?;
    let period: f64 = fields.next()?.parse().ok()?;
    if quota == "max" {
        Some(None)
    } else {
        Some(Some(quota.parse::<f64>().ok()? / period))
    }
}

fn effective_capacity(root: &Path, cgroup: &str) -> Option<(f64, usize)> {
    let mut current = root.join(cgroup.trim_start_matches('/'));
    let root = root
        .canonicalize()
        .ok()
        .unwrap_or_else(|| root.to_path_buf());
    let mut quota: Option<f64> = None;
    let mut cpuset: Option<usize> = None;
    loop {
        if let Ok(value) = fs::read_to_string(current.join("cpu.max")) {
            if let Some(Some(value)) = quota_capacity(&value) {
                quota = Some(quota.map_or(value, |existing| existing.min(value)));
            }
        }
        if let Ok(value) = fs::read_to_string(current.join("cpuset.cpus.effective")) {
            if let Some(value) = parse_cpu_set(&value) {
                cpuset = Some(cpuset.map_or(value, |existing| existing.min(value)));
            }
        }
        if current == root || !current.starts_with(&root) || !current.pop() {
            break;
        }
    }
    let cpuset = cpuset?;
    Some((quota.unwrap_or(cpuset as f64).min(cpuset as f64), cpuset))
}

fn effective_capacity_v1(root: &Path, cgroup: &str) -> Option<(f64, usize)> {
    let relative = cgroup.trim_start_matches('/');
    let cpu = root.join("cpu").join(relative);
    let quota: f64 = fs::read_to_string(cpu.join("cpu.cfs_quota_us"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let period: f64 = fs::read_to_string(cpu.join("cpu.cfs_period_us"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let cpuset = fs::read_to_string(root.join("cpuset").join(relative).join("cpuset.cpus"))
        .ok()
        .and_then(|value| parse_cpu_set(&value))
        .or_else(|| {
            let count = logical_cpu_count(&fs::read_to_string("/proc/stat").ok()?);
            (count > 0).then_some(count)
        })?;
    let quota_capacity = if quota < 0.0 {
        cpuset as f64
    } else {
        quota / period
    };
    Some((quota_capacity.min(cpuset as f64), cpuset))
}

fn read_throttle(path: &Path) -> Option<ThrottleCounters> {
    let value = fs::read_to_string(path).ok()?;
    let field = |name: &str| {
        value
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.trim().parse().ok())
    };
    Some(ThrottleCounters {
        nr_periods: field("nr_periods ")?,
        nr_throttled: field("nr_throttled ")?,
        throttled_usec: field("throttled_usec ")?,
    })
}

fn read_throttle_v1(path: &Path) -> Option<ThrottleCounters> {
    let value = fs::read_to_string(path).ok()?;
    let field = |name: &str| {
        value
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.trim().parse::<u64>().ok())
    };
    Some(ThrottleCounters {
        nr_periods: field("nr_periods ")?,
        nr_throttled: field("nr_throttled ")?,
        throttled_usec: field("throttled_time ")?.saturating_div(1_000),
    })
}

fn unavailable_evidence(
    budget: ScenarioResourceBudget,
    now_ms: u64,
    state: &str,
    reason: &str,
) -> CpuSafetyEvidence {
    CpuSafetyEvidence {
        decision_id: format!(
            "cpu-{now_ms}-{:08}",
            DECISION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ),
        decision_timestamp_epoch_ms: now_ms,
        state: state.into(),
        classification: "BLOCKED".into(),
        blocking: true,
        reason: reason.into(),
        trigger: Some(trigger(
            "telemetry_availability",
            None,
            None,
            "required",
            0,
            1,
        )),
        sample_window_ms: 0,
        ready: false,
        telemetry_fresh: false,
        telemetry_age_ms: u64::MAX,
        observed_at_epoch_ms: now_ms,
        valid_samples: 0,
        consecutive_breaches: 0,
        consecutive_recoveries: 0,
        host: invalid_host(0, now_ms),
        pressure: invalid_pressure(),
        api_cgroup: CgroupTelemetry {
            valid: false,
            version: "v2",
            source: "UNKNOWN".into(),
            effective_capacity_cpus: None,
            effective_cpuset_cpus: None,
            nr_periods_delta: None,
            nr_throttled_delta: None,
            throttled_usec_delta: None,
            throttled_period_ratio: None,
        },
        ue_target_capacity_cpus: 0.75,
        oiran_capture_capacity_cpus: None,
        available_host_cpus: None,
        shared_headroom_cpus: 1.0,
        budget,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SAMPLE_ID: AtomicU64 = AtomicU64::new(1);

    fn raw(
        usage: f64,
        idle: f64,
        psi: f64,
        throttle: f64,
        cpus: usize,
        api_capacity: f64,
    ) -> RawTelemetry {
        let now = epoch_ms();
        RawTelemetry {
            host: HostCpuTelemetry {
                valid: true,
                source: "/proc/stat",
                observed_at_epoch_ms: now,
                sample_duration_ms: 1000,
                logical_cpus: cpus,
                user_percent: Some(usage),
                system_percent: Some(0.0),
                usage_percent: Some(usage),
                idle_percent: Some(idle),
                iowait_percent: Some(0.0),
                steal_percent: Some(0.0),
            },
            pressure: CpuPressureTelemetry {
                valid: true,
                source: "/proc/pressure/cpu",
                some_avg10: Some(psi),
                some_avg60: Some(psi),
                some_avg300: Some(psi),
                full_avg10: Some(0.0),
                full_avg60: Some(0.0),
                full_avg300: Some(0.0),
                some_stall_delta_usec: Some(0),
            },
            api_cgroup: CgroupTelemetry {
                valid: true,
                version: "v2",
                source: "/test".into(),
                effective_capacity_cpus: Some(api_capacity),
                effective_cpuset_cpus: Some(cpus),
                nr_periods_delta: Some(100),
                nr_throttled_delta: Some((throttle * 100.0) as u64),
                throttled_usec_delta: Some(0),
                throttled_period_ratio: Some(throttle),
            },
            oiran_capture_capacity_cpus: Some(2.0),
        }
    }

    fn evaluate_samples(
        monitor: &mut CpuSafetyMonitor,
        samples: Vec<RawTelemetry>,
        budget: ScenarioResourceBudget,
    ) -> CpuSafetyEvidence {
        let mut result = unavailable_evidence(
            budget.clone(),
            epoch_ms(),
            "BLOCKED_STALE_TELEMETRY",
            "TEST",
        );
        for mut sample in samples {
            sample.host.observed_at_epoch_ms =
                epoch_ms().saturating_add(SAMPLE_ID.fetch_add(1, Ordering::Relaxed));
            monitor.inject(sample);
            result = monitor.evaluate(budget.clone());
        }
        result
    }

    #[test]
    fn ten_cpu_host_with_one_busy_process_is_ready() {
        let mut monitor = CpuSafetyMonitor::default();
        let samples = (0..3).map(|_| raw(18.0, 82.0, 2.0, 0.0, 10, 1.0)).collect();
        assert_eq!(
            evaluate_samples(&mut monitor, samples, ScenarioResourceBudget::ue(1)).state,
            "READY"
        );
    }

    #[test]
    fn one_cpu_api_quota_does_not_normalize_host_utilization() {
        let mut monitor = CpuSafetyMonitor::default();
        let samples = (0..3).map(|_| raw(20.0, 80.0, 1.0, 0.0, 10, 1.0)).collect();
        assert!(evaluate_samples(&mut monitor, samples, ScenarioResourceBudget::traffic()).ready);
    }

    #[test]
    fn true_host_saturation_requires_consecutive_samples() {
        let mut monitor = CpuSafetyMonitor::default();
        let first = evaluate_samples(
            &mut monitor,
            vec![raw(95.0, 5.0, 2.0, 0.0, 10, 1.0)],
            ScenarioResourceBudget::traffic(),
        );
        assert_ne!(first.state, "BLOCKED_HOST_CPU");
        let rest = evaluate_samples(
            &mut monitor,
            vec![
                raw(95.0, 5.0, 2.0, 0.0, 10, 1.0),
                raw(95.0, 5.0, 2.0, 0.0, 10, 1.0),
            ],
            ScenarioResourceBudget::traffic(),
        );
        assert_eq!(rest.state, "BLOCKED_HOST_CPU");
    }

    #[test]
    fn target_capacity_blocks_oversized_job() {
        let mut budget = ScenarioResourceBudget::ue(1);
        budget.target_capacity_cpus = 0.5;
        let mut monitor = CpuSafetyMonitor::default();
        let result = evaluate_samples(
            &mut monitor,
            (0..3).map(|_| raw(10.0, 90.0, 0.0, 0.0, 10, 1.0)).collect(),
            budget,
        );
        assert_eq!(result.state, "BLOCKED_RESOURCE_BUDGET");
    }

    #[test]
    fn sustained_throttling_blocks() {
        let mut monitor = CpuSafetyMonitor::default();
        let result = evaluate_samples(
            &mut monitor,
            (0..3).map(|_| raw(10.0, 90.0, 0.0, 0.5, 10, 1.0)).collect(),
            ScenarioResourceBudget::traffic(),
        );
        assert_eq!(result.state, "BLOCKED_CGROUP_THROTTLING");
    }

    #[test]
    fn sustained_psi_blocks() {
        let mut monitor = CpuSafetyMonitor::default();
        let result = evaluate_samples(
            &mut monitor,
            (0..3)
                .map(|_| raw(20.0, 80.0, 25.0, 0.0, 10, 1.0))
                .collect(),
            ScenarioResourceBudget::traffic(),
        );
        assert_eq!(result.state, "BLOCKED_CPU_PRESSURE");
    }

    #[test]
    fn transient_spike_stays_warning_and_recovers_with_hysteresis() {
        let mut monitor = CpuSafetyMonitor::default();
        let budget = ScenarioResourceBudget::traffic();
        let warm = (0..3).map(|_| raw(10.0, 90.0, 0.0, 0.0, 10, 1.0)).collect();
        assert!(evaluate_samples(&mut monitor, warm, budget.clone()).ready);
        let spike = evaluate_samples(
            &mut monitor,
            vec![raw(95.0, 5.0, 0.0, 0.0, 10, 1.0)],
            budget.clone(),
        );
        assert_eq!(spike.state, "WARNING_NON_BLOCKING");
        assert_eq!(spike.classification, "WARNING_NON_BLOCKING");
        assert!(spike.ready);
        assert_eq!(
            spike.trigger.as_ref().map(|value| value.metric.as_str()),
            Some("host_cpu_usage_percent")
        );
        let recovered = evaluate_samples(
            &mut monitor,
            (0..3).map(|_| raw(10.0, 90.0, 0.0, 0.0, 10, 1.0)).collect(),
            budget,
        );
        assert!(recovered.ready);
    }

    #[test]
    fn sustained_block_requires_recovery_hysteresis() {
        let mut monitor = CpuSafetyMonitor::default();
        let budget = ScenarioResourceBudget::traffic();
        let blocked = evaluate_samples(
            &mut monitor,
            (0..3).map(|_| raw(10.0, 90.0, 0.0, 0.5, 10, 1.0)).collect(),
            budget.clone(),
        );
        assert_eq!(blocked.classification, "BLOCKED");
        assert!(!blocked.ready);

        let recovering = evaluate_samples(
            &mut monitor,
            vec![raw(10.0, 90.0, 0.0, 0.0, 10, 1.0)],
            budget.clone(),
        );
        assert_eq!(recovering.state, "WARNING_BLOCKING");
        assert!(!recovering.ready);

        let recovered = evaluate_samples(
            &mut monitor,
            vec![
                raw(10.0, 90.0, 0.0, 0.0, 10, 1.0),
                raw(10.0, 90.0, 0.0, 0.0, 10, 1.0),
            ],
            budget,
        );
        assert_eq!(recovered.state, "READY");
        assert!(recovered.ready);
    }

    #[test]
    fn hard_budget_violation_blocks_without_waiting_for_three_samples() {
        let mut monitor = CpuSafetyMonitor::default();
        let warm = (0..3).map(|_| raw(10.0, 90.0, 0.0, 0.0, 10, 1.0)).collect();
        assert!(evaluate_samples(&mut monitor, warm, ScenarioResourceBudget::traffic()).ready);
        let mut oversized = ScenarioResourceBudget::traffic();
        oversized.cpu_cpus = 1.5;
        oversized.target_capacity_cpus = 1.0;
        let result = monitor.evaluate(oversized);
        assert_eq!(result.state, "BLOCKED_RESOURCE_BUDGET");
        assert_eq!(result.classification, "BLOCKED");
        assert!(!result.ready);
    }

    #[test]
    fn stale_telemetry_fails_closed() {
        let mut monitor = CpuSafetyMonitor::default();
        let mut sample = raw(10.0, 90.0, 0.0, 0.0, 10, 1.0);
        sample.host.observed_at_epoch_ms = epoch_ms().saturating_sub(10_000);
        monitor.inject(sample);
        assert_eq!(
            monitor.evaluate(ScenarioResourceBudget::traffic()).state,
            "BLOCKED_STALE_TELEMETRY"
        );
    }

    #[test]
    fn missing_cgroup_fails_closed() {
        let mut monitor = CpuSafetyMonitor::default();
        let mut sample = raw(10.0, 90.0, 0.0, 0.0, 10, 1.0);
        sample.api_cgroup.valid = false;
        monitor.inject(sample);
        assert_eq!(
            monitor.evaluate(ScenarioResourceBudget::traffic()).state,
            "BLOCKED_STALE_TELEMETRY"
        );
    }

    #[test]
    fn invalid_proc_delta_is_rejected() {
        let previous = CpuCounters {
            user: 10,
            nice: 0,
            system: 0,
            idle: 10,
            iowait: 0,
            irq: 0,
            softirq: 0,
            steal: 0,
        };
        assert!(!host_delta(previous, previous, Duration::from_secs(1), 10, epoch_ms()).valid);
    }

    #[test]
    fn resource_overcommit_blocks() {
        let mut monitor = CpuSafetyMonitor::default();
        let result = evaluate_samples(
            &mut monitor,
            (0..3).map(|_| raw(80.0, 20.0, 0.0, 0.0, 10, 1.0)).collect(),
            ScenarioResourceBudget::four_plane_capture(),
        );
        assert_eq!(result.state, "BLOCKED_RESOURCE_BUDGET");
    }

    #[test]
    fn multiple_ue_reservation_is_bounded_by_target_capacity() {
        let mut monitor = CpuSafetyMonitor::default();
        let result = evaluate_samples(
            &mut monitor,
            (0..3).map(|_| raw(10.0, 90.0, 0.0, 0.0, 10, 1.0)).collect(),
            ScenarioResourceBudget::ue(2),
        );
        assert_eq!(result.budget.cpu_cpus, 1.5);
        assert_eq!(result.budget.target_capacity_cpus, 1.5);
    }

    #[test]
    fn parsers_handle_cpu_pressure_cpuset_and_quota() {
        assert_eq!(parse_cpu_set("0-3,6,8-9"), Some(7));
        assert_eq!(quota_capacity("75000 100000"), Some(Some(0.75)));
        assert_eq!(quota_capacity("max 100000"), Some(None));
        let (pressure, total) = parse_pressure("some avg10=1.00 avg60=2.00 avg300=3.00 total=42\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
        assert!(pressure.valid);
        assert_eq!(total, Some(42));
    }
}
