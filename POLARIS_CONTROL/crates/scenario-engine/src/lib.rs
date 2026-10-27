use serde::{Deserialize, Serialize};
use traffic_engine::Profile;
pub const VERSION: &str = "0.2.0";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StartMode {
    Sequential,
    Staggered,
    Concurrent,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum State {
    Draft,
    Validated,
    AwaitingLiveApproval,
    Running,
    Stopping,
    Stopped,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scenario {
    pub scenario_id: String,
    pub name: String,
    pub ue_count: u8,
    pub start_mode: StartMode,
    pub stagger_seconds: u8,
    pub traffic: Profile,
    pub state: State,
}
pub fn validate(s: &Scenario) -> Result<(), String> {
    if s.scenario_id.is_empty() || s.name.is_empty() {
        return Err("scenario identity required".into());
    }
    if s.ue_count == 0 || s.ue_count > 10 {
        return Err("UE count must be between 1 and 10".into());
    }
    if s.stagger_seconds > 30 {
        return Err("stagger exceeds 30 seconds".into());
    }
    Ok(())
}
pub fn transition(from: State, to: State) -> Result<State, String> {
    let ok = matches!(
        (&from, &to),
        (State::Draft, State::Validated)
            | (State::Validated, State::AwaitingLiveApproval)
            | (State::AwaitingLiveApproval, State::Running)
            | (State::Running, State::Stopping)
            | (State::Stopping, State::Stopped)
            | (_, State::Failed)
    );
    ok.then_some(to).ok_or("invalid scenario transition".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    use traffic_engine::{Profile, Protocol};
    fn s() -> Scenario {
        Scenario {
            scenario_id: "s1".into(),
            name: "bounded".into(),
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
            state: State::Draft,
        }
    }
    #[test]
    fn validates_ue_limit() {
        assert!(validate(&s()).is_ok());
        let mut x = s();
        x.ue_count = 11;
        assert!(validate(&x).is_err())
    }
    #[test]
    fn transitions_are_explicit() {
        assert_eq!(
            transition(State::Draft, State::Validated).unwrap(),
            State::Validated
        );
        assert!(transition(State::Draft, State::Running).is_err())
    }
}
