//! Fixture-driven tests. Each fixture exercises the full `verify()` pipeline
//! and asserts the exact gate verdicts + final verdict + blockers.

use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

#[test]
fn e0497_reproduces_no_lte_e2e_real_pass_with_exact_blockers() {
    let report = lte_e2e_verify::verify(&fixture("e0497")).expect("verify");
    assert_eq!(report.run_id, "lte-run-e0497fd986d8429e03c642cc7fae3de9");

    let gate = |name: &str| {
        report
            .gates
            .iter()
            .find(|(gate, _)| *gate == name)
            .map(|(_, verdict)| verdict.label())
            .unwrap_or_default()
    };
    assert_eq!(gate("S1_SETUP"), "PASS");
    assert_eq!(gate("ATTACH"), "PASS");
    assert_eq!(gate("EPS_BEARER"), "PASS_CONTROL_PLANE_ONLY");
    assert_eq!(gate("S1U_GTPU"), "FAIL");
    assert_eq!(gate("PING_UL"), "FAIL");
    assert_eq!(gate("PING_DL"), "FAIL");
    assert_eq!(gate("UDP_UL"), "FAIL");
    assert_eq!(gate("UDP_DL"), "FAIL");
    assert_eq!(gate("CLEANUP"), "PASS");
    assert_eq!(gate("GRANT_REVOKED"), "PASS");
    assert_eq!(gate("DUMPCAP"), "PASS");

    assert_eq!(
        report.blockers(),
        vec!["PING_UL", "S1U_GTPU", "PING_DL", "UDP_UL", "UDP_DL"]
    );
    assert_eq!(report.final_verdict(), "NO_LTE_E2E_REAL_PASS");

    // The rendered report must contain the mission header and the exact
    // blocker string so Codex and ANR3 can grep for them.
    let rendered = report.render();
    assert!(rendered.starts_with("MISSION=LTE_E2E_NORTH_STAR\n"));
    assert!(rendered.contains("\nBLOCKERS=PING_UL,S1U_GTPU,PING_DL,UDP_UL,UDP_DL\n"));
    assert!(rendered.ends_with("\nFINAL_VERDICT=NO_LTE_E2E_REAL_PASS\n"));
}

#[test]
fn synthetic_complete_run_emits_real_pass() {
    let report = lte_e2e_verify::verify(&fixture("synthetic-complete")).expect("verify");
    assert_eq!(report.run_id, "lte-run-synthetic-complete-0001");
    assert!(report.blockers().is_empty());
    assert_eq!(report.final_verdict(), "REAL_PASS");
    assert!(report
        .gates
        .iter()
        .all(|(_, verdict)| verdict.passed()));
    assert!(report.render().contains("\nFINAL_VERDICT=REAL_PASS\n"));
}

#[test]
fn teid_mismatch_fails_s1u_gtpu_only() {
    let report = lte_e2e_verify::verify(&fixture("teid-mismatch")).expect("verify");
    assert_eq!(report.run_id, "lte-run-teid-mismatch-0001");
    // Every other gate passes; S1U_GTPU is the only blocker.
    assert_eq!(report.blockers(), vec!["S1U_GTPU"]);
    assert_eq!(report.final_verdict(), "NO_LTE_E2E_REAL_PASS");
}

#[test]
fn e0497_with_0295_diagnostics_keeps_identical_blockers_and_exposes_runtime_diagnostic() {
    // 0.1.1: the same e0497 run, re-emitted by POLARIS 0.29.5 with the new
    // ping_runtime_diagnostic persisted on the failed step, must yield the
    // same verdict + the same blocker list AND let the caller introspect
    // the diagnostic without parsing the raw JSON itself.
    let report =
        lte_e2e_verify::verify(&fixture("e0497-with-0295-diagnostics")).expect("verify");
    assert_eq!(
        report.blockers(),
        vec!["PING_UL", "S1U_GTPU", "PING_DL", "UDP_UL", "UDP_DL"]
    );
    assert_eq!(report.final_verdict(), "NO_LTE_E2E_REAL_PASS");

    // Re-load the control proof separately via the public types to prove the
    // new accessor returns the persisted sub-document.
    let path = fixture("e0497-with-0295-diagnostics")
        .join("sanitized-summaries/RUN.control-proof.json");
    let bytes = std::fs::read(&path).unwrap();
    let control: lte_e2e_verify::ControlProof = serde_json::from_slice(&bytes).unwrap();
    let step = control
        .steps
        .iter()
        .find(|step| step.index == 6)
        .expect("ping_ul step");
    let diagnostic = step
        .ping_runtime_diagnostic()
        .expect("ping_runtime_diagnostic persisted");
    let evidence = diagnostic.get("evidence").expect("evidence sub-document");
    for key in [
        "ping",
        "ue_link",
        "ue_routes",
        "srsue_log_tail",
        "srsenb_log_tail",
        "enb",
        "enb_link_counters",
        "container_image_ids",
    ] {
        assert!(evidence.get(key).is_some(), "missing persisted key {key}");
    }
    // Sanitizer must have redacted any subscriber material. The fixture
    // contains "[REDACTED_SUBSCRIBER_MATERIAL]" tokens; the verifier must
    // never see raw IMSI/IMEI/MSISDN/K/OPc strings.
    let serialized = serde_json::to_string(diagnostic).unwrap();
    for forbidden in ["IMSI=", "IMEI=", "IMEISV=", "MSISDN=", "OPC=", "Ki="] {
        assert!(
            !serialized.contains(forbidden),
            "diagnostic unexpectedly contains {forbidden}"
        );
    }
}

#[test]
fn verifier_0_1_2_exposes_enb_link_counters_for_s1u_and_zmq() {
    // 0.1.2: the POLARIS fix commit c5f191f adds `enb_link_counters` with the
    // s1u and zmq roles. The verifier must expose this sub-document via
    // `Step::enb_link_counters()` so Codex can introspect the UL/DL byte and
    // drop counters without re-parsing the raw JSON.
    let path = fixture("e0497-with-0295-diagnostics")
        .join("sanitized-summaries/RUN.control-proof.json");
    let bytes = std::fs::read(&path).unwrap();
    let control: lte_e2e_verify::ControlProof = serde_json::from_slice(&bytes).unwrap();
    let step = control
        .steps
        .iter()
        .find(|step| step.index == 6)
        .expect("ping_ul step");
    let counters = step
        .enb_link_counters()
        .expect("enb_link_counters sub-document");
    let s1u = counters.get("s1u").expect("s1u role");
    let zmq = counters.get("zmq").expect("zmq role");
    for role in [s1u, zmq] {
        assert_eq!(role.get("exit_code").and_then(|v| v.as_i64()), Some(0));
        let stdout = role
            .get("stdout")
            .and_then(|v| v.as_str())
            .expect("stdout string");
        // The dump must mention the UTF-8 bounded ip -s link counters header.
        assert!(stdout.contains("RX:") && stdout.contains("TX:"));
        // Payload must be ≤ 512 bytes (sanity on the fixture, not a
        // verifier-enforced invariant).
        assert!(stdout.len() <= 512);
    }
}

#[test]
fn run_4762954c_shows_proven_not_proven_and_open_states_together() {
    // 0.1.3: the run `lte-run-4762954cf008935038162a0b8289dc67` reported by
    // Codex on Issue #10 comment 6589742429 is the canonical example of the
    // three state() values coexisting:
    //
    // - PROVEN                   : S1_SETUP, ATTACH, UE_IP, CLEANUP,
    //                              GRANT_REVOKED, DUMPCAP (all observed)
    // - NOT_PROVEN               : EPS_BEARER, PING_UL, S1U_GTPU
    //                              (evidence was expected but missing/wrong)
    // - OPEN                     : PING_DL, UDP_UL, UDP_DL
    //                              (orchestrator skipped the step after
    //                               PING_UL failed; nothing was observed)
    //
    // EPS_BEARER is NOT_PROVEN (not OPEN) because the gate had the chance to
    // observe S11 CSReq/CSRsp + E-RAB during the attach window; those never
    // materialised. The verifier must mark that as NOT_PROVEN, not OPEN.
    let report = lte_e2e_verify::verify(&fixture("run-4762954c-mixed-states")).expect("verify");
    assert_eq!(report.run_id, "lte-run-4762954cf008935038162a0b8289dc67");

    let state = |name: &str| -> &'static str {
        report
            .gates
            .iter()
            .find(|(gate, _)| *gate == name)
            .map(|(_, verdict)| verdict.state())
            .unwrap_or("MISSING")
    };

    // PROVEN
    assert_eq!(state("S1_SETUP"), "PROVEN");
    assert_eq!(state("ATTACH"), "PROVEN");
    assert_eq!(state("CLEANUP"), "PROVEN");
    assert_eq!(state("GRANT_REVOKED"), "PROVEN");
    assert_eq!(state("DUMPCAP"), "PROVEN");

    // NOT_PROVEN
    assert_eq!(state("EPS_BEARER"), "NOT_PROVEN");
    assert_eq!(state("PING_UL"), "NOT_PROVEN");
    assert_eq!(state("S1U_GTPU"), "NOT_PROVEN");

    // OPEN — orchestrator skipped these steps after PING_UL failed.
    assert_eq!(state("PING_DL"), "OPEN");
    assert_eq!(state("UDP_UL"), "OPEN");
    assert_eq!(state("UDP_DL"), "OPEN");

    // The rendered label stays FAIL for Open so e0497's contract still holds.
    let label = |name: &str| -> String {
        report
            .gates
            .iter()
            .find(|(gate, _)| *gate == name)
            .map(|(_, verdict)| verdict.label())
            .unwrap_or_default()
    };
    assert_eq!(label("PING_DL"), "FAIL");

    // Overall verdict still NOT a REAL_PASS.
    assert_eq!(report.final_verdict(), "NO_LTE_E2E_REAL_PASS");
    assert!(report.blockers().contains(&"PING_DL"));
    assert!(report.blockers().contains(&"EPS_BEARER"));
}

#[test]
fn eps_bearer_degrades_to_proven_cp_only_when_cp_proven_but_s1u_empty() {
    // 0.1.3: when S11 CSReq/CSRsp + E-RAB are observed AND S1-U is empty
    // (packet_count=0), EPS_BEARER must emit PASS_CONTROL_PLANE_ONLY with
    // state() == PROVEN_CONTROL_PLANE_ONLY. The existing e0497 fixture is
    // the canonical case.
    let report = lte_e2e_verify::verify(&fixture("e0497")).expect("verify");
    let eps_bearer = report
        .gates
        .iter()
        .find(|(gate, _)| *gate == "EPS_BEARER")
        .map(|(_, verdict)| verdict.state())
        .expect("EPS_BEARER gate");
    assert_eq!(eps_bearer, "PROVEN_CONTROL_PLANE_ONLY");
}

#[test]
fn missing_grant_section_fails_grant_revoked_gate() {
    // The missing-field fixture drops the `grant` section entirely from the
    // control proof. The verifier must fail that gate with its code and must
    // not degrade to PASS.
    let report = lte_e2e_verify::verify(&fixture("missing-field")).expect("verify");
    assert_eq!(report.run_id, "lte-run-missing-field-0001");
    assert_eq!(report.blockers(), vec!["GRANT_REVOKED"]);
    assert_eq!(report.final_verdict(), "NO_LTE_E2E_REAL_PASS");
}

// -------- Pure unit tests on the verdict functions --------

#[test]
fn s1_setup_requires_sctp_ppid_18() {
    use lte_e2e_verify::{verdict_s1_setup, Manifest, S1apEvent, Verdict};
    let manifest = Manifest {
        plane: "S1_MME".into(),
        packet_count: 2,
        first_packet_at: None,
        last_packet_at: None,
        source_sha256: None,
        s1ap_procedures: vec![S1apEvent {
            procedure: 17,
            sctp_ppid: Some(99),
            e_rab_id: None,
            s1_u_teid: None,
            s1_u_endpoint: None,
        }],
        nas_eps: vec![],
        gtpv2c: vec![],
        gtpu: None,
    };
    assert_eq!(verdict_s1_setup(&manifest), Verdict::Fail("S1_SETUP".into()));
}

#[test]
fn udp_rate_above_cap_fails_closed() {
    use lte_e2e_verify::{
        verdict_udp, ControlProof, UdpCounters, UdpSection, Verdict,
    };
    let control = ControlProof {
        run_id: "x".into(),
        started_at: None,
        ended_at: None,
        final_state: None,
        state: None,
        steps: vec![],
        ping: None,
        udp: Some(UdpSection {
            ul: Some(UdpCounters {
                bytes: 10,
                rate_bps: Some(1_500_000),
            }),
            dl: None,
        }),
        cleanup: None,
        grant: None,
        dumpcap: None,
    };
    assert_eq!(verdict_udp(&control, "ul"), Verdict::Fail("UDP_UL".into()));
}

#[test]
fn dumpcap_pid_change_fails_closed() {
    use lte_e2e_verify::{verdict_dumpcap, ControlProof, DumpcapSection, Verdict};
    let before: Vec<u32> = (1..=12).collect();
    let mut after = before.clone();
    after[0] = 999;
    let control = ControlProof {
        run_id: "x".into(),
        started_at: None,
        ended_at: None,
        final_state: None,
        state: None,
        steps: vec![],
        ping: None,
        udp: None,
        cleanup: None,
        grant: None,
        dumpcap: Some(DumpcapSection {
            before_pids: before,
            after_pids: after,
        }),
    };
    assert_eq!(
        verdict_dumpcap(&control),
        Verdict::Fail("DUMPCAP".into())
    );
}
