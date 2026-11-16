//! 0.36.8 (ANR1 #9 — gNB NGAP pre-check + restart ciblé).
//!
//! Avant chaque scénario 5G, le gNB UERANSIM doit avoir établi
//! l'association SCTP NGAP avec l'AMF. ANR1 #10 6898459838 a prouvé
//! que lorsque le gNB démarre avant l'AMF, il reçoit `Connection
//! refused` sur SCTP 38412 et ne retente jamais → cellule barrée →
//! UE jamais enregistré → le run échoue en `PDU_DNN_NOT_OBSERVED`
//! (lib.rs:2643), cause masquée.
//!
//! Ce module expose deux fonctions **pures** testables isolément :
//!
//! - [`parse_nr_cli_status`] : classe la sortie de `nr-cli <gnb> -e
//!   status` en `NgapState { NgapUp | NgapDown | Unknown }`. Toute
//!   sortie non reconnue est traitée comme `NgapDown` (invariant
//!   anti-silent).
//! - [`decide_gnb_recovery`] : décide l'action à prendre à partir
//!   d'un `NgapState` + un bool `amf_listening`. Les 4 transitions
//!   sont explicites.
//!
//! Le code *impure* (docker exec, inspect, restart) est orchestré
//! par [`check_gnb_ngap_up_or_recover`] qui utilise ces deux
//! helpers et une [`GnbNgapChecker`] trait pour isoler l'IO en test.

/// 0.36.8 — Résultat du parse de `nr-cli status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NgapState {
    NgapUp,
    NgapDown,
    /// Sortie inconnue (champ absent, format changé). Traitée par
    /// le reste du module comme `NgapDown` pour ne jamais
    /// présumer `Up` (règle « un écart se déclare OUVERT, jamais
    /// par hypothèse »).
    Unknown,
}

impl NgapState {
    /// Renvoie `true` seulement si l'état est explicitement
    /// [`NgapState::NgapUp`]. `Unknown` et `NgapDown` sont les deux
    /// traités comme *not up*.
    pub fn is_up(self) -> bool {
        matches!(self, NgapState::NgapUp)
    }
}

/// 0.36.8 — Parseur pur de `nr-cli <gnb-node> -e status`. UERANSIM
/// affiche une ligne par champ, dont `is-ngap-up: true/false`. Le
/// matching est insensible à la casse et à l'espacement.
///
/// Toute sortie où `is-ngap-up` n'apparaît pas, ou apparaît avec
/// une valeur non littérale `true`/`false`, est classée `Unknown` —
/// le caller la traite comme un écart à signaler, pas comme un
/// `Up` optimiste.
pub fn parse_nr_cli_status(output: &str) -> NgapState {
    for raw in output.lines() {
        let line = raw.trim();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("is-ngap-up") {
            return match value.trim().to_ascii_lowercase().as_str() {
                "true" => NgapState::NgapUp,
                "false" => NgapState::NgapDown,
                _ => NgapState::Unknown,
            };
        }
    }
    NgapState::Unknown
}

/// 0.36.11 (ANR2 #10 6915042783) — `is-ngap-up: true` ne suffit PAS :
/// après un redémarrage de l'AMF, UERANSIM garde `is-ngap-up: true`
/// alors que sa liste d'AMF est VIDE (« Could not find a suitable AMF »,
/// aucun Initial NAS ne part). NGAP n'est déclaré up que si la liste
/// `nr-cli <gnb> -e amf-list` contient au moins un AMF. Liste illisible
/// (commande en échec) → `Unknown` (jamais d'up présumé).
pub fn effective_ngap_state(status_output: &str, amf_list: Result<&str, &str>) -> NgapState {
    match parse_nr_cli_status(status_output) {
        NgapState::NgapUp => match amf_list {
            Ok(list) if amf_count(list) > 0 => NgapState::NgapUp,
            Ok(_) => NgapState::NgapDown,
            Err(_) => NgapState::Unknown,
        },
        other => other,
    }
}

/// Nombre d'AMF listés par `nr-cli <gnb> -e amf-list` (sortie YAML :
/// une entrée `- id: N` par AMF ; liste vide = sortie vide ou `[]`).
pub fn amf_count(output: &str) -> usize {
    output
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("- ") || line.starts_with("id:"))
        .count()
}

/// 0.36.8 — Décision de reprise. Un `NgapState` observé + un
/// booléen d'écoute AMF donne 4 transitions :
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GnbRecoveryDecision {
    /// Rien à faire : NGAP est up. Pré-check passe silencieusement.
    Ready,
    /// NGAP est down ET l'AMF écoute : restart ciblé du conteneur
    /// gNB (jamais un conteneur Open5GS), puis retest du status.
    /// L'action doit être tracée dans le run (événement
    /// « gNB redémarré : NGAP down »).
    RestartGnb,
    /// NGAP down ET l'AMF n'écoute pas : aucune action gNB —
    /// redémarrer le gNB ne servirait à rien tant que l'AMF est
    /// absente. Le scénario échoue immédiatement avec un code
    /// explicite pour que l'opérateur agisse sur l'AMF.
    Fail(&'static str),
}

/// 0.36.8 — Table de transition. 4 cas, pas d'implicite.
pub fn decide_gnb_recovery(ngap: NgapState, amf_listening: bool) -> GnbRecoveryDecision {
    match (ngap, amf_listening) {
        (NgapState::NgapUp, _) => GnbRecoveryDecision::Ready,
        (NgapState::NgapDown, true) => GnbRecoveryDecision::RestartGnb,
        // Revue Claude : un statut illisible (timeout CLI, format
        // inconnu) ne prouve pas que NGAP est down → jamais de
        // redémarrage sur Unknown (il couperait tous les UE à chaque
        // lancement). Erreur explicite, aucune action.
        (NgapState::Unknown, _) => GnbRecoveryDecision::Fail(GNB_NGAP_STATUS_UNREADABLE),
        (NgapState::NgapDown, false) => {
            // Code d'erreur stable pour que le run surface la cause
            // en amont, au lieu du générique PDU_DNN_NOT_OBSERVED
            // qui masquait la racine (lib.rs:2643).
            GnbRecoveryDecision::Fail("GNB_NGAP_DOWN_AMF_UNAVAILABLE")
        }
    }
}

/// 0.36.8 — Code d'erreur publié au run quand le pré-check gNB
/// échoue et qu'aucune reprise n'a été possible (ou qu'elle n'a pas
/// rétabli NGAP dans le délai imparti).
pub const GNB_NGAP_DOWN: &str = "GNB_NGAP_DOWN";
pub const GNB_NGAP_DOWN_AMF_UNAVAILABLE: &str = "GNB_NGAP_DOWN_AMF_UNAVAILABLE";
/// Revue Claude 0.36.8 — statut `nr-cli status` illisible : aucune reprise.
pub const GNB_NGAP_STATUS_UNREADABLE: &str = "GNB_NGAP_STATUS_UNREADABLE";
/// 0.36.16 — gNB redémarré, NGAP up, mais le conteneur n'est pas revenu
/// `healthy` dans le délai : la gate santé du job échouerait (course
/// prouvée ANR2 #10, job simple-data-ul-dl-19900c89a294).
pub const GNB_NOT_HEALTHY_AFTER_RESTART: &str = "GNB_NOT_HEALTHY_AFTER_RESTART";
/// 0.36.16 — délai max d'attente du healthcheck docker du gNB après restart.
pub const GNB_HEALTH_TIMEOUT_SECONDS: u64 = 120;

/// 0.36.8 — Trait d'injection pour isoler l'IO docker en test.
/// Implémenté en prod par [`DockerGnbNgapChecker`] ci-dessous ; en
/// test par un double qui retourne des sorties fixes.
pub trait GnbNgapChecker {
    /// Exécute `docker exec <gnb-container> nr-cli <node> -e status`
    /// et retourne la sortie brute. `Err` si docker/nr-cli ont échoué
    /// (le caller traite ça comme `Unknown`).
    fn nr_cli_status(&self) -> Result<String, String>;
    /// 0.36.11 — `docker exec <gnb-container> nr-cli <node> -e amf-list`.
    fn nr_cli_amf_list(&self) -> Result<String, String>;
    /// Teste si l'AMF écoute sur son endpoint NGAP SCTP. `true` =
    /// socket listening observée, `false` sinon.
    fn amf_listening(&self) -> bool;
    /// Redémarre le conteneur gNB (et SEULEMENT lui — jamais un
    /// conteneur Open5GS). Blocant, retourne quand docker a accepté
    /// la commande.
    fn restart_gnb(&self) -> Result<(), String>;
    /// Attend que `nr_cli_status()` retourne `NgapUp` ou qu'un
    /// `timeout` soit atteint. Retourne `Ok(NgapState)` avec l'état
    /// final observé (peut rester `Down` si le restart n'a pas
    /// suffi).
    fn wait_for_ngap_up(&self, timeout_seconds: u64) -> NgapState;
    /// 0.36.16 — attend que le conteneur gNB soit `running/healthy`
    /// (healthcheck docker) après un restart. `Ok` seulement sur
    /// `healthy` observé ; délai dépassé → `Err(état observé)`.
    fn wait_for_container_healthy(&self, timeout_seconds: u64) -> Result<(), String>;
}

/// 0.36.8 — Flux de décision + action. Pure côté logique, les IO
/// passent par le trait. Un restart qui ne rétablit pas NGAP dans
/// le délai imparti remonte `Err(GNB_NGAP_DOWN)` — pas de reprise
/// silencieuse.
pub fn check_gnb_ngap_up_or_recover<C: GnbNgapChecker>(
    checker: &C,
    restart_timeout_seconds: u64,
) -> Result<GnbNgapOutcome, String> {
    let initial_output = checker.nr_cli_status().unwrap_or_default();
    let amf_list = checker.nr_cli_amf_list();
    let initial_state = effective_ngap_state(
        &initial_output,
        amf_list.as_deref().map_err(String::as_str),
    );
    match decide_gnb_recovery(initial_state, checker.amf_listening()) {
        GnbRecoveryDecision::Ready => Ok(GnbNgapOutcome::AlreadyUp),
        GnbRecoveryDecision::Fail(code) => Err(code.to_string()),
        GnbRecoveryDecision::RestartGnb => {
            checker.restart_gnb()?;
            let after = checker.wait_for_ngap_up(restart_timeout_seconds);
            if !after.is_up() {
                return Err(GNB_NGAP_DOWN.into());
            }
            // 0.36.16 — NGAP up ne suffit pas : la gate santé du job
            // exige le conteneur `healthy`. Sans cette attente, la gate
            // était évaluée < 1 s après le restart → LAB_HEALTH_GATE_FAILED.
            checker
                .wait_for_container_healthy(GNB_HEALTH_TIMEOUT_SECONDS)
                .map_err(|observed| format!("{GNB_NOT_HEALTHY_AFTER_RESTART}: {observed}"))?;
            Ok(GnbNgapOutcome::RestartedAndUp)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GnbNgapOutcome {
    AlreadyUp,
    RestartedAndUp,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn parse_nr_cli_status_classifies_true_false_and_unknown() {
        let up = "cli-mode: shell\nis-ngap-up: true\nrrc-connected: 0";
        assert_eq!(parse_nr_cli_status(up), NgapState::NgapUp);

        let down = "is-ngap-up: false";
        assert_eq!(parse_nr_cli_status(down), NgapState::NgapDown);

        // Sortie tronquée / inconnue : jamais présumée Up.
        assert_eq!(parse_nr_cli_status(""), NgapState::Unknown);
        assert_eq!(parse_nr_cli_status("cli-mode: shell"), NgapState::Unknown);
        assert_eq!(
            parse_nr_cli_status("is-ngap-up: maybe"),
            NgapState::Unknown
        );

        // Casse mixte + espacement irrégulier → tolérés.
        assert_eq!(
            parse_nr_cli_status("Is-Ngap-Up :   TRUE  "),
            NgapState::NgapUp
        );
    }

    #[test]
    fn decide_gnb_recovery_covers_the_four_transitions() {
        assert_eq!(
            decide_gnb_recovery(NgapState::NgapUp, true),
            GnbRecoveryDecision::Ready
        );
        assert_eq!(
            decide_gnb_recovery(NgapState::NgapUp, false),
            GnbRecoveryDecision::Ready
        );
        assert_eq!(
            decide_gnb_recovery(NgapState::NgapDown, true),
            GnbRecoveryDecision::RestartGnb
        );
        assert_eq!(
            decide_gnb_recovery(NgapState::NgapDown, false),
            GnbRecoveryDecision::Fail(GNB_NGAP_DOWN_AMF_UNAVAILABLE)
        );
        // Statut illisible : jamais de redémarrage, erreur explicite.
        assert_eq!(
            decide_gnb_recovery(NgapState::Unknown, true),
            GnbRecoveryDecision::Fail(GNB_NGAP_STATUS_UNREADABLE)
        );
        assert_eq!(
            decide_gnb_recovery(NgapState::Unknown, false),
            GnbRecoveryDecision::Fail(GNB_NGAP_STATUS_UNREADABLE)
        );
    }

    /// Double de test qui scripte les sorties nr-cli + l'état AMF +
    /// l'issue du restart. Permet de couvrir `check_gnb_ngap_up_or_recover`
    /// sans docker réel.
    struct ScriptedChecker {
        initial_status: String,
        after_restart_status: String,
        amf_listening: bool,
        restart_ok: bool,
        restart_calls: Cell<u32>,
        healthy_after_restart: bool,
        health_waits: Cell<u32>,
    }

    /// Liste d'AMF du double : non vide par défaut (cas nominal).
    const ONE_AMF: &str = "- id: 2";

    impl GnbNgapChecker for ScriptedChecker {
        fn nr_cli_status(&self) -> Result<String, String> {
            if self.restart_calls.get() == 0 {
                Ok(self.initial_status.clone())
            } else {
                Ok(self.after_restart_status.clone())
            }
        }
        fn nr_cli_amf_list(&self) -> Result<String, String> {
            Ok(ONE_AMF.into())
        }
        fn amf_listening(&self) -> bool {
            self.amf_listening
        }
        fn restart_gnb(&self) -> Result<(), String> {
            self.restart_calls.set(self.restart_calls.get() + 1);
            if self.restart_ok {
                Ok(())
            } else {
                Err("DOCKER_RESTART_FAILED".into())
            }
        }
        fn wait_for_ngap_up(&self, _timeout_seconds: u64) -> NgapState {
            parse_nr_cli_status(&self.after_restart_status)
        }
        fn wait_for_container_healthy(&self, _timeout_seconds: u64) -> Result<(), String> {
            self.health_waits.set(self.health_waits.get() + 1);
            if self.healthy_after_restart {
                Ok(())
            } else {
                Err("running/starting".into())
            }
        }
    }

    #[test]
    fn check_gnb_ready_short_circuits_without_restart() {
        let checker = ScriptedChecker {
            initial_status: "is-ngap-up: true".into(),
            after_restart_status: String::new(),
            amf_listening: true,
            restart_ok: false,
            restart_calls: Cell::new(0),
            healthy_after_restart: true,
            health_waits: Cell::new(0),
        };
        let out = check_gnb_ngap_up_or_recover(&checker, 10).unwrap();
        assert_eq!(out, GnbNgapOutcome::AlreadyUp);
        assert_eq!(checker.restart_calls.get(), 0);
    }

    #[test]
    fn check_gnb_down_with_amf_listening_restarts_then_passes() {
        let checker = ScriptedChecker {
            initial_status: "is-ngap-up: false".into(),
            after_restart_status: "is-ngap-up: true".into(),
            amf_listening: true,
            restart_ok: true,
            restart_calls: Cell::new(0),
            healthy_after_restart: true,
            health_waits: Cell::new(0),
        };
        let out = check_gnb_ngap_up_or_recover(&checker, 10).unwrap();
        assert_eq!(out, GnbNgapOutcome::RestartedAndUp);
        assert_eq!(checker.restart_calls.get(), 1);
    }

    #[test]
    fn check_gnb_down_with_amf_listening_restart_fails_to_recover_returns_gnb_ngap_down() {
        let checker = ScriptedChecker {
            initial_status: "is-ngap-up: false".into(),
            after_restart_status: "is-ngap-up: false".into(),
            amf_listening: true,
            restart_ok: true,
            restart_calls: Cell::new(0),
            healthy_after_restart: true,
            health_waits: Cell::new(0),
        };
        let err = check_gnb_ngap_up_or_recover(&checker, 10).unwrap_err();
        assert_eq!(err, GNB_NGAP_DOWN);
        assert_eq!(checker.restart_calls.get(), 1);
    }

    #[test]
    fn check_gnb_down_with_amf_not_listening_fails_without_restart() {
        let checker = ScriptedChecker {
            initial_status: "is-ngap-up: false".into(),
            after_restart_status: "is-ngap-up: true".into(),
            amf_listening: false,
            restart_ok: true,
            restart_calls: Cell::new(0),
            healthy_after_restart: true,
            health_waits: Cell::new(0),
        };
        let err = check_gnb_ngap_up_or_recover(&checker, 10).unwrap_err();
        assert_eq!(err, GNB_NGAP_DOWN_AMF_UNAVAILABLE);
        // CRITIQUE : aucun restart n'est tenté si l'AMF n'écoute pas.
        assert_eq!(checker.restart_calls.get(), 0);
    }

    #[test]
    fn check_gnb_unknown_status_with_amf_down_also_fails_without_restart() {
        let checker = ScriptedChecker {
            initial_status: "cli-mode: shell".into(),
            after_restart_status: String::new(),
            amf_listening: false,
            restart_ok: true,
            restart_calls: Cell::new(0),
            healthy_after_restart: true,
            health_waits: Cell::new(0),
        };
        let err = check_gnb_ngap_up_or_recover(&checker, 10).unwrap_err();
        assert_eq!(err, GNB_NGAP_STATUS_UNREADABLE);
        assert_eq!(checker.restart_calls.get(), 0);
    }

    #[test]
    fn check_gnb_unknown_status_with_amf_up_never_restarts() {
        let checker = ScriptedChecker {
            initial_status: "cli-mode: shell".into(),
            after_restart_status: String::new(),
            amf_listening: true,
            restart_ok: true,
            restart_calls: Cell::new(0),
            healthy_after_restart: true,
            health_waits: Cell::new(0),
        };
        let err = check_gnb_ngap_up_or_recover(&checker, 10).unwrap_err();
        assert_eq!(err, GNB_NGAP_STATUS_UNREADABLE);
        assert_eq!(checker.restart_calls.get(), 0);
    }

    /// 0.36.11 — cas prouvé par ANR2 : is-ngap-up true + amf-list vide.
    #[test]
    fn ngap_up_with_an_empty_amf_list_is_down() {
        assert_eq!(effective_ngap_state("is-ngap-up: true", Ok("")), NgapState::NgapDown);
        assert_eq!(effective_ngap_state("is-ngap-up: true", Ok("[]")), NgapState::NgapDown);
        assert_eq!(effective_ngap_state("is-ngap-up: true", Ok("- id: 2")), NgapState::NgapUp);
        assert_eq!(effective_ngap_state("is-ngap-up: true", Err("x")), NgapState::Unknown);
        assert_eq!(effective_ngap_state("is-ngap-up: false", Ok("- id: 2")), NgapState::NgapDown);
    }

    struct EmptyAmfListChecker {
        restart_calls: Cell<u32>,
    }
    impl GnbNgapChecker for EmptyAmfListChecker {
        fn nr_cli_status(&self) -> Result<String, String> {
            Ok("is-ngap-up: true".into())
        }
        fn nr_cli_amf_list(&self) -> Result<String, String> {
            Ok(String::new())
        }
        fn amf_listening(&self) -> bool {
            true
        }
        fn restart_gnb(&self) -> Result<(), String> {
            self.restart_calls.set(self.restart_calls.get() + 1);
            Ok(())
        }
        fn wait_for_ngap_up(&self, _timeout_seconds: u64) -> NgapState {
            NgapState::NgapUp
        }
        fn wait_for_container_healthy(&self, _timeout_seconds: u64) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn empty_amf_list_with_amf_listening_triggers_a_gnb_restart() {
        let checker = EmptyAmfListChecker { restart_calls: Cell::new(0) };
        let outcome = check_gnb_ngap_up_or_recover(&checker, 10).unwrap();
        assert_eq!(outcome, GnbNgapOutcome::RestartedAndUp);
        assert_eq!(checker.restart_calls.get(), 1);
    }

    /// 0.36.16 — restart gNB + NGAP up mais conteneur pas `healthy` →
    /// erreur explicite, jamais RestartedAndUp (la gate échouerait ensuite).
    #[test]
    fn restart_with_ngap_up_but_container_not_healthy_fails_explicitly() {
        let checker = ScriptedChecker {
            initial_status: "is-ngap-up: false".into(),
            after_restart_status: "is-ngap-up: true".into(),
            amf_listening: true,
            restart_ok: true,
            restart_calls: Cell::new(0),
            healthy_after_restart: false,
            health_waits: Cell::new(0),
        };
        let err = check_gnb_ngap_up_or_recover(&checker, 10).unwrap_err();
        assert!(err.starts_with(GNB_NOT_HEALTHY_AFTER_RESTART), "{err}");
        assert_eq!(checker.health_waits.get(), 1);
    }

    /// 0.36.16 — chemin nominal : le restart attend `healthy` avant de rendre la main.
    #[test]
    fn restart_waits_for_container_healthy_before_returning() {
        let checker = ScriptedChecker {
            initial_status: "is-ngap-up: false".into(),
            after_restart_status: "is-ngap-up: true".into(),
            amf_listening: true,
            restart_ok: true,
            restart_calls: Cell::new(0),
            healthy_after_restart: true,
            health_waits: Cell::new(0),
        };
        assert_eq!(check_gnb_ngap_up_or_recover(&checker, 10).unwrap(), GnbNgapOutcome::RestartedAndUp);
        assert_eq!(checker.health_waits.get(), 1);
    }

}
