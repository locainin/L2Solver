use std::error::Error;

use l2_lab::{
    ObservationMode,
    dhcp::{Fault, IngressPolicy, MessageKind, Options, Outcome, Scenario},
};
use l2_scenario::Cleanup;
use l2_segmentation::EvaluationStatus;

use super::{budget, fixture};

#[test]
fn unavailable_or_lossy_observers_and_missing_positive_control_are_inconclusive()
-> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let scenario = Scenario::new(config)?;
    let guard = IngressPolicy::TrustOnly(config.authorized_server.agent());
    for options in [
        Options {
            receiver: ObservationMode::Unavailable,
            ..Options::default()
        },
        Options {
            receiver: ObservationMode::Dropped,
            ..Options::default()
        },
        Options {
            state: ObservationMode::Unavailable,
            ..Options::default()
        },
        Options {
            state: ObservationMode::Dropped,
            ..Options::default()
        },
        Options {
            fault: Fault::MissingControlOffer,
            ..Options::default()
        },
        Options {
            fault: Fault::MissingControlAck,
            ..Options::default()
        },
        Options {
            fault: Fault::MissingTargetOffer,
            ..Options::default()
        },
        Options {
            fault: Fault::MissingTargetAck,
            ..Options::default()
        },
    ] {
        let run = scenario.run(guard, budget()?, options)?;
        assert_eq!(run.status(), EvaluationStatus::Inconclusive, "{options:?}");
    }
    Ok(())
}

#[test]
fn inconsistent_ack_transaction_or_address_fails_with_observed_evidence()
-> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let scenario = Scenario::new(config)?;
    for fault in [Fault::WrongTargetTransaction, Fault::WrongTargetAddress] {
        let run = scenario.run(
            IngressPolicy::TrustOnly(config.authorized_server.agent()),
            budget()?,
            Options {
                fault,
                ..Options::default()
            },
        )?;
        assert_eq!(run.status(), EvaluationStatus::Fail, "{fault:?}");
        assert!(
            run.received()
                .iter()
                .any(|message| message.kind == MessageKind::Ack && message.client == config.client)
        );
    }
    Ok(())
}

#[test]
fn configured_address_limit_detects_excess_server_assignments() -> Result<(), Box<dyn Error>> {
    let mut config = fixture()?;
    config.authorized_lease_limit = 1;
    let run = Scenario::new(config)?.run(
        IngressPolicy::TrustOnly(config.authorized_server.agent()),
        budget()?,
        Options::default(),
    )?;
    assert_eq!(run.status(), EvaluationStatus::Fail);
    assert_eq!(
        run.state_during()
            .ok_or("missing state")?
            .server_leases()
            .iter()
            .flatten()
            .count(),
        2
    );
    Ok(())
}

#[test]
fn spoofed_server_identifier_does_not_change_ingress_identity() -> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let scenario = Scenario::new(config)?;
    let options = Options {
        fault: Fault::RogueSpoofsIdentifier,
        ..Options::default()
    };
    let guarded = scenario.run(
        IngressPolicy::TrustOnly(config.authorized_server.agent()),
        budget()?,
        options,
    )?;
    assert_eq!(guarded.status(), EvaluationStatus::Pass);
    let permissive = scenario.run(IngressPolicy::AllowAll, budget()?, options)?;
    assert_eq!(permissive.status(), EvaluationStatus::Fail);
    assert!(
        permissive
            .received()
            .iter()
            .any(|message| message.source == config.rogue_server.agent()
                && message.server_identifier == Some(config.authorized_server.identifier()))
    );
    Ok(())
}

#[test]
fn missing_state_observation_and_unrestored_state_never_confirm_cleanup()
-> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let scenario = Scenario::new(config)?;
    let guard = IngressPolicy::TrustOnly(config.authorized_server.agent());
    let unavailable = scenario.run(
        guard,
        budget()?,
        Options {
            state: ObservationMode::Unavailable,
            ..Options::default()
        },
    )?;
    assert_eq!(unavailable.execution().cleanup(), Cleanup::Unconfirmed);
    assert_eq!(unavailable.state_before(), None);
    assert_eq!(unavailable.state_after(), None);
    let unrestored = scenario.run(
        guard,
        budget()?,
        Options {
            fault: Fault::CleanupNotRestored,
            ..Options::default()
        },
    )?;
    assert_eq!(unrestored.execution().cleanup(), Cleanup::Unconfirmed);
    assert_ne!(unrestored.state_before(), unrestored.state_after());
    assert_eq!(unrestored.status(), EvaluationStatus::Fail);
    Ok(())
}

#[test]
fn state_observation_can_prove_a_rogue_binding_when_receiver_capture_is_lost()
-> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let run = Scenario::new(config)?.run(
        IngressPolicy::AllowAll,
        budget()?,
        Options {
            receiver: ObservationMode::Dropped,
            ..Options::default()
        },
    )?;
    assert!(run.received().is_empty());
    assert_eq!(run.outcome(), Outcome::InconsistentLease);
    assert_eq!(run.status(), EvaluationStatus::Fail);
    Ok(())
}

#[test]
fn trusting_the_wrong_port_does_not_change_the_expected_server() -> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let run = Scenario::new(config)?.run(
        IngressPolicy::TrustOnly(config.rogue_server.agent()),
        budget()?,
        Options::default(),
    )?;
    assert_eq!(run.outcome(), Outcome::UnauthorizedResponse);
    assert_eq!(run.status(), EvaluationStatus::Fail);
    Ok(())
}
