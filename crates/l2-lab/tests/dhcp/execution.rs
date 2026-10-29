use std::{error::Error, net::Ipv4Addr};

use l2_canary::{AgentId, RunId};
use l2_lab::{
    Cancellation, ObservationMode,
    dhcp::{Fault, IngressPolicy, MessageKind, Options, Outcome, Scenario, Server},
};
use l2_onpath::Budget;
use l2_scenario::{Cleanup, StopReason};
use l2_segmentation::EvaluationStatus;

use super::{budget, fixture};

#[test]
fn guarded_exchange_selects_authorized_server_and_restores_state() -> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let scenario = Scenario::new(config)?;
    let run = scenario.run(
        IngressPolicy::TrustOnly(config.authorized_server.agent()),
        budget()?,
        Options::default(),
    )?;
    assert_eq!(run.status(), EvaluationStatus::Pass);
    assert_eq!(run.outcome(), Outcome::Consistent);
    assert_eq!(run.execution().stop_reason(), StopReason::Exhausted);
    assert_eq!(run.execution().cleanup(), Cleanup::Confirmed);
    assert_eq!(run.execution().packets(), 10);
    assert_eq!(run.execution().bytes(), 5_760);
    assert_eq!(run.execution().elapsed_millis(), 10);

    // The sender observes both rogue attempts, while the receiver observes neither
    for kind in [MessageKind::Offer, MessageKind::Ack] {
        assert!(run.sent().iter().any(|message| {
            message.source == config.rogue_server.agent() && message.kind == kind
        }));
        assert!(!run.received().iter().any(|message| {
            message.source == config.rogue_server.agent() && message.kind == kind
        }));
    }
    let state = run.state_during().ok_or("state observer unavailable")?;
    assert_eq!(state.client_leases().iter().flatten().count(), 2);
    assert_eq!(state.client_leases(), state.server_leases());
    assert!(
        state
            .client_leases()
            .iter()
            .flatten()
            .all(|lease| lease.server == config.authorized_server.agent())
    );
    assert_eq!(run.state_before(), run.state_after());
    assert!(run.state_before().is_some());
    Ok(())
}

#[test]
fn cancellation_is_bounded_and_preserves_observed_violations() -> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let scenario = Scenario::new(config)?;
    for after in [0, 1, 4, 5, 9] {
        let options = Options {
            cancellation: Cancellation::After(after),
            ..Options::default()
        };
        let run = scenario.run(
            IngressPolicy::TrustOnly(config.authorized_server.agent()),
            budget()?,
            options,
        )?;
        assert_eq!(run.execution().stop_reason(), StopReason::Cancelled);
        assert_eq!(run.execution().packets(), after);
        assert_eq!(run.execution().cleanup(), Cleanup::Confirmed);
        assert_eq!(run.status(), EvaluationStatus::Inconclusive);
        assert_eq!(run.state_before(), run.state_after());
    }
    let run = scenario.run(
        IngressPolicy::AllowAll,
        budget()?,
        Options {
            cancellation: Cancellation::After(6),
            ..Options::default()
        },
    )?;
    assert_eq!(run.status(), EvaluationStatus::Fail);
    assert_eq!(run.execution().stop_reason(), StopReason::Cancelled);
    Ok(())
}

#[test]
fn scheduler_rejects_insufficient_resources_before_dispatch() -> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let scenario = Scenario::new(config)?;
    let guard = IngressPolicy::TrustOnly(config.authorized_server.agent());
    for budget in [
        Budget::new(9, 5_760, 10)?,
        Budget::new(10, 5_759, 10)?,
        Budget::new(10, 5_760, 9)?,
    ] {
        assert!(scenario.run(guard, budget, Options::default()).is_err());
    }
    Ok(())
}

#[test]
fn duplicate_identities_transactions_and_addresses_are_rejected() -> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let mut invalid = config;
    invalid.client = config.control_client;
    assert!(Scenario::new(invalid).is_err());
    invalid = config;
    invalid.rogue_server = config.authorized_server;
    assert!(Scenario::new(invalid).is_err());
    invalid = config;
    invalid.transaction = config.control_transaction;
    assert!(Scenario::new(invalid).is_err());
    invalid = config;
    invalid.transaction = 0;
    assert!(Scenario::new(invalid).is_err());
    invalid = config;
    invalid.rogue_address = config.authorized_address;
    assert!(Scenario::new(invalid).is_err());
    invalid = config;
    invalid.authorized_address = Ipv4Addr::UNSPECIFIED;
    assert!(Scenario::new(invalid).is_err());
    invalid = config;
    invalid.authorized_lease_limit = 0;
    assert!(Scenario::new(invalid).is_err());
    Ok(())
}

#[test]
fn identical_recorded_id_and_inputs_reproduce_the_virtual_transcript() -> Result<(), Box<dyn Error>>
{
    let config = fixture()?;
    let scenario = Scenario::new(config)?;
    let policy = IngressPolicy::TrustOnly(config.authorized_server.agent());
    let first = scenario.run(policy, budget()?, Options::default())?;
    let second = scenario.run(policy, budget()?, Options::default())?;
    assert_eq!(first, second);
    assert_eq!(first.run_id(), config.run_id);
    Ok(())
}

#[test]
fn report_retains_policy_expectations_and_capture_conditions() -> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let policy = IngressPolicy::TrustOnly(config.authorized_server.agent());
    let options = Options {
        receiver: ObservationMode::Dropped,
        cancellation: Cancellation::After(7),
        ..Options::default()
    };
    let run = Scenario::new(config)?.run(policy, budget()?, options)?;
    assert_eq!(run.config(), config);
    assert_eq!(run.ingress_policy(), policy);
    assert_eq!(run.options(), options);
    assert_eq!(run.outcome(), Outcome::IncompleteRun);
    Ok(())
}

#[test]
fn different_valid_topology_and_transaction_boundary_are_supported() -> Result<(), Box<dyn Error>> {
    let mut config = fixture()?;
    config.run_id = RunId::from_recorded([42; 16])?;
    config.control_client = AgentId::new([11; 16])?;
    config.client = AgentId::new([12; 16])?;
    config.authorized_server = Server::new(AgentId::new([13; 16])?, Ipv4Addr::new(198, 51, 100, 1));
    config.rogue_server = Server::new(AgentId::new([14; 16])?, Ipv4Addr::new(198, 51, 100, 2));
    config.control_address = Ipv4Addr::new(198, 51, 100, 10);
    config.authorized_address = Ipv4Addr::new(198, 51, 100, 11);
    config.rogue_address = Ipv4Addr::new(198, 51, 100, 12);
    config.control_transaction = u32::MAX - 1;
    config.transaction = u32::MAX;
    let scenario = Scenario::new(config)?;
    let policy = IngressPolicy::TrustOnly(config.authorized_server.agent());
    assert_eq!(
        scenario
            .run(policy, budget()?, Options::default())?
            .status(),
        EvaluationStatus::Pass
    );
    let invalid_ack = scenario.run(
        policy,
        budget()?,
        Options {
            fault: Fault::WrongTargetTransaction,
            ..Options::default()
        },
    )?;
    assert_eq!(invalid_ack.outcome(), Outcome::InconsistentAcknowledgement);
    assert!(
        invalid_ack
            .received()
            .iter()
            .any(|message| message.kind == MessageKind::Ack
                && message.client == config.client
                && message.transaction == 0)
    );
    Ok(())
}

#[test]
fn cancellation_at_completed_boundary_keeps_the_completed_result() -> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let run = Scenario::new(config)?.run(
        IngressPolicy::TrustOnly(config.authorized_server.agent()),
        budget()?,
        Options {
            cancellation: Cancellation::After(10),
            ..Options::default()
        },
    )?;
    assert_eq!(run.execution().stop_reason(), StopReason::Exhausted);
    assert_eq!(run.status(), EvaluationStatus::Pass);
    Ok(())
}

#[test]
fn missing_control_offer_charges_opportunities_but_only_records_emitted_messages()
-> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let run = Scenario::new(config)?.run(
        IngressPolicy::TrustOnly(config.authorized_server.agent()),
        budget()?,
        Options {
            fault: Fault::MissingControlOffer,
            ..Options::default()
        },
    )?;
    assert_eq!(run.outcome(), Outcome::MissingMessage);
    assert_eq!(run.execution().packets(), 10);
    assert_eq!(run.execution().bytes(), 5_760);
    assert_eq!(run.sent().len(), 7);
    assert!(run.sent().iter().all(|message| {
        message.client != config.control_client || message.kind == MessageKind::Discover
    }));
    Ok(())
}
