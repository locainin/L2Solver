use std::error::Error;

use l2_lab::dhcp::{Fault, IngressPolicy, MessageKind, Options, Outcome, Scenario};
use l2_scenario::Cleanup;
use l2_segmentation::EvaluationStatus;

use super::{budget, fixture};

#[test]
fn permissive_ingress_exposes_rogue_offer_and_assignment() -> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let run = Scenario::new(config)?.run(IngressPolicy::AllowAll, budget()?, Options::default())?;
    assert_eq!(run.status(), EvaluationStatus::Fail);
    assert!(
        run.received()
            .iter()
            .any(|message| message.source == config.rogue_server.agent()
                && message.kind == MessageKind::Offer)
    );
    let state = run.state_during().ok_or("state observer unavailable")?;
    assert!(
        state
            .client_leases()
            .iter()
            .flatten()
            .any(|lease| lease.server == config.rogue_server.agent()
                && lease.address == config.rogue_address)
    );
    assert_eq!(run.execution().cleanup(), Cleanup::Confirmed);
    Ok(())
}

#[test]
fn independent_client_and_server_state_reveals_unapplied_bindings() -> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let scenario = Scenario::new(config)?;
    for fault in [
        Fault::TargetClientDoesNotBind,
        Fault::TargetServerDoesNotBind,
    ] {
        let run = scenario.run(
            IngressPolicy::TrustOnly(config.authorized_server.agent()),
            budget()?,
            Options {
                fault,
                ..Options::default()
            },
        )?;
        assert_eq!(run.status(), EvaluationStatus::Fail, "{fault:?}");
        assert_eq!(run.outcome(), Outcome::InconsistentLease, "{fault:?}");
        let state = run.state_during().ok_or("missing endpoint state")?;
        assert_ne!(state.target().client_lease, state.target().server_lease);
        assert!(
            run.received()
                .iter()
                .any(|message| message.kind == MessageKind::Ack && message.client == config.client)
        );
    }
    Ok(())
}

#[test]
fn spoofed_ack_is_detected_when_guard_filters_offers_but_not_acknowledgements()
-> Result<(), Box<dyn Error>> {
    let config = fixture()?;
    let scenario = Scenario::new(config)?;
    let options = Options {
        fault: Fault::RogueSpoofsSelectedReply,
        ..Options::default()
    };
    let run = scenario.run(
        IngressPolicy::TrustOffersOnly(config.authorized_server.agent()),
        budget()?,
        options,
    )?;
    assert_eq!(run.outcome(), Outcome::UnauthorizedResponse);
    assert!(
        run.received()
            .iter()
            .all(|message| message.source != config.rogue_server.agent()
                || message.kind != MessageKind::Offer)
    );
    assert!(run.received().iter().any(|message| {
        message.source == config.rogue_server.agent()
            && message.kind == MessageKind::Ack
            && message.server_identifier == Some(config.authorized_server.identifier())
            && message.address == Some(config.authorized_address)
    }));
    let target = run.state_during().ok_or("missing target state")?;
    assert_eq!(
        target
            .target()
            .selected_offer
            .ok_or("missing selection")?
            .source,
        config.authorized_server.agent()
    );
    assert_eq!(
        target
            .target()
            .client_lease
            .ok_or("missing client binding")?
            .server,
        config.rogue_server.agent()
    );
    assert_eq!(
        target
            .target()
            .server_lease
            .ok_or("missing server binding")?
            .server,
        config.authorized_server.agent()
    );
    let protected = scenario.run(
        IngressPolicy::TrustOnly(config.authorized_server.agent()),
        budget()?,
        options,
    )?;
    assert_eq!(protected.status(), EvaluationStatus::Pass);
    Ok(())
}
