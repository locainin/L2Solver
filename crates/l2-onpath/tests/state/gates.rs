use std::error::Error;

use l2_onpath::{
    AddressFamily, ArmReceipt, AssessmentPhase, AssessmentSession, AssessmentStatus,
    CanaryWireEvidence, CheckKind, CleanupReceipt, EvidenceOrigin, MacAddress, NeighborBinding,
    NeighborDisposition, OriginalBindingReceipt, PrecheckReceipt, ReceiptError, SessionError,
    StimulusReceipt,
};

use super::support::{
    RUN, Scenario, advance_to_transitions, agent, canary_for, cleanup_tx, endpoint_interface,
    observed_at, packet_ref, receiver_interface, result, tx,
};

#[test]
fn early_receipts_are_rejected() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);

    // A created session has no authority to ingest later lifecycle evidence
    assert_eq!(session.phase(), AssessmentPhase::Created);
    assert!(
        session
            .record_stimulus(
                StimulusReceipt::new(
                    RUN,
                    scenario.stimulus.id(),
                    tx(scenario.stimulus)?,
                    packet_ref(0xa1, 1)?,
                )?,
                super::support::budget_time(4)?
            )
            .is_err()
    );
    assert!(
        session
            .record_original_binding(
                OriginalBindingReceipt::new(
                    RUN,
                    scenario
                        .plan
                        .endpoints()
                        .first()
                        .ok_or("endpoint")?
                        .binding(),
                    endpoint_interface(1)?,
                    EvidenceOrigin::Unavailable
                )?,
                super::support::budget_time(2)?
            )
            .is_err()
    );

    // Evaluation reports every missing gate instead of inferring success
    let report = session.evaluate();
    assert_eq!(report.overall_status(), AssessmentStatus::Inconclusive);
    let check = result(&report)?;
    assert_eq!(check.committed_stimuli(), 0);
    assert_eq!(check.planned_stimuli(), 1);
    assert_eq!(check.transitions(), 0);

    let mut empty_plan = l2_onpath::AssessmentPlan::for_replay(RUN)?;
    empty_plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
    let empty_session = AssessmentSession::new(&empty_plan, super::support::budget_timebase()?);
    let empty_report = empty_session.evaluate();
    assert_eq!(result(&empty_report)?.planned_stimuli(), 0);

    for expected in [
        "precheck was not completed cleanly",
        "original bindings are missing",
        "controlled endpoints were not armed",
        "committed bounded stimulus receipts are incomplete",
        "neighbor transition receipts are incomplete",
        "authenticated canary traversal receipts are incomplete",
        "cleanup or restoration receipts are missing",
    ] {
        assert!(
            check
                .limitations()
                .iter()
                .any(|item| item.contains(expected)),
            "{expected}"
        );
    }
    Ok(())
}

#[test]
fn original_binding_match_plan() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    session.record_precheck(
        PrecheckReceipt::complete_for_endpoints(
            RUN,
            u16::try_from(scenario.plan.endpoints().len())?,
        )?,
        super::support::budget_time(1)?,
    )?;
    let original = scenario
        .plan
        .endpoints()
        .first()
        .ok_or("endpoint")?
        .binding();
    let changed = NeighborBinding::new(
        original.endpoint(),
        original.address(),
        MacAddress::new([0x02, 9, 9, 9, 9, 9])?,
    )?;

    // The snapshot is authoritative for the later cleanup comparison
    assert!(
        session
            .record_original_binding(
                OriginalBindingReceipt::new(
                    RUN,
                    changed,
                    endpoint_interface(1)?,
                    EvidenceOrigin::Packet(packet_ref(0x22, 1)?)
                )?,
                super::support::budget_time(2)?
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn precheck_covers_every_endpoint() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    let incomplete = PrecheckReceipt::complete_for_endpoints(RUN, 1)?;

    // A clean flag cannot compensate for an endpoint count mismatch
    assert!(
        session
            .record_precheck(incomplete, super::support::budget_time(1)?)
            .is_err()
    );
    assert_eq!(session.phase(), AssessmentPhase::Created);
    Ok(())
}

#[test]
fn precheck_plans_without_cleanup_reserves() -> Result<(), Box<dyn Error>> {
    let endpoint = super::support::endpoint(1, 10)?;
    let mut plan = l2_onpath::AssessmentPlan::for_replay(RUN)?;
    plan.add_endpoint(endpoint)?;
    plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
    let mut session = AssessmentSession::new(&plan, super::support::budget_timebase()?);
    let precheck = PrecheckReceipt::complete_for_endpoints(RUN, 1)?;

    assert!(matches!(
        session.record_precheck(precheck, super::support::budget_time(1)?),
        Err(SessionError::CleanupCommitmentsIncomplete)
    ));
    assert_eq!(session.phase(), AssessmentPhase::Created);
    Ok(())
}

#[test]
fn gates_accept_only_planned_receipts() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    let first = *scenario.plan.endpoints().first().ok_or("endpoint")?;
    let second = *scenario.plan.endpoints().get(1).ok_or("endpoint")?;
    let precheck = PrecheckReceipt::complete_for_endpoints(RUN, 2)?;
    establish_precheck_and_reject_invalid_originals(&mut session, first, precheck)?;

    let first_original = OriginalBindingReceipt::new(
        RUN,
        first.binding(),
        first.interface(),
        EvidenceOrigin::Packet(packet_ref(0x22, 1)?),
    )?;
    session.record_original_binding(first_original, super::support::budget_time(2)?)?;
    assert!(
        session
            .record_original_binding(first_original, super::support::budget_time(2)?)
            .is_ok()
    );
    session.record_original_binding(
        OriginalBindingReceipt::new(
            RUN,
            second.binding(),
            second.interface(),
            EvidenceOrigin::Packet(packet_ref(0x22, 2)?),
        )?,
        super::support::budget_time(2)?,
    )?;
    assert_eq!(session.phase(), AssessmentPhase::OriginalBindingRecorded);
    reject_unknown_arm_and_record_endpoints(&mut session, first, second)?;
    Ok(())
}

fn establish_precheck_and_reject_invalid_originals(
    session: &mut AssessmentSession,
    first: l2_onpath::ControlledEndpoint,
    precheck: PrecheckReceipt,
) -> Result<(), Box<dyn Error>> {
    // Run identity is checked before a receipt can advance a gate
    assert!(
        session
            .record_precheck(
                PrecheckReceipt::complete_for_endpoints([9; l2_onpath::ID_LEN], 2)?,
                super::support::budget_time(1)?
            )
            .is_err()
    );
    session.record_precheck(precheck, super::support::budget_time(1)?)?;
    assert!(
        session
            .record_precheck(precheck, super::support::budget_time(1)?)
            .is_err()
    );

    assert!(
        session
            .record_original_binding(
                OriginalBindingReceipt::new(
                    [9; l2_onpath::ID_LEN],
                    first.binding(),
                    first.interface(),
                    EvidenceOrigin::Packet(packet_ref(0x22, 1)?)
                )?,
                super::support::budget_time(2)?
            )
            .is_err()
    );

    let unknown = NeighborBinding::new(
        agent(9)?,
        "192.0.2.9".parse()?,
        MacAddress::new([0x02, 0, 0, 0, 0, 9])?,
    )?;
    assert!(
        session
            .record_original_binding(
                OriginalBindingReceipt::new(
                    RUN,
                    unknown,
                    endpoint_interface(9)?,
                    EvidenceOrigin::Packet(packet_ref(0x22, 2)?)
                )?,
                super::support::budget_time(2)?
            )
            .is_err()
    );
    Ok(())
}

fn reject_unknown_arm_and_record_endpoints(
    session: &mut AssessmentSession,
    first: l2_onpath::ControlledEndpoint,
    second: l2_onpath::ControlledEndpoint,
) -> Result<(), Box<dyn Error>> {
    // Unknown endpoint identities cannot be armed into this plan
    assert!(
        session
            .arm_endpoint(
                ArmReceipt::new(RUN, agent(9)?, AddressFamily::Ipv4, endpoint_interface(9)?)?,
                super::support::budget_time(3)?
            )
            .is_err()
    );
    session.arm_endpoint(
        ArmReceipt::new(RUN, first.id(), first.family(), first.interface())?,
        super::support::budget_time(3)?,
    )?;
    assert_eq!(session.phase(), AssessmentPhase::OriginalBindingRecorded);
    session.arm_endpoint(
        ArmReceipt::new(RUN, second.id(), second.family(), second.interface())?,
        super::support::budget_time(3)?,
    )?;
    assert_eq!(session.phase(), AssessmentPhase::EndpointsArmed);
    Ok(())
}

#[test]
fn original_arm_interface_without_mutation() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    session.record_precheck(
        PrecheckReceipt::complete_for_endpoints(RUN, 2)?,
        super::support::budget_time(1)?,
    )?;
    let first = scenario.plan.endpoints().first().ok_or("endpoint")?;
    let wrong_interface = endpoint_interface(90)?;

    assert!(matches!(
        session.record_original_binding(OriginalBindingReceipt::new(RUN, first.binding(), wrong_interface, EvidenceOrigin::Unavailable)?,
            super::support::budget_time(2)?
        ),
        Err(SessionError::Receipt(
            ReceiptError::EndpointInterfaceMismatch { expected, actual }
        )) if expected == first.interface() && actual == wrong_interface
    ));
    assert_eq!(session.phase(), AssessmentPhase::Precheck);

    for endpoint in scenario.plan.endpoints() {
        session.record_original_binding(
            OriginalBindingReceipt::new(
                RUN,
                endpoint.binding(),
                endpoint.interface(),
                EvidenceOrigin::Packet(packet_ref(0x22, 1)?),
            )?,
            super::support::budget_time(2)?,
        )?;
    }
    assert_eq!(session.phase(), AssessmentPhase::OriginalBindingRecorded);
    assert!(matches!(
        session.arm_endpoint(ArmReceipt::new(RUN, first.id(), first.family(), wrong_interface)?,
            super::support::budget_time(3)?
        ),
        Err(SessionError::Receipt(
            ReceiptError::EndpointInterfaceMismatch { expected, actual }
        )) if expected == first.interface() && actual == wrong_interface
    ));
    assert_eq!(session.phase(), AssessmentPhase::OriginalBindingRecorded);

    for endpoint in scenario.plan.endpoints() {
        session.arm_endpoint(
            ArmReceipt::new(RUN, endpoint.id(), endpoint.family(), endpoint.interface())?,
            super::support::budget_time(3)?,
        )?;
    }
    assert_eq!(session.phase(), AssessmentPhase::EndpointsArmed);
    Ok(())
}

#[test]
fn cleanup_receipt_interface_without_mutation() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;
    session.record_canary_wire(
        &canary.wire,
        &canary.key,
        CanaryWireEvidence::new(
            canary.tx()?,
            canary.window(0, true)?,
            receiver_interface()?,
            observed_at(27)?,
            packet_ref(0xb1, 1)?,
        ),
        super::support::budget_time(6)?,
    )?;
    let first = scenario.plan.endpoints().first().ok_or("endpoint")?;
    let wrong_interface = endpoint_interface(90)?;

    assert!(matches!(
        session.record_cleanup(&CleanupReceipt::new(RUN, wrong_interface, first.binding(), true, cleanup_tx(*first, 3)?, packet_ref(0xc1, 1)?)?,
            super::support::budget_time(50)?
        ),
        Err(SessionError::Receipt(
            ReceiptError::EndpointInterfaceMismatch { expected, actual }
        )) if expected == first.interface() && actual == wrong_interface
    ));
    assert_eq!(session.phase(), AssessmentPhase::CanariesRecorded);
    session.record_cleanup(
        &CleanupReceipt::new(
            RUN,
            first.interface(),
            first.binding(),
            true,
            cleanup_tx(*first, 3)?,
            packet_ref(0xc1, 1)?,
        )?,
        super::support::budget_time(50)?,
    )?;
    assert_eq!(session.phase(), AssessmentPhase::CleanupInProgress);
    Ok(())
}

fn session_ready_for_cleanup(scenario: &Scenario) -> Result<AssessmentSession, Box<dyn Error>> {
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;
    session.record_canary_wire(
        &canary.wire,
        &canary.key,
        CanaryWireEvidence::new(
            canary.tx()?,
            canary.window(0, true)?,
            receiver_interface()?,
            observed_at(27)?,
            packet_ref(0xb1, 1)?,
        ),
        super::support::budget_time(6)?,
    )?;
    Ok(session)
}

#[test]
fn cleanup_binding_scope_outcome_validated() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let first = scenario.plan.endpoints().first().ok_or("endpoint")?;
    let second = scenario.plan.endpoints().get(1).ok_or("endpoint")?;
    let original = first.binding();
    let changed = NeighborBinding::new(
        first.id(),
        first.binding().address(),
        MacAddress::new([0x02, 0, 0, 0, 0, 0xaa])?,
    )?;
    let unrelated_endpoint = NeighborBinding::new(
        second.id(),
        second.binding().address(),
        MacAddress::new([0x02, 0, 0, 0, 0, 0xbb])?,
    )?;
    let wrong_family = NeighborBinding::new(
        first.id(),
        "2001:db8::10".parse()?,
        MacAddress::new([0x02, 0, 0, 0, 0, 0xcc])?,
    )?;
    let wrong_address = NeighborBinding::new(
        first.id(),
        "192.0.2.11".parse()?,
        MacAddress::new([0x02, 0, 0, 0, 0, 0xdd])?,
    )?;

    // Cleanup outcome and observed binding must tell the same story
    for (observed, restored) in [(original, false), (changed, true)] {
        let mut session = session_ready_for_cleanup(&scenario)?;
        assert!(
            session
                .record_cleanup(
                    &CleanupReceipt::new(
                        RUN,
                        first.interface(),
                        observed,
                        restored,
                        cleanup_tx(*first, 3)?,
                        packet_ref(0xc1, 1)?
                    )?,
                    super::support::budget_time(50)?
                )
                .is_err()
        );
        assert_eq!(session.phase(), AssessmentPhase::CanariesRecorded);
    }

    // Endpoint, family, and address scope are required for both outcomes
    for observed in [unrelated_endpoint, wrong_family, wrong_address] {
        for restored in [false, true] {
            let mut session = session_ready_for_cleanup(&scenario)?;
            assert!(
                session
                    .record_cleanup(
                        &CleanupReceipt::new(
                            RUN,
                            first.interface(),
                            observed,
                            restored,
                            cleanup_tx(*first, 3)?,
                            packet_ref(0xc1, 1)?
                        )?,
                        super::support::budget_time(50)?
                    )
                    .is_err()
            );
            assert_eq!(session.phase(), AssessmentPhase::CanariesRecorded);
        }
    }

    // Both valid outcomes retain their exact binding evidence
    for (observed, restored) in [(changed, false), (original, true)] {
        let mut session = session_ready_for_cleanup(&scenario)?;
        session.record_cleanup(
            &CleanupReceipt::new(
                RUN,
                first.interface(),
                observed,
                restored,
                cleanup_tx(*first, 3)?,
                packet_ref(0xc1, 1)?,
            )?,
            super::support::budget_time(50)?,
        )?;
        assert_eq!(session.phase(), AssessmentPhase::CleanupInProgress);
    }
    Ok(())
}
