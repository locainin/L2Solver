use std::error::Error;

use l2_onpath::{
    AssessmentPhase, AssessmentSession, AssessmentStatus, CanaryWireEvidence, CheckKind,
    CleanupReceipt, NeighborDisposition, PathExpectation, StimulusReceipt,
};

use super::support::{
    RUN, Scenario, advance_to_armed, advance_to_armed_with_unavailable_origin,
    advance_to_transitions, assert_limitation, canary_for, cleanup_tx, finish_cleanup, observed_at,
    packet_ref, receiver_interface, result, transition, tx,
};

#[test]
fn structurally_committed_cannot_protected_result() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    assert_eq!(result(&session.evaluate())?.canary_traversals(), 0);

    // The raw wire remains visible at the point where authentication is tested
    let canary = canary_for(&scenario.plan)?;
    session.record_blocked_canary_wire(
        &canary.wire,
        &canary.key,
        canary.tx()?,
        canary.window(0, true)?,
        packet_ref(0xb1, 1)?,
        super::support::budget_time(6)?,
    )?;
    assert_eq!(session.phase(), AssessmentPhase::CanariesRecorded);

    // Cleanup is recorded one endpoint at a time so the phase boundary stays covered
    let first = scenario.plan.endpoints().first().ok_or("endpoint")?;
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
    let second = scenario.plan.endpoints().get(1).ok_or("endpoint")?;
    session.record_cleanup(
        &CleanupReceipt::new(
            RUN,
            second.interface(),
            second.binding(),
            true,
            cleanup_tx(*second, 4)?,
            packet_ref(0xc1, 2)?,
        )?,
        super::support::budget_time(50)?,
    )?;
    assert_eq!(session.phase(), AssessmentPhase::CleanupRecorded);

    let report = session.evaluate();
    assert_eq!(report.phase(), AssessmentPhase::CleanupRecorded);
    assert_eq!(report.status(), AssessmentStatus::Inconclusive);
    assert_eq!(report.overall_status(), AssessmentStatus::Inconclusive);

    let check = result(&report)?;
    assert_eq!(check.status(), AssessmentStatus::Inconclusive);
    assert!(!check.defensible_evidence());
    assert_eq!(check.check(), CheckKind::ArpSpoofSusceptibility);
    assert_eq!(check.committed_stimuli(), 1);
    assert_eq!(check.planned_stimuli(), 1);
    assert_eq!(check.transitions(), 1);
    assert_eq!(check.canary_traversals(), 1);
    assert!(
        check
            .limitations()
            .iter()
            .any(|item| item.contains("check-specific semantic binding"))
    );
    assert_eq!(
        check.evidence_packets(),
        [packet_ref(0xa1, 1)?, packet_ref(0xb1, 1)?]
    );
    Ok(())
}

#[test]
fn assessment_status_predicates() {
    // Status flags describe the outcome independently of a session's evidence
    assert!(AssessmentStatus::Protected.is_protected());
    assert!(!AssessmentStatus::Protected.is_vulnerable());
    assert!(AssessmentStatus::Vulnerable.is_vulnerable());
    assert!(!AssessmentStatus::Vulnerable.is_protected());
    assert!(!AssessmentStatus::Inconclusive.is_vulnerable());
    assert!(!AssessmentStatus::Inconclusive.is_protected());
}

#[test]
fn missing_original_reference_complete_inconclusive() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_armed_with_unavailable_origin(&mut session, &scenario.plan, true)?;
    session.record_stimulus(
        StimulusReceipt::new(
            RUN,
            scenario.stimulus.id(),
            tx(scenario.stimulus)?,
            packet_ref(0xa1, 1)?,
        )?,
        super::support::budget_time(4)?,
    )?;
    session.record_transition(
        transition(scenario.stimulus, NeighborDisposition::ConflictRejected, 0)?,
        super::support::budget_time(5)?,
    )?;

    let canary = canary_for(&scenario.plan)?;
    session.record_blocked_canary_wire(
        &canary.wire,
        &canary.key,
        canary.tx()?,
        canary.window(0, true)?,
        packet_ref(0xb1, 1)?,
        super::support::budget_time(6)?,
    )?;
    finish_cleanup(&mut session, &scenario.plan, true)?;

    let report = session.evaluate();
    let check = result(&report)?;
    assert_eq!(check.status(), AssessmentStatus::Inconclusive);
    assert!(!check.defensible_evidence());
    assert!(check.limitations().iter().any(|item| {
        item.contains("original binding evidence source reference is unavailable")
    }));
    Ok(())
}

#[test]
fn accepted_conflict_without_stimulus_inconclusive() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictAccepted,
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
    finish_cleanup(&mut session, &scenario.plan, true)?;

    let report = session.evaluate();
    let check = result(&report)?;
    assert_eq!(check.status(), AssessmentStatus::Inconclusive);
    assert!(!check.defensible_evidence());
    assert_limitation(&report, "check-specific semantic binding")?;
    Ok(())
}

#[test]
fn incomplete_evidence_stays_inconclusive() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let canary = canary_for(&scenario.plan)?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictAccepted,
    )?;
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
    assert_eq!(
        session.evaluate().overall_status(),
        AssessmentStatus::Inconclusive
    );

    finish_cleanup(&mut session, &scenario.plan, false)?;
    let incomplete = session.evaluate();
    assert_eq!(incomplete.overall_status(), AssessmentStatus::Inconclusive);
    assert!(!result(&incomplete)?.defensible_evidence());
    assert_limitation(&incomplete, "not restored")?;

    // Capture loss keeps an otherwise complete restoration conservative
    let mut lossy = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_armed(&mut lossy, &scenario.plan)?;
    lossy.record_stimulus(
        StimulusReceipt::new(
            RUN,
            scenario.stimulus.id(),
            tx(scenario.stimulus)?,
            packet_ref(0xa1, 1)?,
        )?,
        super::support::budget_time(4)?,
    )?;
    lossy.record_transition(
        transition(scenario.stimulus, NeighborDisposition::ConflictRejected, 1)?,
        super::support::budget_time(5)?,
    )?;
    lossy.record_canary_wire(
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
    finish_cleanup(&mut lossy, &scenario.plan, true)?;
    let lossy_report = lossy.evaluate();
    assert_eq!(
        lossy_report.overall_status(),
        AssessmentStatus::Inconclusive
    );
    assert_limitation(&lossy_report, "capture loss")?;
    Ok(())
}

#[test]
fn forwarded_path_inconclusive_when_blocked() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::for_expectation(PathExpectation::Forwarded)?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_transitions(
        &mut session,
        &scenario.plan,
        scenario.stimulus,
        NeighborDisposition::ConflictRejected,
    )?;
    let canary = canary_for(&scenario.plan)?;
    session.record_blocked_canary_wire(
        &canary.wire,
        &canary.key,
        canary.tx()?,
        canary.window(0, true)?,
        packet_ref(0xb1, 1)?,
        super::support::budget_time(6)?,
    )?;
    finish_cleanup(&mut session, &scenario.plan, true)?;

    let report = session.evaluate();
    assert_eq!(report.overall_status(), AssessmentStatus::Inconclusive);
    assert_limitation(&report, "check-specific semantic binding")?;
    Ok(())
}

#[test]
fn arrived_canary_without_stimulus_inconclusive() -> Result<(), Box<dyn Error>> {
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
    finish_cleanup(&mut session, &scenario.plan, true)?;

    let report = session.evaluate();
    let check = result(&report)?;
    assert_eq!(check.status(), AssessmentStatus::Inconclusive);
    assert!(!check.defensible_evidence());
    assert_limitation(&report, "check-specific semantic binding")?;
    Ok(())
}

#[test]
fn lossy_arrival_without_stimulus_inconclusive() -> Result<(), Box<dyn Error>> {
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
            canary.window(1, false)?,
            receiver_interface()?,
            observed_at(27)?,
            packet_ref(0xb1, 1)?,
        ),
        super::support::budget_time(6)?,
    )?;
    finish_cleanup(&mut session, &scenario.plan, true)?;

    let report = session.evaluate();
    let check = result(&report)?;
    assert_eq!(check.status(), AssessmentStatus::Inconclusive);
    assert!(!check.defensible_evidence());
    assert_limitation(&report, "check-specific semantic binding")?;
    Ok(())
}

#[test]
fn missing_canary_expectation_stays_inconclusive() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::without_canary()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_armed(&mut session, &scenario.plan)?;
    session.record_stimulus(
        StimulusReceipt::new(
            RUN,
            scenario.stimulus.id(),
            tx(scenario.stimulus)?,
            packet_ref(0xa1, 1)?,
        )?,
        super::support::budget_time(4)?,
    )?;
    session.record_transition(
        transition(scenario.stimulus, NeighborDisposition::ConflictRejected, 0)?,
        super::support::budget_time(5)?,
    )?;

    let report = session.evaluate();
    assert_eq!(report.overall_status(), AssessmentStatus::Inconclusive);
    assert_limitation(&report, "no authenticated canary expectation")?;
    Ok(())
}
