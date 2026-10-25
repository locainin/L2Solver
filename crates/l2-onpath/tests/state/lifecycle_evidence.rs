use std::error::Error;

use l2_onpath::{
    AssessmentPhase, AssessmentSession, CleanupReceipt, NeighborDisposition, PrecheckReceipt,
    ReceiptError, SessionError,
};

use super::support::{
    RUN, Scenario, advance_to_armed, advance_to_armed_with_unavailable_origin,
    advance_to_transitions, canary_for, cleanup_tx, finish_cleanup, packet_ref, result,
};

#[test]
fn preserves_borrowed_cleanup_evidence() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_armed(&mut session, &scenario.plan)?;
    let endpoint = scenario.plan.endpoints().first().ok_or("endpoint")?;
    let mut receipt = CleanupReceipt::new(
        RUN,
        endpoint.interface(),
        endpoint.binding(),
        true,
        cleanup_tx(*endpoint, 3)?,
        packet_ref(0xc1, 1)?,
    )?;
    let accepted = receipt;

    session.record_cleanup(&receipt, super::support::budget_time(50)?)?;
    assert_eq!(session.phase(), AssessmentPhase::CleanupInProgress);

    // Repeating a borrowed receipt keeps the accepted snapshot and clock unchanged
    session.record_cleanup(&receipt, super::support::budget_time(51)?)?;
    receipt = receipt.with_capture_loss(1);
    assert!(matches!(
        session.record_cleanup(&receipt, super::support::budget_time(52)?),
        Err(SessionError::Receipt(ReceiptError::ConflictingReceipt))
    ));

    // Changing caller-owned evidence cannot replace the session's accepted copy
    let report = session.evaluate();
    assert_eq!(
        report
            .lifecycle_evidence()
            .cleanup_receipts()
            .collect::<Vec<_>>(),
        [&accepted]
    );

    // A later endpoint can still use the last accepted receipt time
    finish_cleanup(&mut session, &scenario.plan, true)?;
    assert_eq!(session.phase(), AssessmentPhase::CleanupRecorded);
    Ok(())
}

#[test]
fn lifecycle_sources_separate_packets() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
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
    let evidence = report.lifecycle_evidence();
    let original_packets = evidence
        .original_bindings()
        .map(|receipt| receipt.evidence_origin().packet())
        .collect::<Vec<_>>();
    let cleanup_packets = evidence
        .cleanup_receipts()
        .map(CleanupReceipt::evidence_packet)
        .collect::<Vec<_>>();

    assert_eq!(
        original_packets,
        [Some(packet_ref(0x22, 1)?), Some(packet_ref(0x22, 2)?)]
    );
    assert_eq!(
        cleanup_packets,
        [packet_ref(0xc1, 1)?, packet_ref(0xc1, 2)?]
    );
    assert_eq!(evidence.missing_original_bindings().count(), 0);
    assert_eq!(evidence.missing_cleanup_receipts().count(), 0);
    assert_eq!(
        result(&report)?.evidence_packets(),
        [packet_ref(0xa1, 1)?, packet_ref(0xb1, 1)?]
    );
    Ok(())
}

#[test]
fn unavailable_original_source_unavailable() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    advance_to_armed_with_unavailable_origin(&mut session, &scenario.plan, true)?;

    let report = session.evaluate();
    let evidence = report.lifecycle_evidence();
    let original_packets = evidence
        .original_bindings()
        .map(|receipt| receipt.evidence_origin().packet())
        .collect::<Vec<_>>();

    assert_eq!(original_packets, [None, Some(packet_ref(0x22, 2)?)]);
    assert_eq!(evidence.missing_original_bindings().count(), 0);
    assert_eq!(evidence.missing_cleanup_receipts().count(), 2);
    assert!(result(&report)?.limitations().iter().any(|item| {
        item.contains("original binding evidence source reference is unavailable")
    }));
    Ok(())
}

#[test]
fn lists_endpoints_no_lifecycle_receipts() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let mut session = AssessmentSession::new(&scenario.plan, super::support::budget_timebase()?);
    session.record_precheck(
        PrecheckReceipt::complete_for_endpoints(
            *scenario.plan.run_id(),
            u16::try_from(scenario.plan.endpoints().len())?,
        )?,
        super::support::budget_time(1)?,
    )?;

    let report = session.evaluate();
    let evidence = report.lifecycle_evidence();

    assert_eq!(evidence.original_bindings().len(), 0);
    assert_eq!(evidence.missing_original_bindings().count(), 2);
    assert_eq!(evidence.cleanup_receipts().len(), 0);
    assert_eq!(evidence.missing_cleanup_receipts().count(), 2);
    Ok(())
}
