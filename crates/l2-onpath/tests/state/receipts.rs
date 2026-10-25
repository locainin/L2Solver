use std::error::Error;

use l2_onpath::{
    AddressFamily, ArmReceipt, AuthenticatedCanaryReceipt, CanaryArrivalReceipt, CanaryTraversal,
    CleanupReceipt, EvidenceOrigin, MacAddress, NeighborBinding, NeighborDisposition,
    NeighborTransitionReceipt, ObservationWindowReceipt, OriginalBindingReceipt, PrecheckReceipt,
    StimulusId, StimulusReceipt,
};
use l2_segmentation::TxReceipt;

use super::support::{
    RUN, Scenario, agent, canary, cleanup_tx, observed_at, packet_ref, receiver_interface, tx,
    tx_timing, window_timing,
};

#[test]
fn lifecycle_receipts_preserve_fields() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let endpoint = scenario.plan.endpoints().first().ok_or("endpoint")?;
    let binding = endpoint.binding();

    // Precheck accessors distinguish clean, incomplete, and lossy evidence
    assert!(PrecheckReceipt::complete_for_endpoints([0; l2_onpath::ID_LEN], 2).is_err());
    let precheck = PrecheckReceipt::new(RUN, 2, 3, false)?;
    assert_eq!(precheck.run_id(), RUN);
    assert_eq!(precheck.endpoint_count(), 2);
    assert_eq!(precheck.capture_loss(), 3);
    assert!(!precheck.is_complete());
    assert!(!precheck.is_clean());
    let incomplete = PrecheckReceipt::new(RUN, 2, 0, false)?;
    assert!(!incomplete.is_clean());
    let complete = PrecheckReceipt::complete_for_endpoints(RUN, 2)?;
    assert!(complete.is_complete());
    assert!(complete.is_clean());

    // Original binding and arm receipts retain their checked identity and scope
    let original = OriginalBindingReceipt::new(
        RUN,
        binding,
        endpoint.interface(),
        EvidenceOrigin::Unavailable,
    )?;
    assert_eq!(original.run_id(), RUN);
    assert_eq!(original.binding(), binding);
    assert_eq!(original.interface(), endpoint.interface());
    assert_eq!(original.evidence_origin(), EvidenceOrigin::Unavailable);
    let arm = ArmReceipt::new(
        RUN,
        binding.endpoint(),
        binding.family(),
        endpoint.interface(),
    )?;
    assert_eq!(arm.run_id(), RUN);
    assert_eq!(arm.endpoint(), binding.endpoint());
    assert_eq!(arm.family(), binding.family());
    assert_eq!(arm.interface(), endpoint.interface());
    Ok(())
}

#[test]
fn stimulus_transition_receipts_preserve_fields() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;

    // Stimulus receipts expose the shared bounded transmit unchanged
    let transmit = tx(scenario.stimulus)?;
    let committed =
        StimulusReceipt::new(RUN, scenario.stimulus.id(), transmit, packet_ref(0x11, 10)?)?;
    assert_eq!(committed.run_id(), RUN);
    assert_eq!(committed.stimulus(), scenario.stimulus.id());
    assert_eq!(committed.tx(), transmit);
    assert_eq!(committed.sequence(), scenario.stimulus.sequence());
    assert_eq!(committed.evidence_packet(), packet_ref(0x11, 10)?);
    let second_tx = TxReceipt::new(
        RUN,
        2,
        l2_onpath::InterfaceBindingRequest::new(1, 2, 3, 1)?,
        [6; 32],
        tx_timing(2, 16, 23)?,
    )?;
    let second = StimulusReceipt::new(RUN, StimulusId::new(2)?, second_tx, packet_ref(0x11, 11)?)?;
    assert_eq!(second.sequence(), 2);

    // Transition receipts preserve the observation window and optional binding
    let endpoint = scenario.plan.endpoints().first().ok_or("endpoint")?;
    let binding = endpoint.binding();
    let window = ObservationWindowReceipt::new(
        RUN,
        scenario.stimulus.sequence(),
        agent(1)?,
        receiver_interface()?,
        window_timing(scenario.stimulus.sequence(), (10, 21), (11, 15, 17))?,
        0,
        true,
    )?;
    let transition = NeighborTransitionReceipt::new(
        RUN,
        scenario.stimulus.id(),
        AddressFamily::Ipv4,
        NeighborDisposition::ConflictRejected,
        window,
    )?
    .with_observed_binding(binding);
    assert_eq!(transition.run_id(), RUN);
    assert_eq!(transition.stimulus(), scenario.stimulus.id());
    assert_eq!(transition.family(), AddressFamily::Ipv4);
    assert_eq!(
        transition.disposition(),
        NeighborDisposition::ConflictRejected
    );
    assert_eq!(transition.window(), window);
    assert_eq!(transition.observed_binding(), Some(binding));
    Ok(())
}

#[test]
fn canary_cleanup_receipts_preserve_fields() -> Result<(), Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    let endpoint = scenario.plan.endpoints().first().ok_or("endpoint")?;
    let binding = endpoint.binding();

    // Raw bytes are verified before either authenticated traversal is built
    let canary = canary()?;
    let arrival_window = canary.window_at((27, 28))?;
    let arrival = CanaryArrivalReceipt::from_verified(
        l2_canary::verify(l2_canary::UnverifiedCanary::new(&canary.wire), &canary.key)?,
        arrival_window,
        receiver_interface()?,
        observed_at(27)?,
        packet_ref(0x12, 12)?,
    )?;
    let arrived = AuthenticatedCanaryReceipt::from_arrival(arrival, canary.tx()?)?;
    assert_eq!(arrived.canary(), canary.canary);
    assert_eq!(arrived.transmit(), canary.tx()?);
    assert_eq!(arrived.window(), arrival_window);
    assert_eq!(arrived.evidence_packet(), packet_ref(0x12, 12)?);
    assert_eq!(arrived.traversal(), CanaryTraversal::Arrived);

    let blocked_window = canary.window_at((26, 27))?;
    let blocked = AuthenticatedCanaryReceipt::from_verified_blocked(
        l2_canary::verify(l2_canary::UnverifiedCanary::new(&canary.wire), &canary.key)?,
        canary.tx()?,
        blocked_window,
        packet_ref(0x13, 13)?,
    )?;
    assert_eq!(blocked.traversal(), CanaryTraversal::NotObserved);

    // Cleanup accessors expose restoration and capture quality explicitly
    let observed = NeighborBinding::new(
        binding.endpoint(),
        binding.address(),
        MacAddress::new([0x02, 0, 0, 0, 0, 0xaa])?,
    )?;
    let cleanup = CleanupReceipt::new(
        RUN,
        endpoint.interface(),
        observed,
        false,
        cleanup_tx(*endpoint, 3)?,
        packet_ref(0x14, 14)?,
    )?
    .with_capture_loss(2);
    assert_eq!(cleanup.run_id(), RUN);
    assert_eq!(cleanup.endpoint(), binding.endpoint());
    assert_eq!(cleanup.family(), binding.family());
    assert_eq!(cleanup.interface(), endpoint.interface());
    assert_eq!(cleanup.observed_binding(), observed);
    assert!(!cleanup.restored());
    assert_eq!(cleanup.capture_loss(), 2);
    assert_eq!(cleanup.transmit(), cleanup_tx(*endpoint, 3)?);
    assert_eq!(cleanup.evidence_packet(), packet_ref(0x14, 14)?);
    Ok(())
}
