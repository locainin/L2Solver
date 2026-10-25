use std::error::Error;

use l2_canary::{AgentId, encode};
use l2_helper_protocol::InterfaceBindingRequest;
use l2_segmentation::{
    ClockDomainId, ClockStamp, ControllerEvent, EvaluationContext, EvaluationError,
    EvaluationStatus, Evaluator, ObservationDisposition, ObservationRejection,
    ObservationWindowReceipt, ObservationWindowTiming, ReceiptError, RuleExpectation,
};

use super::support::{RUN, agent_interface, input_with_rule, key_for, packet_ref, record_transmit};

fn interface(ifindex: u32) -> Result<InterfaceBindingRequest, Box<dyn Error>> {
    Ok(InterfaceBindingRequest::new(1, 2, ifindex, 1)?)
}

fn window(
    sequence: u64,
    receiver: AgentId,
    receiver_interface: InterfaceBindingRequest,
    domain: ClockDomainId,
) -> Result<ObservationWindowReceipt, Box<dyn Error>> {
    Ok(ObservationWindowReceipt::new(
        RUN,
        sequence,
        receiver,
        receiver_interface,
        ObservationWindowTiming::new(
            ClockStamp::new(domain, 100)?,
            ClockStamp::new(domain, 200)?,
            ControllerEvent::new(RUN, sequence, sequence * 10 + 1)?,
            ControllerEvent::new(RUN, sequence, sequence * 10 + 5)?,
            ControllerEvent::new(RUN, sequence, sequence * 10 + 7)?,
        )?,
        0,
        true,
    )?)
}

fn window_with_events(
    sequence: u64,
    receiver: AgentId,
    receiver_interface: InterfaceBindingRequest,
    domain: ClockDomainId,
    events: [u64; 3],
) -> Result<ObservationWindowReceipt, Box<dyn Error>> {
    Ok(ObservationWindowReceipt::new(
        RUN,
        sequence,
        receiver,
        receiver_interface,
        ObservationWindowTiming::new(
            ClockStamp::new(domain, 100)?,
            ClockStamp::new(domain, 200)?,
            ControllerEvent::new(RUN, sequence, events[0])?,
            ControllerEvent::new(RUN, sequence, events[1])?,
            ControllerEvent::new(RUN, sequence, events[2])?,
        )?,
        0,
        true,
    )?)
}

#[test]
fn source_side_cannot_destination_arrival() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let wire = encode(&canary, &key)?;
    let domain = ClockDomainId::new([0x21; 16])?;
    let source_interface = interface(10)?;
    let source_window = window(
        probe.sequence(),
        probe.source_agent_id(),
        source_interface,
        domain,
    )?;
    let mut evaluator = Evaluator::new(&plan);

    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            source_window,
            source_interface,
            ClockStamp::new(domain, 150)?,
            packet_ref(0x88, 41)?,
        )?,
        ObservationDisposition::Ignored(ObservationRejection::WrongObservationPoint)
    );
    let status = evaluator
        .evaluate(&EvaluationContext::healthy())
        .results()
        .first()
        .map(l2_segmentation::RuleResult::status)
        .ok_or("missing rule result")?;
    assert_eq!(status, EvaluationStatus::Inconclusive);
    Ok(())
}

#[test]
fn independent_tap_cannot_destination_arrival() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let wire = encode(&canary, &key)?;
    let domain = ClockDomainId::new([0x22; 16])?;
    let tap_interface = interface(11)?;
    let tap_window = window(
        probe.sequence(),
        AgentId::new([0x77; 16])?,
        tap_interface,
        domain,
    )?;
    let mut evaluator = Evaluator::new(&plan);

    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            tap_window,
            tap_interface,
            ClockStamp::new(domain, 150)?,
            packet_ref(0x88, 42)?,
        )?,
        ObservationDisposition::Ignored(ObservationRejection::WrongObservationPoint)
    );
    Ok(())
}

#[test]
fn destination_observation_requires_window_interface() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let wire = encode(&canary, &key)?;
    let domain = ClockDomainId::new([0x23; 16])?;
    let destination_interface = agent_interface(2)?;
    let destination_window = window(
        probe.sequence(),
        probe.destination_agent_id(),
        destination_interface,
        domain,
    )?;
    let mut evaluator = Evaluator::new(&plan);

    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            destination_window,
            interface(13)?,
            ClockStamp::new(domain, 150)?,
            packet_ref(0x88, 43)?,
        ),
        Err(EvaluationError::Receipt(
            ReceiptError::ObservationInterfaceMismatch
        ))
    );
    Ok(())
}

#[test]
fn destination_observation_planned_agent_interface() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let wire = encode(&canary, &key)?;
    let domain = ClockDomainId::new([0x27; 16])?;
    let unrelated_interface = interface(90)?;
    let unrelated_window = window(
        probe.sequence(),
        probe.destination_agent_id(),
        unrelated_interface,
        domain,
    )?;
    let mut evaluator = Evaluator::new(&plan);

    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            unrelated_window,
            unrelated_interface,
            ClockStamp::new(domain, 150)?,
            packet_ref(0x88, 46)?,
        ),
        Err(EvaluationError::Receipt(
            ReceiptError::DestinationInterfaceMismatch
        ))
    );
    assert_eq!(
        evaluator
            .evaluate(&EvaluationContext::healthy())
            .results()
            .first()
            .map(l2_segmentation::RuleResult::status),
        Some(EvaluationStatus::Inconclusive)
    );
    Ok(())
}

#[test]
fn destination_observation_stamp_inside_window() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let wire = encode(&canary, &key)?;
    let domain = ClockDomainId::new([0x24; 16])?;
    let destination_interface = agent_interface(2)?;
    let destination_window = window(
        probe.sequence(),
        probe.destination_agent_id(),
        destination_interface,
        domain,
    )?;
    let mut evaluator = Evaluator::new(&plan);

    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            destination_window,
            destination_interface,
            ClockStamp::new(ClockDomainId::new([0x25; 16])?, 150)?,
            packet_ref(0x88, 44)?,
        ),
        Err(EvaluationError::Receipt(ReceiptError::ClockDomainMismatch))
    );
    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            destination_window,
            destination_interface,
            ClockStamp::new(domain, 201)?,
            packet_ref(0x88, 44)?,
        ),
        Err(EvaluationError::Receipt(
            ReceiptError::ObservationOutsideWindow
        ))
    );
    Ok(())
}

#[test]
fn destination_observation_direct_arrival_evidence() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 1)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let wire = encode(&canary, &key)?;
    let domain = ClockDomainId::new([0x26; 16])?;
    let destination_interface = agent_interface(2)?;
    let destination_window = window(
        probe.sequence(),
        probe.destination_agent_id(),
        destination_interface,
        domain,
    )?;
    let mut evaluator = Evaluator::new(&plan);
    record_transmit(&mut evaluator, &canary, &key, &wire)?;

    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            destination_window,
            destination_interface,
            ClockStamp::new(domain, 150)?,
            packet_ref(0x88, 45)?,
        )?,
        ObservationDisposition::Accepted
    );
    let status = evaluator
        .evaluate(&EvaluationContext::healthy())
        .results()
        .first()
        .map(l2_segmentation::RuleResult::status)
        .ok_or("missing rule result")?;
    assert_eq!(status, EvaluationStatus::Fail);
    Ok(())
}

#[test]
fn destination_arrival_causally_covered_transmit() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 2)?)?;
    let probe = *plan.probes().first().ok_or("missing probe")?;
    let retry_probe = *plan.probes().get(1).ok_or("missing retry probe")?;
    let canary = probe.canary()?;
    let key = key_for(&canary)?;
    let wire = encode(&canary, &key)?;
    let domain = ClockDomainId::new([0x28; 16])?;
    let destination_interface = agent_interface(2)?;
    let missing_tx_window = window(
        probe.sequence(),
        probe.destination_agent_id(),
        destination_interface,
        domain,
    )?;
    let mut evaluator = Evaluator::new(&plan);

    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            missing_tx_window,
            destination_interface,
            ClockStamp::new(domain, 150)?,
            packet_ref(0x88, 47)?,
        ),
        Err(EvaluationError::Receipt(
            ReceiptError::MissingTransmitReceipt
        ))
    );
    record_transmit(&mut evaluator, &canary, &key, &wire)?;
    let noncausal_window = window_with_events(
        probe.sequence(),
        probe.destination_agent_id(),
        destination_interface,
        domain,
        [4, 5, 7],
    )?;
    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            noncausal_window,
            destination_interface,
            ClockStamp::new(domain, 150)?,
            packet_ref(0x88, 47)?,
        ),
        Err(EvaluationError::Receipt(
            ReceiptError::CausalCoverageMissing
        ))
    );

    evaluator.record_window(window_with_events(
        retry_probe.sequence(),
        retry_probe.destination_agent_id(),
        retry_probe.destination_interface(),
        domain,
        [4, 25, 27],
    )?)?;
    assert_eq!(
        evaluator
            .evaluate(&EvaluationContext::healthy())
            .results()
            .first()
            .map(l2_segmentation::RuleResult::status),
        Some(EvaluationStatus::Inconclusive)
    );
    Ok(())
}

#[test]
fn accepted_arrival_reserves_window_events() -> Result<(), Box<dyn Error>> {
    let plan = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 2)?)?;
    let first = *plan.probes().first().ok_or("missing first probe")?;
    let second = *plan.probes().get(1).ok_or("missing second probe")?;
    let canary = first.canary()?;
    let key = key_for(&canary)?;
    let wire = encode(&canary, &key)?;
    let domain = ClockDomainId::new([0x29; 16])?;
    let destination_interface = first.destination_interface();

    let mut evaluator = Evaluator::new(&plan);
    record_transmit(&mut evaluator, &canary, &key, &wire)?;
    assert_eq!(
        evaluator.observe_wire(
            &wire,
            &key,
            window(
                first.sequence(),
                first.destination_agent_id(),
                destination_interface,
                domain,
            )?,
            destination_interface,
            ClockStamp::new(domain, 150)?,
            packet_ref(0x88, 48)?,
        )?,
        ObservationDisposition::Accepted
    );

    let conflicting = ObservationWindowReceipt::new(
        RUN,
        second.sequence(),
        second.destination_agent_id(),
        second.destination_interface(),
        ObservationWindowTiming::new(
            ClockStamp::new(domain, 100)?,
            ClockStamp::new(domain, 200)?,
            ControllerEvent::new(RUN, second.sequence(), 11)?,
            ControllerEvent::new(RUN, second.sequence(), 25)?,
            ControllerEvent::new(RUN, second.sequence(), 27)?,
        )?,
        0,
        true,
    )?;
    assert_eq!(
        evaluator.record_window(conflicting),
        Err(ReceiptError::ControllerEventReuse { ordinal: 11 })
    );
    Ok(())
}
