use super::support::{
    RUN, agent_interface, healthy, input_with_rule, key_for, observation_claim, observe,
    observe_after_transmit, packet_ref, record_transmit,
};
use l2_canary::encode;
use l2_segmentation::{
    DirectedRule, EvaluationContext, EvaluationStatus, Evaluator, ObservationDisposition,
    ObservationRejection, PlanInput, RuleExpectation, SegmentId,
};
use sha2::{Digest, Sha256};
use std::error::Error;

#[test]
fn deny_receipt_confirmed_failure() -> Result<(), Box<dyn Error>> {
    let planned = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 2)?)?;
    let mut evaluator = Evaluator::new(&planned);
    let first = planned.probes().first().ok_or("missing probe")?.canary()?;

    assert_eq!(
        observe(&mut evaluator, &first, 42)?,
        ObservationDisposition::Accepted
    );
    let report = evaluator.evaluate(&healthy());
    let result = report.results().first().ok_or("missing result")?;
    assert_eq!(result.status(), EvaluationStatus::Fail);
    assert_eq!(result.planned_attempts(), 2);
    assert_eq!(result.matching_receipts(), 1);
    assert_eq!(result.missing_attempts(), 1);
    let evidence = result
        .evidence()
        .first()
        .ok_or("missing arrival evidence")?;
    assert_eq!(evidence.packet_reference(), packet_ref(0x88, 42)?);
    assert_eq!(evidence.canary(), first);
    assert_eq!(evidence.source_interface(), agent_interface(1)?);
    assert_eq!(evidence.observation_interface(), agent_interface(2)?);
    assert_eq!(evidence.observed_at().domain().get(), [0x44; 16]);
    assert_eq!(evidence.observed_at().ticks(), 150);
    let key = key_for(&first)?;
    let wire = encode(&first, &key)?;
    assert_eq!(
        evidence.canary_wire_sha256(),
        <[u8; 32]>::from(Sha256::digest(wire))
    );
    assert_eq!(evidence.transmit_event().ordinal(), 13);
    assert_eq!(evidence.window().timing().arm_ack().ordinal(), 11);
    assert_eq!(evidence.window().timing().close_issued().ordinal(), 15);
    assert_eq!(evidence.window().timing().complete().ordinal(), 17);
    assert!(
        result.absence_evidence().is_empty(),
        "an observed canary cannot also prove absence"
    );
    Ok(())
}

#[test]
fn cross_source_packet_identity() -> Result<(), Box<dyn Error>> {
    let planned = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 2)?)?;
    let mut evaluator = Evaluator::new(&planned);
    for (index, probe) in planned.probes().iter().enumerate() {
        let canary = probe.canary()?;
        let key = key_for(&canary)?;
        let wire = encode(&canary, &key)?;
        record_transmit(&mut evaluator, &canary, &key, &wire)?;
        let (window, interface, observed_at) = observation_claim(&canary)?;
        let source = u8::try_from(index)? + 0x41;
        evaluator.observe_wire(
            &wire,
            &key,
            window,
            interface,
            observed_at,
            packet_ref(source, 1)?,
        )?;
    }

    let report = evaluator.evaluate(&healthy());
    let evidence = report
        .results()
        .first()
        .ok_or("missing rule result")?
        .evidence();
    let references: Vec<_> = evidence
        .iter()
        .map(|item| item.packet_reference())
        .collect();

    assert_eq!(references, [packet_ref(0x41, 1)?, packet_ref(0x42, 1)?]);
    Ok(())
}

#[test]
fn deny_without_execution_evidence_inconclusive() -> Result<(), Box<dyn Error>> {
    let planned = l2_segmentation::plan(&input_with_rule(RuleExpectation::Deny, 2)?)?;
    let evaluator = Evaluator::new(&planned);
    let report = evaluator.evaluate(&healthy());
    let result = report.results().first().ok_or("missing result")?;

    assert_eq!(result.status(), EvaluationStatus::Inconclusive);
    assert_eq!(result.planned_attempts(), 2);
    assert_eq!(result.matching_receipts(), 0);
    assert_eq!(result.missing_attempts(), 2);
    assert!(
        result
            .limitations()
            .iter()
            .any(|value| value == "one or more planned probes lack a committed transmit receipt")
    );
    assert!(result.limitations().iter().any(|value| {
        value
            == "one or more receiver windows lack complete loss-free coverage of the committed send"
    }));

    for (context, limitation) in [
        (
            EvaluationContext::new(
                false,
                true,
                l2_segmentation::CaptureQuality::Complete,
                false,
            ),
            "sender availability was incomplete",
        ),
        (
            EvaluationContext::new(
                true,
                false,
                l2_segmentation::CaptureQuality::Complete,
                false,
            ),
            "receiver availability was incomplete",
        ),
        (
            EvaluationContext::new(
                true,
                true,
                l2_segmentation::CaptureQuality::Incomplete,
                false,
            ),
            "capture quality was incomplete",
        ),
        (
            EvaluationContext::new(true, true, l2_segmentation::CaptureQuality::Dropped, false),
            "capture reported dropped observations",
        ),
        (
            EvaluationContext::new(true, true, l2_segmentation::CaptureQuality::Complete, true),
            "observation was cancelled before completion",
        ),
    ] {
        let report = Evaluator::new(&planned).evaluate(&context);
        let result = report.results().first().ok_or("missing result")?;
        assert_eq!(result.status(), EvaluationStatus::Inconclusive);
        assert!(result.limitations().iter().any(|value| value == limitation));
    }
    Ok(())
}

#[test]
fn allow_requires_all_planned_receipts() -> Result<(), Box<dyn Error>> {
    let planned = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 2)?)?;
    let mut evaluator = Evaluator::new(&planned);
    let first = planned
        .probes()
        .first()
        .ok_or("missing first probe")?
        .canary()?;
    assert_eq!(
        observe(&mut evaluator, &first, 70)?,
        ObservationDisposition::Accepted
    );
    assert_eq!(
        evaluator
            .evaluate(&healthy())
            .results()
            .first()
            .ok_or("missing result")?
            .status(),
        EvaluationStatus::Inconclusive
    );

    let second = planned
        .probes()
        .get(1)
        .ok_or("missing second probe")?
        .canary()?;
    assert_eq!(
        observe(&mut evaluator, &second, 71)?,
        ObservationDisposition::Accepted
    );
    let report = evaluator.evaluate(&healthy());
    let result = report.results().first().ok_or("missing result")?;
    assert_eq!(result.status(), EvaluationStatus::Pass);
    assert_eq!(result.planned_attempts(), 2);
    assert_eq!(result.matching_receipts(), 2);
    assert_eq!(result.missing_attempts(), 0);
    assert!(result.limitations().is_empty());
    assert_eq!(
        result
            .evidence()
            .iter()
            .map(|evidence| evidence.packet_reference())
            .collect::<Vec<_>>(),
        [packet_ref(0x88, 70)?, packet_ref(0x88, 71)?]
    );
    Ok(())
}

#[test]
fn evaluation_scoped_each_direction() -> Result<(), Box<dyn Error>> {
    let mut input = PlanInput::for_replay(RUN)?;
    input
        .segments
        .extend([SegmentId::new(1), SegmentId::new(2), SegmentId::new(3)]);
    input.agents.extend([
        super::support::agent(1, 1)?,
        super::support::agent(2, 2)?,
        super::support::agent(3, 3)?,
    ]);
    input.rules.extend([
        DirectedRule::new(
            SegmentId::new(1),
            SegmentId::new(2),
            RuleExpectation::Allow,
            1,
        ),
        DirectedRule::new(
            SegmentId::new(1),
            SegmentId::new(3),
            RuleExpectation::Allow,
            1,
        ),
    ]);
    let planned = l2_segmentation::plan(&input)?;
    let mut evaluator = Evaluator::new(&planned);
    let first = planned
        .probes()
        .first()
        .ok_or("missing first probe")?
        .canary()?;
    let second = planned
        .probes()
        .get(1)
        .ok_or("missing second probe")?
        .canary()?;
    assert_eq!(
        observe(&mut evaluator, &first, 201)?,
        ObservationDisposition::Accepted
    );
    assert_eq!(
        observe(&mut evaluator, &second, 202)?,
        ObservationDisposition::Accepted
    );

    let report = evaluator.evaluate(&healthy());
    let results = report.results();
    let first_result = results.first().ok_or("missing first result")?;
    let second_result = results.get(1).ok_or("missing second result")?;
    let first_evidence = first_result
        .evidence()
        .first()
        .ok_or("missing first evidence")?;
    let second_evidence = second_result
        .evidence()
        .first()
        .ok_or("missing second evidence")?;
    assert_eq!(first_result.planned_attempts(), 1);
    assert_eq!(first_result.matching_receipts(), 1);
    assert_eq!(first_result.missing_attempts(), 0);
    assert_eq!(first_evidence.packet_reference(), packet_ref(0x88, 201)?);
    assert_eq!(second_result.planned_attempts(), 1);
    assert_eq!(second_result.matching_receipts(), 1);
    assert_eq!(second_evidence.packet_reference(), packet_ref(0x88, 202)?);
    assert_ne!(
        first_evidence.observation_interface(),
        second_evidence.observation_interface()
    );
    Ok(())
}

#[test]
fn duplicate_stale_receipts_rejected() -> Result<(), Box<dyn Error>> {
    let planned = l2_segmentation::plan(&input_with_rule(RuleExpectation::Allow, 2)?)?;
    let mut evaluator = Evaluator::new(&planned);
    let first = planned
        .probes()
        .first()
        .ok_or("missing first probe")?
        .canary()?;
    let second = planned
        .probes()
        .get(1)
        .ok_or("missing second probe")?
        .canary()?;
    let first_key = key_for(&first)?;
    let first_wire = encode(&first, &first_key)?;
    let second_key = key_for(&second)?;
    let second_wire = encode(&second, &second_key)?;
    record_transmit(&mut evaluator, &first, &first_key, &first_wire)?;
    record_transmit(&mut evaluator, &second, &second_key, &second_wire)?;

    assert_eq!(
        observe_after_transmit(&mut evaluator, &second, &second_key, &second_wire, 92)?,
        ObservationDisposition::Accepted
    );
    assert_eq!(
        observe_after_transmit(&mut evaluator, &first, &first_key, &first_wire, 91)?,
        ObservationDisposition::Ignored(ObservationRejection::Stale)
    );
    assert_eq!(
        observe_after_transmit(&mut evaluator, &second, &second_key, &second_wire, 99)?,
        ObservationDisposition::Ignored(ObservationRejection::Duplicate)
    );
    let report = evaluator.evaluate(&healthy());
    let result = report.results().first().ok_or("missing result")?;
    assert_eq!(result.matching_receipts(), 1);
    assert_eq!(
        result
            .evidence()
            .iter()
            .map(|evidence| evidence.packet_reference())
            .collect::<Vec<_>>(),
        [packet_ref(0x88, 92)?]
    );
    assert!(
        result.absence_evidence().is_empty(),
        "accepted and stale authenticated arrivals both disprove absence"
    );
    Ok(())
}

#[test]
fn overall_status_is_conservative() -> Result<(), Box<dyn Error>> {
    let mut input = input_with_rule(RuleExpectation::Deny, 1)?;
    input.rules.push(DirectedRule::new(
        SegmentId::new(2),
        SegmentId::new(1),
        RuleExpectation::Allow,
        1,
    ));
    let planned = l2_segmentation::plan(&input)?;
    let evaluator = Evaluator::new(&planned);
    let report = evaluator.evaluate(&healthy());
    assert_eq!(report.overall_status(), EvaluationStatus::Inconclusive);
    Ok(())
}

#[test]
fn empty_plan_is_inconclusive() -> Result<(), Box<dyn Error>> {
    let planned = l2_segmentation::plan(&PlanInput::for_replay(RUN)?)?;
    let report = Evaluator::new(&planned).evaluate(&healthy());
    assert_eq!(report.overall_status(), EvaluationStatus::Inconclusive);
    assert!(report.results().is_empty());
    Ok(())
}
