mod support;

use std::error::Error;

use l2_canary::AgentId;
use l2_lab::{
    BridgeMode, Cancellation, LabError, ObservationMode, RunOptions, VirtualEndpoint, VirtualLab,
    VlanId,
};
use l2_onpath::Budget;
use l2_scenario::{AdmissionError, Cleanup, StopReason};
use l2_segmentation::{EvaluationStatus, RuleExpectation, SegmentId};
use sha2::{Digest, Sha256};

use support::{SYNTHETIC_KEY, binding, budget, scenario};

#[test]
fn access_ports_forward_within_vlan_and_isolate_other_vlans() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    let run = lab.run(&SYNTHETIC_KEY, budget()?, RunOptions::default())?;

    assert_eq!(run.evaluation().overall_status(), EvaluationStatus::Pass);
    assert_eq!(
        run.capture().records().len(),
        2,
        "only same-VLAN frames reach receivers"
    );
    for result in run.evaluation().results() {
        match result.expectation() {
            RuleExpectation::Allow => {
                assert_eq!(result.matching_receipts(), 2);
                assert_eq!(result.evidence().len(), 2);
            }
            RuleExpectation::Deny => {
                assert_eq!(result.absence_evidence().len(), 2);
                assert_eq!(result.status(), EvaluationStatus::Pass);
            }
        }
    }
    assert_eq!(run.execution().packets(), 6);
    assert_eq!(run.execution().cleanup(), Cleanup::Confirmed);
    assert_eq!(run.execution().stop_reason(), StopReason::Exhausted);
    Ok(())
}

#[test]
fn leaking_bridge_fails_deny_rules_from_receiver_observations() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::LeaksAcrossVlans)?;
    let run = lab.run(&SYNTHETIC_KEY, budget()?, RunOptions::default())?;

    assert_eq!(run.evaluation().overall_status(), EvaluationStatus::Fail);
    assert_eq!(run.capture().records().len(), 6);
    for result in run.evaluation().results() {
        if result.expectation() == RuleExpectation::Deny {
            assert_eq!(result.status(), EvaluationStatus::Fail);
            assert_eq!(result.evidence().len(), 2);
        }
    }
    for record in run.capture().records() {
        let frame = l2_core::decode(record.frame())?;
        let probe = plan
            .probes()
            .iter()
            .find(|probe| probe.sequence() == record.sequence());
        assert_eq!(
            probe.map(|probe| probe.destination_agent_id()),
            Some(record.receiver())
        );
        assert_eq!(
            frame.field,
            l2_core::FrameField::EtherType(l2_canary::ETHER_TYPE)
        );
        assert_eq!(frame.payload.len(), l2_canary::WIRE_LEN);
    }
    Ok(())
}

#[test]
fn wrong_access_vlan_is_detected_without_changing_the_policy() -> Result<(), Box<dyn Error>> {
    let (plan, mut endpoints) = scenario()?;
    let third = endpoints.pop().ok_or("missing fixture endpoint")?;
    endpoints.push(VirtualEndpoint::new(
        third.agent_id(),
        third.interface(),
        third.mac(),
        VlanId::new(10)?,
    )?);
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    let run = lab.run(&SYNTHETIC_KEY, budget()?, RunOptions::default())?;

    let denied = run
        .evaluation()
        .results()
        .iter()
        .find(|result| {
            result.source() == SegmentId::new(1) && result.destination() == SegmentId::new(2)
        })
        .ok_or("missing deny rule")?;
    assert_eq!(denied.status(), EvaluationStatus::Fail);
    assert_eq!(denied.evidence().len(), 2);
    Ok(())
}

#[test]
fn unavailable_or_lossy_observer_never_proves_absence() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    for observer in [ObservationMode::Unavailable, ObservationMode::Dropped] {
        let options = RunOptions::new(observer, Cancellation::Never);
        let run = lab.run(&SYNTHETIC_KEY, budget()?, options)?;
        assert_eq!(
            run.evaluation().overall_status(),
            EvaluationStatus::Inconclusive
        );
        assert!(run.capture().records().is_empty());
        for rule in run.evaluation().results() {
            assert_eq!(rule.status(), EvaluationStatus::Inconclusive);
            assert!(rule.absence_evidence().is_empty());
        }
    }
    Ok(())
}

#[test]
fn unobserved_leak_is_inconclusive_instead_of_a_pass() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::LeaksAcrossVlans)?;
    for observer in [ObservationMode::Unavailable, ObservationMode::Dropped] {
        let run = lab.run(
            &SYNTHETIC_KEY,
            budget()?,
            RunOptions::new(observer, Cancellation::Never),
        )?;
        assert_eq!(
            run.evaluation().overall_status(),
            EvaluationStatus::Inconclusive
        );
        assert!(run.capture().records().is_empty());
        assert!(
            run.evaluation()
                .results()
                .iter()
                .all(|rule| rule.absence_evidence().is_empty())
        );
    }
    Ok(())
}

#[test]
fn cancellation_preserves_a_previously_observed_leak() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::LeaksAcrossVlans)?;
    let run = lab.run(
        &SYNTHETIC_KEY,
        budget()?,
        RunOptions::new(ObservationMode::Healthy, Cancellation::After(3)),
    )?;
    assert_eq!(run.execution().stop_reason(), StopReason::Cancelled);
    assert_eq!(run.evaluation().overall_status(), EvaluationStatus::Fail);
    let denied = run
        .evaluation()
        .results()
        .iter()
        .find(|rule| rule.expectation() == RuleExpectation::Deny)
        .ok_or("missing deny rule")?;
    assert_eq!(denied.status(), EvaluationStatus::Fail);
    assert_eq!(denied.evidence().len(), 1);
    Ok(())
}

#[test]
fn cancelled_run_stops_dispatch_and_reports_only_virtual_cleanup() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    for after in [0, 1] {
        let options = RunOptions::new(ObservationMode::Healthy, Cancellation::After(after));
        let run = lab.run(&SYNTHETIC_KEY, budget()?, options)?;
        assert_eq!(run.execution().stop_reason(), StopReason::Cancelled);
        assert_eq!(run.execution().packets(), after);
        assert_eq!(run.execution().cleanup(), Cleanup::Confirmed);
        assert_eq!(
            run.evaluation().overall_status(),
            EvaluationStatus::Inconclusive
        );
    }
    Ok(())
}

#[test]
fn same_inputs_produce_identical_capture_and_evaluation() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    let first = lab.run(&SYNTHETIC_KEY, budget()?, RunOptions::default())?;
    let second = lab.run(&SYNTHETIC_KEY, budget()?, RunOptions::default())?;
    assert_eq!(first.capture(), second.capture());
    assert_eq!(first.evaluation(), second.evaluation());
    assert_eq!(first.execution(), second.execution());
    let digest: [u8; 32] = Sha256::digest(first.capture().bytes()?).into();
    assert_eq!(*first.capture().source().as_bytes(), digest);
    for result in first.evaluation().results() {
        for evidence in result.evidence() {
            assert_eq!(
                evidence.packet_reference().source(),
                first.capture().source()
            );
            let number = usize::try_from(evidence.packet_reference().packet_number())?;
            let record = first
                .capture()
                .records()
                .get(number - 1)
                .ok_or("missing packet")?;
            assert_eq!(record.sequence(), evidence.canary().sequence());
            let frame_digest: [u8; 32] = Sha256::digest(record.frame()).into();
            assert_eq!(frame_digest, evidence.frame_sha256());
        }
    }
    Ok(())
}

#[test]
fn reserved_vlans_and_invalid_mac_addresses_are_rejected() -> Result<(), Box<dyn Error>> {
    assert!(VlanId::new(0).is_err());
    assert!(VlanId::new(4095).is_err());
    assert_eq!(VlanId::new(1)?.get(), 1);
    assert_eq!(VlanId::new(4094)?.get(), 4094);
    assert!(
        VirtualEndpoint::new(
            AgentId::new([9; 16])?,
            binding(9)?,
            [0; 6],
            VlanId::new(10)?
        )
        .is_err()
    );
    assert!(
        VirtualEndpoint::new(
            AgentId::new([9; 16])?,
            binding(9)?,
            [0xff; 6],
            VlanId::new(10)?
        )
        .is_err()
    );
    assert!(
        VirtualEndpoint::new(
            AgentId::new([9; 16])?,
            binding(9)?,
            [1, 0, 0, 0, 0, 1],
            VlanId::new(10)?
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn unbound_or_duplicate_virtual_ports_are_rejected() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    assert!(
        VirtualLab::new(
            &plan,
            endpoints.get(..2).ok_or("missing fixture endpoints")?,
            BridgeMode::VlanAware
        )
        .is_err()
    );
    let mut duplicate = endpoints.clone();
    duplicate.pop();
    duplicate.push(*endpoints.first().ok_or("missing fixture endpoint")?);
    assert!(VirtualLab::new(&plan, &duplicate, BridgeMode::VlanAware).is_err());
    let first = *endpoints.first().ok_or("missing fixture endpoint")?;
    let last = *endpoints.last().ok_or("missing fixture endpoint")?;
    let mut duplicate_mac = endpoints.clone();
    duplicate_mac.pop();
    duplicate_mac.push(VirtualEndpoint::new(
        last.agent_id(),
        last.interface(),
        first.mac(),
        last.vlan(),
    )?);
    assert!(matches!(
        VirtualLab::new(&plan, &duplicate_mac, BridgeMode::VlanAware),
        Err(LabError::DuplicateEndpoint)
    ));
    let mut duplicate_interface = endpoints.clone();
    duplicate_interface.pop();
    duplicate_interface.push(VirtualEndpoint::new(
        last.agent_id(),
        first.interface(),
        last.mac(),
        last.vlan(),
    )?);
    assert!(matches!(
        VirtualLab::new(&plan, &duplicate_interface, BridgeMode::VlanAware),
        Err(LabError::DuplicateEndpoint)
    ));
    let mut unknown_agent = endpoints.clone();
    unknown_agent.pop();
    unknown_agent.push(VirtualEndpoint::new(
        AgentId::new([9; 16])?,
        last.interface(),
        last.mac(),
        last.vlan(),
    )?);
    assert!(matches!(
        VirtualLab::new(&plan, &unknown_agent, BridgeMode::VlanAware),
        Err(LabError::UnboundTopology)
    ));
    let mut wrong_binding = endpoints;
    let endpoint = wrong_binding.pop().ok_or("missing fixture endpoint")?;
    wrong_binding.push(VirtualEndpoint::new(
        endpoint.agent_id(),
        binding(9)?,
        endpoint.mac(),
        VlanId::new(20)?,
    )?);
    assert!(VirtualLab::new(&plan, &wrong_binding, BridgeMode::VlanAware).is_err());
    Ok(())
}

#[test]
fn insufficient_budget_is_rejected_before_any_virtual_run() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    assert!(matches!(
        lab.run(
            &SYNTHETIC_KEY,
            Budget::new(1, 10_000, 100)?,
            RunOptions::default()
        ),
        Err(LabError::Admission(AdmissionError::PacketLimit))
    ));
    assert!(matches!(
        lab.run(
            &SYNTHETIC_KEY,
            Budget::new(32, 1, 100)?,
            RunOptions::default()
        ),
        Err(LabError::Admission(AdmissionError::ByteLimit))
    ));
    assert!(matches!(
        lab.run(
            &SYNTHETIC_KEY,
            Budget::new(32, 10_000, 1)?,
            RunOptions::default()
        ),
        Err(LabError::Admission(AdmissionError::DurationLimit))
    ));
    assert!(matches!(
        lab.run(&[1; 4], budget()?, RunOptions::default()),
        Err(LabError::Key(_))
    ));
    Ok(())
}

#[test]
fn exact_resource_budget_matches_dispatched_ethernet_frame_sizes() -> Result<(), Box<dyn Error>> {
    let (plan, endpoints) = scenario()?;
    let packets = u64::try_from(plan.probes().len())?;
    let bytes_per_packet = u64::try_from(14 + l2_canary::WIRE_LEN)?;
    let lab = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    let run = lab.run(
        &SYNTHETIC_KEY,
        Budget::new(packets, packets * bytes_per_packet, packets)?,
        RunOptions::default(),
    )?;
    assert_eq!(run.execution().packets(), packets);
    assert_eq!(run.execution().bytes(), packets * bytes_per_packet);
    assert_eq!(run.execution().elapsed_millis(), packets);
    Ok(())
}

#[test]
fn port_inventory_order_does_not_change_observations() -> Result<(), Box<dyn Error>> {
    let (plan, mut endpoints) = scenario()?;
    let first = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    endpoints.reverse();
    let second = VirtualLab::new(&plan, &endpoints, BridgeMode::VlanAware)?;
    assert_eq!(
        first.run(&SYNTHETIC_KEY, budget()?, RunOptions::default())?,
        second.run(&SYNTHETIC_KEY, budget()?, RunOptions::default())?,
    );
    Ok(())
}
