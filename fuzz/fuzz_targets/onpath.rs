#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use l2_canary::{AgentKey, CanaryIdentity, MIN_KEY_LEN, RunId, SessionKey, encode};
use l2_onpath::{
    AddressFamily, ArmReceipt, AssessmentPlan, AssessmentSession, BudgetTimebase, Canary,
    CanaryExpectation, CanaryWireEvidence, CleanupReceipt, ClockDomainId, ClockStamp,
    ControlledEndpoint, ControllerEvent, EvidenceOrigin, EvidenceSourceId, InterfaceBindingRequest,
    MacAddress, NeighborBinding, NeighborDisposition, NeighborTransitionReceipt,
    ObservationWindowReceipt, ObservationWindowTiming, OriginalBindingReceipt, PacketReference,
    PathExpectation, PlannedCanaryFrame, PrecheckReceipt, Stimulus, StimulusReceipt, TxCommitment,
    TxTiming,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 4_096;
const MAX_OPERATIONS: usize = 32;
const ID_LEN: usize = l2_onpath::ID_LEN;

// Exercise bounded endpoint validation, receipt scope checks, and lifecycle gates
fuzz_target!(|data: &[u8]| {
    let length = data.len().min(MAX_INPUT_BYTES);
    let Some(input) = data.get(..length) else {
        return;
    };
    let Some(fixture) = Fixture::from_input(input) else {
        return;
    };
    let Some(key) = canary_key(fixture.canary) else {
        return;
    };
    let Some(wire) = encode(&fixture.canary, &key).ok() else {
        return;
    };
    let Some(timebase) = budget_timebase() else {
        return;
    };
    let Some(packet) = packet_reference(input) else {
        return;
    };

    // Feed a bounded operation stream in arbitrary order to the lifecycle gates
    let mut exploratory = AssessmentSession::new(&fixture.plan, timebase);
    for byte in input.iter().take(MAX_OPERATIONS) {
        exercise_operation(&mut exploratory, &fixture, &key, *byte, input);
    }
    let exploratory_report = exploratory.evaluate();
    let _ = (
        exploratory_report.phase(),
        exploratory_report.overall_status(),
        exploratory_report.results(),
    );

    // Establish a valid prefix, then send both arbitrary and canonical canary wires
    let mut session = AssessmentSession::new(&fixture.plan, timebase);
    if !advance_to_transitions(&mut session, &fixture, packet) {
        return;
    }
    let (Some(transmit), Some(window)) = (canary_tx(&fixture), canary_window(&fixture, 0, true))
    else {
        return;
    };
    let Some(observed_interface) = receiver_interface() else {
        return;
    };
    let Some(observed_at) = canary_observed_at(byte_at(input, 2)) else {
        return;
    };
    let Some(received_at) = budget_stamp(6) else {
        return;
    };
    let _ = session.record_canary_wire(
        input,
        &key,
        CanaryWireEvidence::new(transmit, window, observed_interface, observed_at, packet),
        received_at,
    );
    if session.phase() == l2_onpath::AssessmentPhase::TransitionsRecorded {
        let (Some(transmit), Some(window)) =
            (canary_tx(&fixture), canary_window(&fixture, 0, true))
        else {
            return;
        };
        let _ = session.record_canary_wire(
            &wire,
            &key,
            CanaryWireEvidence::new(transmit, window, observed_interface, observed_at, packet),
            received_at,
        );
    }

    // Cleanup stays bounded and lets input select restoration and capture quality
    let restored = byte_at(input, 0) & 1 == 0;
    let capture_loss = u64::from(byte_at(input, 1));
    for endpoint in [fixture.source, fixture.destination] {
        let observed = if restored {
            endpoint.binding()
        } else {
            let Some(mac) = MacAddress::new([0x02, 0, 0, 0, 0, 0xee]).ok() else {
                continue;
            };
            let Some(binding) =
                NeighborBinding::new(endpoint.id(), endpoint.binding().address(), mac).ok()
            else {
                continue;
            };
            binding
        };
        let Some(transmit) = cleanup_tx(&fixture, endpoint) else {
            continue;
        };
        let Some(receipt) = CleanupReceipt::new(
            fixture.run_id,
            endpoint.interface(),
            observed,
            restored,
            transmit,
            packet,
        )
        .ok() else {
            continue;
        };
        let Some(received_at) = budget_stamp(50) else {
            continue;
        };
        let _ = session.record_cleanup(&receipt.with_capture_loss(capture_loss), received_at);
    }
    let report = session.evaluate();
    let _ = (report.phase(), report.overall_status(), report.results());
});

fn exercise_operation(
    session: &mut AssessmentSession,
    fixture: &Fixture,
    key: &SessionKey,
    byte: u8,
    input: &[u8],
) {
    let timestamp = u64::from(byte).max(1);
    let Some(received_at) = budget_stamp(timestamp) else {
        return;
    };
    let Some(packet) = packet_reference(input) else {
        return;
    };
    match byte % 7 {
        0 => {
            if let Ok(receipt) = PrecheckReceipt::new(
                fixture.run_id,
                u16::from(byte),
                u64::from(byte),
                byte & 1 != 0,
            ) {
                let _ = session.record_precheck(receipt, received_at);
            }
        }
        1 => {
            if let Ok(receipt) = OriginalBindingReceipt::new(
                fixture.run_id,
                fixture.source.binding(),
                fixture.source.interface(),
                EvidenceOrigin::Packet(packet),
            ) {
                let _ = session.record_original_binding(receipt, received_at);
            }
        }
        2 => {
            if let Ok(receipt) = ArmReceipt::new(
                fixture.run_id,
                fixture.source.id(),
                fixture.source.family(),
                fixture.source.interface(),
            ) {
                let _ = session.arm_endpoint(receipt, received_at);
            }
        }
        3 => {
            if let Some(tx) = stimulus_tx(fixture, byte)
                && let Ok(receipt) =
                    StimulusReceipt::new(fixture.run_id, fixture.stimulus.id(), tx, packet)
            {
                let _ = session.record_stimulus(receipt, received_at);
            }
        }
        4 => {
            let loss = u64::from(byte);
            if let Some(receipt) = transition(fixture, loss, byte & 1 != 0) {
                let _ = session.record_transition(receipt, received_at);
            }
        }
        5 => {
            if let (Some(transmit), Some(window)) = (
                canary_tx(fixture),
                canary_window(fixture, u64::from(byte), byte & 1 != 0),
            ) && let (Some(observed_interface), Some(observed_at)) =
                (receiver_interface(), canary_observed_at(byte))
            {
                let _ = session.record_canary_wire(
                    input,
                    key,
                    CanaryWireEvidence::new(
                        transmit,
                        window,
                        observed_interface,
                        observed_at,
                        packet,
                    ),
                    received_at,
                );
            }
        }
        _ => exercise_cleanup(session, fixture, byte, packet, received_at),
    }
}

// Keep restoration and capture-loss claims together for exploratory cleanup
fn exercise_cleanup(
    session: &mut AssessmentSession,
    fixture: &Fixture,
    byte: u8,
    packet: PacketReference,
    received_at: ClockStamp,
) {
    let restored = byte & 1 != 0;
    let observed = if restored {
        Some(fixture.source.binding())
    } else {
        MacAddress::new([0x02, 0, 0, 0, 0, 0xee])
            .ok()
            .and_then(|mac| {
                NeighborBinding::new(fixture.source.id(), fixture.source.binding().address(), mac)
                    .ok()
            })
    };
    let Some(observed) = observed else {
        return;
    };
    if let Some(transmit) = cleanup_tx(fixture, fixture.source)
        && let Ok(receipt) = CleanupReceipt::new(
            fixture.run_id,
            fixture.source.interface(),
            observed,
            restored,
            transmit,
            packet,
        )
    {
        let _ = session.record_cleanup(&receipt.with_capture_loss(u64::from(byte)), received_at);
    }
}

fn advance_to_transitions(
    session: &mut AssessmentSession,
    fixture: &Fixture,
    packet: PacketReference,
) -> bool {
    let Some(precheck) = PrecheckReceipt::complete_for_endpoints(fixture.run_id, 2).ok() else {
        return false;
    };
    let Some(received_at) = budget_stamp(1) else {
        return false;
    };
    if session.record_precheck(precheck, received_at).is_err() {
        return false;
    }
    for endpoint in [fixture.source, fixture.destination] {
        let Some(receipt) = OriginalBindingReceipt::new(
            fixture.run_id,
            endpoint.binding(),
            endpoint.interface(),
            EvidenceOrigin::Packet(packet),
        )
        .ok() else {
            return false;
        };
        let Some(received_at) = budget_stamp(2) else {
            return false;
        };
        if session
            .record_original_binding(receipt, received_at)
            .is_err()
        {
            return false;
        }
    }
    for endpoint in [fixture.source, fixture.destination] {
        let Some(receipt) = ArmReceipt::new(
            fixture.run_id,
            endpoint.id(),
            endpoint.family(),
            endpoint.interface(),
        )
        .ok() else {
            return false;
        };
        let Some(received_at) = budget_stamp(3) else {
            return false;
        };
        if session.arm_endpoint(receipt, received_at).is_err() {
            return false;
        }
    }
    let Some(tx) = stimulus_tx(fixture, 1) else {
        return false;
    };
    let Some(stimulus) =
        StimulusReceipt::new(fixture.run_id, fixture.stimulus.id(), tx, packet).ok()
    else {
        return false;
    };
    let Some(received_at) = budget_stamp(4) else {
        return false;
    };
    if session.record_stimulus(stimulus, received_at).is_err() {
        return false;
    }
    let Some(receipt) = transition(fixture, 0, true) else {
        return false;
    };
    let Some(received_at) = budget_stamp(5) else {
        return false;
    };
    session.record_transition(receipt, received_at).is_ok()
}

// Keep send claims on one stable interface while observation claims use the receiver binding
fn transmit_interface() -> Option<InterfaceBindingRequest> {
    InterfaceBindingRequest::new(1, 2, 3, 1).ok()
}

fn receiver_interface() -> Option<InterfaceBindingRequest> {
    InterfaceBindingRequest::new(1, 2, 4, 1).ok()
}

// Keep the receiver-local arrival stamp inside the canonical observation interval
fn canary_observed_at(marker: u8) -> Option<ClockStamp> {
    let domain = ClockDomainId::new([22; 16]).ok()?;
    ClockStamp::new(domain, 25_u64.saturating_add(u64::from(marker % 6))).ok()
}

fn canary_key(canary: Canary) -> Option<SessionKey> {
    let agent_key = AgentKey::new(canary.source_agent_id(), &[0x42; MIN_KEY_LEN]).ok()?;
    SessionKey::derive(&agent_key, &canary.identity()).ok()
}

fn ethernet_frame(ether_type: u16, payload: &[u8], marker: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, marker]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 1, marker]);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

// Generic stimulus claims hash the exact valid Ethernet bytes sent by the fixture
fn stimulus_commitment(run_id: [u8; ID_LEN], sequence: u64) -> Option<TxCommitment> {
    let interface = transmit_interface()?;
    let payload = sequence.to_be_bytes();
    let frame = ethernet_frame(0x0800, &payload, 0x44);
    TxCommitment::from_frame_claim(run_id, sequence, interface, &frame).ok()
}

// Canary claims retain the authenticated payload and complete Ethernet frame together
fn canary_commitment(canary: Canary) -> Option<TxCommitment> {
    let key = canary_key(canary)?;
    let payload = encode(&canary, &key).ok()?;
    let frame = ethernet_frame(l2_canary::ETHER_TYPE, &payload, 0x55);
    let planned = PlannedCanaryFrame::from_canary(canary, &key, &frame).ok()?;
    Some(TxCommitment::from_planned_frame(
        &planned,
        transmit_interface()?,
    ))
}

fn cleanup_commitment(
    run_id: [u8; ID_LEN],
    endpoint: ControlledEndpoint,
    sequence: u64,
) -> Option<TxCommitment> {
    let payload = sequence.to_be_bytes();
    let frame = ethernet_frame(0x0806, &payload, 0x66);
    TxCommitment::from_frame_claim(run_id, sequence, endpoint.interface(), &frame).ok()
}

fn cleanup_tx(fixture: &Fixture, endpoint: ControlledEndpoint) -> Option<l2_onpath::TxReceipt> {
    let commitment = fixture
        .plan
        .cleanup_commitment(endpoint.id(), endpoint.family())?;
    let sequence = commitment.sequence();
    let ordinal = sequence.checked_mul(10)?.checked_add(3)?;
    l2_onpath::TxReceipt::new(
        fixture.run_id,
        sequence,
        endpoint.interface(),
        commitment.frame_hash(),
        TxTiming::new(
            ClockStamp::new(
                ClockDomainId::new([11; 16]).ok()?,
                sequence.checked_add(30)?,
            )
            .ok()?,
            ControllerEvent::new(fixture.run_id, sequence, ordinal).ok()?,
        ),
    )
    .ok()
}

fn stimulus_tx(fixture: &Fixture, marker: u8) -> Option<l2_onpath::TxReceipt> {
    let committed_at = 15_u64.saturating_add(u64::from(marker % 4));
    let commitment = fixture.plan.commitment(fixture.stimulus.sequence())?;
    l2_onpath::TxReceipt::new(
        fixture.run_id,
        fixture.stimulus.sequence(),
        commitment.interface(),
        commitment.frame_hash(),
        TxTiming::new(
            ClockStamp::new(ClockDomainId::new([11; 16]).ok()?, committed_at).ok()?,
            ControllerEvent::new(
                fixture.run_id,
                fixture.stimulus.sequence(),
                fixture
                    .stimulus
                    .sequence()
                    .saturating_mul(10)
                    .saturating_add(3),
            )
            .ok()?,
        ),
    )
    .ok()
}

fn transition(
    fixture: &Fixture,
    capture_loss: u64,
    complete: bool,
) -> Option<NeighborTransitionReceipt> {
    let window = ObservationWindowReceipt::new(
        fixture.run_id,
        fixture.stimulus.sequence(),
        fixture.source.id(),
        fixture.source.interface(),
        ObservationWindowTiming::new(
            ClockStamp::new(ClockDomainId::new([22; 16]).ok()?, 10).ok()?,
            ClockStamp::new(ClockDomainId::new([22; 16]).ok()?, 25).ok()?,
            ControllerEvent::new(
                fixture.run_id,
                fixture.stimulus.sequence(),
                fixture
                    .stimulus
                    .sequence()
                    .saturating_mul(10)
                    .saturating_add(1),
            )
            .ok()?,
            ControllerEvent::new(
                fixture.run_id,
                fixture.stimulus.sequence(),
                fixture
                    .stimulus
                    .sequence()
                    .saturating_mul(10)
                    .saturating_add(5),
            )
            .ok()?,
            ControllerEvent::new(
                fixture.run_id,
                fixture.stimulus.sequence(),
                fixture
                    .stimulus
                    .sequence()
                    .saturating_mul(10)
                    .saturating_add(7),
            )
            .ok()?,
        )
        .ok()?,
        capture_loss,
        complete,
    )
    .ok()?;
    NeighborTransitionReceipt::new(
        fixture.run_id,
        fixture.stimulus.id(),
        AddressFamily::Ipv4,
        if capture_loss == 0 {
            NeighborDisposition::ConflictRejected
        } else {
            NeighborDisposition::Unknown
        },
        window,
    )
    .ok()
}

fn canary_tx(fixture: &Fixture) -> Option<l2_onpath::TxReceipt> {
    let commitment = fixture.plan.commitment(fixture.canary.sequence())?;
    l2_onpath::TxReceipt::new(
        fixture.run_id,
        fixture.canary.sequence(),
        commitment.interface(),
        commitment.frame_hash(),
        TxTiming::new(
            ClockStamp::new(ClockDomainId::new([11; 16]).ok()?, 27).ok()?,
            ControllerEvent::new(
                fixture.run_id,
                fixture.canary.sequence(),
                fixture
                    .canary
                    .sequence()
                    .saturating_mul(10)
                    .saturating_add(3),
            )
            .ok()?,
        ),
    )
    .ok()
}

fn canary_window(
    fixture: &Fixture,
    capture_loss: u64,
    complete: bool,
) -> Option<ObservationWindowReceipt> {
    ObservationWindowReceipt::new(
        fixture.run_id,
        fixture.canary.sequence(),
        fixture.destination.id(),
        fixture.destination.interface(),
        ObservationWindowTiming::new(
            ClockStamp::new(ClockDomainId::new([22; 16]).ok()?, 25).ok()?,
            ClockStamp::new(ClockDomainId::new([22; 16]).ok()?, 30).ok()?,
            ControllerEvent::new(
                fixture.run_id,
                fixture.canary.sequence(),
                fixture
                    .canary
                    .sequence()
                    .saturating_mul(10)
                    .saturating_add(1),
            )
            .ok()?,
            ControllerEvent::new(
                fixture.run_id,
                fixture.canary.sequence(),
                fixture
                    .canary
                    .sequence()
                    .saturating_mul(10)
                    .saturating_add(5),
            )
            .ok()?,
            ControllerEvent::new(
                fixture.run_id,
                fixture.canary.sequence(),
                fixture
                    .canary
                    .sequence()
                    .saturating_mul(10)
                    .saturating_add(7),
            )
            .ok()?,
        )
        .ok()?,
        capture_loss,
        complete,
    )
    .ok()
}

fn budget_timebase() -> Option<BudgetTimebase> {
    BudgetTimebase::new(ClockDomainId::new([0x77; ID_LEN]).ok()?, 1).ok()
}

fn budget_stamp(ticks: u64) -> Option<ClockStamp> {
    ClockStamp::new(ClockDomainId::new([0x77; ID_LEN]).ok()?, ticks).ok()
}

fn packet_reference(input: &[u8]) -> Option<PacketReference> {
    PacketReference::new(
        EvidenceSourceId::from_bytes([0x91; 32]),
        u64_from(input, 0).max(1),
    )
    .ok()
}

fn byte_at(input: &[u8], offset: usize) -> u8 {
    input.get(offset).copied().map_or(0, |value| value)
}

struct Fixture {
    run_id: [u8; ID_LEN],
    plan: AssessmentPlan,
    source: ControlledEndpoint,
    destination: ControlledEndpoint,
    stimulus: Stimulus,
    canary: Canary,
}

impl Fixture {
    fn from_input(input: &[u8]) -> Option<Self> {
        let run_id = identity_from(input, 0, 0x11);
        let source_id = identity_from(input, 16, 0x21);
        let mut destination_id = identity_from(input, 32, 0x31);
        if source_id == destination_id
            && let Some(first) = destination_id.first_mut()
        {
            *first ^= 1;
            if *first == 0 {
                *first = 0x31;
            }
        }
        let source_id = l2_onpath::AgentId::new(source_id).ok()?;
        let destination_id = l2_onpath::AgentId::new(destination_id).ok()?;
        let source = ControlledEndpoint::new(
            NeighborBinding::new(
                source_id,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, byte_at(input, 48).max(1))),
                MacAddress::new(mac_from(input, 54, 0x41)).ok()?,
            )
            .ok()?,
            transmit_interface()?,
        );
        let destination = ControlledEndpoint::new(
            NeighborBinding::new(
                destination_id,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, byte_at(input, 60).max(1))),
                MacAddress::new(mac_from(input, 66, 0x51)).ok()?,
            )
            .ok()?,
            receiver_interface()?,
        );
        let sequence = u64_from(input, 72).max(1);
        let stimulus =
            Stimulus::new(1, l2_onpath::CheckKind::ArpMitmProof, source.id(), sequence).ok()?;
        let identity = CanaryIdentity::new(
            RunId::from_recorded(run_id).ok()?,
            source.id(),
            destination.id(),
        )
        .ok()?;
        let canary = l2_canary::Canary::new(
            identity,
            u64_from(input, 80).max(1),
            identity_from(input, 88, 0x61),
        )
        .ok()?;
        let mut plan = AssessmentPlan::for_replay(run_id).ok()?;
        plan.add_endpoint(source).ok()?;
        plan.add_endpoint(destination).ok()?;
        plan.add_check(l2_onpath::CheckKind::ArpMitmProof).ok()?;
        plan.add_stimulus(stimulus).ok()?;
        plan.add_canary(CanaryExpectation::new(canary, PathExpectation::Blocked, 1).ok()?)
            .ok()?;
        plan.add_commitment(stimulus_commitment(run_id, stimulus.sequence())?)
            .ok()?;
        plan.add_commitment(canary_commitment(canary)?).ok()?;
        let mut cleanup_sequence = 100_u64;
        for endpoint in [source, destination] {
            while cleanup_sequence == stimulus.sequence() || cleanup_sequence == canary.sequence() {
                cleanup_sequence = cleanup_sequence.checked_add(1)?;
            }
            plan.add_cleanup_commitment(
                endpoint.id(),
                endpoint.family(),
                cleanup_commitment(run_id, endpoint, cleanup_sequence)?,
            )
            .ok()?;
            cleanup_sequence = cleanup_sequence.checked_add(1)?;
        }
        Some(Self {
            run_id,
            plan,
            source,
            destination,
            stimulus,
            canary,
        })
    }
}

fn identity_from<const N: usize>(input: &[u8], offset: usize, marker: u8) -> [u8; N] {
    let mut value = [0_u8; N];
    for (index, slot) in value.iter_mut().enumerate() {
        if let Some(byte) = input.get(offset.saturating_add(index)) {
            *slot = *byte;
        }
    }
    if value.iter().all(|byte| *byte == 0)
        && let Some(first) = value.first_mut()
    {
        *first = marker;
    }
    value
}

fn mac_from(input: &[u8], offset: usize, marker: u8) -> [u8; 6] {
    let mut value = identity_from(input, offset, marker);
    if let Some(first) = value.first_mut() {
        *first = (*first & 0xfe) | 0x02;
    }
    if let Some(last) = value.last_mut()
        && *last == 0
    {
        *last = marker;
    }
    value
}

fn u64_from(input: &[u8], offset: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (index, slot) in bytes.iter_mut().enumerate() {
        if let Some(byte) = input.get(offset.saturating_add(index)) {
            *slot = *byte;
        }
    }
    u64::from_be_bytes(bytes)
}
