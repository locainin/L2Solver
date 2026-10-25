use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr},
};

use l2_canary::{AgentKey, Canary, CanaryIdentity, MIN_KEY_LEN, RunId, SessionKey, encode};
use l2_onpath::{
    AddressFamily, ArmReceipt, AssessmentPlan, AssessmentReport, AssessmentSession, BudgetTimebase,
    CanaryExpectation, CheckKind, CheckResult, CleanupReceipt, ClockDomainId, ClockStamp,
    ControlledEndpoint, ControllerEvent, EvidenceOrigin, InterfaceBindingRequest, MacAddress,
    NeighborBinding, NeighborDisposition, NeighborTransitionReceipt, ObservationWindowReceipt,
    ObservationWindowTiming, OriginalBindingReceipt, PathExpectation, PlannedCanaryFrame,
    PrecheckReceipt, Stimulus, StimulusReceipt, TxTiming,
};
use l2_segmentation::{EvidenceSourceId, PacketReference, TxCommitment, TxReceipt};

// A fixed replay identity keeps every receipt in a fixture on one evidence run
pub const RUN: [u8; l2_onpath::ID_LEN] = [0x11; l2_onpath::ID_LEN];

pub fn transmit_interface() -> Result<InterfaceBindingRequest, Box<dyn Error>> {
    Ok(InterfaceBindingRequest::new(1, 2, 3, 1)?)
}

pub fn receiver_interface() -> Result<InterfaceBindingRequest, Box<dyn Error>> {
    Ok(InterfaceBindingRequest::new(1, 2, 4, 1)?)
}

pub fn endpoint_interface(value: u8) -> Result<InterfaceBindingRequest, Box<dyn Error>> {
    Ok(InterfaceBindingRequest::new(1, 2, u32::from(value) + 2, 1)?)
}

pub fn observed_at(ticks: u64) -> Result<ClockStamp, Box<dyn Error>> {
    Ok(ClockStamp::new(ClockDomainId::new([22; 16])?, ticks)?)
}

pub fn budget_time(ticks: u64) -> Result<ClockStamp, Box<dyn Error>> {
    Ok(ClockStamp::new(ClockDomainId::new([0x77; 16])?, ticks)?)
}

pub fn budget_timebase() -> Result<BudgetTimebase, Box<dyn Error>> {
    Ok(BudgetTimebase::new(ClockDomainId::new([0x77; 16])?, 1)?)
}

pub fn packet_ref(source: u8, number: u64) -> Result<PacketReference, Box<dyn Error>> {
    Ok(PacketReference::new(
        EvidenceSourceId::from_bytes([source; 32]),
        number,
    )?)
}

pub fn ethernet_frame(ether_type: u16, payload: &[u8], marker: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, marker]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 1, marker]);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn stimulus_commitment(sequence: u64) -> Result<TxCommitment, Box<dyn Error>> {
    let frame = ethernet_frame(0x0800, &sequence.to_be_bytes(), 0x40);
    Ok(TxCommitment::from_frame_claim(
        RUN,
        sequence,
        transmit_interface()?,
        &frame,
    )?)
}

pub fn cleanup_commitment(
    endpoint: ControlledEndpoint,
    sequence: u64,
) -> Result<TxCommitment, Box<dyn Error>> {
    let frame = ethernet_frame(0x0806, &sequence.to_be_bytes(), 0x60);
    Ok(TxCommitment::from_frame_claim(
        RUN,
        sequence,
        endpoint.interface(),
        &frame,
    )?)
}

pub fn cleanup_tx(
    endpoint: ControlledEndpoint,
    sequence: u64,
) -> Result<TxReceipt, Box<dyn Error>> {
    let commitment = cleanup_commitment(endpoint, sequence)?;
    let event_ordinal = sequence
        .checked_mul(10)
        .and_then(|value| value.checked_add(1))
        .ok_or("cleanup event ordinal overflow")?;
    Ok(TxReceipt::new(
        RUN,
        sequence,
        endpoint.interface(),
        commitment.frame_hash(),
        TxTiming::new(
            ClockStamp::new(
                ClockDomainId::new([11; 16])?,
                sequence
                    .checked_add(30)
                    .ok_or("cleanup clock tick overflow")?,
            )?,
            ControllerEvent::new(RUN, sequence, event_ordinal)?,
        ),
    )?)
}

fn canary_key(canary: Canary) -> Result<SessionKey, Box<dyn Error>> {
    Ok(SessionKey::derive(
        &AgentKey::new(canary.source_agent_id(), &[9; MIN_KEY_LEN])?,
        &canary.identity(),
    )?)
}

fn canary_commitment(canary: Canary) -> Result<TxCommitment, Box<dyn Error>> {
    let key = canary_key(canary)?;
    let payload = encode(&canary, &key)?;
    let frame = ethernet_frame(l2_canary::ETHER_TYPE, &payload, 0x50);
    let planned = PlannedCanaryFrame::from_canary(canary, &key, &frame)?;
    Ok(TxCommitment::from_planned_frame(
        &planned,
        transmit_interface()?,
    ))
}

pub fn tx_timing(
    sequence: u64,
    local_ticks: u64,
    committed_event: u64,
) -> Result<TxTiming, Box<dyn Error>> {
    Ok(TxTiming::new(
        ClockStamp::new(ClockDomainId::new([11; 16])?, local_ticks)?,
        ControllerEvent::new(RUN, sequence, committed_event)?,
    ))
}

pub fn window_timing(
    sequence: u64,
    interval: (u64, u64),
    events: (u64, u64, u64),
) -> Result<ObservationWindowTiming, Box<dyn Error>> {
    Ok(ObservationWindowTiming::new(
        ClockStamp::new(ClockDomainId::new([22; 16])?, interval.0)?,
        ClockStamp::new(ClockDomainId::new([22; 16])?, interval.1)?,
        ControllerEvent::new(RUN, sequence, events.0)?,
        ControllerEvent::new(RUN, sequence, events.1)?,
        ControllerEvent::new(RUN, sequence, events.2)?,
    )?)
}

// Small repeated identities make the scenario relationships easy to inspect
pub const fn agent(value: u8) -> Result<l2_onpath::AgentId, l2_onpath::AgentIdError> {
    l2_onpath::AgentId::new([value; l2_onpath::ID_LEN])
}

// Build one checked IPv4 endpoint for plan and receipt fixtures
pub fn endpoint(value: u8, ip: u8) -> Result<ControlledEndpoint, Box<dyn Error>> {
    Ok(ControlledEndpoint::new(
        NeighborBinding::new(
            agent(value)?,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, ip)),
            MacAddress::new([0x02, 0, 0, 0, 0, value])?,
        )?,
        endpoint_interface(value)?,
    ))
}

// A scenario owns the plan and its single bounded stimulus together
pub struct Scenario {
    pub plan: AssessmentPlan,
    pub stimulus: Stimulus,
}

impl Scenario {
    // The default path expects the authenticated canary to remain blocked
    pub fn blocked() -> Result<Self, Box<dyn Error>> {
        Self::for_expectation(PathExpectation::Blocked)
    }

    // Keep expectation changes local to the plan fixture
    pub fn for_expectation(expectation: PathExpectation) -> Result<Self, Box<dyn Error>> {
        Self::build(expectation, true, true)
    }

    // A plan without commitments exercises the session's missing-proof gate
    pub fn without_commitments() -> Result<Self, Box<dyn Error>> {
        Self::build(PathExpectation::Blocked, false, false)
    }

    // A plan with only the stimulus commitment isolates the canary proof gate
    pub fn without_canary_commitment() -> Result<Self, Box<dyn Error>> {
        Self::build(PathExpectation::Blocked, true, false)
    }

    fn build(
        expectation: PathExpectation,
        add_stimulus_commitment: bool,
        add_canary_commitment: bool,
    ) -> Result<Self, Box<dyn Error>> {
        let first = endpoint(1, 10)?;
        let second = endpoint(2, 20)?;
        let stimulus = Stimulus::new(1, CheckKind::ArpSpoofSusceptibility, first.id(), 1)?;
        let canary_identity =
            CanaryIdentity::new(RunId::from_recorded(RUN)?, first.id(), second.id())?;
        let canary = Canary::new(canary_identity, 2, [3; l2_canary::NONCE_LEN])?;

        // Plan ordering mirrors the lifecycle ordering exercised by the tests
        let mut plan = AssessmentPlan::for_replay(RUN)?;
        plan.add_endpoint(first)?;
        plan.add_endpoint(second)?;
        plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
        plan.add_stimulus(stimulus)?;
        plan.add_canary(CanaryExpectation::new(canary, expectation, 1)?)?;
        if add_stimulus_commitment {
            plan.add_commitment(stimulus_commitment(stimulus.sequence())?)?;
        }
        if add_canary_commitment {
            plan.add_commitment(canary_commitment(canary)?)?;
        }
        let endpoints = plan.endpoints().to_vec();
        for (index, item) in endpoints.iter().enumerate() {
            let sequence = u64::try_from(index + 3)?;
            plan.add_cleanup_commitment(
                item.id(),
                item.family(),
                cleanup_commitment(*item, sequence)?,
            )?;
        }
        Ok(Self { plan, stimulus })
    }

    // A one-endpoint plan covers the no-canary evaluation branch
    pub fn without_canary() -> Result<Self, Box<dyn Error>> {
        let first = endpoint(1, 10)?;
        let stimulus = Stimulus::new(1, CheckKind::ArpSpoofSusceptibility, first.id(), 1)?;
        let mut plan = AssessmentPlan::for_replay(RUN)?;
        plan.add_endpoint(first)?;
        plan.add_check(CheckKind::ArpSpoofSusceptibility)?;
        plan.add_stimulus(stimulus)?;
        plan.add_commitment(stimulus_commitment(stimulus.sequence())?)?;
        plan.add_cleanup_commitment(first.id(), first.family(), cleanup_commitment(first, 2)?)?;
        Ok(Self { plan, stimulus })
    }
}

// Keep the raw authenticated bytes visible to wire-focused tests
pub struct CanaryFixture {
    pub canary: Canary,
    pub key: SessionKey,
    pub wire: Vec<u8>,
}

impl CanaryFixture {
    // Match the canary transmit to the shared segmentation receipt
    pub fn tx(&self) -> Result<TxReceipt, Box<dyn Error>> {
        let commitment = canary_commitment(self.canary)?;
        Ok(TxReceipt::new(
            RUN,
            self.canary.sequence(),
            transmit_interface()?,
            commitment.frame_hash(),
            tx_timing(self.canary.sequence(), 27, 23)?,
        )?)
    }

    // Build the normal receiver window used by complete and incomplete cases
    pub fn window(
        &self,
        loss: u64,
        complete: bool,
    ) -> Result<ObservationWindowReceipt, Box<dyn Error>> {
        Ok(ObservationWindowReceipt::new(
            RUN,
            self.canary.sequence(),
            agent(2)?,
            receiver_interface()?,
            window_timing(self.canary.sequence(), (25, 30), (21, 25, 27))?,
            loss,
            complete,
        )?)
    }

    // Allow boundary tests to place a window before or after the transmit
    pub fn window_at(
        &self,
        interval: (u64, u64),
    ) -> Result<ObservationWindowReceipt, Box<dyn Error>> {
        self.window_at_events(interval, (21, 25, 27))
    }

    pub fn window_at_events(
        &self,
        interval: (u64, u64),
        events: (u64, u64, u64),
    ) -> Result<ObservationWindowReceipt, Box<dyn Error>> {
        Ok(ObservationWindowReceipt::new(
            RUN,
            self.canary.sequence(),
            agent(2)?,
            receiver_interface()?,
            window_timing(self.canary.sequence(), interval, events)?,
            0,
            true,
        )?)
    }
}

// Authenticate the plan's expected canary while retaining its raw wire bytes
pub fn canary_for(plan: &AssessmentPlan) -> Result<CanaryFixture, Box<dyn Error>> {
    let expected = plan
        .canaries()
        .first()
        .ok_or("scenario has no canary")?
        .canary();
    let key = canary_key(expected)?;
    let wire = encode(&expected, &key)?.to_vec();
    Ok(CanaryFixture {
        canary: expected,
        key,
        wire,
    })
}

// Use the default blocked scenario for receipt-only canary construction
pub fn canary() -> Result<CanaryFixture, Box<dyn Error>> {
    let scenario = Scenario::blocked()?;
    canary_for(&scenario.plan)
}

// Build the bounded stimulus transmit receipt used by neighbor transitions
pub fn tx(stimulus: Stimulus) -> Result<TxReceipt, Box<dyn Error>> {
    let commitment = stimulus_commitment(stimulus.sequence())?;
    Ok(TxReceipt::new(
        RUN,
        stimulus.sequence(),
        transmit_interface()?,
        commitment.frame_hash(),
        tx_timing(stimulus.sequence(), 15, 13)?,
    )?)
}

// Build one transition with a window covering the stimulus transmit
pub fn transition(
    stimulus: Stimulus,
    disposition: NeighborDisposition,
    loss: u64,
) -> Result<NeighborTransitionReceipt, Box<dyn Error>> {
    let window = ObservationWindowReceipt::new(
        RUN,
        stimulus.sequence(),
        agent(1)?,
        endpoint_interface(1)?,
        window_timing(stimulus.sequence(), (10, 21), (11, 15, 17))?,
        loss,
        loss == 0,
    )?;
    let receipt = NeighborTransitionReceipt::new(
        RUN,
        stimulus.id(),
        AddressFamily::Ipv4,
        disposition,
        window,
    )?;
    if disposition.requires_changed_binding() {
        let changed = NeighborBinding::new(
            agent(1)?,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            MacAddress::new([0x02, 0, 0, 0, 0, 0xaa])?,
        )?;
        Ok(receipt.with_observed_binding(changed))
    } else {
        Ok(receipt)
    }
}

// Move a session through its mandatory precheck, snapshot, and arm gates
pub fn advance_to_armed(
    session: &mut AssessmentSession,
    plan: &AssessmentPlan,
) -> Result<(), Box<dyn Error>> {
    advance_to_armed_with_unavailable_origin(session, plan, false)
}

pub fn advance_to_armed_with_unavailable_origin(
    session: &mut AssessmentSession,
    plan: &AssessmentPlan,
    unavailable_origin: bool,
) -> Result<(), Box<dyn Error>> {
    session.record_precheck(
        PrecheckReceipt::complete_for_endpoints(RUN, u16::try_from(plan.endpoints().len())?)?,
        budget_time(1)?,
    )?;
    for (index, item) in plan.endpoints().iter().enumerate() {
        let evidence_origin = if unavailable_origin && index == 0 {
            EvidenceOrigin::Unavailable
        } else {
            EvidenceOrigin::Packet(packet_ref(0x22, u64::try_from(index + 1)?)?)
        };
        session.record_original_binding(
            OriginalBindingReceipt::new(RUN, item.binding(), item.interface(), evidence_origin)?,
            budget_time(2)?,
        )?;
    }
    for item in plan.endpoints() {
        session.arm_endpoint(
            ArmReceipt::new(RUN, item.id(), item.family(), item.interface())?,
            budget_time(3)?,
        )?;
    }
    Ok(())
}

// Move a session through a clean stimulus and neighbor transition
pub fn advance_to_transitions(
    session: &mut AssessmentSession,
    plan: &AssessmentPlan,
    stimulus: Stimulus,
    disposition: NeighborDisposition,
) -> Result<(), Box<dyn Error>> {
    advance_to_armed(session, plan)?;
    session.record_stimulus(
        StimulusReceipt::new(RUN, stimulus.id(), tx(stimulus)?, packet_ref(0xa1, 1)?)?,
        budget_time(4)?,
    )?;
    session.record_transition(transition(stimulus, disposition, 0)?, budget_time(5)?)?;
    Ok(())
}

// Record cleanup for every endpoint with one shared restoration outcome
pub fn finish_cleanup(
    session: &mut AssessmentSession,
    plan: &AssessmentPlan,
    restored: bool,
) -> Result<(), Box<dyn Error>> {
    for (index, item) in plan.endpoints().iter().enumerate() {
        let observed = if restored {
            item.binding()
        } else {
            NeighborBinding::new(
                item.id(),
                item.binding().address(),
                MacAddress::new([0x02, 0, 0, 0, 0, 0xee])?,
            )?
        };
        session.record_cleanup(
            &CleanupReceipt::new(
                RUN,
                item.interface(),
                observed,
                restored,
                cleanup_tx(*item, u64::try_from(index + 3)?)?,
                packet_ref(0xc1, u64::try_from(index + 1)?)?,
            )?,
            budget_time(50)?,
        )?;
    }
    Ok(())
}

// Return the only result expected by the focused single-check scenarios
#[track_caller]
pub fn result<'report>(
    report: &'report AssessmentReport<'_>,
) -> Result<&'report CheckResult, Box<dyn Error>> {
    report
        .results()
        .first()
        .ok_or_else(|| Box::<dyn Error>::from("report has no check result"))
}

// Keep repeated limitation assertions concise while preserving test locations
#[track_caller]
pub fn assert_limitation(report: &AssessmentReport<'_>, text: &str) -> Result<(), Box<dyn Error>> {
    let result = result(report)?;
    assert!(
        result.limitations().iter().any(|item| item.contains(text)),
        "missing limitation containing {text:?}"
    );
    Ok(())
}
