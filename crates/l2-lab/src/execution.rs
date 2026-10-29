//! Deterministic dispatch, virtual delivery, and independent evaluation

use l2_onpath::Budget;
use l2_scenario::{
    AdmissionError, Cleanup, Control, MAX_STIMULI, RunReport, Schedule, Stimulus, StopReason,
};
use l2_segmentation::{
    CaptureQuality, EvaluationContext, EvaluationReport, Evaluator, ObservationDisposition,
    PacketReference, Plan, PlannedCanaryFrame, Probe,
};

use crate::capture::{CapturedFrame, VirtualCapture};
use crate::frame::{self, FRAME_LEN};
use crate::receipts;
use crate::topology::Topology;
use crate::{BridgeMode, Cancellation, LabError, ObservationMode, RunOptions, VirtualEndpoint};

/// A stateless virtual access-port bridge borrowing a validated segmentation plan
#[derive(Debug)]
pub struct VirtualLab<'a> {
    plan: &'a Plan,
    topology: Topology,
}

/// A modeled capture, canonical policy evaluation, and virtual execution report
///
/// Receipts, interface labels, clock stamps, and packet references in this
/// value describe the virtual model only and do not attest to physical traffic
#[derive(Debug, Eq, PartialEq)]
pub struct VirtualRun {
    capture: VirtualCapture,
    evaluation: EvaluationReport,
    execution: RunReport,
}

impl VirtualRun {
    /// Return the synthetic receiver capture
    #[must_use]
    pub const fn capture(&self) -> &VirtualCapture {
        &self.capture
    }

    /// Return the canonical evaluator's results for the modeled observations
    #[must_use]
    pub const fn evaluation(&self) -> &EvaluationReport {
        &self.evaluation
    }

    /// Return accounting and cleanup for the stateless virtual backend
    #[must_use]
    pub const fn execution(&self) -> RunReport {
        self.execution
    }
}

struct Emission {
    probe: Probe,
    frame: PlannedCanaryFrame,
    at_millis: u64,
    capture_index: Option<usize>,
}

struct Transcript {
    emissions: Vec<Emission>,
    captured: Vec<CapturedFrame>,
}

impl Transcript {
    fn new(capacity: usize) -> Result<Self, LabError> {
        let mut emissions = Vec::new();
        emissions
            .try_reserve_exact(capacity)
            .map_err(|_| LabError::Allocation)?;
        let mut captured = Vec::new();
        captured
            .try_reserve_exact(capacity)
            .map_err(|_| LabError::Allocation)?;
        Ok(Self {
            emissions,
            captured,
        })
    }
}

impl<'a> VirtualLab<'a> {
    /// Bind each planned agent to one unique modeled access port
    ///
    /// Segment expectations remain independent of assigned VLANs and bridge
    /// behavior, allowing a wrong port VLAN to be detected as a policy failure
    ///
    /// # Errors
    /// Rejects unbound agents, mismatched interface labels, or duplicate ports
    pub fn new(
        plan: &'a Plan,
        endpoints: &[VirtualEndpoint],
        mode: BridgeMode,
    ) -> Result<Self, LabError> {
        let topology = Topology::new(plan, endpoints, mode)?;
        Ok(Self { plan, topology })
    }

    /// Execute admitted probes against the in-memory bridge and receivers
    ///
    /// The caller supplies synthetic key material scoped to this model. The
    /// deterministic scheduler assigns each probe a single instantaneous tick;
    /// controller ordinals preserve ordering inside that tick. This is not a
    /// latency, packet loss rate, VLAN tag, trunk, or physical-network test
    ///
    /// # Errors
    /// Rejects an insufficient budget, invalid key, or inconsistent modeled
    /// evidence. Failures have no operating-system or persistent side effects
    pub fn run(
        &self,
        synthetic_key: &[u8],
        budget: Budget,
        options: RunOptions,
    ) -> Result<VirtualRun, LabError> {
        let (schedule, mut transcript) = self.admit(budget, synthetic_key)?;
        let execution = self.dispatch(schedule, synthetic_key, options, &mut transcript)?;
        let capture = VirtualCapture::new(transcript.captured)?;
        let evaluation = self.evaluate(
            &transcript.emissions,
            &capture,
            synthetic_key,
            options.observer,
            execution.stop_reason(),
        )?;
        Ok(VirtualRun {
            capture,
            evaluation,
            execution,
        })
    }

    fn admit(
        &self,
        budget: Budget,
        synthetic_key: &[u8],
    ) -> Result<(Schedule, Transcript), LabError> {
        let schedule = self.schedule(budget)?;
        let first = self
            .plan
            .probes()
            .first()
            .copied()
            .ok_or(LabError::Invariant)?;
        // Validate key material and reserve bounded transcript storage before dispatch
        let _validated_key = frame::session_key(first, synthetic_key)?;
        let transcript = Transcript::new(self.plan.probes().len())?;
        Ok((schedule, transcript))
    }

    fn dispatch(
        &self,
        schedule: Schedule,
        synthetic_key: &[u8],
        options: RunOptions,
        transcript: &mut Transcript,
    ) -> Result<RunReport, LabError> {
        let mut runner = schedule.start();
        let mut probes = self.plan.probes().iter().copied();
        loop {
            let control = match options.cancellation {
                // The plan caps emissions at 4096, so this count fits in u64
                Cancellation::After(limit) if transcript.emissions.len() as u64 >= limit => {
                    Control::Cancel
                }
                Cancellation::Never | Cancellation::After(_) => Control::Continue,
            };
            let Some(dispatch) = runner.next(control) else {
                break;
            };
            let probe = probes.next().ok_or(LabError::Invariant)?;
            if dispatch.sequence() != probe.sequence() {
                return Err(LabError::Invariant);
            }
            let emission = self.deliver(
                probe,
                dispatch.at_millis(),
                dispatch.frame_bytes(),
                synthetic_key,
                options.observer,
                &mut transcript.captured,
            )?;
            transcript.emissions.push(emission);
        }
        // The bridge has immutable ports and no queues or mutable device state
        Ok(runner.report(Cleanup::Confirmed)?)
    }

    fn schedule(&self, budget: Budget) -> Result<Schedule, LabError> {
        if self.plan.probes().len() > MAX_STIMULI {
            return Err(AdmissionError::ScheduleLimit.into());
        }
        let mut stimuli = Vec::new();
        stimuli
            .try_reserve_exact(self.plan.probes().len())
            .map_err(|_| LabError::Allocation)?;
        for probe in self.plan.probes() {
            // Probe sequences determine both ordering and virtual millisecond ticks
            stimuli.push(Stimulus::new(
                probe.sequence(),
                probe.sequence(),
                FRAME_LEN as u64,
            ));
        }
        Ok(Schedule::new(&stimuli, budget)?)
    }

    fn deliver(
        &self,
        probe: Probe,
        at_millis: u64,
        admitted_bytes: u64,
        material: &[u8],
        observer: ObservationMode,
        captured: &mut Vec<CapturedFrame>,
    ) -> Result<Emission, LabError> {
        let source = self.topology.endpoint(probe.source_agent_id())?;
        let destination = self.topology.endpoint(probe.destination_agent_id())?;
        let key = frame::session_key(probe, material)?;
        let frame = frame::prepare(probe, source, destination, &key)?;
        if frame.frame_length() != admitted_bytes {
            return Err(LabError::Invariant);
        }
        let delivered = self.topology.forward(source, frame.bytes())?;
        let capture_index =
            if let (Some(delivery), ObservationMode::Healthy) = (delivered, observer) {
                // Observation bytes come from the actual bridge output at the receiver
                let bytes: [u8; FRAME_LEN] =
                    delivery.frame.try_into().map_err(|_| LabError::Invariant)?;
                let index = captured.len();
                captured.push(CapturedFrame {
                    sequence: probe.sequence(),
                    receiver: delivery.receiver.agent_id(),
                    frame: bytes,
                });
                Some(index)
            } else {
                None
            };
        Ok(Emission {
            probe,
            frame,
            at_millis,
            capture_index,
        })
    }

    fn evaluate(
        &self,
        emissions: &[Emission],
        capture: &VirtualCapture,
        material: &[u8],
        observer: ObservationMode,
        stop: StopReason,
    ) -> Result<EvaluationReport, LabError> {
        let mut evaluator = Evaluator::new(self.plan);
        for emission in emissions {
            record_emission(&mut evaluator, emission, capture, material, observer)?;
        }
        Ok(evaluator.evaluate(&evaluation_context(observer, stop)))
    }
}

fn record_emission(
    evaluator: &mut Evaluator,
    emission: &Emission,
    capture: &VirtualCapture,
    material: &[u8],
    observer: ObservationMode,
) -> Result<(), LabError> {
    let claims = receipts::claims(
        emission.probe,
        &emission.frame,
        emission.at_millis,
        observer,
    )?;
    evaluator.record_commitment(claims.commitment)?;
    evaluator.record_tx(claims.transmit)?;
    if let Some(index) = emission.capture_index {
        record_arrival(evaluator, emission, capture, material, index, &claims)?;
    } else if let Some(window) = claims.window {
        evaluator.record_window(window)?;
    }
    Ok(())
}

fn record_arrival(
    evaluator: &mut Evaluator,
    emission: &Emission,
    capture: &VirtualCapture,
    material: &[u8],
    index: usize,
    claims: &receipts::Claims,
) -> Result<(), LabError> {
    let (record, reference) = captured_delivery(capture, emission, index)?;
    let window = claims.window.ok_or(LabError::Invariant)?;
    let decoded = l2_core::decode(record.frame())?;
    let key = frame::session_key(emission.probe, material)?;
    let disposition = evaluator.observe_wire(
        decoded.payload,
        &key,
        window,
        emission.probe.destination_interface(),
        claims.observed_at,
        reference,
    )?;
    if disposition != ObservationDisposition::Accepted {
        return Err(LabError::Invariant);
    }
    Ok(())
}

fn captured_delivery<'a>(
    capture: &'a VirtualCapture,
    emission: &Emission,
    index: usize,
) -> Result<(&'a CapturedFrame, PacketReference), LabError> {
    let record = capture.records().get(index).ok_or(LabError::Invariant)?;
    if record.receiver() != emission.probe.destination_agent_id() {
        return Err(LabError::Invariant);
    }
    // Captures are bounded by the plan's 4096 probes and references are one based
    let number = index as u64 + 1;
    let reference =
        PacketReference::new(capture.source(), number).map_err(|_| LabError::Invariant)?;
    Ok((record, reference))
}

fn evaluation_context(observer: ObservationMode, stop: StopReason) -> EvaluationContext {
    let quality = match observer {
        ObservationMode::Healthy => CaptureQuality::Complete,
        ObservationMode::Unavailable => CaptureQuality::Incomplete,
        ObservationMode::Dropped => CaptureQuality::Dropped,
    };
    EvaluationContext::new(
        true,
        observer != ObservationMode::Unavailable,
        quality,
        stop == StopReason::Cancelled,
    )
}
