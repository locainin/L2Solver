//! Admit, execute, observe, evaluate, and restore one virtual run

use l2_canary::{AgentId, RunId};
use l2_onpath::Budget;
use l2_scenario::{Cleanup, Control, RunReport, Runner, Schedule, Stimulus, StopReason};
use l2_segmentation::{EvaluationStatus, EvidenceSourceId, PacketReference};

use crate::{Cancellation, ObservationMode, RunOptions};

use super::DiscoveryError;
use super::capture;
use super::model::{Check, Expectation, Observation, Observed, Probe, Protocol};
use super::receiver::Receiver;

/// Maximum number of synthetic frames and neighbor entries in one run
pub const MAX_PROBES: usize = 64;
/// Maximum untagged Ethernet frame size accepted by this model, excluding FCS
pub const MAX_FRAME_BYTES: usize = 1_514;

/// A bounded discovery workload borrowing caller-owned synthetic frames
#[derive(Debug)]
pub struct DiscoveryLab<'a> {
    run_id: RunId,
    receiver: AgentId,
    probes: &'a [Probe<'a>],
}

/// Evidence, evaluation, scheduler accounting, and observed restoration
#[derive(Debug, Eq, PartialEq)]
pub struct DiscoveryRun<'a> {
    run_id: RunId,
    receiver: AgentId,
    observations: Vec<Observation<'a>>,
    checks: Vec<Check<'a>>,
    source: EvidenceSourceId,
    execution: RunReport,
    status: EvaluationStatus,
    cleanup_state: Option<(usize, usize)>,
    observer: ObservationMode,
}

impl<'a> DiscoveryRun<'a> {
    /// Return the exact receiver-side observations in dispatch order
    #[must_use]
    pub fn observations(&self) -> &[Observation<'a>] {
        &self.observations
    }
    /// Return results for the dispatched probes in dispatch order
    #[must_use]
    pub fn checks(&self) -> &[Check<'a>] {
        &self.checks
    }
    /// Return the digest of the exact synthetic capture stream
    #[must_use]
    pub const fn source(&self) -> EvidenceSourceId {
        self.source
    }
    /// Return resource accounting and independently observed cleanup
    #[must_use]
    pub const fn execution(&self) -> RunReport {
        self.execution
    }
    /// Return the conservative aggregate policy result
    #[must_use]
    pub const fn status(&self) -> EvaluationStatus {
        self.status
    }
    /// Return neighbor counts read before the run and after restoration, if observed
    #[must_use]
    pub const fn cleanup_state(&self) -> Option<(usize, usize)> {
        self.cleanup_state
    }
    /// Return the configured observation quality for this run
    #[must_use]
    pub const fn observation_mode(&self) -> ObservationMode {
        self.observer
    }
    /// Serialize the synthetic capture stream whose digest identifies the source
    ///
    /// # Errors
    /// Returns an allocation or internal size error
    pub fn capture_bytes(&self) -> Result<Vec<u8>, DiscoveryError> {
        capture::serialize(self.run_id, self.receiver, &self.observations)
    }
}

impl<'a> DiscoveryLab<'a> {
    /// Bind a synthetic receiver and expected events to a recorded replay ID
    ///
    /// Device and port identifiers remain borrowed. Expected LLDP IDs include
    /// the subtype octet; CDP IDs contain only their TLV value bytes
    ///
    /// # Errors
    /// Rejects excessive probes or frames, empty frames, oversized or empty
    /// expected identities, and a source sharing the receiver's agent ID
    pub fn new(
        run_id: RunId,
        receiver: AgentId,
        probes: &'a [Probe<'a>],
    ) -> Result<Self, DiscoveryError> {
        if probes.len() > MAX_PROBES {
            return Err(DiscoveryError::ProbeLimit);
        }
        for probe in probes {
            validate_probe(receiver, probe)?;
        }
        Ok(Self {
            run_id,
            receiver,
            probes,
        })
    }

    /// Execute the fully admitted schedule in a fresh in-memory receiver
    ///
    /// Cancellation is sampled between frames. Missing or lossy observation
    /// cannot establish a pass or confirm cleanup. No physical I/O occurs
    ///
    /// # Errors
    /// Returns an admission, allocation, or internal consistency error
    pub fn run(
        &self,
        budget: Budget,
        options: RunOptions,
    ) -> Result<DiscoveryRun<'a>, DiscoveryError> {
        let schedule = self.schedule(budget)?;
        let mut receiver = Receiver::new(self.probes.len())?;
        let mut transcript = Transcript::new(self.probes.len())?;
        let initial_count = receiver.count();
        let mut runner = schedule.start();
        self.dispatch(&mut runner, &mut receiver, &mut transcript, options)?;
        // Restore the controlled table, then read it again before confirming cleanup
        receiver.clear();
        let cleanup_state = (options.observer == ObservationMode::Healthy)
            .then(|| (initial_count, receiver.count()));
        let cleanup = if cleanup_state.is_some_and(|(before, after)| before == after) {
            Cleanup::Confirmed
        } else {
            Cleanup::Unconfirmed
        };
        let execution = runner.report(cleanup)?;
        let source = attach_evidence(
            self.run_id,
            self.receiver,
            &mut transcript.observations,
            &mut transcript.checks,
        )?;
        let status = overall_status(&transcript.checks, execution.stop_reason());
        Ok(DiscoveryRun {
            run_id: self.run_id,
            receiver: self.receiver,
            observations: transcript.observations,
            checks: transcript.checks,
            source,
            execution,
            status,
            cleanup_state,
            observer: options.observer,
        })
    }

    fn dispatch(
        &self,
        runner: &mut Runner,
        receiver: &mut Receiver<'a>,
        transcript: &mut Transcript<'a>,
        options: RunOptions,
    ) -> Result<(), DiscoveryError> {
        loop {
            // A check is retained for every completed dispatch
            let dispatched =
                u64::try_from(transcript.checks.len()).map_err(|_| DiscoveryError::Invariant)?;
            let control = match options.cancellation {
                Cancellation::After(limit) if dispatched >= limit => Control::Cancel,
                Cancellation::Never | Cancellation::After(_) => Control::Continue,
            };
            let Some(dispatch) = runner.next(control) else {
                break;
            };
            let probe = self
                .probes
                .iter()
                .find(|item| item.sequence == dispatch.sequence())
                .ok_or(DiscoveryError::Invariant)?;
            transcript.record(probe, dispatch.at_millis(), receiver, options.observer);
        }
        Ok(())
    }

    fn schedule(&self, budget: Budget) -> Result<Schedule, DiscoveryError> {
        let mut stimuli = Vec::new();
        stimuli
            .try_reserve_exact(self.probes.len())
            .map_err(|_| DiscoveryError::Allocation)?;
        for probe in self.probes {
            let bytes = u64::try_from(probe.frame.len()).map_err(|_| DiscoveryError::Invariant)?;
            stimuli.push(Stimulus::new(probe.sequence, probe.at_millis, bytes));
        }
        Ok(Schedule::new(&stimuli, budget)?)
    }
}

fn validate_probe(receiver: AgentId, probe: &Probe<'_>) -> Result<(), DiscoveryError> {
    if probe.source == receiver {
        return Err(DiscoveryError::SameAgent);
    }
    if probe.frame.is_empty() || probe.frame.len() > MAX_FRAME_BYTES {
        return Err(DiscoveryError::FrameLimit);
    }
    validate_expectation(probe.protocol, probe.expectation)
}

fn validate_expectation(
    protocol: Protocol,
    expectation: Expectation<'_>,
) -> Result<(), DiscoveryError> {
    if let Expectation::Accepted(identity) | Expectation::Withdrawn(identity) = expectation {
        let (minimum, maximum) = match protocol {
            Protocol::Lldp => (2, 256),
            Protocol::Cdp => (1, 255),
        };
        if !(minimum..=maximum).contains(&identity.device().len())
            || !(minimum..=maximum).contains(&identity.port().len())
        {
            return Err(DiscoveryError::IdentityLimit);
        }
    }
    Ok(())
}

// The transcript owns bounded observations and their separate policy checks
struct Transcript<'a> {
    observations: Vec<Observation<'a>>,
    checks: Vec<Check<'a>>,
    placeholder: PacketReference,
}

impl<'a> Transcript<'a> {
    fn new(capacity: usize) -> Result<Self, DiscoveryError> {
        let mut observations = Vec::new();
        let mut checks = Vec::new();
        observations
            .try_reserve_exact(capacity)
            .map_err(|_| DiscoveryError::Allocation)?;
        checks
            .try_reserve_exact(capacity)
            .map_err(|_| DiscoveryError::Allocation)?;
        let placeholder = PacketReference::new(EvidenceSourceId::from_bytes([0; 32]), 1)
            .map_err(|_| DiscoveryError::Invariant)?;
        Ok(Self {
            observations,
            checks,
            placeholder,
        })
    }

    fn record(
        &mut self,
        probe: &Probe<'a>,
        at_millis: u64,
        receiver: &mut Receiver<'a>,
        observer: ObservationMode,
    ) {
        let (decision, before, after) =
            receiver.receive(probe.source, probe.protocol, probe.frame, at_millis);
        let status = if observer == ObservationMode::Healthy {
            // The observer receives the actual transition, never the expected value
            self.observations.push(Observation {
                sequence: probe.sequence,
                at_millis,
                source: probe.source,
                protocol: probe.protocol,
                frame: probe.frame,
                observed: decision,
                before,
                after,
                reference: self.placeholder,
            });
            evaluate(probe.expectation, decision, before, after)
        } else {
            EvaluationStatus::Inconclusive
        };
        self.checks.push(Check {
            sequence: probe.sequence,
            expectation: probe.expectation,
            status,
            evidence: None,
        });
    }
}

fn attach_evidence(
    run_id: RunId,
    receiver: AgentId,
    observations: &mut [Observation<'_>],
    checks: &mut [Check<'_>],
) -> Result<EvidenceSourceId, DiscoveryError> {
    let capture_bytes = capture::serialize(run_id, receiver, observations)?;
    let source = capture::source(&capture_bytes);
    for (index, (observation, check)) in observations.iter_mut().zip(checks).enumerate() {
        let number = u64::try_from(index).map_err(|_| DiscoveryError::Invariant)? + 1;
        let reference =
            PacketReference::new(source, number).map_err(|_| DiscoveryError::Invariant)?;
        observation.reference = reference;
        check.evidence = Some(reference);
    }
    Ok(source)
}

fn evaluate(
    expectation: Expectation<'_>,
    observed: Observed<'_>,
    before: Option<super::Identity<'_>>,
    after: Option<super::Identity<'_>>,
) -> EvaluationStatus {
    let matches = match (expectation, observed) {
        (Expectation::Accepted(expected), Observed::Accepted(actual)) => {
            expected == actual && after == Some(expected)
        }
        (Expectation::Rejected, Observed::Rejected) => before == after,
        (Expectation::Withdrawn(expected), Observed::Withdrawn(actual)) => {
            expected == actual && before == Some(expected) && after.is_none()
        }
        _ => false,
    };
    if matches {
        EvaluationStatus::Pass
    } else {
        EvaluationStatus::Fail
    }
}

fn overall_status(checks: &[Check<'_>], stop: StopReason) -> EvaluationStatus {
    if checks
        .iter()
        .any(|check| check.status == EvaluationStatus::Fail)
    {
        EvaluationStatus::Fail
    } else if stop == StopReason::Cancelled
        || checks
            .iter()
            .any(|check| check.status == EvaluationStatus::Inconclusive)
    {
        EvaluationStatus::Inconclusive
    } else {
        EvaluationStatus::Pass
    }
}
