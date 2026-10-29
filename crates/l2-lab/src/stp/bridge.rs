//! Mutable virtual bridge state and bounded BPDU dispatch

use l2_codecs::BridgeId;
use l2_onpath::Budget;
use l2_scenario::{Cleanup, Control, Dispatch, Runner, StopReason};
use l2_segmentation::EvaluationStatus;

use crate::{Cancellation, ObservationMode};

use super::admission::{self, PreparedFrame, superior, validate_bridge_id};
use super::capture::CaptureBuilder;
use super::{CleanupMode, Error, Guard, GuardExpectation, Options, Port, Report, Scenario};

/// Observable state of the modeled edge port
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortState {
    /// The modeled edge port can process received BPDUs
    Forwarding,
    /// BPDU guard disabled the edge port
    Disabled,
    /// Root guard blocked a superior advertisement
    RootInconsistent,
}

/// Snapshot of modeled root and edge-port state
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeState {
    root: BridgeId,
    root_port: Option<Port>,
    edge: PortState,
}

impl BridgeState {
    /// Return the root selected by the virtual bridge
    #[must_use]
    pub const fn root(self) -> BridgeId {
        self.root
    }
    /// Return the selected virtual root port, or none when the local bridge is root
    #[must_use]
    pub const fn root_port(self) -> Option<Port> {
        self.root_port
    }
    /// Return the observed edge-port state
    #[must_use]
    pub const fn edge(self) -> PortState {
        self.edge
    }
}

/// A two-port in-memory bridge with one independently configured guard
#[derive(Debug)]
pub struct Bridge {
    initial: BridgeState,
    state: BridgeState,
    guard: Guard,
}

impl Bridge {
    /// Start with the local bridge as root and the edge port forwarding
    ///
    /// # Errors
    /// Rejects a bridge identifier that cannot name a modeled unicast bridge
    pub fn new(local: BridgeId, guard: Guard) -> Result<Self, Error> {
        validate_bridge_id(local)?;
        let initial = BridgeState {
            root: local,
            root_port: None,
            edge: PortState::Forwarding,
        };
        Ok(Self {
            initial,
            state: initial,
            guard,
        })
    }

    /// Return the current virtual state without opening a real interface
    #[must_use]
    pub const fn state(&self) -> BridgeState {
        self.state
    }

    /// Restore the original modeled state, including the root and port state
    ///
    /// Repeating restoration leaves the same state
    pub const fn restore(&mut self) -> BridgeState {
        self.state = self.initial;
        self.state
    }

    /// Admit two complete BPDUs and observe their virtual bridge effects
    ///
    /// The trusted control must advertise the explicitly expected root and the
    /// edge frame must advertise a strictly superior root identifier. This
    /// bounded model orders root IDs only and does not model equal-root ties,
    /// full protocol timers, convergence, or physical bridge behavior
    ///
    /// # Errors
    /// Rejects malformed frames, non-superior inputs, a dirty bridge, resource
    /// limits, or inconsistent scheduler accounting before an unbounded action
    pub fn run(
        &mut self,
        scenario: &Scenario<'_>,
        budget: Budget,
        options: Options,
    ) -> Result<Report, Error> {
        if self.state != self.initial {
            return Err(Error::DirtyState);
        }
        let admitted = admission::admit(scenario, self.initial.root, budget)?;
        let healthy = options.observer == ObservationMode::Healthy;
        let mut capture =
            CaptureBuilder::new(admitted.control.bytes, admitted.attack.bytes, healthy)?;
        let mut runner = admitted.schedule.start();
        let before = healthy.then_some(self.state);
        let observed = self.dispatch(
            &mut runner,
            &admitted.control,
            &admitted.attack,
            options,
            &mut capture,
        );
        let (control_state, attack_state) = match observed {
            Ok(states) => states,
            Err(error) => {
                // A failed dispatch cannot leave mutated virtual state behind
                self.restore();
                return Err(error);
            }
        };
        let (after_cleanup, cleanup) = self.finish_cleanup(options.cleanup, before);
        let execution = runner.report(cleanup).map_err(Error::Scheduler)?;
        let status = evaluate(
            scenario,
            admitted.attack.root,
            control_state,
            attack_state,
            execution,
        );
        Ok(Report {
            guard: self.guard,
            expected_guard: scenario.expectation,
            expected_root: scenario.expected_root,
            observer: options.observer,
            status,
            before,
            control: control_state,
            attack: attack_state,
            cleanup: after_cleanup,
            capture: capture.finish()?,
            execution,
        })
    }

    fn finish_cleanup(
        &mut self,
        mode: CleanupMode,
        before: Option<BridgeState>,
    ) -> (Option<BridgeState>, Cleanup) {
        if mode == CleanupMode::Restore {
            self.restore();
        }
        // Confirmation compares independently observed before and after states
        let after = before.map(|_| self.state);
        let cleanup = if before.is_some() && before == after {
            Cleanup::Confirmed
        } else {
            Cleanup::Unconfirmed
        };
        (after, cleanup)
    }

    fn dispatch(
        &mut self,
        runner: &mut Runner,
        control: &PreparedFrame<'_>,
        attack: &PreparedFrame<'_>,
        options: Options,
        capture: &mut CaptureBuilder,
    ) -> Result<(Option<BridgeState>, Option<BridgeState>), Error> {
        let healthy = options.observer == ObservationMode::Healthy;
        let mut control_state = None;
        let mut attack_state = None;
        let mut count = 0_u64;
        loop {
            let next = dispatch_control(options.cancellation, count);
            let Some(dispatch) = runner.next(next) else {
                break;
            };
            let (port, prepared) = scheduled_frame(dispatch, control, attack)?;
            // The ingress tap records the exact frame before guard processing
            capture.record(dispatch.sequence(), port);
            self.receive(port, prepared.root);
            let observed = healthy.then_some(self.state);
            match port {
                Port::Trusted => control_state = observed,
                Port::Edge => attack_state = observed,
            }
            count += 1;
        }
        Ok((control_state, attack_state))
    }

    fn receive(&mut self, port: Port, root: BridgeId) {
        if self.guard == Guard::DropAll {
            return;
        }
        if port == Port::Edge {
            match self.guard {
                Guard::BpduGuard => {
                    self.state.edge = PortState::Disabled;
                    return;
                }
                Guard::RootGuard if superior(root, self.state.root) => {
                    self.state.edge = PortState::RootInconsistent;
                    return;
                }
                Guard::None | Guard::RootGuard | Guard::DropAll => {}
            }
        }
        if superior(root, self.state.root) {
            self.state.root = root;
            self.state.root_port = Some(port);
        }
    }
}

const fn dispatch_control(cancellation: Cancellation, count: u64) -> Control {
    match cancellation {
        Cancellation::After(limit) if count >= limit => Control::Cancel,
        Cancellation::Never | Cancellation::After(_) => Control::Continue,
    }
}

fn scheduled_frame<'a, 'frame>(
    dispatch: Dispatch,
    control: &'a PreparedFrame<'frame>,
    attack: &'a PreparedFrame<'frame>,
) -> Result<(Port, &'a PreparedFrame<'frame>), Error> {
    let (port, prepared) = match dispatch.sequence() {
        1 => (Port::Trusted, control),
        2 => (Port::Edge, attack),
        _ => return Err(Error::Invariant),
    };
    if dispatch.frame_bytes()
        != u64::try_from(prepared.bytes.len()).map_err(|_| Error::Invariant)?
    {
        return Err(Error::Invariant);
    }
    Ok((port, prepared))
}

fn evaluate(
    scenario: &Scenario<'_>,
    hostile: BridgeId,
    control: Option<BridgeState>,
    attack: Option<BridgeState>,
    execution: l2_scenario::RunReport,
) -> EvaluationStatus {
    // An observed forbidden root remains a failure even if cleanup is unconfirmed
    if attack.is_some_and(|state| state.root == hostile) {
        return EvaluationStatus::Fail;
    }
    let (Some(control), Some(attack)) = (control, attack) else {
        return EvaluationStatus::Inconclusive;
    };
    if control.root != scenario.expected_root || control.root_port != Some(Port::Trusted) {
        return EvaluationStatus::Inconclusive;
    }
    if !guard_state_matches(control, attack, scenario.expectation) {
        return EvaluationStatus::Fail;
    }
    if execution.cleanup() != Cleanup::Confirmed || execution.stop_reason() != StopReason::Exhausted
    {
        return EvaluationStatus::Inconclusive;
    }
    EvaluationStatus::Pass
}

fn guard_state_matches(
    control: BridgeState,
    attack: BridgeState,
    expectation: GuardExpectation,
) -> bool {
    let expected_edge = match expectation {
        GuardExpectation::BpduGuard => PortState::Disabled,
        GuardExpectation::RootGuard => PortState::RootInconsistent,
    };
    attack.root == control.root
        && attack.root_port == control.root_port
        && attack.edge == expected_edge
}
