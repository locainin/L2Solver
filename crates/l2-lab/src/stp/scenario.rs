//! Scenario inputs, independent expectations, and modeled observations

use l2_codecs::BridgeId;
use l2_scenario::RunReport;
use l2_segmentation::EvaluationStatus;

use crate::{Cancellation, ObservationMode};

use super::{BridgeState, Capture};

/// Behavior of the modeled edge port, separate from its expected protection
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Guard {
    /// Admit superior root advertisements on the edge port
    None,
    /// Disable the edge port on a supported BPDU
    BpduGuard,
    /// Block the edge port when a better root is advertised
    RootGuard,
    /// Fault injection: discard every BPDU including the trusted control
    DropAll,
}

/// Port behavior that a scenario independently expects to observe
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardExpectation {
    /// A received edge BPDU should disable the edge port
    BpduGuard,
    /// A superior edge BPDU should make the edge port root inconsistent
    RootGuard,
}

/// Synthetic ingress port that delivered a complete frame to the bridge
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Port {
    /// Trusted upstream port used by the positive control
    Trusted,
    /// Untrusted edge port used by the superior-root test
    Edge,
}

/// Controlled cleanup behavior for fault injection
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CleanupMode {
    /// Restore the complete pre-run bridge state
    #[default]
    Restore,
    /// Simulate a failed restore and leave the bridge state in place
    Skip,
}

/// Observer, cancellation, and cleanup controls for one virtual run
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Options {
    pub(super) observer: ObservationMode,
    pub(super) cancellation: Cancellation,
    pub(super) cleanup: CleanupMode,
}

impl Options {
    /// Select independent collection and fault conditions
    #[must_use]
    pub const fn new(
        observer: ObservationMode,
        cancellation: Cancellation,
        cleanup: CleanupMode,
    ) -> Self {
        Self {
            observer,
            cancellation,
            cleanup,
        }
    }
}

/// Two complete Ethernet BPDUs and the independently expected protection
#[derive(Debug)]
pub struct Scenario<'a> {
    pub(super) control: &'a [u8],
    pub(super) attack: &'a [u8],
    pub(super) expected_root: BridgeId,
    pub(super) expectation: GuardExpectation,
}

impl<'a> Scenario<'a> {
    /// Describe a trusted control frame and a separately guarded edge frame
    #[must_use]
    pub const fn new(
        control: &'a [u8],
        attack: &'a [u8],
        expected_root: BridgeId,
        expectation: GuardExpectation,
    ) -> Self {
        Self {
            control,
            attack,
            expected_root,
            expectation,
        }
    }
}

/// Actual virtual observations and the scenario-specific conservative outcome
#[derive(Debug, Eq, PartialEq)]
pub struct Report {
    pub(super) guard: Guard,
    pub(super) expected_guard: GuardExpectation,
    pub(super) expected_root: BridgeId,
    pub(super) observer: ObservationMode,
    pub(super) status: EvaluationStatus,
    pub(super) before: Option<BridgeState>,
    pub(super) control: Option<BridgeState>,
    pub(super) attack: Option<BridgeState>,
    pub(super) cleanup: Option<BridgeState>,
    pub(super) capture: Capture,
    pub(super) execution: RunReport,
}

impl Report {
    /// Return the bridge behavior configured independently from expectations
    #[must_use]
    pub const fn guard(&self) -> Guard {
        self.guard
    }
    /// Return the expected protection assessed by this run
    #[must_use]
    pub const fn expected_guard(&self) -> GuardExpectation {
        self.expected_guard
    }
    /// Return the root required by the trusted positive control
    #[must_use]
    pub const fn expected_root(&self) -> BridgeId {
        self.expected_root
    }
    /// Return the modeled state and ingress observer condition
    #[must_use]
    pub const fn observation_mode(&self) -> ObservationMode {
        self.observer
    }
    /// Return the outcome based solely on observed virtual state
    #[must_use]
    pub const fn status(&self) -> EvaluationStatus {
        self.status
    }
    /// Return the state observed before stimulus dispatch
    #[must_use]
    pub const fn before(&self) -> Option<BridgeState> {
        self.before
    }
    /// Return the observation after the trusted control frame
    #[must_use]
    pub const fn after_control(&self) -> Option<BridgeState> {
        self.control
    }
    /// Return the observation after the edge frame
    #[must_use]
    pub const fn after_attack(&self) -> Option<BridgeState> {
        self.attack
    }
    /// Return the separately observed state after cleanup
    #[must_use]
    pub const fn after_cleanup(&self) -> Option<BridgeState> {
        self.cleanup
    }
    /// Return the source-tagged synthetic ingress capture
    #[must_use]
    pub const fn capture(&self) -> &Capture {
        &self.capture
    }
    /// Return virtual dispatch and observed cleanup accounting
    #[must_use]
    pub const fn execution(&self) -> RunReport {
        self.execution
    }
}
