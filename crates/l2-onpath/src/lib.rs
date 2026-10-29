//! Bounded endpoint and on-path identity validation foundations
//!
//! This crate plans and evaluates controlled ARP/IPv4, NDP/IPv6, and switch
//! identity checks. It owns no socket, interface, timer, packet transmitter, or
//! cryptographic key. A caller supplies structurally checked claims and a
//! temporary [`l2_canary::SessionKey`] only while authenticating a canary wire.
//! These claims do not attest physical activity; authority integration remains gated.

#![forbid(unsafe_code)]

mod catalog;
mod error;
mod model;
pub mod neighbor;
mod receipts;
mod state;

pub use catalog::{CheckDescriptor, catalog, descriptor};
pub use error::{BudgetError, ModelError, PlanError, ReceiptError, SessionError};
pub use l2_canary::{
    AgentId, AgentIdError, Canary, CanaryIdentity, ID_LEN, NONCE_LEN, RunId, RunIdError,
    SessionKey, VerifiedCanary,
};
pub use l2_helper_protocol::InterfaceBindingRequest;
pub use l2_segmentation::{
    CanaryArrivalReceipt, ClockDomainId, ClockStamp, CommitmentSubject, ControllerEvent,
    EvidenceSourceId, ObservationWindowReceipt, ObservationWindowTiming, PacketReference,
    PlannedCanaryFrame, TxCommitment, TxReceipt, TxTiming,
};
pub use model::{
    ActivityClass, AddressFamily, AssessmentPlan, Budget, BudgetTimebase, CanaryExpectation,
    CheckKind, ControlledEndpoint, MAX_BYTE_BUDGET, MAX_CANARIES, MAX_CHECKS, MAX_COMMITMENTS,
    MAX_DURATION_BUDGET_MILLIS, MAX_ENDPOINTS, MAX_PACKET_BUDGET, MAX_STIMULI, MacAddress,
    NeighborBinding, NeighborDisposition, PathExpectation, ProtocolFamily, RiskClass, Stimulus,
    StimulusId,
};
pub use receipts::{
    ArmReceipt, AuthenticatedCanaryReceipt, CanaryTraversal, CanaryWireEvidence, CleanupReceipt,
    CommittedTxReceipt, EvidenceOrigin, NeighborTransitionReceipt, NeighborWindowReceipt,
    OriginalBindingReceipt, PrecheckReceipt, StimulusReceipt,
};
pub use state::{
    AssessmentPhase, AssessmentReport, AssessmentSession, AssessmentStatus, CheckBudgetUsage,
    CheckResult, LifecycleEvidence,
};
