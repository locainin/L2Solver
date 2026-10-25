//! Deterministic planning and evaluation for distributed Layer-2 isolation
//!
//! This crate owns no sockets, interfaces, timers, or transmit authority
//! Callers encode and transmit the planned [`l2_canary::Canary`] values

#![forbid(unsafe_code)]

mod error;
mod evaluator;
mod event_ledger;
mod model;
mod planned_frame;
mod planner;
mod receipts;

pub use error::{EvaluationError, PlanError, PlannedFrameError, ReceiptError};
pub use evaluator::{
    AbsenceEvidence, ArrivalEvidence, CaptureQuality, EvaluationContext, EvaluationReport,
    EvaluationStatus, Evaluator, ObservationDisposition, ObservationRejection, RuleResult,
};
pub use event_ledger::ControllerEventLedger;
pub use l2_canary::{AgentId, AgentIdError, RunId, RunIdError};
pub use l2_capture::{EvidenceSourceId, PacketReference};
pub use l2_helper_protocol::InterfaceBindingRequest;
pub use model::{Agent, DirectedRule, Plan, PlanInput, Probe, RuleExpectation, SegmentId};
pub use planned_frame::PlannedCanaryFrame;
pub use planner::{
    MAX_AGENTS, MAX_ATTEMPTS_PER_RULE, MAX_DIRECTED_RULES, MAX_PROBES, MAX_SEGMENTS,
    MIN_ATTEMPTS_PER_RULE, plan,
};
pub use receipts::{
    CanaryArrivalReceipt, ClockDomainId, ClockStamp, CommitmentSubject, ControllerEvent,
    ObservationWindowReceipt, ObservationWindowTiming, TxCommitment, TxReceipt, TxTiming,
};
