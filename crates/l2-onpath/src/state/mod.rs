//! Cohesive lifecycle state and evaluation for bounded on-path assessments

mod budget;
mod evaluation;
mod lifecycle;
mod support;

use std::collections::BTreeMap;

use l2_segmentation::ControllerEventLedger;
use l2_segmentation::{ClockStamp, TxCommitment};

use crate::{
    AddressFamily, AgentId, ArmReceipt, AssessmentPlan, AuthenticatedCanaryReceipt, BudgetTimebase,
    CheckKind, CleanupReceipt, NeighborTransitionReceipt, OriginalBindingReceipt, PrecheckReceipt,
    StimulusId, StimulusReceipt,
};

pub use budget::CheckBudgetUsage;
use budget::{TxUsage, next_tx_usage, report_usage, validate_cleanup_reserve};
pub use evaluation::{AssessmentReport, AssessmentStatus, CheckResult, LifecycleEvidence};
pub use lifecycle::AssessmentPhase;

/// Stateful bounded session; it owns no socket, key, interface, or transmitter
#[derive(Clone, Debug)]
pub struct AssessmentSession {
    plan: AssessmentPlan,
    phase: lifecycle::AssessmentPhase,
    precheck: Option<PrecheckReceipt>,
    originals: BTreeMap<(AgentId, AddressFamily), OriginalBindingReceipt>,
    arms: BTreeMap<(AgentId, AddressFamily), ArmReceipt>,
    stimuli: BTreeMap<StimulusId, StimulusReceipt>,
    transitions: BTreeMap<StimulusId, NeighborTransitionReceipt>,
    canaries: BTreeMap<support::CanaryKey, AuthenticatedCanaryReceipt>,
    cleanup: BTreeMap<(AgentId, AddressFamily), CleanupReceipt>,
    controller_events: ControllerEventLedger,
    timebase: BudgetTimebase,
    budget_started_at: Option<ClockStamp>,
    last_receipt_at: Option<ClockStamp>,
    resource_usage: BTreeMap<CheckKind, TxUsage>,
}

impl AssessmentSession {
    fn validate_receipt_time(
        &self,
        received_at: ClockStamp,
        cleanup: bool,
    ) -> Result<(), crate::SessionError> {
        if received_at.domain() != self.timebase.domain() {
            return Err(crate::SessionError::ReceiptClockDomainMismatch {
                expected: self.timebase.domain(),
                actual: received_at.domain(),
            });
        }
        if let Some(previous) = self.last_receipt_at
            && received_at.ticks() < previous.ticks()
        {
            return Err(crate::SessionError::ReceiptClockMovedBackwards {
                previous: previous.ticks(),
                actual: received_at.ticks(),
            });
        }
        if !cleanup {
            self.validate_duration(received_at)?;
        }
        Ok(())
    }

    fn validate_duration(&self, received_at: ClockStamp) -> Result<(), crate::SessionError> {
        let Some(started_at) = self.budget_started_at else {
            return Ok(());
        };
        let Some(duration_limit) = self
            .plan
            .checks()
            .iter()
            .map(|check| check.descriptor().duration_budget_millis())
            .min()
        else {
            return Ok(());
        };
        let elapsed_ticks = u128::from(received_at.ticks())
            .checked_sub(u128::from(started_at.ticks()))
            .ok_or_else(|| crate::SessionError::ReceiptClockMovedBackwards {
                previous: started_at.ticks(),
                actual: received_at.ticks(),
            })?;
        let limit_ticks =
            u128::from(duration_limit) * u128::from(self.timebase.ticks_per_millisecond());
        if elapsed_ticks > limit_ticks {
            return Err(crate::SessionError::DurationBudgetExceeded {
                elapsed_ticks,
                limit_ticks,
            });
        }
        Ok(())
    }

    const fn accept_receipt_time(&mut self, received_at: ClockStamp) {
        if self.budget_started_at.is_none() {
            self.budget_started_at = Some(received_at);
        }
        self.last_receipt_at = Some(received_at);
    }

    fn next_tx_usage(
        &self,
        check: CheckKind,
        commitment: TxCommitment,
    ) -> Result<TxUsage, crate::SessionError> {
        let current = self.resource_usage.get(&check).copied().unwrap_or_default();
        next_tx_usage(&self.plan, check, current, commitment)
    }

    fn accept_tx_usage(&mut self, check: CheckKind, usage: TxUsage) {
        self.resource_usage.insert(check, usage);
    }

    /// Return accepted transmit use and cleanup reserve for one selected check
    #[must_use]
    pub fn budget_usage(&self, check: CheckKind) -> CheckBudgetUsage {
        let usage = self.resource_usage.get(&check).copied().unwrap_or_default();
        let elapsed_millis = self.elapsed_millis();
        report_usage(&self.plan, check, usage, elapsed_millis)
    }

    fn elapsed_millis(&self) -> Option<u64> {
        let started_at = self.budget_started_at?;
        let last_at = self.last_receipt_at?;
        let elapsed = last_at.ticks().checked_sub(started_at.ticks())?;
        Some(elapsed / self.timebase.ticks_per_millisecond())
    }
}
