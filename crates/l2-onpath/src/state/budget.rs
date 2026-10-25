//! Receipt-backed resource accounting for each selected check

use crate::{AssessmentPlan, Budget, CheckKind, SessionError};
use l2_segmentation::TxCommitment;

/// Reported packet and byte use, including the exact reserved cleanup cost
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckBudgetUsage {
    packets_used: u64,
    bytes_used: u64,
    cleanup_packets_reserved: u128,
    cleanup_bytes_reserved: u128,
    packet_limit: u64,
    byte_limit: u64,
    duration_limit_millis: u64,
    elapsed_millis: Option<u64>,
}

impl CheckBudgetUsage {
    /// Return accepted stimulus and canary transmit count
    #[must_use]
    pub const fn packets_used(self) -> u64 {
        self.packets_used
    }

    /// Return accepted stimulus and canary frame bytes
    #[must_use]
    pub const fn bytes_used(self) -> u64 {
        self.bytes_used
    }

    /// Return the cleanup packet count kept out of experiment allowance
    #[must_use]
    pub const fn cleanup_packets_reserved(self) -> u128 {
        self.cleanup_packets_reserved
    }

    /// Return exact bytes reserved by planned endpoint cleanup frames
    #[must_use]
    pub const fn cleanup_bytes_reserved(self) -> u128 {
        self.cleanup_bytes_reserved
    }

    /// Return the selected check's packet ceiling
    #[must_use]
    pub const fn packet_limit(self) -> u64 {
        self.packet_limit
    }

    /// Return the selected check's byte ceiling
    #[must_use]
    pub const fn byte_limit(self) -> u64 {
        self.byte_limit
    }

    /// Return the selected check's duration ceiling in milliseconds
    #[must_use]
    pub const fn duration_limit_millis(self) -> u64 {
        self.duration_limit_millis
    }

    /// Return elapsed monotonic time when precheck has started the session
    #[must_use]
    pub const fn elapsed_millis(self) -> Option<u64> {
        self.elapsed_millis
    }
}

/// Accepted experiment traffic, before the cleanup reserve is applied
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct TxUsage {
    pub(super) packets: u64,
    pub(super) bytes: u64,
}

pub(super) fn next_tx_usage(
    plan: &AssessmentPlan,
    check: CheckKind,
    current: TxUsage,
    commitment: TxCommitment,
) -> Result<TxUsage, SessionError> {
    let budget = check.descriptor().budget();
    let (cleanup_packets, cleanup_bytes) = cleanup_reserve(plan);
    let attempted_packets = u128::from(current.packets) + 1 + cleanup_packets;
    let attempted_bytes =
        u128::from(current.bytes) + u128::from(commitment.frame_length()) + cleanup_bytes;
    if exceeds(budget, attempted_packets, attempted_bytes) {
        return Err(SessionError::ResourceBudgetExceeded {
            check,
            packets: attempted_packets,
            bytes: attempted_bytes,
            packet_limit: budget.packets(),
            byte_limit: budget.bytes(),
        });
    }
    let packets = current
        .packets
        .checked_add(1)
        .ok_or(SessionError::BudgetCounterOverflow)?;
    let bytes = current
        .bytes
        .checked_add(commitment.frame_length())
        .ok_or(SessionError::BudgetCounterOverflow)?;
    Ok(TxUsage { packets, bytes })
}

pub(super) fn report_usage(
    plan: &AssessmentPlan,
    check: CheckKind,
    usage: TxUsage,
    elapsed_millis: Option<u64>,
) -> CheckBudgetUsage {
    let (cleanup_packets, cleanup_bytes) = cleanup_reserve(plan);
    let budget = check.descriptor().budget();
    CheckBudgetUsage {
        packets_used: usage.packets,
        bytes_used: usage.bytes,
        cleanup_packets_reserved: cleanup_packets,
        cleanup_bytes_reserved: cleanup_bytes,
        packet_limit: budget.packets(),
        byte_limit: budget.bytes(),
        duration_limit_millis: budget.duration_millis(),
        elapsed_millis,
    }
}

fn cleanup_reserve(plan: &AssessmentPlan) -> (u128, u128) {
    let packets = plan
        .cleanup_commitments()
        .fold(0_u128, |count, _| count + 1);
    let bytes = plan
        .cleanup_commitments()
        .map(|commitment| u128::from(commitment.frame_length()))
        .sum();
    (packets, bytes)
}

pub(super) fn validate_cleanup_reserve(plan: &AssessmentPlan) -> Result<(), SessionError> {
    let (packets, bytes) = cleanup_reserve(plan);
    for check in plan.checks() {
        let budget = check.descriptor().budget();
        if exceeds(budget, packets, bytes) {
            return Err(SessionError::ResourceBudgetExceeded {
                check: *check,
                packets,
                bytes,
                packet_limit: budget.packets(),
                byte_limit: budget.bytes(),
            });
        }
    }
    Ok(())
}

fn exceeds(budget: Budget, packets: u128, bytes: u128) -> bool {
    packets > u128::from(budget.packets()) || bytes > u128::from(budget.bytes())
}
