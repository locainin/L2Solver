//! Sequence the bounded control, test, and follow-up requests

use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use l2_active::{ArpReport, Limits, StopReason};

use super::budget::{phase_deadline, remaining_limits};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    ControlBefore,
    Test,
    ControlAfter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkipReason {
    Cancelled,
    Deadline,
    Budget,
    PreviousFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureStage {
    Prepare,
    Open,
    Run,
}

#[derive(Debug)]
pub enum Attempt {
    Report {
        report: ArpReport,
        close_error: Option<io::Error>,
    },
    Failure {
        stage: FailureStage,
        error: io::Error,
        close_error: Option<io::Error>,
    },
}

#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "three bounded phase results avoid extra heap allocations"
)]
pub enum Step {
    Attempted { limits: Limits, outcome: Attempt },
    Skipped(SkipReason),
}

#[derive(Debug)]
pub struct Assessment {
    pub(super) before: Step,
    pub(super) test: Step,
    pub(super) after: Step,
}

pub fn run(
    budget: Limits,
    deadline: Instant,
    cancelled: &AtomicBool,
    mut execute: impl FnMut(Phase, Limits, Instant) -> Attempt,
) -> Assessment {
    let before = step(
        Phase::ControlBefore,
        budget,
        (Some(0), Some(0)),
        deadline,
        3,
        cancelled,
        &mut execute,
    );
    let test = stop_after(&before, cancelled).map_or_else(
        || {
            step(
                Phase::Test,
                budget,
                (Some(0), Some(0)),
                deadline,
                2,
                cancelled,
                &mut execute,
            )
        },
        Step::Skipped,
    );
    let after = stop_after(&test, cancelled).map_or_else(
        || {
            step(
                Phase::ControlAfter,
                budget,
                usage(&before),
                deadline,
                1,
                cancelled,
                &mut execute,
            )
        },
        Step::Skipped,
    );
    Assessment {
        before,
        test,
        after,
    }
}

fn step(
    phase: Phase,
    budget: Limits,
    used: (Option<u64>, Option<u64>),
    deadline: Instant,
    phases_left: u32,
    cancelled: &AtomicBool,
    execute: &mut impl FnMut(Phase, Limits, Instant) -> Attempt,
) -> Step {
    if cancelled.load(Ordering::Acquire) {
        return Step::Skipped(SkipReason::Cancelled);
    }
    let now = Instant::now();
    let Some(end) = phase_deadline(now, deadline, phases_left) else {
        return Step::Skipped(SkipReason::Deadline);
    };
    // The second control cannot exceed the first control's unused allowance
    let Some(limits) = remaining_limits(budget, used.0, used.1, end.duration_since(now)) else {
        return Step::Skipped(SkipReason::Budget);
    };
    Step::Attempted {
        limits,
        outcome: execute(phase, limits, end),
    }
}

fn stop_after(step: &Step, cancelled: &AtomicBool) -> Option<SkipReason> {
    if cancelled.load(Ordering::Acquire) {
        return Some(SkipReason::Cancelled);
    }
    match step {
        Step::Skipped(reason) => Some(*reason),
        Step::Attempted {
            outcome: Attempt::Failure { .. },
            ..
        }
        | Step::Attempted {
            outcome:
                Attempt::Report {
                    close_error: Some(_),
                    ..
                },
            ..
        } => Some(SkipReason::PreviousFailure),
        Step::Attempted {
            outcome: Attempt::Report { report, .. },
            ..
        } => {
            let summary = report.summary();
            if summary.stop_reason() == StopReason::Cancelled {
                return Some(SkipReason::Cancelled);
            }
            // Do not run the next phase if the preceding send was not accepted
            if summary.sent_packets() != 1 {
                return Some(SkipReason::PreviousFailure);
            }
            // A failed final scope sample cannot authorize another phase
            if summary.backlog_error().is_some() {
                return Some(SkipReason::PreviousFailure);
            }
            match summary.stop_reason() {
                StopReason::BackendDeadline
                | StopReason::InterfaceDown
                | StopReason::TransportError
                | StopReason::BackendViolation => Some(SkipReason::PreviousFailure),
                _ => None,
            }
        }
    }
}

const fn usage(step: &Step) -> (Option<u64>, Option<u64>) {
    match step {
        Step::Attempted {
            outcome: Attempt::Report { report, .. },
            ..
        } => (
            report.summary().total_received_packets(),
            report.summary().total_received_bytes(),
        ),
        _ => (None, None),
    }
}
