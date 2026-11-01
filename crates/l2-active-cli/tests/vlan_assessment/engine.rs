use std::{
    collections::VecDeque,
    error::Error,
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use l2_active::{ActiveLink, Limits, PreSendUsage, ReceiveEvent};
use l2_capture::LinuxInterfaceIdentity;

use super::{
    arp_fixture,
    engine::{self, Attempt, FailureStage, Phase, SkipReason, Step},
    report_fixture::report,
};

#[test]
fn runs_control_test_control_with_separate_budgets_and_one_deadline() -> Result<(), Box<dyn Error>>
{
    let budget = Limits::new(Duration::from_secs(3), 10, 1_000)?;
    let mut reports = VecDeque::from([
        report(&[arp_fixture::REMOTE_MAC], Some(PreSendUsage::new(2, 100)))?,
        report(&[], Some(PreSendUsage::new(0, 0)))?,
        report(&[arp_fixture::REMOTE_MAC], Some(PreSendUsage::new(0, 0)))?,
    ]);
    let mut calls = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    let result = engine::run(
        budget,
        deadline,
        &AtomicBool::new(false),
        |phase, limits, end| {
            calls.push((phase, limits, end));
            reports.pop_front().map_or_else(
                || Attempt::Failure {
                    stage: FailureStage::Open,
                    error: io::Error::other("unexpected extra attempt"),
                    close_error: None,
                },
                |report| Attempt::Report {
                    report,
                    close_error: None,
                },
            )
        },
    );
    let phases: Vec<_> = calls.iter().map(|(phase, _, _)| *phase).collect();
    assert_eq!(
        phases,
        [Phase::ControlBefore, Phase::Test, Phase::ControlAfter]
    );
    let first = calls.first().ok_or("missing first call")?;
    let test = calls.get(1).ok_or("missing test call")?;
    let last = calls.get(2).ok_or("missing final call")?;
    assert_eq!(
        (first.1.max_received_packets(), first.1.max_received_bytes()),
        (10, 1_000)
    );
    assert_eq!(
        (test.1.max_received_packets(), test.1.max_received_bytes()),
        (10, 1_000)
    );
    assert_eq!(
        (last.1.max_received_packets(), last.1.max_received_bytes()),
        (7, 840)
    );
    assert!(calls.iter().all(|(_, _, end)| *end <= deadline));
    let Step::Attempted { limits, .. } = &result.before else {
        return Err("missing first attempt limits".into());
    };
    assert_eq!(*limits, first.1);
    assert!(matches!(result.before, Step::Attempted { .. }));
    assert!(matches!(result.test, Step::Attempted { .. }));
    assert!(matches!(result.after, Step::Attempted { .. }));
    Ok(())
}

#[test]
fn unknown_control_accounting_still_allows_the_separately_bounded_test_but_not_control_after()
-> Result<(), Box<dyn Error>> {
    let budget = Limits::new(Duration::from_secs(1), 10, 1_000)?;
    let mut reports = VecDeque::from([
        report(&[arp_fixture::REMOTE_MAC], None)?,
        report(&[], Some(PreSendUsage::new(0, 0)))?,
    ]);
    let mut phases = Vec::new();
    let result = engine::run(
        budget,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
        |phase, _, _| {
            phases.push(phase);
            reports.pop_front().map_or_else(
                || Attempt::Failure {
                    stage: FailureStage::Open,
                    error: io::Error::other("unexpected extra attempt"),
                    close_error: None,
                },
                |report| Attempt::Report {
                    report,
                    close_error: None,
                },
            )
        },
    );
    assert_eq!(phases, [Phase::ControlBefore, Phase::Test]);
    assert!(matches!(result.after, Step::Skipped(SkipReason::Budget)));
    Ok(())
}

#[test]
fn cancellation_after_control_prevents_both_later_transmissions() -> Result<(), Box<dyn Error>> {
    let budget = Limits::new(Duration::from_secs(1), 10, 1_000)?;
    let cancelled = AtomicBool::new(false);
    let mut first = Some(report(
        &[arp_fixture::REMOTE_MAC],
        Some(PreSendUsage::new(0, 0)),
    )?);
    let mut calls = 0;
    let result = engine::run(
        budget,
        Instant::now() + Duration::from_secs(1),
        &cancelled,
        |_, _, _| {
            calls += 1;
            cancelled.store(true, Ordering::Release);
            first.take().map_or_else(
                || Attempt::Failure {
                    stage: FailureStage::Open,
                    error: io::Error::other("unexpected extra attempt"),
                    close_error: None,
                },
                |report| Attempt::Report {
                    report,
                    close_error: None,
                },
            )
        },
    );
    assert_eq!(calls, 1);
    assert!(matches!(result.test, Step::Skipped(SkipReason::Cancelled)));
    assert!(matches!(result.after, Step::Skipped(SkipReason::Cancelled)));
    Ok(())
}

#[test]
fn helper_open_failure_stops_remaining_phases() -> Result<(), Box<dyn Error>> {
    let budget = Limits::new(Duration::from_secs(1), 10, 1_000)?;
    let mut calls = 0;
    let result = engine::run(
        budget,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
        |_, _, _| {
            calls += 1;
            Attempt::Failure {
                stage: FailureStage::Open,
                error: io::Error::from(io::ErrorKind::PermissionDenied),
                close_error: None,
            }
        },
    );
    assert_eq!(calls, 1);
    assert!(matches!(
        result.test,
        Step::Skipped(SkipReason::PreviousFailure)
    ));
    assert!(matches!(
        result.after,
        Step::Skipped(SkipReason::PreviousFailure)
    ));
    Ok(())
}

#[test]
fn send_timeout_before_acceptance_stops_the_remaining_phases() -> Result<(), Box<dyn Error>> {
    let budget = Limits::new(Duration::from_secs(1), 10, 1_000)?;
    let mut link = arp_fixture::Link::new(Vec::new(), Some(0))?;
    link.timeout_during_send = true;
    let report = arp_fixture::probe(Some(arp_fixture::REMOTE_MAC), 10, 1_000)?
        .run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(
        report.summary().stop_reason(),
        l2_active::StopReason::Deadline
    );
    assert_eq!(report.summary().sent_packets(), 0);
    let mut report = Some(report);
    let mut calls = 0;
    let result = engine::run(
        budget,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
        |_, _, _| {
            calls += 1;
            report.take().map_or_else(
                || Attempt::Failure {
                    stage: FailureStage::Open,
                    error: io::Error::other("unexpected extra attempt"),
                    close_error: None,
                },
                |report| Attempt::Report {
                    report,
                    close_error: None,
                },
            )
        },
    );
    assert_eq!(calls, 1);
    assert!(matches!(
        result.test,
        Step::Skipped(SkipReason::PreviousFailure)
    ));
    assert!(matches!(
        result.after,
        Step::Skipped(SkipReason::PreviousFailure)
    ));
    Ok(())
}

#[test]
fn silent_control_with_an_accepted_send_does_not_stop_the_other_phases()
-> Result<(), Box<dyn Error>> {
    let budget = Limits::new(Duration::from_secs(1), 10, 1_000)?;
    let mut reports = VecDeque::from([
        report(&[], Some(PreSendUsage::new(0, 0)))?,
        report(&[], Some(PreSendUsage::new(0, 0)))?,
        report(&[], Some(PreSendUsage::new(0, 0)))?,
    ]);
    let mut calls = 0;
    let result = engine::run(
        budget,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
        |_, _, _| {
            calls += 1;
            reports.pop_front().map_or_else(
                || Attempt::Failure {
                    stage: FailureStage::Open,
                    error: io::Error::other("unexpected extra attempt"),
                    close_error: None,
                },
                |report| Attempt::Report {
                    report,
                    close_error: None,
                },
            )
        },
    );
    assert_eq!(calls, 3);
    assert!(matches!(result.after, Step::Attempted { .. }));
    Ok(())
}

struct ChangedBacklog(arp_fixture::Link);

impl ActiveLink for ChangedBacklog {
    fn interface(&self) -> LinuxInterfaceIdentity {
        self.0.interface()
    }

    fn send(&mut self, frame: &[u8], deadline: Instant, cancelled: &AtomicBool) -> io::Result<()> {
        self.0.send(frame, deadline, cancelled)
    }

    fn pre_send_usage(&mut self) -> io::Result<Option<PreSendUsage>> {
        self.0.pre_send_usage()
    }

    fn receive(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
        max_bytes: usize,
    ) -> io::Result<ReceiveEvent> {
        self.0.receive(deadline, cancelled, max_bytes)
    }

    fn capture_loss(&mut self) -> io::Result<Option<u64>> {
        self.0.capture_loss()
    }

    fn capture_backlog(&mut self) -> io::Result<Option<bool>> {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            l2_active_linux::VlanScopeChanged,
        ))
    }
}

#[test]
fn final_scope_sample_failure_stops_the_other_phases() -> Result<(), Box<dyn Error>> {
    let budget = Limits::new(Duration::from_secs(1), 10, 1_000)?;
    let mut link = ChangedBacklog(arp_fixture::Link::new(
        vec![ReceiveEvent::TimedOut],
        Some(0),
    )?);
    let report = arp_fixture::probe(Some(arp_fixture::REMOTE_MAC), 10, 1_000)?
        .run(&mut link, &AtomicBool::new(false))?;
    assert_eq!(report.summary().sent_packets(), 1);
    assert_eq!(
        report.summary().stop_reason(),
        l2_active::StopReason::Deadline
    );
    assert!(report.summary().backlog_error().is_some());
    let mut report = Some(report);
    let mut calls = 0;
    let result = engine::run(
        budget,
        Instant::now() + Duration::from_secs(1),
        &AtomicBool::new(false),
        |_, _, _| {
            calls += 1;
            report.take().map_or_else(
                || Attempt::Failure {
                    stage: FailureStage::Open,
                    error: io::Error::other("unexpected extra attempt"),
                    close_error: None,
                },
                |report| Attempt::Report {
                    report,
                    close_error: None,
                },
            )
        },
    );
    assert_eq!(calls, 1);
    assert!(matches!(
        result.test,
        Step::Skipped(SkipReason::PreviousFailure)
    ));
    assert!(matches!(
        result.after,
        Step::Skipped(SkipReason::PreviousFailure)
    ));
    Ok(())
}

#[test]
fn preparation_and_run_failures_keep_their_error_and_cleanup_details() -> Result<(), Box<dyn Error>>
{
    let budget = Limits::new(Duration::from_secs(1), 10, 1_000)?;
    for expected in [FailureStage::Prepare, FailureStage::Run] {
        let result = engine::run(
            budget,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
            |_, _, _| Attempt::Failure {
                stage: expected,
                error: io::Error::from(io::ErrorKind::PermissionDenied),
                close_error: Some(io::Error::other("cleanup was not confirmed")),
            },
        );
        let Step::Attempted {
            outcome:
                Attempt::Failure {
                    stage,
                    error,
                    close_error,
                },
            ..
        } = result.before
        else {
            return Err("failed attempt was not retained".into());
        };
        assert_eq!(stage, expected);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(close_error.is_some());
        assert!(matches!(
            result.test,
            Step::Skipped(SkipReason::PreviousFailure)
        ));
    }
    Ok(())
}
