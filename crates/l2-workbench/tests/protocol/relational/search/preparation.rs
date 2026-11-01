use super::super::input::group_sessions;
use super::{
    RelationalRecordSample, RelationalTransformError, RelationalTransformLimits,
    build_selector_indexes, payload_locators, seed_locators, shared_selectors,
};
use crate::job::{Job, JobError};
use crate::protocol::{Direction, MessageContext};
use std::{cell::Cell, error::Error};

type TestResult = Result<(), Box<dyn Error>>;

fn samples() -> [RelationalRecordSample<'static>; 4] {
    static BYTES: [[u8; 4]; 4] = [
        [0x31, 0x15, 0x21, 0x32],
        [0x31, 0x26, 0x32, 0x43],
        [0x31, 0x37, 0x43, 0x54],
        [0x31, 0x48, 0x54, 0x65],
    ];
    let mut session = 0_u64;
    BYTES.each_ref().map(|bytes| {
        session += 1;
        RelationalRecordSample {
            sample: session,
            context: MessageContext {
                source: "preparation".to_owned(),
                scope: "independent sessions".to_owned(),
                session,
                direction: Direction::FirstToSecond,
            },
            session_order: session,
            bytes,
        }
    })
}

fn cancel_after_first_action<'a>(
    job: &'a Job,
    checks: &'a Cell<usize>,
) -> impl FnMut() -> Result<(), RelationalTransformError> + 'a {
    move || {
        checks.set(checks.get() + 1);
        if checks.get() == 2 {
            job.request_cancel();
        }
        job.check_cancelled().map_err(Into::into)
    }
}

fn assert_cancelled<T>(result: &Result<T, RelationalTransformError>, checks: &Cell<usize>) {
    assert!(
        matches!(
            result,
            Err(RelationalTransformError::Job(JobError::Cancelled))
        ),
        "preparation must stop at the first requested cancellation"
    );
    assert_eq!(checks.get(), 2, "preparation continued after cancellation");
}

#[test]
fn session_grouping_stops_between_messages() {
    let job = Job::new("cancel session grouping");
    let checks = Cell::new(0);
    let result = group_sessions(
        &samples(),
        RelationalTransformLimits::default(),
        &mut cancel_after_first_action(&job, &checks),
    );
    assert_cancelled(&result, &checks);
}

#[test]
fn selector_indexing_stops_inside_one_message() -> TestResult {
    let samples = samples();
    let limits = RelationalTransformLimits::default();
    let groups = group_sessions(&samples, limits, &mut || Ok(()))?;
    let job = Job::new("cancel selector indexing");
    let checks = Cell::new(0);
    let result = build_selector_indexes(
        &samples,
        &groups,
        limits,
        &mut cancel_after_first_action(&job, &checks),
    );
    assert_cancelled(&result, &checks);
    Ok(())
}

#[test]
fn common_selector_intersection_stops_between_selectors() -> TestResult {
    let samples = samples();
    let limits = RelationalTransformLimits::default();
    let groups = group_sessions(&samples, limits, &mut || Ok(()))?;
    let indexes = build_selector_indexes(&samples, &groups, limits, &mut || Ok(()))?;
    let job = Job::new("cancel selector intersection");
    let checks = Cell::new(0);
    let result = shared_selectors(&indexes, &mut cancel_after_first_action(&job, &checks));
    assert_cancelled(&result, &checks);
    Ok(())
}

#[test]
fn seed_locator_generation_stops_inside_one_selector() -> TestResult {
    let samples = samples();
    let limits = RelationalTransformLimits::default();
    let groups = group_sessions(&samples, limits, &mut || Ok(()))?;
    let indexes = build_selector_indexes(&samples, &groups, limits, &mut || Ok(()))?;
    let selectors = shared_selectors(&indexes, &mut || Ok(()))?;
    assert_eq!(
        selectors.len(),
        1,
        "the control must use one shared selector"
    );
    let job = Job::new("cancel seed locators");
    let checks = Cell::new(0);
    let result = seed_locators(
        &samples,
        &groups,
        &indexes,
        &selectors,
        limits,
        &mut cancel_after_first_action(&job, &checks),
    );
    assert_cancelled(&result, &checks);
    Ok(())
}

#[test]
fn payload_locator_generation_stops_inside_one_selector() -> TestResult {
    let samples = samples();
    let limits = RelationalTransformLimits::default();
    let groups = group_sessions(&samples, limits, &mut || Ok(()))?;
    let indexes = build_selector_indexes(&samples, &groups, limits, &mut || Ok(()))?;
    let selectors = shared_selectors(&indexes, &mut || Ok(()))?;
    assert_eq!(
        selectors.len(),
        1,
        "the control must use one shared selector"
    );
    let job = Job::new("cancel payload locators");
    let checks = Cell::new(0);
    let result = payload_locators(
        &samples,
        &groups,
        &indexes,
        &selectors,
        limits,
        limits.max_locator_candidates,
        &mut cancel_after_first_action(&job, &checks),
    );
    assert_cancelled(&result, &checks);
    Ok(())
}
