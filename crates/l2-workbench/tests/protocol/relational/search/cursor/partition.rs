use super::{
    Job, MemoryBudget, RelationalCursorError, RelationalRestoreBudget, TestResult, borrow_samples,
};
use l2_workbench::protocol::{
    Direction, RelationalTransformError, RelationalTransformLimits,
    prepare_relational_session_partition,
};

#[test]
fn partition_orders_capture_ties_by_session_and_keeps_sessions_together() -> TestResult<()> {
    let records = vec![
        (9, Direction::FirstToSecond, vec![1]),
        (1, Direction::FirstToSecond, vec![2]),
        (2, Direction::FirstToSecond, vec![3]),
        (4, Direction::FirstToSecond, vec![4]),
        (7, Direction::FirstToSecond, vec![5]),
        (9, Direction::SecondToFirst, vec![6]),
    ];
    let mut samples = borrow_samples(&records)?;
    for sample in &mut samples {
        sample.session_order = match sample.context.session {
            1 | 9 => 1,
            2 => 3,
            4 => 4,
            7 => 5,
            _ => return Err("unexpected session".into()),
        };
    }
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let mut work = RelationalRestoreBudget::new(1_000_000, 0);
    let (discovery, heldout, lease) = prepare_relational_session_partition(
        &samples,
        RelationalTransformLimits::default(),
        None,
        &memory,
        &mut work,
    )?;
    assert_eq!(
        discovery.iter().map(|id| id.session).collect::<Vec<_>>(),
        [1, 9, 2]
    );
    assert_eq!(
        heldout.iter().map(|id| id.session).collect::<Vec<_>>(),
        [4, 7]
    );
    assert!(
        discovery
            .iter()
            .chain(&heldout)
            .all(|id| { id.source == "synthetic-source" && id.scope == "synthetic-scope" })
    );
    assert!(work.verification_work_bytes() > 0);
    assert!(memory.snapshot()?.used_bytes > 0);
    drop((discovery, heldout));
    drop(lease);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn partition_rejects_invalid_source_records_and_charges_the_attempt() -> TestResult<()> {
    let records = vec![
        (1, Direction::FirstToSecond, vec![1]),
        (2, Direction::SecondToFirst, vec![2]),
    ];
    let samples = borrow_samples(&records)?;
    let mut empty_source = samples.clone();
    empty_source
        .first_mut()
        .ok_or("missing source sample")?
        .context
        .source
        .clear();
    let mut duplicate_id = samples.clone();
    let first_id = duplicate_id.first().ok_or("missing first sample")?.sample;
    duplicate_id
        .get_mut(1)
        .ok_or("missing second sample")?
        .sample = first_id;
    let mut conflicting_order = samples.clone();
    let first = conflicting_order.first().ok_or("missing first sample")?;
    let session = first.context.session;
    let order = first
        .session_order
        .checked_add(1)
        .ok_or("session order overflow")?;
    let second = conflicting_order
        .get_mut(1)
        .ok_or("missing second sample")?;
    second.context.session = session;
    second.session_order = order;
    for invalid in [empty_source, duplicate_id, conflicting_order] {
        let memory = MemoryBudget::new(16 * 1024 * 1024);
        let mut work = RelationalRestoreBudget::new(1_000_000, 0);
        assert!(matches!(
            prepare_relational_session_partition(
                &invalid,
                RelationalTransformLimits::default(),
                None,
                &memory,
                &mut work,
            ),
            Err(RelationalCursorError::Search(
                RelationalTransformError::InvalidInput(_)
            ))
        ));
        assert!(work.verification_work_bytes() > 0);
        assert_eq!(memory.snapshot()?.used_bytes, 0);
    }
    Ok(())
}

#[test]
fn partition_respects_work_memory_session_and_cancellation_limits() -> TestResult<()> {
    let records = vec![
        (1, Direction::FirstToSecond, vec![1]),
        (2, Direction::SecondToFirst, vec![2]),
    ];
    let samples = borrow_samples(&records)?;
    let limits = RelationalTransformLimits::default();
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let mut no_work = RelationalRestoreBudget::new(0, 0);
    assert!(matches!(
        prepare_relational_session_partition(&samples, limits, None, &memory, &mut no_work),
        Err(RelationalCursorError::RestoreWorkLimit)
    ));
    assert_eq!(memory.snapshot()?.used_bytes, 0);

    let mut limited = RelationalRestoreBudget::new(1_024, 0);
    assert!(limited.try_charge_verification(23));
    assert!(matches!(
        prepare_relational_session_partition(&samples, limits, None, &memory, &mut limited),
        Err(RelationalCursorError::RestoreWorkLimit)
    ));
    assert!(limited.verification_work_bytes() > 23);
    assert_eq!(memory.snapshot()?.used_bytes, 0);

    let no_memory = MemoryBudget::new(0);
    let mut work = RelationalRestoreBudget::new(1_000_000, 0);
    assert!(matches!(
        prepare_relational_session_partition(&samples, limits, None, &no_memory, &mut work),
        Err(RelationalCursorError::Memory(_))
    ));
    assert!(work.verification_work_bytes() > 0);

    let mut capped = limits;
    capped.max_sessions = 1;
    let mut work = RelationalRestoreBudget::new(1_000_000, 0);
    assert!(matches!(
        prepare_relational_session_partition(&samples, capped, None, &memory, &mut work),
        Err(RelationalCursorError::Search(
            RelationalTransformError::TooManySessions { .. }
        ))
    ));
    assert!(work.verification_work_bytes() > 0);
    assert_eq!(memory.snapshot()?.used_bytes, 0);

    let job = Job::new("partition cancellation");
    job.request_cancel();
    let mut cancelled = RelationalRestoreBudget::new(1_000_000, 0);
    assert!(matches!(
        prepare_relational_session_partition(&samples, limits, Some(&job), &memory, &mut cancelled),
        Err(RelationalCursorError::Search(_))
    ));
    assert_eq!(cancelled.verification_work_bytes(), 0);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn partition_charges_longer_source_and_scope_strings() -> TestResult<()> {
    let records = vec![
        (1, Direction::FirstToSecond, vec![1]),
        (2, Direction::SecondToFirst, vec![2]),
    ];
    let samples = borrow_samples(&records)?;
    let mut longer = samples.clone();
    for sample in &mut longer {
        sample.context.source.push_str(&"x".repeat(512));
        sample.context.scope.push_str(&"y".repeat(512));
    }
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let mut first = RelationalRestoreBudget::new(1_000_000, 0);
    let short = prepare_relational_session_partition(
        &samples,
        RelationalTransformLimits::default(),
        None,
        &memory,
        &mut first,
    )?;
    let mut second = RelationalRestoreBudget::new(1_000_000, 0);
    let long = prepare_relational_session_partition(
        &longer,
        RelationalTransformLimits::default(),
        None,
        &memory,
        &mut second,
    )?;
    assert!(second.verification_work_bytes() > first.verification_work_bytes());
    drop((short, long));
    Ok(())
}

#[test]
fn realistic_cohort_partition_fits_a_bounded_verification_allowance() -> TestResult<()> {
    let records = (0_u32..500)
        .map(|index| (1 + index % 20, Direction::FirstToSecond, vec![1]))
        .collect::<Vec<_>>();
    let samples = borrow_samples(&records)?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let mut work = RelationalRestoreBudget::new(32 * 1024 * 1024, 0);
    let (discovery, heldout, lease) = prepare_relational_session_partition(
        &samples,
        RelationalTransformLimits::default(),
        None,
        &memory,
        &mut work,
    )?;
    assert_eq!(discovery.len(), 10);
    assert_eq!(heldout.len(), 10);
    assert!(work.verification_work_bytes() <= 32 * 1024 * 1024);
    drop((discovery, heldout));
    drop(lease);
    Ok(())
}
