use super::{Counter, Job, JobSnapshot, Phase, TestResult};
use l2_workbench::job::{JobError, MemoryBudget};

fn malformed_snapshots() -> Result<Vec<JobSnapshot>, Box<dyn std::error::Error>> {
    let saved = Job::new("saved progress").snapshot()?;
    let mut missing = saved.clone();
    // The fuzz reproducer retained only preparation and omitted all later phases
    missing.phases.truncate(1);
    let mut duplicate = saved.clone();
    duplicate
        .phases
        .get_mut(1)
        .ok_or("missing second phase")?
        .phase = Phase::Preparation;
    let mut invalid_progress = saved;
    invalid_progress
        .phases
        .first_mut()
        .ok_or("missing preparation phase")?
        .progress_percent = Some(101);
    Ok(vec![missing, duplicate, invalid_progress])
}

fn assert_live_job_unchanged(before: &JobSnapshot, job: &Job) -> TestResult {
    let mut after = job.snapshot()?;
    assert!(after.elapsed_ms >= before.elapsed_ms);
    // Clock advancement is independent of accepting or refusing a checkpoint
    after.elapsed_ms = before.elapsed_ms;
    assert_eq!(&after, before);
    Ok(())
}

#[test]
fn restore_rejects_malformed_phases_without_changing_live_state() -> TestResult {
    for saved in malformed_snapshots()? {
        let memory = MemoryBudget::new(1024 * 1024);
        let job = Job::with_memory_budget("current progress", &memory);
        job.increment(Counter::CacheMisses, 7)?;
        job.request_cancel();
        let before = job.snapshot()?;
        let allocated = memory.snapshot()?.used_bytes;
        assert_eq!(job.restore(saved), Err(JobError::InvalidCheckpoint));
        assert_live_job_unchanged(&before, &job)?;
        assert_eq!(memory.snapshot()?.used_bytes, allocated);
    }
    Ok(())
}

#[test]
fn preview_rejects_malformed_phases_without_changing_live_state() -> TestResult {
    for saved in malformed_snapshots()? {
        let memory = MemoryBudget::new(1024 * 1024);
        let job = Job::with_memory_budget("current progress", &memory);
        job.increment(Counter::CacheMisses, 7)?;
        job.request_cancel();
        let before = job.snapshot()?;
        let allocated = memory.snapshot()?.used_bytes;
        assert_eq!(
            job.preview_checkpoint(Some(&saved)),
            Err(JobError::InvalidCheckpoint)
        );
        assert_live_job_unchanged(&before, &job)?;
        assert_eq!(memory.snapshot()?.used_bytes, allocated);
    }
    Ok(())
}
