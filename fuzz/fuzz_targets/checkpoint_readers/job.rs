use l2_workbench::job::{Job, JobSnapshot, MemoryBudget};
use std::error::Error;

pub fn restore(input: &[u8]) -> Result<Job, Box<dyn Error>> {
    let snapshot: JobSnapshot = serde_json::from_slice(input)?;
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let job = Job::with_memory_budget("fuzz restore", &memory);
    job.restore(snapshot)?;
    assert!(job.snapshot()?.is_valid_checkpoint());
    Ok(job)
}
