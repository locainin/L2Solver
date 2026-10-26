use super::*;
use crate::result_directory::ResultKind;
use l2_workbench::job::{Counter, Phase, PhaseOutcome, cache::SourceIdentity};

#[test]
fn restarted_bounded_stage_counts_the_new_pass_without_losing_cumulative_work()
-> Result<(), Box<dyn Error>> {
    for prior_completion in [40, 100] {
        check_restarted_ingestion(prior_completion)?;
    }
    Ok(())
}

fn check_restarted_ingestion(prior_completion: u64) -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        1024 * 1024,
    )?;
    let identity = ResultIdentity {
        kind: ResultKind::Extract,
        algorithm_version: 3,
        source: SourceIdentity::from_sha256("1".repeat(64))?,
        settings: json!({}),
    };
    let original = Job::new("interrupted ingestion");
    let checkpoint = CheckpointWriter::start(&cache, &identity, &original, false)?;
    original.start(Phase::Ingestion, Some(100))?;
    original.advance(Phase::Ingestion, prior_completion)?;
    original.increment(Counter::Bytes, prior_completion)?;
    if prior_completion == 100 {
        original.finish(Phase::Ingestion, PhaseOutcome::Completed)?;
    }
    checkpoint.finish(false)?;
    let resumed = Job::new("resumed ingestion");

    let checkpoint = CheckpointWriter::start(&cache, &identity, &resumed, false)?;
    resumed.start(Phase::Ingestion, Some(100))?;
    resumed.advance(Phase::Ingestion, 10)?;
    resumed.increment(Counter::Bytes, 10)?;

    let snapshot = resumed.snapshot()?;
    let phase = snapshot
        .phase(Phase::Ingestion)
        .ok_or("ingestion phase missing")?;
    assert_eq!(phase.completed, 10, "prior progress: {prior_completion}");
    assert_eq!(phase.progress_percent, Some(10));
    assert_eq!(
        snapshot.counters.get(&Counter::Bytes),
        Some(&(prior_completion + 10))
    );
    checkpoint.finish(false)?;
    Ok(())
}
