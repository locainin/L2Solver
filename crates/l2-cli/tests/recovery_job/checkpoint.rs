use super::*;
use crate::result_directory::ResultKind;
use l2_workbench::job::cache::SourceIdentity;
use l2_workbench::job::{Counter, Phase};
use serde_json::json;

#[test]
fn interrupted_job_restores_cumulative_work_and_replays_cached_stages() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("cache"),
        temporary.path().join("state"),
        1024 * 1024,
    )?;
    let identity = ResultIdentity {
        kind: ResultKind::Extract,
        algorithm_version: 2,
        source: SourceIdentity::from_sha256("0".repeat(64))?,
        settings: json!({"profile":"normal"}),
    };
    let original = Job::new("original");
    let checkpoint = CheckpointWriter::start(&cache, &identity, &original, false)?;
    original.start(Phase::TransformDiscovery, None)?;
    original.increment(Counter::CandidatesExamined, 17)?;
    original.request_cancel();
    checkpoint.finish(false)?;
    let resumed = Job::new("resumed");
    let writer = CheckpointWriter::start(&cache, &identity, &resumed, false)?;
    let snapshot = resumed.snapshot()?;
    assert_eq!(
        snapshot.created_at_unix_ms,
        original.snapshot()?.created_at_unix_ms
    );
    assert_eq!(
        snapshot.counters.get(&Counter::CandidatesExamined),
        Some(&17)
    );
    assert!(!resumed.is_cancelled());
    assert_eq!(
        snapshot
            .phase(Phase::TransformDiscovery)
            .map(|phase| phase.state),
        Some(PhaseState::Pending)
    );
    writer.finish(true)?;
    Ok(())
}
