use super::{add_tcp_run, add_unresolved_tcp_runs, capture, framing_plan, framing_policy};
use crate::workbench::recovery_executor::{JobProgress, execute_internal};
use l2_workbench::{
    evidence::Case,
    job::{
        Job, RecoveryCohortReason, RecoveryTransitionOutcome, RecoveryTransitionSample,
        RecoveryTransitionStage,
    },
};
use std::error::Error;

#[test]
fn framing_cohort_events_bind_admission_and_missing_context_to_the_source()
-> Result<(), Box<dyn Error>> {
    let mut case = Case::new();
    let source = capture(&mut case, "framing-cohort-transitions")?;
    let run = add_tcp_run(&mut case, &source, "cohort", 10, 0, 0, b"alpha|beta|")?;
    let (orphan, _mixed) = add_unresolved_tcp_runs(&mut case, &source)?;
    let policy = framing_policy(&case)?;
    let job = Job::new("framing cohort transitions");
    let progress = JobProgress::new(job.clone());
    execute_internal(
        &mut case,
        &framing_plan(),
        &policy,
        true,
        Some(&progress),
        None,
        None,
    )?;
    let snapshot = job.snapshot()?;
    let source_digest = source
        .strip_prefix("sha256:")
        .and_then(l2_workbench::parse_sha256_digest)
        .ok_or("invalid source identity")?;
    for (outcome, node_id, reason) in [
        (
            RecoveryTransitionOutcome::CohortAdmitted,
            run,
            RecoveryCohortReason::Admitted,
        ),
        (
            RecoveryTransitionOutcome::CohortOmitted,
            orphan,
            RecoveryCohortReason::MissingContext,
        ),
    ] {
        let record = snapshot
            .recovery_transitions
            .records()
            .iter()
            .find(|record| {
                record.stage() == RecoveryTransitionStage::Framing && record.outcome() == outcome
            })
            .ok_or("framing cohort transition is missing")?;
        let Some(RecoveryTransitionSample::Cohort(sample)) = record.sample() else {
            return Err("framing cohort source sample is missing".into());
        };
        assert_eq!(sample.source_sha256, Some(source_digest));
        assert_eq!(sample.input_node_id, Some(node_id));
        assert_eq!(sample.reason, reason);
        if outcome == RecoveryTransitionOutcome::CohortAdmitted {
            assert!(sample.candidate_index.is_some());
            assert!(sample.input_batch_sha256.is_some());
            assert!(sample.task_sha256.is_some());
        } else {
            assert_eq!(sample.candidate_index, None);
        }
        let node = case.node(node_id).ok_or("cohort input node is missing")?;
        let digest = node
            .blob
            .as_deref()
            .and_then(|blob| blob.strip_prefix("sha256:"))
            .and_then(l2_workbench::parse_sha256_digest);
        assert_eq!(sample.input_blob_sha256, digest);
    }
    Ok(())
}
