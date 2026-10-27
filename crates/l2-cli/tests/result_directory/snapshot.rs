use super::{
    Fixture, ResultDirectory, ResultKind, TestResult, assert_invalid_snapshot_error, json_field,
    read_manifest, set_json_field, write_manifest,
};
use l2_workbench::job::{
    Job, RecoveryTransition, RecoveryTransitionOutcome as Outcome, RecoveryTransitionStage as Stage,
};
use serde_json::json;

#[test]
fn result_receipt_rejects_a_duplicate_phase_even_when_the_count_is_correct() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    let mut phases = json_field(&manifest, "/l2solver_result/job/phases")?
        .as_array()
        .ok_or("job phases must be an array")?
        .clone();
    let duplicate = phases.first().ok_or("first phase missing")?.clone();
    *phases.get_mut(1).ok_or("second phase missing")? = duplicate;
    set_json_field(&mut manifest, "/l2solver_result/job/phases", json!(phases))?;
    write_manifest(&fixture.output, &manifest)?;
    assert_invalid_snapshot_error(&fixture.output)
}

#[test]
fn result_receipt_rejects_a_missing_phase() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    let mut phases = json_field(&manifest, "/l2solver_result/job/phases")?
        .as_array()
        .ok_or("job phases must be an array")?
        .clone();
    phases.pop().ok_or("phase missing")?;
    set_json_field(&mut manifest, "/l2solver_result/job/phases", json!(phases))?;
    write_manifest(&fixture.output, &manifest)?;
    assert_invalid_snapshot_error(&fixture.output)
}

#[test]
fn result_receipt_rejects_progress_above_one_hundred_percent() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let mut manifest = read_manifest(&fixture.output)?;
    set_json_field(
        &mut manifest,
        "/l2solver_result/job/phases/0/progress_percent",
        json!(101),
    )?;
    write_manifest(&fixture.output, &manifest)?;
    assert_invalid_snapshot_error(&fixture.output)
}

#[test]
fn result_receipt_accepts_all_128_distinct_transition_categories() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.publish("complete", b"artifact-content")?;
    let job = Job::new("transition fixture");
    let stages = [
        Stage::Cohort,
        Stage::Framing,
        Stage::Transform,
        Stage::Schema,
        Stage::Assembly,
        Stage::Validation,
        Stage::Expansion,
        Stage::Publication,
    ];
    let outcomes = [
        Outcome::Derived,
        Outcome::ReportRetained,
        Outcome::Hypothesis,
        Outcome::Validated,
        Outcome::Contradicted,
        Outcome::InputContradicted,
        Outcome::BudgetExhausted,
        Outcome::WorkOmitted,
        Outcome::Unsupported,
        Outcome::CohortAdmitted,
        Outcome::CohortOmitted,
        Outcome::LearningSampleOmitted,
        Outcome::Published,
        Outcome::PublishedDurabilityUncertain,
        Outcome::PublishedReplacementUncertain,
        Outcome::PublicationFailed,
    ];
    for stage in stages {
        for outcome in outcomes {
            job.record_recovery_transition(RecoveryTransition {
                stage,
                outcome,
                sample: None,
            })?;
        }
    }
    let summary = job.snapshot()?.recovery_transitions;
    assert_eq!(summary.records().len(), 128);
    let mut manifest = read_manifest(&fixture.output)?;
    set_json_field(
        &mut manifest,
        "/l2solver_result/job/recovery_transitions",
        serde_json::to_value(summary)?,
    )?;
    write_manifest(&fixture.output, &manifest)?;
    ResultDirectory::inspect(&fixture.output, ResultKind::Extract)?;
    Ok(())
}
