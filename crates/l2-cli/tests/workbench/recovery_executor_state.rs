use super::execution_state::{SchedulerCursor, SchedulerPhase, step};
use super::{
    CaseIndex, CaseIndexScanLedger, JobProgress, RecoveryPlan, normal_policy, test_support,
};
use l2_workbench::{evidence::Case, job::Job};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn saved_control_cursor_continues_live_executor_without_reseeding() -> TestResult {
    let mut case = Case::new();
    case.add_bytes_node("http_body", b"4142", Vec::new(), serde_json::json!({}))?;
    case.add_bytes_node("udp_payload", b"4344", Vec::new(), serde_json::json!({}))?;
    let plan = RecoveryPlan {
        discover_transforms: true,
        ..RecoveryPlan::default()
    };
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.case_index = CaseIndex::with_ledger(CaseIndexScanLedger::new()?);
    let mut cursor = SchedulerCursor::default();
    // Pause after actual candidate work rather than just source enumeration
    for _ in 0..100 {
        assert!(step(&mut executor, &mut cursor)?);
        if executor.coordinator.work_bytes_charged() > 0 {
            break;
        }
    }
    let charged = executor.coordinator.work_bytes_charged();
    assert!(charged > 0);
    assert!(matches!(cursor.phase, SchedulerPhase::Running));
    let index_charged = executor.case_index.scan_ledger.charged();
    let mut restored: SchedulerCursor = serde_json::from_slice(&serde_json::to_vec(&cursor)?)?;
    while step(&mut executor, &mut restored)? {}

    assert!(executor.case.blobs().iter().any(|blob| blob.bytes == b"AB"));
    assert!(executor.case.blobs().iter().any(|blob| blob.bytes == b"CD"));
    assert!(executor.coordinator.work_bytes_charged() >= charged);
    assert!(executor.case_index.scan_ledger.charged() >= index_charged);
    assert!(matches!(restored.phase, SchedulerPhase::Finished));
    Ok(())
}

#[test]
fn cancellation_during_seeding_keeps_the_cursor_and_frontier_unchanged() -> TestResult {
    let mut case = Case::new();
    case.add_bytes_node("http_body", b"4142", Vec::new(), serde_json::json!({}))?;
    case.add_bytes_node("udp_payload", b"4344", Vec::new(), serde_json::json!({}))?;
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.case_index = CaseIndex::with_ledger(CaseIndexScanLedger::new()?);
    let mut cursor = SchedulerCursor::default();
    assert!(step(&mut executor, &mut cursor)?);
    assert!(step(&mut executor, &mut cursor)?);
    assert!(matches!(
        cursor.phase,
        SchedulerPhase::Seeding { next: 1, .. }
    ));
    let saved = serde_json::to_vec(&cursor)?;
    let next_candidate = executor.coordinator.peek_next_id();
    let candidates = executor.coordinator.candidate_count();
    let job = Job::new("cancel source admission");
    job.request_cancel();
    executor.job = Some(JobProgress::new(job));

    assert!(step(&mut executor, &mut cursor).is_err());
    assert_eq!(serde_json::to_vec(&cursor)?, saved);
    assert_eq!(executor.coordinator.peek_next_id(), next_candidate);
    assert_eq!(executor.coordinator.candidate_count(), candidates);
    Ok(())
}

#[test]
fn invalid_seed_position_or_kind_is_rejected_before_admitting_work() -> TestResult {
    for invalid_position in [false, true] {
        let mut case = Case::new();
        case.add_bytes_node("http_body", b"4142", Vec::new(), serde_json::json!({}))?;
        let plan = RecoveryPlan::default();
        let policy = normal_policy(&case)?;
        let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
        executor.case_index = CaseIndex::with_ledger(CaseIndexScanLedger::new()?);
        let mut cursor = SchedulerCursor::default();
        assert!(step(&mut executor, &mut cursor)?);
        let SchedulerPhase::Seeding { roots, next } = &mut cursor.phase else {
            return Err("fixture has no source admission phase".into());
        };
        if invalid_position {
            *next = roots.len() + 1;
        } else {
            roots.first_mut().ok_or("missing source")?.1 = "changed_kind".to_owned();
        }
        let candidates = executor.coordinator.candidate_count();
        assert!(step(&mut executor, &mut cursor).is_err());
        assert_eq!(executor.coordinator.candidate_count(), candidates);
    }
    Ok(())
}

#[test]
fn finished_control_cursor_never_reopens_a_cancelled_job() -> TestResult {
    let mut case = Case::new();
    let plan = RecoveryPlan::default();
    let policy = normal_policy(&case)?;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    executor.case_index = CaseIndex::with_ledger(CaseIndexScanLedger::new()?);
    let mut cursor = SchedulerCursor::default();
    while step(&mut executor, &mut cursor)? {}
    assert!(matches!(cursor.phase, SchedulerPhase::Finished));
    let job = Job::new("already completed scheduler");
    job.request_cancel();
    executor.job = Some(JobProgress::new(job));
    assert!(!step(&mut executor, &mut cursor)?);
    assert_eq!(executor.coordinator.candidate_count(), 0);
    Ok(())
}
