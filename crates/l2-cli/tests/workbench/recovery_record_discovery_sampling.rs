use super::{LearningSample, RecordDiscoveryContext, suffix_inputs};
use crate::workbench::recovery_executor::record_discovery::input::{
    RecordCohortKey, RecordCohortOrigin, RecordDiscoveryInputOmissions, RecordFrameInput,
};
use l2_workbench::protocol::{ByteRange, Direction, RecordSchemaProposalLimits};
use std::{error::Error, sync::Arc};

fn cohort_key() -> RecordCohortKey {
    RecordCohortKey {
        source_id: "source".into(),
        scope_json: "{}".into(),
        endpoints_json: "[]".into(),
        direction: Direction::FirstToSecond,
        origin: RecordCohortOrigin::TcpMaterialized,
        framing_rule_json: "{}".into(),
    }
}

fn frame(session: u64, index: usize, size: usize) -> RecordFrameInput {
    RecordFrameInput {
        node_id: session * 100 + u64::try_from(index).unwrap_or(u64::MAX) + 1,
        blob_id: String::new(),
        receipt_node_id: session * 1000,
        session_node_id: session,
        direction_node_id: session,
        episode_node_id: session,
        session_id: session,
        frame_index: index,
        stream_range: ByteRange {
            start: index * size,
            end: (index + 1) * size,
        },
        stream_offset: 0,
        byte_length: size,
    }
}

#[test]
fn suffix_sampling_preserves_session_counts_and_respects_byte_limit() -> Result<(), Box<dyn Error>>
{
    let all = vec![
        frame(1, 0, 4),
        frame(1, 1, 4),
        frame(1, 2, 4),
        frame(1, 3, 20),
        frame(2, 0, 4),
        frame(2, 1, 4),
        frame(2, 2, 4),
        frame(2, 3, 4),
    ];
    let context = RecordDiscoveryContext {
        key: cohort_key(),
        inputs: all
            .iter()
            .take(2)
            .chain(all.iter().skip(4).take(2))
            .cloned()
            .collect(),
        application_inputs: Arc::from(all),
        sampling: LearningSample::SessionPrefix,
        omitted_frames: 4,
        eligibility_omissions: RecordDiscoveryInputOmissions::default(),
    };
    let mut limits = RecordSchemaProposalLimits::default();
    limits.discovery.record_limits.max_input_bytes = 31;
    assert!(
        suffix_inputs(&context, limits)?.is_none(),
        "later samples exceeding the existing byte limit must not be scheduled"
    );
    limits.discovery.record_limits.max_input_bytes = 32;
    let first = suffix_inputs(&context, limits)?.ok_or("suffix samples are missing")?;
    let second = suffix_inputs(&context, limits)?
        .ok_or("suffix samples are missing on repeated selection")?;
    let ids =
        |inputs: &[RecordFrameInput]| inputs.iter().map(|input| input.node_id).collect::<Vec<_>>();
    assert_eq!(ids(&first), vec![103, 104, 203, 204]);
    assert_eq!(ids(&first), ids(&second));
    assert_eq!(first.len(), context.inputs.len());
    assert_eq!(
        first.iter().map(|input| input.byte_length).sum::<usize>(),
        32
    );
    Ok(())
}

#[test]
fn suffix_fallback_admission_leaves_the_last_candidate_slot_for_normal_assembly()
-> Result<(), Box<dyn Error>> {
    use crate::workbench::recovery_executor::{
        RecoveryPlan, execute_executor, finish_executor, normal_policy, test_support,
    };
    use l2_workbench::recovery::{EnqueueOutcome, RecoveryResult, RecoveryTask};
    use serde_json::json;

    let (mut case, frame_node) = test_support::record_case()?;
    let later_node = case.add_bytes_node(
        "custom_protocol_frame",
        &[0x21, 1, 1, b'y'],
        Vec::new(),
        json!({}),
    )?;
    let report_node = test_support::add_report(&mut case, "normal schema")?;
    let plan = RecoveryPlan::default();
    let mut policy = normal_policy(&case)?;
    policy.resources.max_candidates = 2;
    let mut executor = test_support::build_executor(&mut case, &plan, &policy)?;
    let outcome = executor.coordinator.enqueue_nodes(
        executor.case,
        &[frame_node],
        RecoveryTask::RecordDiscovery,
    )?;
    let EnqueueOutcome::Queued(id) = outcome else {
        return Err("record discovery was not queued".into());
    };
    assert_eq!(executor.coordinator.pop_next()?, Some(id));
    executor
        .coordinator
        .finish(executor.case, id, RecoveryResult::Unsupported)?;
    let mut first = frame(1, 0, 4);
    first.node_id = frame_node;
    let mut later = frame(1, 1, 4);
    later.node_id = later_node;
    let context = RecordDiscoveryContext {
        key: cohort_key(),
        inputs: vec![first.clone()],
        application_inputs: Arc::from(vec![first, later]),
        sampling: LearningSample::SessionPrefix,
        omitted_frames: 1,
        eligibility_omissions: RecordDiscoveryInputOmissions::default(),
    };
    executor.record_discoveries.insert(id, vec![context]);
    executor
        .pending_record_suffixes
        .push_back(super::PendingRecordSuffix {
            candidate_id: id,
            context_index: 0,
        });
    executor.defer_record_schema_group(vec![(
        vec![frame_node],
        test_support::test_schema(),
        report_node,
    )])?;
    execute_executor(&mut executor)?;
    let outcome = finish_executor(executor)?;
    assert_normal_assembly_before_suffix(&outcome);
    Ok(())
}

fn assert_normal_assembly_before_suffix(
    outcome: &crate::workbench::recovery_executor::RecoveryExecutionOutcome,
) {
    use l2_workbench::recovery::{
        RecoveryCandidateState, RecoveryResource, RecoveryResult, RecoveryTask,
    };
    assert!(
        outcome.candidates.iter().any(|candidate| matches!(
            candidate.task(),
            RecoveryTask::AssembleRecords(_)
        ) && matches!(
            candidate.state(),
            RecoveryCandidateState::Finished {
                result: RecoveryResult::Derived { .. },
                ..
            }
        )),
        "normal schema assembly must retain the last candidate slot"
    );
    assert!(
        outcome.omissions.iter().any(|omission| matches!(
            omission,
            crate::workbench::recovery_executor::RecoveryOmission::ResourceExhausted {
                task: RecoveryTask::RecordDiscovery,
                resource: RecoveryResource::CandidateCount,
                ..
            }
        )),
        "the later optional search must report the exhausted candidate limit"
    );
}
