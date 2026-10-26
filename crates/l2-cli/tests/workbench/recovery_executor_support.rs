use super::{CaseIndex, Executor, RecoveryExecutionPolicy, RecoveryPlan};
use l2_workbench::{
    evidence::Case,
    protocol::{
        ByteField, ByteOrder, IntegerField, RecordCount, RecordLengthMeaning, RecordSchema,
    },
};
use serde_json::json;
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;

pub(super) fn test_schema() -> RecordSchema {
    RecordSchema {
        records_offset: 0,
        count: RecordCount::UntilEnd,
        identifier: ByteField {
            offset: 0,
            width: 1,
        },
        sequence: IntegerField {
            offset: 1,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        length: IntegerField {
            offset: 2,
            width: 1,
            byte_order: ByteOrder::BigEndian,
        },
        data_offset: 3,
        length_meaning: RecordLengthMeaning::PayloadBytes,
        sequence_base: 0,
        terminal_sequence: None,
    }
}

pub(super) fn record_case() -> TestResult<(Case, u64)> {
    let mut case = Case::new();
    let input = case.add_bytes_node(
        "custom_protocol_frame",
        &[0x21, 0, 1, b'x'],
        Vec::new(),
        json!({"fixture":"single valid record"}),
    )?;
    Ok((case, input))
}

pub(super) fn add_report(case: &mut Case, label: &str) -> TestResult<u64> {
    Ok(case.add_bytes_node(
        "recovery_record_discovery_report",
        label.as_bytes(),
        Vec::new(),
        json!({"fixture":label}),
    )?)
}

pub(super) fn build_executor<'a>(
    case: &'a mut Case,
    plan: &'a RecoveryPlan,
    policy: &RecoveryExecutionPolicy,
) -> Result<Executor<'a>, super::RecoveryExecutionError> {
    let case_index = CaseIndex::new(case)?;
    Ok(Executor {
        case,
        plan,
        policy: policy.clone(),
        coordinator: l2_workbench::recovery::RecoveryCoordinator::new(policy.resources),
        case_index,
        candidate_ids: Vec::new(),
        candidate_index: std::collections::HashSet::new(),
        snapshot_candidates: true,
        job: None,
        validated_artifacts: std::collections::HashSet::new(),
        transform_cohorts: Vec::new(),
        derived_discovery: super::derived_discovery::DerivedDiscovery::default(),
        transform_discoveries: std::collections::HashMap::new(),
        framing_selection_bases: std::collections::HashMap::new(),
        framing_discoveries: std::collections::HashMap::new(),
        record_discoveries: std::collections::HashMap::new(),
        record_discovery_context_by_report: std::collections::HashMap::new(),
        deferred_record_discovery_plan: None,
        record_schema_report_links: std::collections::HashMap::new(),
        record_schema_associations_charged: 0,
        record_phase_work_charged: 0,
        pending_record_assemblies: std::collections::VecDeque::new(),
        pending_record_assembly_count: 0,
        relational_samples: super::RelationalSampleCollections::default(),
        relational_discoveries: std::collections::HashMap::new(),
        transform_proposal_receipts: std::collections::HashMap::new(),
        omissions: Vec::new(),
        complete_negative_transform_searches: 0,
        cycle_skips: 0,
    })
}
