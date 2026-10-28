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
    let mut executor = super::new_executor(case, plan, policy.clone(), true, None, None)?;
    executor.case_index = case_index;
    Ok(executor)
}
