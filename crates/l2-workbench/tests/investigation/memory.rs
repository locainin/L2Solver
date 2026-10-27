use l2_workbench::{
    evidence::EvidenceError,
    investigation::{
        BuildInput, build_selected_with_limits, build_selected_with_limits_and_memory,
    },
    job::{MemoryBudget, MemoryClass, MemoryError},
    reconstruction::Limits,
    sha256,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn native_case_builder_charges_the_shared_budget_and_preserves_evidence() -> TestResult {
    let digest = sha256(b"");
    let input = BuildInput {
        label: "empty.pcap",
        length: 0,
        sha256_hex: &digest,
        records: &[],
        frames_seen: 0,
    };
    let expected = build_selected_with_limits(input, 0, Limits::default())?;
    let budget = MemoryBudget::new(1_000_000);
    let actual = build_selected_with_limits_and_memory(input, 0, Limits::default(), &budget)?;
    assert_eq!(actual.case, expected.case);
    assert!(budget.snapshot()?.used(MemoryClass::Case) > 0);
    drop(actual);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn native_case_builder_reports_pressure_without_leaking_a_partial_case() -> TestResult {
    let digest = sha256(b"");
    let input = BuildInput {
        label: "empty.pcap",
        length: 0,
        sha256_hex: &digest,
        records: &[],
        frames_seen: 0,
    };
    let budget = MemoryBudget::new(0);
    let result = build_selected_with_limits_and_memory(input, 0, Limits::default(), &budget);
    let error = result.err().ok_or("expected memory pressure")?;
    assert!(matches!(
        error.downcast_ref::<EvidenceError>(),
        Some(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
