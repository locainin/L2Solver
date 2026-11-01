use std::{error::Error, mem::size_of};

use crate::{
    artifact::{
        ArtifactStructure, ArtifactValidationFormat, ArtifactValidationOutcome, ArtifactValidator,
        DerNode,
    },
    job::{MemoryBudget, MemoryClass, MemoryError},
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn der_inventory_and_oid_remain_charged_until_the_report_drops() -> TestResult {
    let bytes = [0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03];
    let budget = MemoryBudget::new(64 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Publication, 9)?;
    let outcome = ArtifactValidator::default().validate_as_with_memory(
        ArtifactValidationFormat::Der,
        &bytes,
        &mut lease,
    )?;
    let ArtifactValidationOutcome::Validated {
        structure: ArtifactStructure::Der(report),
        ..
    } = &outcome
    else {
        return Err("expected a validated DER report".into());
    };
    assert!(
        report
            .nodes
            .iter()
            .any(|node| node.oid.as_deref() == Some("2.5.4.3"))
    );
    let retained = report.nodes.capacity() * size_of::<DerNode>()
        + report
            .nodes
            .iter()
            .map(|node| node.value_preview.capacity())
            .sum::<usize>()
        + report
            .nodes
            .iter()
            .filter_map(|node| node.oid.as_ref())
            .map(String::capacity)
            .sum::<usize>();
    assert_eq!(lease.bytes(), 9 + u64::try_from(retained)?);
    drop(outcome);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn der_pressure_and_partial_rejection_restore_the_existing_charge() -> TestResult {
    let valid = [0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03];
    let budget = MemoryBudget::new(64 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Publication, 11)?;
    let blocker = budget.try_reserve(MemoryClass::Cache, budget.snapshot()?.limit_bytes - 11)?;
    assert!(matches!(
        ArtifactValidator::default().validate_as_with_memory(
            ArtifactValidationFormat::Der,
            &valid,
            &mut lease,
        ),
        Err(MemoryError::Limit { .. })
    ));
    assert_eq!(lease.bytes(), 11);
    drop(blocker);

    // The second child ends before its declared value can be read
    let truncated = [0x30, 0x04, 0x05, 0x00, 0x05, 0x01];
    let outcome = ArtifactValidator::default().validate_as_with_memory(
        ArtifactValidationFormat::Der,
        &truncated,
        &mut lease,
    )?;
    assert!(matches!(
        outcome,
        ArtifactValidationOutcome::Rejected { .. }
    ));
    assert_eq!(lease.bytes(), 11);
    drop(outcome);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
