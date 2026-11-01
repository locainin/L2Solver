use std::{error::Error, mem::size_of};

use l2_workbench::{
    evidence::{ByteMapping, EvidenceError, SourceRange, clip_byte_mappings_with_memory},
    job::{MemoryBudget, MemoryClass, MemoryError},
};

type TestResult = Result<(), Box<dyn Error>>;

fn mappings() -> Vec<ByteMapping> {
    [(0, 100), (1, 101)]
        .into_iter()
        .map(|(offset, source_offset)| ByteMapping {
            offset,
            range: SourceRange {
                source: "source-hash".to_owned(),
                packet: Some(7),
                offset: source_offset,
                length: 1,
            },
        })
        .collect()
}

#[test]
fn clipped_mappings_keep_vector_and_source_charges_until_drop() -> TestResult {
    let input = mappings();
    let budget = MemoryBudget::new(64 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Publication, 17)?;
    let clipped = clip_byte_mappings_with_memory(&input, 0..2, &mut lease)?;
    let [first, second] = clipped.as_slice() else {
        return Err("expected both clipped mappings".into());
    };
    assert_eq!(
        (first.offset, first.range.offset, first.range.length),
        (0, 100, 1)
    );
    assert_eq!(
        (second.offset, second.range.offset, second.range.length),
        (1, 101, 1)
    );
    let retained = clipped.capacity() * size_of::<ByteMapping>()
        + clipped
            .iter()
            .map(|mapping| mapping.range.source.capacity())
            .sum::<usize>();
    assert_eq!(lease.bytes(), 17 + u64::try_from(retained)?);
    drop(clipped);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn clip_pressure_and_invalid_later_mapping_restore_the_existing_charge() -> TestResult {
    let mut input = mappings();
    let budget = MemoryBudget::new(64 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Publication, 17)?;
    let blocker = budget.try_reserve(MemoryClass::Cache, budget.snapshot()?.limit_bytes - 17)?;
    assert!(matches!(
        clip_byte_mappings_with_memory(&input, 0..2, &mut lease),
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(lease.bytes(), 17);
    drop(blocker);
    input
        .last_mut()
        .ok_or("fixture has no second mapping")?
        .offset = usize::MAX;
    assert!(matches!(
        clip_byte_mappings_with_memory(&input, 0..2, &mut lease),
        Err(EvidenceError::InvalidSourceRange)
    ));
    assert_eq!(lease.bytes(), 17);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
