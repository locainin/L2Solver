use super::reserve_one;
use crate::job::{MemoryBudget, MemoryClass, MemoryError};
use std::error::Error;

#[test]
fn vector_growth_is_denied_before_replacing_its_existing_buffer() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(1024);
    let mut charge = Some(budget.try_reserve(MemoryClass::Executor, 0)?);
    let mut values = Vec::new();
    reserve_one::<u64>(&mut values, &mut charge)?;
    values.extend([1, 2, 3, 4]);
    let current = charge.as_ref().ok_or("vector lease missing")?.bytes();
    let blocker = budget.try_reserve(MemoryClass::Cache, 1024 - current)?;
    assert!(matches!(
        reserve_one(&mut values, &mut charge),
        Err(super::AnalyzerError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(values, [1, 2, 3, 4]);
    assert_eq!(
        charge.as_ref().ok_or("vector lease missing")?.bytes(),
        current
    );
    drop(values);
    drop(charge);
    drop(blocker);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn vector_growth_charges_both_buffers_until_the_old_one_is_dropped() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(1024);
    let mut charge = Some(budget.try_reserve(MemoryClass::Executor, 0)?);
    let mut values = Vec::new();
    reserve_one::<u64>(&mut values, &mut charge)?;
    values.extend([1, 2, 3, 4]);
    let old_bytes = u64::try_from(values.capacity() * std::mem::size_of::<u64>())?;
    reserve_one(&mut values, &mut charge)?;
    let new_bytes = u64::try_from(values.capacity() * std::mem::size_of::<u64>())?;
    assert_eq!(
        charge.as_ref().ok_or("vector lease missing")?.bytes(),
        new_bytes
    );
    assert!(budget.snapshot()?.peak_bytes >= old_bytes + new_bytes);
    assert_eq!(values, [1, 2, 3, 4]);
    drop(values);
    drop(charge);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
