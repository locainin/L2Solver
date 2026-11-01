use super::{MemoryBudget, MemoryClass};
use std::error::Error;

#[test]
fn splitting_live_memory_preserves_scoped_credit_until_each_owner_drops()
-> Result<(), Box<dyn Error>> {
    let root = MemoryBudget::new(64 * 1024);
    let scope = root.try_working_set(24 * 1024)?;
    let mut parent = scope
        .budget()
        .try_reserve(MemoryClass::Executor, 12 * 1024)?;
    let before = root.snapshot()?;
    let child = parent.split_off(5 * 1024).ok_or("split failed")?;
    let after = root.snapshot()?;
    assert_eq!(parent.bytes(), 7 * 1024);
    assert_eq!(child.bytes(), 5 * 1024);
    assert_eq!(after.used_bytes, before.used_bytes);
    assert_eq!(
        after.working_sets.reserved_bytes,
        before.working_sets.reserved_bytes
    );
    assert!(parent.split_off(7 * 1024 + 1).is_none());
    assert_eq!(parent.bytes(), 7 * 1024);
    assert_eq!(root.snapshot()?.used_bytes, before.used_bytes);
    drop(parent);
    let partial = root.snapshot()?;
    assert_eq!(partial.used_bytes, before.used_bytes - 7 * 1024);
    assert_eq!(
        partial.working_sets.reserved_bytes,
        before.working_sets.reserved_bytes + 7 * 1024
    );
    drop(child);
    let released = root.snapshot()?;
    assert_eq!(released.used_bytes, before.used_bytes - 12 * 1024);
    assert_eq!(released.working_sets.reserved_bytes, 24 * 1024);
    drop(scope);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn dropping_split_child_first_releases_only_its_own_charge() -> Result<(), Box<dyn Error>> {
    let budget = MemoryBudget::new(100);
    let mut parent = budget.try_reserve(MemoryClass::Executor, 80)?;
    let child = parent.split_off(30).ok_or("split failed")?;
    drop(child);
    assert_eq!(parent.bytes(), 50);
    assert_eq!(budget.snapshot()?.used_bytes, 50);
    drop(parent);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn combining_charges_preserves_working_set_credit_and_rejects_other_owners()
-> Result<(), Box<dyn Error>> {
    let root = MemoryBudget::new(64 * 1024);
    let scope = root.try_working_set(512)?;
    let mut target = scope.budget().try_reserve(MemoryClass::Executor, 80)?;
    let other = scope.budget().try_reserve(MemoryClass::Executor, 120)?;
    let before = root.snapshot()?;
    target
        .try_absorb(other)
        .map_err(|_| "matching charges failed to combine")?;
    assert_eq!(target.bytes(), 200);
    let after = root.snapshot()?;
    assert_eq!(after.used_bytes, before.used_bytes);
    assert_eq!(
        after.working_sets.reserved_bytes,
        before.working_sets.reserved_bytes
    );
    let foreign = root.try_reserve(MemoryClass::Executor, 20)?;
    let foreign = target
        .try_absorb(foreign)
        .err()
        .ok_or("foreign charge was combined")?;
    assert_eq!(target.bytes(), 200);
    assert_eq!(foreign.bytes(), 20);
    assert_eq!(
        root.snapshot()?.working_sets.reserved_bytes,
        before.working_sets.reserved_bytes
    );
    drop(foreign);
    drop(target);
    drop(scope);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}
