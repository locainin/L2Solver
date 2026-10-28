use super::*;

const KIB: u64 = 1024;

#[test]
fn working_set_credit_protects_future_growth_without_counting_live_bytes_twice() -> TestResult {
    let root = MemoryBudget::new(64 * KIB);
    let base = root.try_reserve(MemoryClass::Base, 8 * KIB)?;
    let work = root.try_working_set(24 * KIB)?;
    let child = work.budget().clone();
    let admitted = root.snapshot()?;
    assert_eq!(admitted.working_sets.active_cases, 1);
    assert_eq!(admitted.working_sets.reserved_bytes, 24 * KIB);
    assert!(admitted.used_bytes > base.bytes());

    let bytes = child.try_reserve(MemoryClass::Case, 8 * KIB)?;
    let live = root.snapshot()?;
    assert_eq!(live.used_bytes, admitted.used_bytes + 8 * KIB);
    assert_eq!(live.working_sets.reserved_bytes, 16 * KIB);
    assert_eq!(
        live.used_bytes + live.working_sets.reserved_bytes,
        admitted.used_bytes + admitted.working_sets.reserved_bytes
    );

    drop(bytes);
    assert_eq!(root.snapshot()?.working_sets.reserved_bytes, 24 * KIB);
    drop(work);
    assert_eq!(root.snapshot()?.working_sets.reserved_bytes, 0);
    assert_eq!(root.snapshot()?.working_sets.active_cases, 0);
    drop(child);
    assert_eq!(root.snapshot()?.used_bytes, base.bytes());
    drop(base);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn root_allocations_cannot_spend_another_cases_reserved_working_set() -> TestResult {
    let root = MemoryBudget::new(64 * KIB);
    let work = root.try_working_set(24 * KIB)?;
    let admitted = root.snapshot()?;
    let free = admitted.limit_bytes - admitted.used_bytes - admitted.working_sets.reserved_bytes;
    let background = root.try_reserve(MemoryClass::Cache, free)?;
    assert!(root.try_reserve(MemoryClass::Publication, 1).is_err());

    // The admitted Case can still use the capacity reserved for its later operations
    let retained = work.budget().try_reserve(MemoryClass::Case, 24 * KIB)?;
    assert_eq!(root.snapshot()?.working_sets.reserved_bytes, 0);
    assert_eq!(root.snapshot()?.used_bytes, admitted.limit_bytes);
    drop(retained);
    assert_eq!(root.snapshot()?.working_sets.reserved_bytes, 24 * KIB);
    drop(background);
    drop(work);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn retired_working_set_releases_future_credit_while_queued_bytes_remain_charged() -> TestResult {
    let root = MemoryBudget::new(64 * KIB);
    let work = root.try_working_set(24 * KIB)?;
    let retained = work.budget().try_reserve(MemoryClass::Case, 8 * KIB)?;
    drop(work);
    let queued = root.snapshot()?;
    assert_eq!(queued.working_sets.active_cases, 0);
    assert_eq!(queued.working_sets.reserved_bytes, 0);
    assert_eq!(queued.used(MemoryClass::Case), 8 * KIB);
    assert!(queued.used_bytes >= retained.bytes());
    drop(retained);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn failed_working_set_admission_preserves_the_live_reservation() -> TestResult {
    let root = MemoryBudget::new(32 * KIB);
    let work = root.try_working_set(24 * KIB)?;
    let before = root.snapshot()?;
    assert!(root.try_working_set(16 * KIB).is_err());
    let after = root.snapshot()?;
    assert_eq!(after.used_bytes, before.used_bytes);
    assert_eq!(
        after.working_sets.reserved_bytes,
        before.working_sets.reserved_bytes
    );
    assert_eq!(after.working_sets.active_cases, 1);
    assert_eq!(
        after.working_sets.admission_denials,
        before.working_sets.admission_denials + 1
    );
    drop(work);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn failed_scoped_growth_keeps_the_original_lease_and_remaining_credit() -> TestResult {
    let root = MemoryBudget::new(64 * KIB);
    let work = root.try_working_set(24 * KIB)?;
    let mut retained = work.budget().try_reserve(MemoryClass::Case, 8 * KIB)?;
    let live = root.snapshot()?;
    let background = root.try_reserve(
        MemoryClass::Cache,
        live.limit_bytes - live.used_bytes - live.working_sets.reserved_bytes,
    )?;
    let before = root.snapshot()?;
    assert!(retained.try_resize(24 * KIB + 1).is_err());
    let after = root.snapshot()?;
    assert_eq!(retained.bytes(), 8 * KIB);
    assert_eq!(after.used_bytes, before.used_bytes);
    assert_eq!(
        after.working_sets.reserved_bytes,
        before.working_sets.reserved_bytes
    );
    retained.try_resize(24 * KIB)?;
    assert_eq!(root.snapshot()?.working_sets.reserved_bytes, 0);
    drop(background);
    drop(retained);
    drop(work);
    assert_eq!(root.snapshot()?.used_bytes, 0);
    Ok(())
}
