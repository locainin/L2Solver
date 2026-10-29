use super::{
    RecoveryCaseKind, RecoveryContext, RecoveryOptions, case_and_scope, open_cache, recover,
};
use l2_workbench::{
    evidence::Case,
    job::{
        MemoryBudget, MemoryClass,
        cache::{Cache, CacheEntry, CacheReadPolicy},
    },
};
use serde_json::Value;
use std::error::Error;

fn recovery_with_omissions(
    cache: &Cache,
    options: &RecoveryOptions,
    count: usize,
    length: usize,
) -> Result<(Case, Value, super::super::CachedRecovery), Box<dyn Error>> {
    let (mut case, scope) = case_and_scope(b"4142", 93)?;
    let mut recovery = recover(
        &mut case,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            cache: Some(cache),
            job: None,
            memory: None,
            options,
        },
    )?;
    recovery.omissions = (0..count).map(|_| "o".repeat(length)).collect();
    recovery.coverage.omissions = u64::try_from(count)?;
    Ok((case, scope, recovery))
}

fn cached_case_with_omissions(
    cache: &Cache,
    options: &RecoveryOptions,
    count: usize,
    length: usize,
) -> Result<CacheEntry, Box<dyn Error>> {
    let (case, scope, recovery) = recovery_with_omissions(cache, options, count, length)?;
    let key = super::super::recovery_key(RecoveryCaseKind::Flow, &scope, options)?;
    super::super::store_result(cache.lease(&key)?, &case, &recovery, options, None)?;
    cache
        .lookup(&key, CacheReadPolicy::AllowPartial)?
        .ok_or_else(|| "cached recovery fixture was not published".into())
}

#[test]
fn oversized_metadata_copy_is_rejected_before_replacing_the_cached_result()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (case, scope, recovery) = recovery_with_omissions(&cache, &options, 800, 4096)?;
    let key = super::super::recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let previous = cache
        .lookup(&key, CacheReadPolicy::AllowPartial)?
        .ok_or("initial recovery was not cached")?
        .metadata()
        .clone();
    let budget = MemoryBudget::new(3 * 1024 * 1024);
    let error = super::super::store_result(
        cache.lease(&key)?,
        &case,
        &recovery,
        &options,
        Some(&budget),
    )
    .err()
    .ok_or("oversized cached metadata bypassed memory admission")?;
    assert!(crate::memory_error::find(error.as_ref()).is_some());
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    let current = cache
        .lookup(&key, CacheReadPolicy::AllowPartial)?
        .ok_or("the previous cached result was lost")?;
    assert_eq!(current.metadata(), &previous);
    Ok(())
}

#[test]
fn restored_omissions_remain_charged_after_the_case_is_dropped() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let entry = cached_case_with_omissions(&cache, &options, 128, 2048)?;
    let (_, scope) = case_and_scope(b"4142", 93)?;
    let source = scope
        .get("source_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing source")?;
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let (case, recovery) = super::super::cached_result(
        &entry,
        source,
        RecoveryCaseKind::Flow,
        &options,
        Some(&budget),
    )?;
    drop(case);
    assert_eq!(recovery.omissions.len(), 128);
    assert!(
        recovery
            .omissions
            .iter()
            .all(|text| text.len() == 2048 && text.bytes().all(|byte| byte == b'o')),
        "cached omission text must survive the metadata copy"
    );
    let allocated = recovery.omissions.capacity() * size_of::<String>()
        + recovery
            .omissions
            .iter()
            .map(String::capacity)
            .sum::<usize>();
    assert!(
        budget.snapshot()?.used(MemoryClass::Cache) >= u64::try_from(allocated)?,
        "returned omission strings must keep their allocation charge"
    );
    drop(recovery);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn cached_omissions_that_exceed_available_memory_are_rejected() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let entry = cached_case_with_omissions(&cache, &options, 800, 4096)?;
    let (_, scope) = case_and_scope(b"4142", 93)?;
    let source = scope
        .get("source_id")
        .and_then(serde_json::Value::as_str)
        .ok_or("missing source")?;
    let budget = MemoryBudget::new(3 * 1024 * 1024);
    let error = super::super::cached_result(
        &entry,
        source,
        RecoveryCaseKind::Flow,
        &options,
        Some(&budget),
    )
    .err()
    .ok_or("oversized omissions bypassed shared memory admission")?;
    assert!(crate::memory_error::find(error.as_ref()).is_some());
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn restoring_cached_recovery_holds_the_shared_memory_charge_until_case_drop()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut first, scope) = case_and_scope(b"4142", 91)?;
    recover(
        &mut first,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            cache: Some(&cache),
            job: None,
            memory: None,
            options: &options,
        },
    )?;
    let expected = first.to_json()?;
    let budget = MemoryBudget::new(4 * 1024 * 1024);
    let (mut restored, _) = case_and_scope(b"4142", 91)?;
    recover(
        &mut restored,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            cache: Some(&cache),
            job: None,
            memory: Some(&budget),
            options: &options,
        },
    )?;
    assert_eq!(restored.to_json()?, expected);
    assert!(
        budget.snapshot()?.used_bytes > 0,
        "restored Case bypassed the shared budget"
    );
    drop(restored);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn rejected_cache_restore_preserves_the_native_case_and_releases_memory()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions::default();
    let (mut first, scope) = case_and_scope(b"4142", 92)?;
    recover(
        &mut first,
        RecoveryCaseKind::Flow,
        &scope,
        &RecoveryContext {
            cache: Some(&cache),
            job: None,
            memory: None,
            options: &options,
        },
    )?;
    for strict_cache in [false, true] {
        let policy = RecoveryOptions {
            strict_cache,
            ..options.clone()
        };
        let budget = MemoryBudget::new(1);
        let (mut original, _) = case_and_scope(b"4142", 92)?;
        let expected = original.to_json()?;
        let error = recover(
            &mut original,
            RecoveryCaseKind::Flow,
            &scope,
            &RecoveryContext {
                cache: Some(&cache),
                job: None,
                memory: Some(&budget),
                options: &policy,
            },
        )
        .err()
        .ok_or("memory pressure was treated as an ordinary optional cache failure")?;
        assert!(crate::memory_error::find(error.as_ref()).is_some());
        assert_eq!(original.to_json()?, expected);
        assert_eq!(budget.snapshot()?.used_bytes, 0);
        assert!(budget.snapshot()?.rejected > 0);
    }
    Ok(())
}
