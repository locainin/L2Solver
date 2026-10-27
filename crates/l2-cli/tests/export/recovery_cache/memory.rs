use super::{
    RecoveryCaseKind, RecoveryContext, RecoveryOptions, case_and_scope, open_cache, recover,
};
use l2_workbench::job::MemoryBudget;
use std::error::Error;

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
        assert!(super::super::memory_pressure(error.as_ref()));
        assert_eq!(original.to_json()?, expected);
        assert_eq!(budget.snapshot()?.used_bytes, 0);
        assert!(budget.snapshot()?.rejected > 0);
    }
    Ok(())
}
