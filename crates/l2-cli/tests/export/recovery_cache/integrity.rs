use super::{
    CacheReadPolicy, RecoveryCaseKind, RecoveryContext, RecoveryOptions, case_and_scope,
    open_cache, recover, recovery_key,
};
use std::error::Error;

#[test]
fn cached_coverage_cannot_claim_complete_collection_for_an_incomplete_case()
-> Result<(), Box<dyn Error>> {
    for kind in [RecoveryCaseKind::Flow, RecoveryCaseKind::Cohort] {
        let directory = tempfile::tempdir()?;
        let cache = open_cache(directory.path())?;
        let options = RecoveryOptions::default();
        let (mut case, mut scope) = case_and_scope(b"4142", 17)?;
        *scope
            .get_mut("kind")
            .ok_or("fixture scope kind is missing")? =
            serde_json::json!(super::super::kind_name(kind));
        let result = recover(
            &mut case,
            kind,
            &scope,
            &RecoveryContext {
                cache: None,
                job: None,
                options: &options,
            },
        )?;
        assert!(result.coverage.is_complete());

        // The bytes and source remain valid, but the saved coverage no longer describes the Case
        case.mark_incomplete("fixture collection stopped after the coverage was recorded")?;
        let key = recovery_key(kind, &scope, &options)?;
        super::super::store_result(cache.lease(&key)?, &case, &result, &options)?;
        let entry = cache
            .lookup(&key, CacheReadPolicy::AllowPartial)?
            .ok_or("the inconsistent cache fixture was not committed")?;

        assert!(
            super::super::cached_result(&entry, &super::super::source_id(&scope)?, kind, &options,)
                .is_err(),
            "cached {} coverage must agree with the retained collection flag",
            super::super::kind_name(kind)
        );
    }
    Ok(())
}
