use super::*;
use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits, EvidenceError},
    job::cache::CacheError,
};
use std::io::{self, Cursor, Write};

#[test]
fn held_write_lease_recomputes_without_cache_and_strict_mode_fails() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = open_cache(temporary.path())?;
    let options = RecoveryOptions {
        refresh: true,
        ..RecoveryOptions::default()
    };
    let (_, scope) = case_and_scope(b"4142", 53)?;
    let key = recovery_key(RecoveryCaseKind::Flow, &scope, &options)?;
    let held_lease = cache.lease(&key)?;

    let (mut uncached_case, uncached_scope) = case_and_scope(b"4142", 53)?;
    let uncached = recover(
        &mut uncached_case,
        RecoveryCaseKind::Flow,
        &uncached_scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: None,
            options: &options,
        },
    )?;

    let job = Job::new("held recovery cache lease");
    let (mut recovered_case, recovered_scope) = case_and_scope(b"4142", 53)?;
    let recovered = recover(
        &mut recovered_case,
        RecoveryCaseKind::Flow,
        &recovered_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    assert_eq!(recovered_case.to_json()?, uncached_case.to_json()?);
    assert_eq!(
        serde_json::to_value(recovered.coverage)?,
        serde_json::to_value(uncached.coverage)?
    );
    assert_eq!(recovered.omissions, uncached.omissions);
    assert_cache_fallback(&job.snapshot()?, CacheFallbackKind::LeaseUnavailable, 1)?;

    let strict = RecoveryOptions {
        strict_cache: true,
        ..options
    };
    let strict_job = Job::new("strict held recovery cache lease");
    let (mut strict_case, strict_scope) = case_and_scope(b"4142", 53)?;
    let error = recover(
        &mut strict_case,
        RecoveryCaseKind::Flow,
        &strict_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&strict_job),
            options: &strict,
        },
    )
    .err()
    .ok_or("strict cache mode accepted an unavailable write lease")?;
    assert!(
        error
            .to_string()
            .contains("cache entry is currently in use")
    );
    assert_eq!(strict_job.snapshot()?.cache_fallbacks.records().len(), 0);

    drop(held_lease);
    Ok(())
}

#[test]
fn cache_quota_commit_failure_preserves_recovery_and_is_fatal_in_strict_mode()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = Cache::open_at(
        temporary.path().join("quota-cache"),
        temporary.path().join("quota-state"),
        1,
    )?;
    let options = RecoveryOptions {
        refresh: true,
        ..RecoveryOptions::default()
    };

    let (mut uncached_case, uncached_scope) = case_and_scope(b"4142", 59)?;
    let uncached = recover(
        &mut uncached_case,
        RecoveryCaseKind::Flow,
        &uncached_scope,
        &RecoveryContext {
            memory: None,
            cache: None,
            job: None,
            options: &options,
        },
    )?;

    let job = Job::new("recovery cache quota fallback");
    let (mut recovered_case, recovered_scope) = case_and_scope(b"4142", 59)?;
    let recovered = recover(
        &mut recovered_case,
        RecoveryCaseKind::Flow,
        &recovered_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&job),
            options: &options,
        },
    )?;
    assert_eq!(recovered_case.to_json()?, uncached_case.to_json()?);
    assert_eq!(
        serde_json::to_value(recovered.coverage)?,
        serde_json::to_value(uncached.coverage)?
    );
    assert_eq!(recovered.omissions, uncached.omissions);
    assert_cache_fallback(&job.snapshot()?, CacheFallbackKind::CommitQuotaExceeded, 1)?;
    assert_eq!(cache.stats()?.entries, 0);

    let strict = RecoveryOptions {
        strict_cache: true,
        ..options
    };
    let strict_job = Job::new("strict recovery cache quota");
    let (mut strict_case, strict_scope) = case_and_scope(b"4142", 59)?;
    let error = recover(
        &mut strict_case,
        RecoveryCaseKind::Flow,
        &strict_scope,
        &RecoveryContext {
            memory: None,
            cache: Some(&cache),
            job: Some(&strict_job),
            options: &strict,
        },
    )
    .err()
    .ok_or("strict cache mode accepted a quota-rejected commit")?;
    assert!(error.to_string().contains("cache stage needs at least"));
    assert_eq!(strict_job.snapshot()?.cache_fallbacks.records().len(), 0);
    assert_eq!(cache.stats()?.entries, 0);
    Ok(())
}

#[test]
fn snapshot_limit_uses_the_case_size_fallback() -> Result<(), Box<dyn Error>> {
    let (case, _) = case_and_scope(b"4142", 3)?;
    let error = case
        .write_snapshot(
            &mut Vec::new(),
            &mut Vec::new(),
            CaseSnapshotLimits::new(0, 0),
        )
        .err()
        .ok_or("zero storage allowance should reject the snapshot")?;
    assert!(matches!(error, EvidenceError::CaseTooLarge { .. }));
    let size_kind = super::super::cache_commit_fallback_kind(&error);
    assert_eq!(size_kind, CacheFallbackKind::CommitCaseTooLarge);
    Ok(())
}

#[test]
fn case_snapshot_retries_interrupted_graph_and_pack_writes() -> Result<(), Box<dyn Error>> {
    struct InterruptedOnceWriter {
        interrupted: bool,
        written: Vec<u8>,
    }

    impl Write for InterruptedOnceWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let (case, _) = case_and_scope(b"4142", 3)?;
    let limits = CaseSnapshotLimits::new(1024 * 1024, 1024 * 1024);
    let mut graph_writer = InterruptedOnceWriter {
        interrupted: false,
        written: Vec::new(),
    };
    let mut pack_writer = InterruptedOnceWriter {
        interrupted: false,
        written: Vec::new(),
    };
    let usage = case.write_snapshot(&mut graph_writer, &mut pack_writer, limits)?;

    assert!(graph_writer.interrupted);
    assert!(pack_writer.interrupted);
    assert_eq!(
        usage.graph_bytes,
        u64::try_from(graph_writer.written.len())?
    );
    assert_eq!(
        usage.blob_pack_bytes,
        u64::try_from(pack_writer.written.len())?
    );
    let (parsed, _usage) = Case::from_snapshot(
        Cursor::new(graph_writer.written),
        Cursor::new(pack_writer.written),
        limits,
    )?;
    assert_eq!(parsed, case);
    Ok(())
}

#[test]
fn case_snapshot_io_failure_uses_the_storage_fallback() -> Result<(), Box<dyn Error>> {
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("private/capture-controlled/path"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let (case, _) = case_and_scope(b"4142", 3)?;
    let error = case
        .write_snapshot(
            &mut FailingWriter,
            &mut Vec::new(),
            CaseSnapshotLimits::new(1024, 1024),
        )
        .err()
        .ok_or("graph writer failure should reject the snapshot")?;
    assert!(matches!(error, EvidenceError::WriteFailed));
    let io_kind = super::super::cache_commit_fallback_kind(&error);
    assert_eq!(io_kind, CacheFallbackKind::CommitStorageIo);
    Ok(())
}

#[test]
fn cache_commit_errors_map_to_safe_typed_fallbacks() {
    let quota = CacheError::QuotaExceeded {
        limit_bytes: 10,
        required_bytes: 11,
    };
    assert_eq!(
        super::super::cache_commit_fallback_kind(&quota),
        CacheFallbackKind::CommitQuotaExceeded
    );
    let metadata = CacheError::MetadataTooLarge {
        limit_bytes: 10,
        actual_bytes: 11,
    };
    assert_eq!(
        super::super::cache_commit_fallback_kind(&metadata),
        CacheFallbackKind::CommitMetadataTooLarge
    );
    let storage = CacheError::Io(io::Error::other("private/capture-controlled/path"));
    assert_eq!(
        super::super::cache_commit_fallback_kind(&storage),
        CacheFallbackKind::CommitStorageIo
    );
    let unknown = CacheError::InvalidInput("unknown commit failure");
    assert_eq!(
        super::super::cache_commit_fallback_kind(&unknown),
        CacheFallbackKind::CommitFailed
    );
}

#[test]
fn cache_commit_sample_details_do_not_include_error_text() -> Result<(), Box<dyn Error>> {
    let job = Job::new("safe cache diagnostics");
    let error = CacheError::Io(io::Error::other("private/capture-controlled/path"));
    let kind = super::super::cache_commit_fallback_kind(&error);
    job.record_cache_fallback(
        CacheStage::CaseRecovery,
        kind,
        format_args!("{}", super::super::cache_commit_fallback_detail(kind)),
    )?;
    let snapshot = job.snapshot()?;
    let fallback = snapshot
        .cache_fallbacks
        .records()
        .first()
        .ok_or_else(|| io::Error::other("typed storage fallback should be recorded"))?;
    assert_eq!(fallback.kind(), kind);
    assert_eq!(
        fallback.sample_detail(),
        Some("recovery cache storage I/O failed")
    );
    assert!(
        !fallback
            .sample_detail()
            .unwrap_or_default()
            .contains("private/capture-controlled/path")
    );
    Ok(())
}

fn assert_cache_fallback(
    snapshot: &l2_workbench::job::JobSnapshot,
    kind: CacheFallbackKind,
    count: u64,
) -> Result<(), Box<dyn Error>> {
    let fallback = snapshot
        .cache_fallbacks
        .records()
        .iter()
        .find(|record| record.stage() == CacheStage::CaseRecovery && record.kind() == kind)
        .ok_or("expected cache fallback was not recorded")?;
    assert_eq!(fallback.count(), count);
    Ok(())
}
