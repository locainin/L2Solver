use super::checkpoint;
use crate::arguments::RecoveryOptions;
use crate::workbench::recovery_executor::{RecoveryExecutionError, resume::RecoveryResume};
use l2_workbench::{job::MemoryBudget, protocol::RelationalReplayHistory};
use serde::{Serialize, Serializer};

#[test]
fn checkpoint_encoding_distinguishes_byte_limits_from_memory_and_serializer_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let value = serde_json::json!({"payload": [1, 2, 3]});
    let size = checkpoint::encode(&value, 1, None)
        .err()
        .ok_or("size limit was ignored")?;
    assert_eq!(
        checkpoint::unavailable_reason(&size),
        Some(checkpoint::CheckpointUnavailable::SizeLimit)
    );
    let wrapped = RecoveryExecutionError::Operational {
        stage: l2_workbench::recovery::RecoveryStage::TransformDiscovery,
        source: Box::new(std::io::Error::other(
            checkpoint::CheckpointUnavailable::SizeLimit,
        )),
    };
    assert_eq!(
        checkpoint::unavailable_reason(&wrapped),
        Some(checkpoint::CheckpointUnavailable::SizeLimit)
    );

    let history = RelationalReplayHistory::new(1024);
    let history_limit = checkpoint::encode(&history, 1, None)
        .err()
        .ok_or("history size limit was ignored")?;
    assert_eq!(
        checkpoint::unavailable_reason(&history_limit),
        Some(checkpoint::CheckpointUnavailable::SizeLimit)
    );

    let memory = MemoryBudget::new(0);
    let denied = checkpoint::encode(&value, 1024, Some(&memory))
        .err()
        .ok_or("memory denial was ignored")?;
    assert_eq!(checkpoint::unavailable_reason(&denied), None);

    let invalid = checkpoint::encode(&FailsToSerialize, 1024, None)
        .err()
        .ok_or("serializer failure was ignored")?;
    assert_eq!(checkpoint::unavailable_reason(&invalid), None);
    Ok(())
}

struct FailsToSerialize;

impl Serialize for FailsToSerialize {
    fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            "intentional serialization failure",
        ))
    }
}

#[test]
fn optional_cache_propagates_wrapped_resource_failures() -> Result<(), Box<dyn std::error::Error>> {
    use l2_workbench::{
        derivation::DerivationError,
        job::{
            JobError, MemoryClass,
            cache::{Cache, SourceIdentity, StageKey},
        },
        protocol::{RecordError, RelationalCursorError, RelationalTransformError},
        recovery::{RecoveryError, RecoveryStage},
    };

    let directory = tempfile::tempdir()?;
    let cache = Cache::open_at(
        directory.path().join("cache"),
        directory.path().join("state"),
        1024 * 1024,
    )?;
    let key = StageKey::new(
        "allocation_failure",
        1,
        "allocation_failure",
        &serde_json::json!({}),
        &SourceIdentity::from_sha256("a".repeat(64))?,
        &[],
    )?;
    let mut lease = cache.lease(&key)?;
    let options = RecoveryOptions {
        strict_cache: false,
        ..RecoveryOptions::default()
    };
    let reserve_error = Vec::<u8>::new()
        .try_reserve(usize::MAX)
        .err()
        .ok_or("capacity unexpectedly fit the platform maximum")?;
    let memory_error = MemoryBudget::new(0)
        .try_reserve(MemoryClass::Executor, 1)
        .err()
        .ok_or("memory budget unexpectedly admitted the reservation")?;
    let sources: Vec<Box<dyn std::error::Error>> = vec![
        Box::new(reserve_error),
        Box::new(RecoveryError::AllocationFailed),
        Box::new(RelationalCursorError::<RecoveryExecutionError>::AllocationFailed),
        Box::new(RelationalTransformError::AllocationFailed),
        Box::new(RecordError::AllocationFailed),
        Box::new(DerivationError::AllocationFailed),
        Box::new(memory_error),
        Box::new(JobError::Cancelled),
        Box::new(std::io::Error::other(RecoveryError::AllocationFailed)),
    ];
    for source in sources {
        let mut resume = RecoveryResume::new(&mut lease, &options, None);
        let error = RecoveryExecutionError::Operational {
            stage: RecoveryStage::TransformDiscovery,
            source,
        };
        assert!(
            resume.invalid(error, None).is_err(),
            "resource failure must not restart recovery"
        );
    }
    let mut resume = RecoveryResume::new(&mut lease, &options, None);
    assert!(
        resume
            .invalid(RecoveryError::InvalidCheckpoint.into(), None)
            .is_ok(),
        "a corrupt checkpoint must still permit optional-cache fallback"
    );
    Ok(())
}
