//! Apply the same optional cache and checkpoint policy to recovery commands

use super::checkpoint::{CheckpointError, CheckpointWriter};
use crate::{arguments::RecoveryOptions, result_directory::ResultIdentity};
use l2_workbench::job::{CacheFallbackKind, CacheStage, Job, cache::Cache};
use std::{error::Error, fmt};

pub struct RecoveryCache {
    active: Option<ActiveCache>,
}

struct ActiveCache {
    cache: Cache,
    checkpoint: CheckpointWriter,
    strict: bool,
}

impl RecoveryCache {
    pub(crate) const fn disabled() -> Self {
        Self { active: None }
    }

    pub(crate) fn open(
        identity: &ResultIdentity,
        options: &RecoveryOptions,
        stage: CacheStage,
        job: &Job,
    ) -> Result<Self, Box<dyn Error>> {
        job.check_cancelled()?;
        if options.no_cache {
            return Ok(Self::disabled());
        }
        match Cache::from_environment(options.cache_max_bytes) {
            Ok(cache) => Self::from_cache(cache, identity, options, job),
            Err(error) if options.strict_cache => Err(error.into()),
            Err(_) => {
                job.check_cancelled()?;
                job.record_cache_fallback(
                    stage,
                    CacheFallbackKind::CacheUnavailable,
                    format_args!("persistent cache could not be opened"),
                )?;
                Ok(Self::disabled())
            }
        }
    }

    fn from_cache(
        cache: Cache,
        identity: &ResultIdentity,
        options: &RecoveryOptions,
        job: &Job,
    ) -> Result<Self, Box<dyn Error>> {
        // Restored progress must be applied before live phases start
        match CheckpointWriter::start(&cache, identity, job, options.refresh) {
            Ok(checkpoint) => Ok(Self {
                active: Some(ActiveCache {
                    cache,
                    checkpoint,
                    strict: options.strict_cache,
                }),
            }),
            Err(error) if !options.strict_cache && error.is_cache_failure() => {
                job.check_cancelled()?;
                record_checkpoint_fallback(job, "checkpoint could not be started")?;
                // The same unavailable storage also backs cache entries
                Ok(Self::disabled())
            }
            Err(CheckpointError::Job(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn cache(&self) -> Option<&Cache> {
        self.active.as_ref().map(|active| &active.cache)
    }

    pub(crate) fn finish<T>(
        self,
        result: Result<T, Box<dyn Error>>,
        job: &Job,
    ) -> Result<T, Box<dyn Error>> {
        // A late cancellation must not become a successful cache fallback
        let result = result.and_then(|value| {
            job.check_cancelled()?;
            Ok(value)
        });
        let Some(active) = self.active else {
            return result;
        };
        // Join the worker and save final progress before reporting the operation
        let checkpoint_result = active.checkpoint.finish(result.is_ok());
        match checkpoint_result {
            Ok(()) => result,
            Err(error) if !active.strict && error.is_cache_failure() => {
                match record_checkpoint_fallback(job, "checkpoint could not be finished") {
                    Ok(()) => result,
                    Err(fallback_error) => combine_errors(result, fallback_error.into()),
                }
            }
            Err(error) => combine_errors(result, checkpoint_error(error)),
        }
    }
}

fn record_checkpoint_fallback(
    job: &Job,
    detail: &'static str,
) -> Result<(), l2_workbench::job::JobError> {
    job.record_cache_fallback(
        CacheStage::Checkpoint,
        CacheFallbackKind::CacheUnavailable,
        format_args!("{detail}"),
    )
}

fn checkpoint_error(error: CheckpointError) -> Box<dyn Error> {
    match error {
        CheckpointError::Job(error) => error.into(),
        error => error.into(),
    }
}

fn combine_errors<T>(
    result: Result<T, Box<dyn Error>>,
    secondary: Box<dyn Error>,
) -> Result<T, Box<dyn Error>> {
    match result {
        Ok(_) => Err(secondary),
        // Preserve the original error as the source when cleanup also fails
        Err(primary) => Err(Box::new(OperationAndCheckpointError { primary, secondary })),
    }
}

#[derive(Debug)]
struct OperationAndCheckpointError {
    primary: Box<dyn Error>,
    secondary: Box<dyn Error>,
}

impl fmt::Display for OperationAndCheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; checkpoint failure: {}",
            self.primary, self.secondary
        )
    }
}

impl Error for OperationAndCheckpointError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.primary.as_ref())
    }
}

#[cfg(test)]
#[path = "../../tests/recovery_job/cache.rs"]
mod tests;
