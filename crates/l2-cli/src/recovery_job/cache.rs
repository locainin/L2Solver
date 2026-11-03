//! Apply the same optional cache and checkpoint policy to recovery commands

use super::{
    checkpoint::{CheckpointError, CheckpointWriter},
    retain_cleanup_error,
};
use crate::{arguments::RecoveryOptions, result_directory::ResultIdentity};
use l2_workbench::job::{
    CacheFallbackKind, CacheStage, Job, MemoryBudget,
    cache::{Cache, CacheError},
};
use std::error::Error;

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
        memory: Option<&MemoryBudget>,
    ) -> Result<Self, Box<dyn Error>> {
        job.check_cancelled()?;
        if options.no_cache {
            return Ok(Self::disabled());
        }
        // Startup maintenance and checkpoints share the same allowance as recovery
        let opened = memory.map_or_else(
            || Cache::from_environment(options.cache_max_bytes),
            |budget| {
                Cache::from_environment_with_memory_budget(options.cache_max_bytes, budget.clone())
            },
        );
        match opened {
            Ok(cache) => Self::from_cache(cache, identity, options, job),
            Err(error) if options.strict_cache || matches!(error, CacheError::Memory(_)) => {
                Err(error.into())
            }
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
        // Preparation may stay visible while saved progress is restored
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
        // The operation result is fixed before checkpoint cleanup starts
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
                    Err(fallback_error) => {
                        retain_cleanup_error(result, Err(fallback_error.into()), "checkpoint")
                    }
                }
            }
            Err(error) => retain_cleanup_error(result, Err(checkpoint_error(error)), "checkpoint"),
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

#[cfg(test)]
#[path = "../../tests/recovery_job/cache.rs"]
mod tests;
