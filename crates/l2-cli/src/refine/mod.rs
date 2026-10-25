//! Refine standalone byte files and manifest-listed artifact directories

mod analysis;
mod input;
mod output;
mod policy;

#[cfg(test)]
use analysis::analyze_source_cached;
use input::LoadedSource;
#[cfg(test)]
use input::{prepare_input_set, read_sources};
pub use output::refine_source_identity_sha256;
#[cfg(test)]
use output::{default_output_path, result_identity};
#[cfg(test)]
use policy::analyzer_options;

use crate::{
    arguments::RefineOptions,
    result_directory::{ResultDirectory, ResultKind},
    workbench::artifact_export,
};
use l2_workbench::job::{Counter, Job, Phase, PhaseOutcome, cache::Cache};
use policy::RefinePolicy;
use std::{
    error::Error,
    io::{self, Write},
    path::Path,
};

/// Analyze one file or manifest-listed artifact directory and publish a new result directory
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "direct callers use the entry point without a shared job"
    )
)]
pub fn run(options: &RefineOptions, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let job = Job::new("refine files");
    run_with_job(options, output, &job)
}

/// Run refinement while updating the shared job state and honoring cancellation
pub fn run_with_job(
    options: &RefineOptions,
    output: &mut impl Write,
    job: &Job,
) -> Result<bool, Box<dyn Error>> {
    job.check_cancelled()?;
    let destination = options
        .output
        .clone()
        .unwrap_or_else(|| output::default_output_path(&options.input));
    let result_directory = ResultDirectory::inspect(&destination, ResultKind::Refine)?;
    let input_set = input::prepare_input_set(&options.input)?;
    let policy = RefinePolicy::new(&options.recovery, options.salvage)?;

    // The verified snapshots establish the same source identity used by analysis and reuse
    let sources = input::read_sources(
        &input_set,
        policy.total_input_limit,
        policy.per_file_limit,
        job,
    )?;
    let identity = output::result_identity(&sources, &options.recovery, &policy)?;

    if !options.recovery.refresh
        && let Some(reused) = result_directory.reuse(&identity, None, false)?
    {
        skip_file_irrelevant_phases(job)?;
        record_source_counters(job, &sources)?;
        start_input_phases(job, &sources)?;
        skip_refinement_work_phases(job)?;
        job.increment(Counter::CacheHits, 1)?;
        output::write_reused_summary(
            output,
            &destination,
            reused.complete,
            reused.artifacts.len(),
            options.dry_run,
        )?;
        return Ok(reused.complete);
    }

    let mut cache_warnings = Vec::new();
    let cache = open_cache(options, &mut cache_warnings)?;
    // A restored checkpoint must precede every phase transition in this run
    let checkpoint = cache
        .as_ref()
        .map(|cache| {
            crate::recovery_job::CheckpointWriter::start(
                cache,
                &identity,
                job,
                options.recovery.refresh,
            )
        })
        .transpose()?;

    skip_file_irrelevant_phases(job)?;
    record_source_counters(job, &sources)?;
    start_input_phases(job, &sources)?;
    job.start(Phase::Expansion, None)?;
    job.start(
        Phase::TransformDiscovery,
        Some(u64::try_from(sources.len())?),
    )?;

    let result = analyze_and_publish(AnalysisPublishContext {
        options,
        output,
        job,
        destination: &destination,
        result_directory,
        identity: &identity,
        policy: &policy,
        sources: &sources,
        cache: cache.as_ref(),
        cache_warnings: &mut cache_warnings,
    });
    if let Some(checkpoint) = checkpoint {
        checkpoint.finish(result.is_ok() && !job.is_cancelled())?;
    }
    result
}

fn open_cache(
    options: &RefineOptions,
    warnings: &mut Vec<String>,
) -> Result<Option<Cache>, Box<dyn Error>> {
    if options.dry_run || options.recovery.no_cache {
        return Ok(None);
    }
    match Cache::from_environment(options.recovery.cache_max_bytes) {
        Ok(cache) => Ok(Some(cache)),
        Err(error) if options.recovery.strict_cache => Err(error.into()),
        Err(error) => {
            analysis::record_cache_warning(
                warnings,
                format!("persistent cache unavailable: {error}"),
            );
            Ok(None)
        }
    }
}

struct AnalysisPublishContext<'a, W: Write> {
    options: &'a RefineOptions,
    output: &'a mut W,
    job: &'a Job,
    destination: &'a Path,
    result_directory: ResultDirectory,
    identity: &'a crate::result_directory::ResultIdentity,
    policy: &'a RefinePolicy,
    sources: &'a [LoadedSource],
    cache: Option<&'a Cache>,
    cache_warnings: &'a mut Vec<String>,
}

fn analyze_and_publish<W: Write>(
    context: AnalysisPublishContext<'_, W>,
) -> Result<bool, Box<dyn Error>> {
    let AnalysisPublishContext {
        options,
        output,
        job,
        destination,
        result_directory,
        identity,
        policy,
        sources,
        cache,
        cache_warnings,
    } = context;
    job.check_cancelled()?;
    let analyzed = analysis::analyze_sources(
        sources,
        policy,
        &options.recovery,
        cache,
        cache_warnings,
        job,
    )?;
    job.finish(Phase::TransformDiscovery, PhaseOutcome::Completed)?;
    job.finish(Phase::Expansion, PhaseOutcome::Completed)?;

    let selected = artifact_export::select_artifacts(&analyzed.case)?;
    job.start(Phase::Reports, Some(1))?;
    let manifest = output::make_manifest(
        &selected,
        &analyzed.source_records,
        &analyzed.artifact_records,
        analyzed.complete,
    )?;
    let summary = output::format_summary(
        destination,
        &selected,
        &analyzed.source_records,
        analyzed.complete,
    );
    job.advance(Phase::Reports, 1)?;
    job.finish(Phase::Reports, PhaseOutcome::Completed)?;

    if options.dry_run {
        job.finish(Phase::Publication, PhaseOutcome::Skipped)?;
        output::write_summary(
            output,
            destination,
            &selected,
            &analyzed.source_records,
            analyzed.complete,
            true,
        )?;
        output::write_cache_warnings(output, cache_warnings)?;
        return Ok(analyzed.complete);
    }

    job.check_cancelled()?;
    result_directory.publish(identity, job, |staging| {
        artifact_export::write_artifacts_into(staging, &selected)?;
        output::write_manifest(staging, &manifest)?;
        output::write_summary_file(staging, &summary)?;
        Ok(())
    })?;
    output::write_summary(
        output,
        destination,
        &selected,
        &analyzed.source_records,
        analyzed.complete,
        false,
    )?;
    output::write_cache_warnings(output, cache_warnings)?;
    Ok(analyzed.complete)
}

fn record_source_counters(job: &Job, sources: &[LoadedSource]) -> Result<(), Box<dyn Error>> {
    for source in sources {
        job.increment(Counter::Files, 1)?;
        job.increment(Counter::Bytes, u64::try_from(source.bytes.len())?)?;
    }
    Ok(())
}

fn start_input_phases(job: &Job, sources: &[LoadedSource]) -> Result<(), Box<dyn Error>> {
    complete_phase(job, Phase::Preparation, Some(1))?;
    job.start(Phase::Ingestion, Some(u64::try_from(sources.len())?))?;
    for _ in sources {
        job.advance(Phase::Ingestion, 1)?;
    }
    job.finish(Phase::Ingestion, PhaseOutcome::Completed)?;
    Ok(())
}

fn complete_phase(job: &Job, phase: Phase, total: Option<u64>) -> Result<(), Box<dyn Error>> {
    job.start(phase, total)?;
    job.finish(phase, PhaseOutcome::Completed)?;
    Ok(())
}

fn skip_refinement_work_phases(job: &Job) -> Result<(), Box<dyn Error>> {
    for phase in [
        Phase::Expansion,
        Phase::TransformDiscovery,
        Phase::Reports,
        Phase::Publication,
    ] {
        job.finish(phase, PhaseOutcome::Skipped)?;
    }
    Ok(())
}

fn skip_file_irrelevant_phases(job: &Job) -> Result<(), Box<dyn Error>> {
    for phase in [
        Phase::Reconstruction,
        Phase::NativeExtraction,
        Phase::FramingRecordDiscovery,
        Phase::AssemblyValidation,
    ] {
        job.finish(phase, PhaseOutcome::Skipped)?;
    }
    Ok(())
}

fn invalid_input(message: &'static str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message).into()
}

#[cfg(test)]
#[path = "../../tests/refine/mod.rs"]
mod tests;
