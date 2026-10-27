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
use l2_workbench::job::{CacheStage, Counter, Job, Phase, PhaseOutcome, cache::Cache};
use policy::RefinePolicy;
use std::{
    error::Error,
    io::{self, Write},
    path::Path,
};

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

    // A bounded sample locates a likely result without loading complete source files
    let sampled = input::fingerprint_sources(
        &input_set,
        policy.total_input_limit,
        policy.per_file_limit,
        job,
    )?;
    let reuse_identity =
        output::result_identity_with_source(sampled.identity.clone(), &options.recovery, &policy)?;

    if let Some(complete) = try_reuse(ReuseContext {
        options,
        output,
        job,
        destination: &destination,
        result_directory: &result_directory,
        input_set: &input_set,
        sampled: &sampled,
        policy: &policy,
        identity: &reuse_identity,
    })? {
        return Ok(complete);
    }

    // Cold analysis keeps immutable bytes and a strong source identity for checkpoints
    let sources = input::read_sources(
        &input_set,
        policy.total_input_limit,
        policy.per_file_limit,
        job,
    )?;
    ensure_input_unchanged(&input_set, &sampled, &policy, job)?;
    let identity = output::result_identity(&sources, &options.recovery, &policy)?;

    let cache = if options.dry_run {
        crate::recovery_job::RecoveryCache::disabled()
    } else {
        crate::recovery_job::RecoveryCache::open(
            &identity,
            &options.recovery,
            CacheStage::ArtifactAnalysis,
            job,
        )?
    };
    let result = (|| {
        skip_file_irrelevant_phases(job)?;
        record_source_counters(job, &sampled)?;
        start_input_phases(job, sampled.labels.len())?;
        job.start(Phase::Expansion, None)?;
        job.start(
            Phase::TransformDiscovery,
            Some(u64::try_from(sources.len())?),
        )?;

        analyze_and_publish(AnalysisPublishContext {
            options,
            output,
            job,
            destination: &destination,
            result_directory,
            identity: &reuse_identity,
            policy: &policy,
            sources: &sources,
            input_set: &input_set,
            sampled: &sampled,
            cache: cache.cache(),
        })
    })();
    cache.finish(result, job)
}

struct ReuseContext<'a, W: Write> {
    options: &'a RefineOptions,
    output: &'a mut W,
    job: &'a Job,
    destination: &'a Path,
    result_directory: &'a ResultDirectory,
    input_set: &'a input::InputSet,
    sampled: &'a input::FingerprintedSources,
    policy: &'a RefinePolicy,
    identity: &'a crate::result_directory::ResultIdentity,
}

fn try_reuse<W: Write>(context: ReuseContext<'_, W>) -> Result<Option<bool>, Box<dyn Error>> {
    let ReuseContext {
        options,
        output,
        job,
        destination,
        result_directory,
        input_set,
        sampled,
        policy,
        identity,
    } = context;
    if options.recovery.refresh {
        return Ok(None);
    }
    let Some(reused) = result_directory.reuse_refinement(
        identity,
        &sampled.labels,
        options.recovery.strict_cache,
        || {
            input::strong_source_identity(
                input_set,
                policy.total_input_limit,
                policy.per_file_limit,
                job,
            )
        },
    )?
    else {
        return Ok(None);
    };
    ensure_input_unchanged(input_set, sampled, policy, job)?;
    skip_file_irrelevant_phases(job)?;
    record_source_counters(job, sampled)?;
    start_input_phases(job, sampled.labels.len())?;
    skip_refinement_work_phases(job)?;
    job.increment(Counter::CacheHits, 1)?;
    if !options.recovery.quiet {
        output::write_reused_summary(
            output,
            destination,
            reused.complete,
            reused.artifacts.len(),
            options.dry_run,
        )?;
    }
    Ok(Some(reused.complete))
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
    input_set: &'a input::InputSet,
    sampled: &'a input::FingerprintedSources,
    cache: Option<&'a Cache>,
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
        input_set,
        sampled,
        cache,
    } = context;
    job.check_cancelled()?;
    let analyzed =
        analysis::analyze_sources(sources, input_set, policy, &options.recovery, cache, job)?;
    ensure_input_unchanged(input_set, sampled, policy, job)?;
    job.finish(Phase::TransformDiscovery, PhaseOutcome::Completed)?;
    job.finish(Phase::Expansion, PhaseOutcome::Completed)?;

    let validation_receipts = analyzed.analyzer_validation_receipts()?;
    let selected = artifact_export::select_artifacts_with_analyzer_receipts(
        &analyzed.case,
        &validation_receipts,
    )?;
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
        if !options.recovery.quiet {
            output::write_summary(
                output,
                destination,
                &selected,
                &analyzed.source_records,
                analyzed.complete,
                true,
            )?;
        }
        return Ok(analyzed.complete);
    }

    job.check_cancelled()?;
    result_directory.publish(identity, job, |staging| {
        artifact_export::write_artifacts_into(staging, &selected)?;
        output::write_manifest(staging, &manifest)?;
        output::write_summary_file(staging, &summary)?;
        Ok(())
    })?;
    if !options.recovery.quiet {
        output::write_summary(
            output,
            destination,
            &selected,
            &analyzed.source_records,
            analyzed.complete,
            false,
        )?;
    }
    Ok(analyzed.complete)
}

fn ensure_input_unchanged(
    input_set: &input::InputSet,
    expected: &input::FingerprintedSources,
    policy: &RefinePolicy,
    job: &Job,
) -> Result<(), Box<dyn Error>> {
    let actual = input::fingerprint_sources(
        input_set,
        policy.total_input_limit,
        policy.per_file_limit,
        job,
    )?;
    input::ensure_manifest_unchanged(input_set, job)?;
    if actual.identity != expected.identity || actual.labels != expected.labels {
        return Err(invalid_input("input artifact changed during refinement"));
    }
    Ok(())
}

fn record_source_counters(
    job: &Job,
    sources: &input::FingerprintedSources,
) -> Result<(), Box<dyn Error>> {
    job.increment(Counter::Files, u64::try_from(sources.labels.len())?)?;
    job.increment(Counter::Bytes, sources.total_bytes)?;
    Ok(())
}

fn start_input_phases(job: &Job, source_count: usize) -> Result<(), Box<dyn Error>> {
    complete_phase(job, Phase::Preparation, Some(1))?;
    job.start(Phase::Ingestion, Some(u64::try_from(source_count)?))?;
    for _ in 0..source_count {
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
