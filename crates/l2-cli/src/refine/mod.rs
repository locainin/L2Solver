//! Refine standalone byte files and manifest-listed artifact directories

mod analysis;
mod file_artifact;
mod input;
mod output;
mod policy;
mod publication_memory;
mod range_members;
mod range_zip;
mod read_budget;

#[cfg(test)]
use analysis::analyze_source_cached;
use input::LoadedSource;
#[cfg(test)]
use input::{prepare_input_set, read_sources_with_test_budget as read_sources};
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
use l2_workbench::job::{
    CacheStage, Counter, Job, MemoryBudget, Phase, PhaseOutcome, cache::Cache,
};
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
    let memory = MemoryBudget::new(options.recovery.memory_limit);
    run_with_memory_budget(options, output, job, &memory)
}

fn run_with_memory_budget(
    options: &RefineOptions,
    output: &mut impl Write,
    job: &Job,
    memory: &MemoryBudget,
) -> Result<bool, Box<dyn Error>> {
    job.check_cancelled()?;
    let mut publication_buffer = publication_memory::PublicationBuffer::try_new(memory)?;
    let destination = options
        .output
        .clone()
        .unwrap_or_else(|| output::default_output_path(&options.input));
    let result_directory = ResultDirectory::inspect(&destination, ResultKind::Refine)?;
    let policy = RefinePolicy::new(&options.recovery, options.salvage)?;
    let input_set =
        input::prepare_input_set_with_limit(&options.input, policy.source_read_limit, job)?;

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
        memory,
    )?;
    ensure_input_unchanged(&input_set, &sampled, &policy, job)?;
    // A checkpoint cannot use a sample as proof of a range source's identity
    let cache = if options.dry_run || sources.iter().any(|source| source.digest().is_none()) {
        crate::recovery_job::RecoveryCache::disabled()
    } else {
        let identity = output::result_identity(&sources, &options.recovery, &policy)?;
        crate::recovery_job::RecoveryCache::open(
            &identity,
            &options.recovery,
            CacheStage::ArtifactAnalysis,
            job,
            None,
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
            memory,
            publication_buffer: &mut publication_buffer,
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
    memory: &'a MemoryBudget,
    publication_buffer: &'a mut publication_memory::PublicationBuffer,
}

#[expect(
    clippy::too_many_lines,
    reason = "analysis, staged writes, and publication share one transaction"
)]
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
        memory,
        publication_buffer,
    } = context;
    job.check_cancelled()?;
    let analyzed = analysis::analyze_sources(
        sources,
        input_set,
        policy,
        &options.recovery,
        cache,
        job,
        memory,
    )?;
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
        &analyzed.file_artifacts,
        &analyzed.source_records,
        &analyzed.artifact_records,
        analyzed.complete,
    )?;
    let summary = output::format_summary(
        destination,
        &selected,
        &analyzed.file_artifacts,
        &analyzed.source_records,
        analyzed.complete,
    );
    job.advance(Phase::Reports, 1)?;
    job.finish(Phase::Reports, PhaseOutcome::Completed)?;

    if options.dry_run {
        job.finish(Phase::Publication, PhaseOutcome::Skipped)?;
    } else {
        job.check_cancelled()?;
        result_directory.publish(identity, job, |staging| {
            artifact_export::write_artifacts_into(staging, &selected)?;
            write_file_artifacts(
                input_set,
                &analyzed.file_artifacts,
                staging,
                job,
                publication_buffer.bytes_mut(),
            )?;
            output::write_manifest(staging, &manifest)?;
            output::write_summary_file(staging, &summary)?;
            if !analyzed.file_artifacts.is_empty() {
                ensure_input_unchanged(input_set, sampled, policy, job)?;
            }
            Ok(())
        })?;
    }
    if !options.recovery.quiet {
        output::write_summary(
            output,
            destination,
            &selected,
            &analyzed.file_artifacts,
            &analyzed.source_records,
            analyzed.complete,
            options.dry_run,
        )?;
    }
    Ok(analyzed.complete)
}

fn write_file_artifacts(
    input: &input::InputSet,
    artifacts: &[file_artifact::FileArtifact],
    staging: &std::path::Path,
    job: &Job,
    buffer: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    for artifact in artifacts {
        input.write_file_artifact(artifact, staging, job, buffer)?;
    }
    Ok(())
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
    if actual.identity != expected.identity
        || actual.labels != expected.labels
        || actual.sample_set_sha256 != expected.sample_set_sha256
    {
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
