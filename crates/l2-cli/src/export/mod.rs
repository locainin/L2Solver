//! Coordinate full-source artifact recovery and atomic collection publication

mod artifact_collection;
mod collection;
mod coverage;
mod evidence;
mod limitations;
mod manifest;
mod processing;
mod provenance;
mod recovery_cache;
mod session;
mod summary;
mod tshark_objects;

#[cfg(test)]
thread_local! {
    static COHORT_ARTIFACT_LOOKUP_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
#[path = "../../tests/export/collection.rs"]
mod collection_tests;
#[cfg(test)]
#[path = "../../tests/export/coverage.rs"]
mod coverage_tests;
#[cfg(test)]
#[path = "../../tests/export/evidence.rs"]
mod evidence_tests;
#[cfg(test)]
#[path = "../../tests/export/limitations.rs"]
mod limitation_tests;
#[cfg(test)]
#[path = "../../tests/export/provenance.rs"]
mod provenance_tests;
#[cfg(test)]
#[path = "../../tests/export/source_identity.rs"]
mod source_identity_tests;

use self::{
    artifact_collection::{ArtifactCollection, ArtifactLimits},
    collection::collect_export,
    coverage::{
        ExportCompletionInputs, cohort_analysis_complete, discovery_coverage, export_completion,
        flow_analysis_complete, tshark_is_complete,
    },
    limitations::write_limitations,
    manifest::write_manifest,
    summary::{Summary, write_summary},
};
#[cfg(test)]
use self::{
    artifact_collection::{ArtifactCoverage, ArtifactProvenance},
    collection::{
        CaseArtifactIndex, capture_identity_matches, collect_case_artifacts_with_context,
        collect_cohort_artifacts, collect_matching_tshark_snapshot,
    },
    coverage::{DiscoveryCoverage, ExportCompletion, RecoveryCaseKind, RecoveryCoverage},
    evidence::{EvidenceCoverage, EvidenceSidecar},
    limitations::{CaseLimitationOrigin, LimitationSpool, write_artifact_limitations},
    provenance::{
        ArtifactSourceContext, CohortArtifactContextIndex, artifact_provenance,
        selected_artifact_source_ranges,
    },
    summary::{
        artifact_packet_summary, summary_text, write_reconstruction_omissions,
        write_recovery_status, write_tshark_contents,
    },
};
use crate::{
    arguments::ExportOptions,
    publish,
    result_directory::{ResultDirectory, ResultKind},
};
use l2_workbench::job::{
    CacheStage, Counter, Job, MemoryBudget, Phase, PhaseOutcome, RecoveryPublicationSample,
    RecoveryPublicationSourceBasis,
};
use recovery_cache::RecoveryContext;
use std::{
    cell::Cell,
    collections::HashSet,
    error::Error,
    ffi::OsString,
    fs,
    fs::File,
    io,
    io::Write,
    path::{Path, PathBuf},
};

/// Read the complete capture, analyze every indexed flow, and publish one artifact collection
///
/// # Errors
/// Returns capture, analysis, storage, or publication failures
pub fn run_with_job(
    options: &ExportOptions,
    output: &mut impl Write,
    job: &Job,
) -> Result<bool, Box<dyn Error>> {
    let artifact_limits = ArtifactLimits::default();
    let destination = destination(options)?;
    let directory = ResultDirectory::inspect(&destination, ResultKind::Extract)?;
    if options.capture == Path::new("-") {
        return run_standard_input(options, output, artifact_limits, job, &destination);
    }
    let identity = session::identity(options, job)?;
    if !options.recovery.refresh
        && let Some(reused) = directory.reuse(
            &identity,
            Some(&options.capture),
            options.recovery.strict_cache,
        )?
    {
        job.increment(Counter::CacheHits, 1)?;
        if !options.recovery.quiet {
            writeln!(
                output,
                "Reused {} artifacts in {}{}",
                reused.artifacts.len(),
                destination.display().to_string().escape_debug(),
                if reused.complete {
                    ""
                } else {
                    " (partial; summary.txt explains the limits)"
                }
            )?;
        }
        return Ok(reused.complete);
    }
    let cache = crate::recovery_job::RecoveryCache::open(
        &identity,
        &options.recovery,
        CacheStage::CaptureIndex,
        job,
    )?;
    let result = (|| {
        job.start(Phase::Preparation, None)?;
        job.set_current(Phase::Preparation, "input and output policies accepted")?;
        job.check_cancelled()?;
        job.finish(Phase::Preparation, PhaseOutcome::Completed)?;
        let memory = MemoryBudget::new(options.recovery.memory_limit);
        let context = RecoveryContext {
            memory: Some(&memory),
            cache: cache.cache(),
            job: Some(job),
            options: &options.recovery,
        };
        directory.publish(&identity, job, |staging| {
            let result = build_export(staging, options, artifact_limits, &context, None)?;
            session::check_source_unchanged(options, &identity)?;
            Ok(result)
        })
    })();
    let result = cache.finish(result, job);
    let (count, complete) = result?;
    print_completion(output, options, &destination, count, complete)?;
    Ok(complete)
}

fn print_completion(
    output: &mut impl Write,
    options: &ExportOptions,
    destination: &Path,
    count: u64,
    complete: bool,
) -> io::Result<()> {
    if options.recovery.quiet {
        return Ok(());
    }
    writeln!(
        output,
        "Exported {count} {} into {}",
        if count == 1 { "artifact" } else { "artifacts" },
        destination.display().to_string().escape_debug()
    )?;
    if !complete {
        writeln!(
            output,
            "The export is partial; summary.txt explains what could not be completed"
        )?;
    }
    Ok(())
}

fn build_export(
    staging: &Path,
    options: &ExportOptions,
    limits: ArtifactLimits,
    context: &RecoveryContext<'_>,
    publication_sample: Option<&Cell<RecoveryPublicationSample>>,
) -> Result<(u64, bool), Box<dyn Error>> {
    let mut collected = collect_export(staging, options, limits, context)?;
    let artifact_coverage = collected.artifacts.coverage();
    let evidence_coverage = collected.evidence.coverage();
    let tshark_complete = tshark_is_complete(&collected.tshark, collected.tshark_error.as_deref());
    let discovery = discovery_coverage(
        &collected.coverage,
        artifact_coverage,
        limits,
        &collected.recovery,
        tshark_complete,
        evidence_coverage,
    );
    let completion = export_completion(&ExportCompletionInputs {
        coverage: &collected.coverage,
        artifacts: artifact_coverage,
        recovery: &collected.recovery,
        tshark_required: options.require_tshark,
        tshark: &collected.tshark,
        tshark_error: collected.tshark_error.as_deref(),
        blocking_limitations: collected.limitations.blocking_count,
        evidence: evidence_coverage,
    });
    let has_limitations = collected.limitations.count != 0
        || !flow_analysis_complete(&collected.coverage)
        || !cohort_analysis_complete(&collected.coverage)
        || artifact_coverage.references_omitted != 0
        || evidence_coverage.omitted_cases != 0
        || !collected.recovery.is_complete()
        || !tshark_complete;
    let complete = completion.complete;
    let artifact_count = artifact_coverage.unique_artifacts_retained;
    if let Some(job) = context.job {
        job.check_cancelled()?;
        job.start(Phase::Reports, None)?;
        job.set_current(Phase::Reports, "writing manifest and source evidence")?;
    }
    {
        let mut summary = Summary {
            capture: &options.capture,
            completion: &completion,
            coverage: &collected.coverage,
            discovery,
            artifacts: &mut collected.artifacts,
            evidence: collected.evidence.coverage(),
            tshark: &collected.tshark,
            tshark_error: collected.tshark_error.as_deref(),
            limitations: &mut collected.limitations,
        };
        write_manifest(staging, &mut summary)?;
        write_summary(staging, &mut summary)?;
        write_limitations(staging, &mut summary)?;
    }
    collected.evidence.finish()?;
    collected.limitations.remove()?;

    let mut expected_names = collected.artifacts.file_names()?;
    expected_names.insert(OsString::from("manifest.json"));
    expected_names.insert(OsString::from("summary.txt"));
    expected_names.insert(OsString::from(evidence::SIDECAR_FILE_NAME));
    if has_limitations {
        expected_names.insert(OsString::from("limitations.txt"));
    }
    if let Some(publication_sample) = publication_sample {
        capture_publication_sample(
            publication_sample,
            &collected.coverage,
            &collected.artifacts,
            artifact_count,
        );
    }
    collected.artifacts.cleanup_index()?;
    validate_stage(staging, &expected_names)?;
    File::open(staging)?.sync_all()?;
    if let Some(job) = context.job {
        job.finish(Phase::Reports, PhaseOutcome::Completed)?;
    }
    Ok((artifact_count, complete))
}

fn capture_publication_sample(
    target: &Cell<RecoveryPublicationSample>,
    coverage: &crate::workbench::full_source::FullSourceCoverage,
    artifacts: &ArtifactCollection,
    artifact_count: u64,
) {
    let source_set_sha256 = coverage
        .source
        .source_id
        .strip_prefix("sha256:")
        .and_then(l2_workbench::parse_sha256_digest);
    // The manifest writer already flushed this index; a failed diagnostic read is nonfatal
    let artifact = artifacts.first_artifact_sample().ok().flatten();
    target.set(RecoveryPublicationSample {
        source_set_sha256,
        source_basis: if source_set_sha256.is_some() {
            RecoveryPublicationSourceBasis::StagedManifest
        } else {
            RecoveryPublicationSourceBasis::Unavailable
        },
        artifact,
        artifact_count: Some(artifact_count),
    });
}

fn run_standard_input(
    options: &ExportOptions,
    output: &mut impl Write,
    limits: ArtifactLimits,
    job: &Job,
    destination: &Path,
) -> Result<bool, Box<dyn Error>> {
    let memory = MemoryBudget::new(options.recovery.memory_limit);
    let context = RecoveryContext {
        memory: Some(&memory),
        cache: None,
        job: Some(job),
        options: &options.recovery,
    };
    job.start(Phase::Preparation, None)?;
    job.finish(Phase::Preparation, PhaseOutcome::Completed)?;
    let publication_sample = Cell::new(crate::publication_transition::initial_sample(None));
    let publication = publish::create_directory_with_precommit(
        destination,
        |staging| {
            let result = build_export(
                staging,
                options,
                limits,
                &context,
                Some(&publication_sample),
            )?;
            job.check_cancelled()?;
            job.start(Phase::Publication, None)?;
            Ok(result)
        },
        || {
            job.check_cancelled()?;
            Ok(())
        },
    );
    crate::publication_transition::record_result(job, &publication, publication_sample.get());
    let (count, complete) = publication?;
    job.finish(Phase::Publication, PhaseOutcome::Completed)?;
    print_completion(output, options, destination, count, complete)?;
    Ok(complete)
}

fn destination(options: &ExportOptions) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = &options.output {
        return Ok(path.clone());
    }
    if options.capture == Path::new("-") {
        return Err("standard input requires --output NEW_DIRECTORY".into());
    }
    let name = options
        .capture
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or("capture path has no usable filename")?;
    let mut export_name = OsString::from(name);
    export_name.push(".export");
    Ok(options.capture.with_file_name(export_name))
}

fn validate_stage(directory: &Path, expected: &HashSet<OsString>) -> io::Result<()> {
    let mut remaining = expected.clone();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !remaining.remove(&entry.file_name()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "export staging directory contains an unexpected entry",
            ));
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !tshark_objects::safe_regular_file(&metadata) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "export staging entry is not a verified single-link file",
            ));
        }
    }
    if !remaining.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "export staging directory is missing a generated file",
        ));
    }
    Ok(())
}
