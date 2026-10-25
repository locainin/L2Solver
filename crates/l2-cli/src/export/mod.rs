//! Coordinate full-source artifact recovery and atomic collection publication

mod artifact_collection;
mod collection;
mod coverage;
mod evidence;
mod limitations;
mod manifest;
mod provenance;
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
    artifact_collection::ArtifactLimits,
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
    artifact_collection::{ArtifactCollection, ArtifactCoverage, ArtifactProvenance},
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
use crate::{arguments::ExportOptions, publish};
use std::{
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
pub fn run(options: &ExportOptions, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    run_with_artifact_limits(options, output, ArtifactLimits::default())
}

fn run_with_artifact_limits(
    options: &ExportOptions,
    output: &mut impl Write,
    artifact_limits: ArtifactLimits,
) -> Result<bool, Box<dyn Error>> {
    let destination = destination(options)?;
    let (count, complete) = publish::create_directory(&destination, |staging| {
        build_export(staging, options, artifact_limits)
    })?;

    writeln!(
        output,
        "Exported {count} {} into {}",
        if count == 1 { "artifact" } else { "artifacts" },
        destination.display()
    )?;
    if !complete {
        writeln!(
            output,
            "The export is partial; summary.txt explains what could not be completed"
        )?;
    }
    Ok(complete)
}

fn build_export(
    staging: &Path,
    options: &ExportOptions,
    limits: ArtifactLimits,
) -> Result<(u64, bool), Box<dyn Error>> {
    let mut collected = collect_export(staging, options, limits)?;
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
    collected.artifacts.cleanup_index()?;
    validate_stage(staging, &expected_names)?;
    File::open(staging)?.sync_all()?;
    Ok((artifact_count, complete))
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
