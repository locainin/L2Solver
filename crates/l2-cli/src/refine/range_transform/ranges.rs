//! Search transformed spools with the shared bounded range analyzer

use super::super::{file_artifact::DerivedArtifact, input::stream_error};
use super::{JobReader, StreamContext, StreamObject, archive, omit, omit_formatted};
use l2_workbench::{
    artifact::{
        AnalysisFormat, AnalysisOmission, ArtifactAnalysis, ArtifactAnalysisOptions, StreamMemory,
        ZipEndScanLimits, analyze_artifacts_observing_zip_ends,
    },
    job::{Counter, MemoryClass, MemoryLease},
};
use std::{
    error::Error,
    io::{Seek, SeekFrom},
};

struct RangeReport {
    report: ArtifactAnalysis,
    _memory: MemoryLease,
}

pub(super) fn inspect_ranges(
    context: &mut StreamContext<'_>,
    object: &StreamObject,
) -> Result<bool, Box<dyn Error>> {
    let depth = object
        .derived
        .steps
        .len()
        .checked_add(1)
        .ok_or("stream depth overflows")?;
    if depth > context.options.limits.max_depth {
        omit(
            context,
            None,
            "derived range discovery reached the depth limit",
        )?;
        return Ok(false);
    }
    let Some(mut scanned) = scan_spool(context, object)? else {
        return Ok(false);
    };
    let receipt = object
        .derived
        .steps
        .last()
        .ok_or("stream receipt is missing")?;
    record_coverage(
        context,
        std::mem::take(&mut scanned.report.omissions),
        &receipt.output_sha256,
    )?;
    let already_published = context
        .analysis
        .file_artifacts
        .iter()
        .filter(|artifact| {
            artifact.source_index == context.source_index && artifact.shares_spool(&object.derived)
        })
        .try_fold(0_usize, |sum, artifact| {
            sum.checked_add(artifact.range.length)
        })
        .ok_or("derived publication size overflows")?;
    let mut reserved_publication = receipt.output_length.saturating_sub(already_published);
    let mut found = false;
    for artifact in &scanned.report.artifacts {
        if merge_existing(context, object, artifact)? {
            found = true;
            continue;
        }
        let Some((index, files_before)) = archive::next_index(context)? else {
            continue;
        };
        if !reserve_publication(context, artifact.bytes.len(), &mut reserved_publication)? {
            continue;
        }
        let derived = DerivedArtifact::new(
            object.derived.clone(),
            context.memory,
            artifact.origins.len(),
        )?;
        let source_sha256 = context.report.source_sha256.clone();
        context.analysis.append_stream_ranges(
            context.source_index,
            index,
            context.source,
            &source_sha256,
            artifact,
            derived,
        )?;
        if artifact.validation.format == Some(AnalysisFormat::Zip) {
            archive::expand_carved_archive(context, artifact, index, depth, files_before)?;
        }
        context.job.increment(Counter::ValidatedArtifacts, 1)?;
        found = true;
    }
    Ok(found)
}

fn merge_existing(
    context: &mut StreamContext<'_>,
    object: &StreamObject,
    artifact: &l2_workbench::artifact::AnalyzedArtifact,
) -> Result<bool, Box<dyn Error>> {
    for existing in &mut context.analysis.file_artifacts {
        if existing.source_index == context.source_index
            && existing.merge_derived_ranges(artifact, context.source.length(), &object.derived)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn scan_spool(
    context: &mut StreamContext<'_>,
    object: &StreamObject,
) -> Result<Option<RangeReport>, Box<dyn Error>> {
    let receipt = object
        .derived
        .steps
        .last()
        .ok_or("stream receipt is missing")?;
    let length = receipt.output_length;
    let hash_work = length.checked_add(1).ok_or("stream hash work overflows")?;
    let Some(remaining) = context
        .budget
        .work
        .checked_sub(hash_work)
        .filter(|work| *work > 0)
    else {
        omit(
            context,
            None,
            "derived range discovery exceeds the stream work limit",
        )?;
        return Ok(None);
    };
    let mut options = scan_options(context, length, remaining)?;
    let retained = context
        .report
        .artifacts
        .iter()
        .try_fold(0_usize, |sum, artifact| {
            sum.checked_add(artifact.bytes.len())
        })
        .ok_or("retained artifact bytes overflow")?;
    options.limits.max_total_output_bytes = options
        .limits
        .max_total_output_bytes
        .saturating_sub(retained);
    if options.limits.max_total_output_bytes == 0 {
        omit(
            context,
            None,
            "derived range discovery has no remaining output allowance",
        )?;
        return Ok(None);
    }
    context.budget.work = remaining;
    context.report.work_bytes = context
        .report
        .work_bytes
        .checked_add(hash_work)
        .ok_or("stream hash work overflows")?;
    let scanned = run_scanner(context, object, length, options)?;
    if scanned.report.source_sha256 != receipt.output_sha256 {
        return Err("derived stream changed during range discovery".into());
    }
    context
        .budget
        .charge_range_work(scanned.report.work_bytes)?;
    context.report.work_bytes = context
        .report
        .work_bytes
        .checked_add(scanned.report.work_bytes)
        .ok_or("derived range work overflows")?;
    Ok(Some(scanned))
}

fn run_scanner(
    context: &StreamContext<'_>,
    object: &StreamObject,
    length: usize,
    options: ArtifactAnalysisOptions,
) -> Result<RangeReport, Box<dyn Error>> {
    let (scratch, mut retained_memory) =
        super::super::analysis_memory::reserve(context.memory, length, options, false)?;
    let mut png_memory = context.memory.try_reserve(MemoryClass::Executor, 0)?;
    let mut file = object.derived.spool.file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut reader = JobReader {
        inner: &mut file,
        job: context.job,
    };
    let scanned = analyze_artifacts_observing_zip_ends(
        &mut reader,
        length,
        options,
        None,
        false,
        ZipEndScanLimits {
            max_scan_bytes: 0,
            max_candidates: 0,
        },
        Some(StreamMemory {
            png_metadata: &mut png_memory,
            report: &mut retained_memory,
        }),
    )
    .map_err(stream_error)?;
    super::super::analysis_memory::charge_existing_omissions(
        &scanned.analysis.omissions,
        &mut retained_memory,
    )?;
    drop(scratch);
    Ok(RangeReport {
        report: scanned.analysis,
        _memory: retained_memory,
    })
}

fn scan_options(
    context: &StreamContext<'_>,
    length: usize,
    work: usize,
) -> Result<ArtifactAnalysisOptions, Box<dyn Error>> {
    let mut options = context.options;
    let signature_used = context
        .report
        .artifacts
        .iter()
        .filter(|artifact| artifact.signatures_scanned)
        .map(|artifact| artifact.bytes.len())
        .chain(
            context
                .analysis
                .file_artifacts
                .iter()
                .filter(|artifact| {
                    artifact.source_index == context.source_index && artifact.signatures_scanned
                })
                .map(|artifact| artifact.range.length),
        )
        .try_fold(0_usize, usize::checked_add)
        .ok_or("signature work overflows")?;
    // Complete PNG and ZIP objects are longer than this sentinel allowance
    options.limits.max_signature_scan_bytes = options
        .limits
        .max_signature_scan_bytes
        .saturating_sub(signature_used)
        .max(1);
    options.limits.max_total_work_bytes = context
        .budget
        .range_work_limit(length, options.limits.max_total_work_bytes, context.profile)
        .min(work);
    Ok(options)
}

fn record_coverage(
    context: &mut StreamContext<'_>,
    omissions: Vec<AnalysisOmission>,
    output_sha256: &str,
) -> Result<(), Box<dyn Error>> {
    for omission in omissions {
        if let AnalysisOmission::SourceRangeCoverage {
            max_object_bytes,
            omitted_candidates,
            zip_entry_count_limited,
            signature_scans_omitted,
            uncovered_range,
        } = omission
        {
            super::super::analysis_memory::reserve_omission(
                &mut context.report.omissions,
                context.omission_memory,
            )?;
            let output_sha256 = super::super::analysis_memory::copy_message(
                output_sha256,
                context.omission_memory,
            )?;
            context
                .report
                .omissions
                .push(AnalysisOmission::DerivedStreamRangeCoverage {
                    output_sha256,
                    max_object_bytes,
                    omitted_candidates,
                    zip_entry_count_limited,
                    signature_scans_omitted,
                    uncovered_range,
                });
        } else {
            omit_formatted(
                context,
                None,
                format_args!("derived range discovery incomplete: {omission:?}"),
            )?;
        }
    }
    Ok(())
}

pub(super) fn reserve_publication(
    context: &mut StreamContext<'_>,
    length: usize,
    reserved: &mut usize,
) -> Result<bool, Box<dyn Error>> {
    let extra = length.saturating_sub(*reserved);
    if extra > context.budget.work {
        omit(
            context,
            None,
            "derived range publication exceeds the stream work limit",
        )?;
        return Ok(false);
    }
    *reserved = reserved.saturating_sub(length);
    context.budget.work -= extra;
    context.report.work_bytes = context
        .report
        .work_bytes
        .checked_add(extra)
        .ok_or("derived publication work overflows")?;
    Ok(true)
}
