//! Validate derived ZIP spools and merge their bounded member reports

use super::super::file_artifact::DerivedArtifact;
use super::{JobReader, StreamContext, StreamObject, omit, omit_formatted};
use l2_workbench::{
    artifact::{
        AnalysisOmission, AnalyzedArtifact,
        zip::{
            ZipArtifactError, ZipArtifactLimits, ZipArtifactOmissionReason, ZipArtifactReport,
            ZipReadError, ZipReaderBudget, ZipReaderLimits,
            inspect_zip_from_reader_with_source_sha256_and_memory,
        },
    },
    job::Counter,
};
use std::{
    error::Error,
    io::{Cursor, Seek, SeekFrom},
};

pub(super) fn inspect_archive(
    context: &mut StreamContext<'_>,
    object: StreamObject,
) -> Result<Option<StreamObject>, Box<dyn Error>> {
    let prefix = object
        .observation
        .prefix
        .get(..object.observation.prefix_length)
        .ok_or("invalid stream prefix")?;
    if !prefix.starts_with(b"PK\x03\x04") && !prefix.starts_with(b"PK\x05\x06") {
        return Ok(Some(object));
    }
    match parse_archive(context, &object)? {
        Inspection::Unrecognized | Inspection::Omitted => Ok(Some(object)),
        Inspection::Validated(report) => {
            retain_archive(context, &object, report)?;
            Ok(Some(object))
        }
    }
}

enum Inspection {
    Unrecognized,
    Omitted,
    Validated(ZipArtifactReport),
}

fn parse_archive(
    context: &mut StreamContext<'_>,
    object: &StreamObject,
) -> Result<Inspection, Box<dyn Error>> {
    let receipt = object
        .derived
        .steps
        .last()
        .ok_or("stream receipt is missing")?;
    let (limits, mut budget) = parser_limits(context, receipt.output_length)?;
    let initial = budget;
    let memory_before = context.report_memory.bytes();
    let mut file = object.derived.spool.file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut reader = JobReader {
        inner: &mut file,
        job: context.job,
    };
    let result = inspect_zip_from_reader_with_source_sha256_and_memory(
        &mut reader,
        receipt.output_length,
        &receipt.output_sha256,
        limits,
        object.derived.steps.len(),
        &mut budget,
        context.report_memory,
    );
    charge_parser(context, initial, budget)?;
    match result {
        Ok(archive)
            if archive.omissions.iter().any(|omission| {
                matches!(
                    omission.reason,
                    ZipArtifactOmissionReason::EntryCountLimit
                        | ZipArtifactOmissionReason::DepthLimit
                )
            }) =>
        {
            drop(archive);
            context.report_memory.try_resize(memory_before)?;
            omit(
                context,
                None,
                "ZIP entry or depth limit prevented structural validation",
            )?;
            Ok(Inspection::Omitted)
        }
        Ok(report) => Ok(Inspection::Validated(report)),
        Err(ZipReadError::Io(error)) => Err(error.into()),
        Err(ZipReadError::Memory(error)) => Err(error.into()),
        Err(ZipReadError::Format(
            ZipArtifactError::InvalidArchive | ZipArtifactError::AmbiguousEndRecords,
        )) => {
            context.report_memory.try_resize(memory_before)?;
            Ok(Inspection::Unrecognized)
        }
        Err(error) => {
            context.report_memory.try_resize(memory_before)?;
            omit_formatted(
                context,
                None,
                format_args!("derived ZIP inspection incomplete: {error}"),
            )?;
            Ok(Inspection::Unrecognized)
        }
    }
}

pub(super) fn expand_carved_archive(
    context: &mut StreamContext<'_>,
    artifact: &AnalyzedArtifact,
    index: usize,
    depth: usize,
    file_count: usize,
) -> Result<(), Box<dyn Error>> {
    let (limits, mut budget) = parser_limits(context, artifact.bytes.len())?;
    let initial = budget;
    let before = context.report_memory.bytes();
    let mut reader = JobReader {
        inner: Cursor::new(artifact.bytes.as_slice()),
        job: context.job,
    };
    let result = inspect_zip_from_reader_with_source_sha256_and_memory(
        &mut reader,
        artifact.bytes.len(),
        &artifact.sha256,
        limits,
        depth,
        &mut budget,
        context.report_memory,
    );
    charge_parser(context, initial, budget)?;
    match result {
        Ok(archive)
            if archive.omissions.iter().any(|omission| {
                matches!(
                    omission.reason,
                    ZipArtifactOmissionReason::EntryCountLimit
                        | ZipArtifactOmissionReason::DepthLimit
                )
            }) =>
        {
            drop(archive);
            context.report_memory.try_resize(before)?;
            omit(
                context,
                None,
                "carved ZIP expansion reached its entry or depth limit",
            )?;
        }
        Ok(archive) => merge_members(context, archive, index, depth, file_count)?,
        Err(ZipReadError::Io(error)) => return Err(error.into()),
        Err(ZipReadError::Memory(error)) => return Err(error.into()),
        Err(error) => {
            context.report_memory.try_resize(before)?;
            omit_formatted(
                context,
                None,
                format_args!("carved ZIP expansion incomplete: {error}"),
            )?;
        }
    }
    Ok(())
}

fn parser_limits(
    context: &StreamContext<'_>,
    length: usize,
) -> Result<(ZipReaderLimits, ZipReaderBudget), Box<dyn Error>> {
    let retained = context
        .report
        .artifacts
        .iter()
        .try_fold(0_usize, |total, artifact| {
            total.checked_add(artifact.bytes.len())
        })
        .ok_or("retained artifact output overflows")?;
    let remaining = context
        .options
        .limits
        .max_total_output_bytes
        .saturating_sub(retained);
    let read = context.budget.work / 2;
    let expanded = context
        .budget
        .zip
        .min(remaining)
        .min(context.budget.work - read);
    let archive = ZipArtifactLimits {
        max_archive_bytes: length,
        max_entry_expanded_bytes: ZipArtifactLimits::default()
            .max_entry_expanded_bytes
            .min(remaining.max(1)),
        max_total_expanded_bytes: expanded,
        max_depth: context.options.limits.max_depth,
        ..ZipArtifactLimits::default()
    };
    let limits = ZipReaderLimits {
        archive,
        max_directory_bytes: ZipReaderLimits::default()
            .max_directory_bytes
            .min(context.options.limits.max_input_bytes),
    };
    Ok((
        limits,
        ZipReaderBudget {
            read_bytes_remaining: read,
            expanded_bytes_remaining: expanded,
        },
    ))
}

fn charge_parser(
    context: &mut StreamContext<'_>,
    initial: ZipReaderBudget,
    remaining: ZipReaderBudget,
) -> Result<(), Box<dyn Error>> {
    let read = initial.read_bytes_remaining - remaining.read_bytes_remaining;
    let expanded = initial.expanded_bytes_remaining - remaining.expanded_bytes_remaining;
    let work = read.checked_add(expanded).ok_or("ZIP work overflows")?;
    context.budget.work = context
        .budget
        .work
        .checked_sub(work)
        .ok_or("ZIP work exceeded reservation")?;
    context.budget.zip = context
        .budget
        .zip
        .checked_sub(expanded)
        .ok_or("ZIP expansion exceeded reservation")?;
    context.report.work_bytes = context
        .report
        .work_bytes
        .checked_add(work)
        .ok_or("ZIP work overflows")?;
    context.report.zip_expanded_work_bytes = context
        .report
        .zip_expanded_work_bytes
        .checked_add(expanded)
        .ok_or("ZIP expansion work overflows")?;
    Ok(())
}

fn retain_archive(
    context: &mut StreamContext<'_>,
    object: &StreamObject,
    archive: ZipArtifactReport,
) -> Result<(), Box<dyn Error>> {
    let Some((index, file_count)) = next_index(context)? else {
        return Ok(());
    };
    let depth = object.derived.steps.len();
    context.analysis.append_stream_archive(
        context.source_index,
        index,
        context.source,
        &context.report.source_sha256,
        &archive,
        DerivedArtifact::new(object.derived.clone(), context.memory, 1)?,
    )?;
    merge_members(context, archive, index, depth, file_count)?;
    context.job.increment(Counter::ValidatedArtifacts, 1)?;
    Ok(())
}

pub(super) fn next_index(
    context: &mut StreamContext<'_>,
) -> Result<Option<(usize, usize)>, Box<dyn Error>> {
    let files = context
        .analysis
        .file_artifacts
        .iter()
        .filter(|artifact| artifact.source_index == context.source_index);
    let file_count = files.clone().count();
    if context.report.artifacts.len().saturating_add(file_count)
        >= context.options.limits.max_artifacts
    {
        super::super::analysis_memory::reserve_omission(
            &mut context.report.omissions,
            context.omission_memory,
        )?;
        context
            .report
            .omissions
            .push(AnalysisOmission::ArtifactLimit {
                maximum: context.options.limits.max_artifacts,
            });
        return Ok(None);
    }
    let index = context
        .report
        .artifacts
        .iter()
        .map(|artifact| artifact.index)
        .chain(files.map(|artifact| artifact.artifact_index))
        .max()
        .map_or(Some(0), |value| value.checked_add(1))
        .ok_or("artifact index overflows")?;
    Ok(Some((index, file_count)))
}

fn merge_members(
    context: &mut StreamContext<'_>,
    archive: ZipArtifactReport,
    index: usize,
    depth: usize,
    file_count: usize,
) -> Result<(), Box<dyn Error>> {
    let mut options = context.options;
    options.limits.max_artifacts = options.limits.max_artifacts.saturating_sub(file_count);
    options.limits.max_total_work_bytes = context
        .report
        .work_bytes
        .checked_add(context.budget.work)
        .ok_or("member work limit overflows")?;
    options.limits.max_zip_expanded_bytes = context
        .report
        .zip_expanded_work_bytes
        .checked_add(context.budget.zip)
        .ok_or("member expansion limit overflows")?;
    options.limits.max_depth = options.limits.max_depth.saturating_sub(depth);
    let work_before = context.report.work_bytes;
    let expansion_before = context.report.zip_expanded_work_bytes;
    super::super::range_members::append_members(
        context.report,
        archive,
        index,
        options,
        context.omission_memory,
    )?;
    let work = context
        .report
        .work_bytes
        .checked_sub(work_before)
        .ok_or("member work decreased")?;
    context.budget.work = context
        .budget
        .work
        .checked_sub(work)
        .ok_or("member work exceeded budget")?;
    let nested = context
        .report
        .zip_expanded_work_bytes
        .checked_sub(expansion_before)
        .ok_or("nested ZIP accounting is invalid")?;
    context.budget.zip = context
        .budget
        .zip
        .checked_sub(nested)
        .ok_or("nested ZIP expansion exceeded budget")?;
    Ok(())
}
