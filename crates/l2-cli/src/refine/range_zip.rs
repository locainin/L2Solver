//! Inspect complete file-backed ZIP sources with the shared bounded parser

use super::input::{CancellableReader, InputSet};
use l2_workbench::{
    artifact::{
        AnalysisFormat, AnalysisOmission, ArtifactAnalysis, ArtifactAnalysisOptions,
        zip::{
            ZipArtifactLimits, ZipArtifactReport, ZipReadError, ZipReaderBudget, ZipReaderLimits,
            inspect_zip_from_reader_with_source_sha256_and_memory,
        },
    },
    job::{Job, MemoryBudget, MemoryClass, MemoryLease},
};
use std::{
    error::Error,
    fs::File,
    io::{Read, Seek, SeekFrom},
};

const ZIP_END_SCAN_BYTES: usize = 65_535 + 22;

pub(super) struct ZipCandidate {
    pub(super) length: usize,
    pub(super) multiple_boundaries: bool,
}

pub(super) enum TailProbe {
    Skipped,
    ReadLimit,
    WorkLimit,
    Scanned {
        candidate: Option<ZipCandidate>,
        work_bytes: usize,
    },
}

pub(super) fn probe_tail(
    file: &mut File,
    length: usize,
    max_buffer: usize,
    input: &InputSet,
    job: &Job,
    memory: &MemoryBudget,
    remaining_work: usize,
) -> Result<TailProbe, Box<dyn Error>> {
    let count = length.min(ZIP_END_SCAN_BYTES).min(max_buffer);
    if count < 22 {
        return Ok(TailProbe::Skipped);
    }
    // The bounded read and the marker scan each visit the tail once
    let requested = count.checked_mul(2).ok_or("ZIP tail work overflows")?;
    if requested > remaining_work {
        return Ok(TailProbe::WorkLimit);
    }
    if !input.reserve_extra_reads(u64::try_from(count)?)? {
        return Ok(TailProbe::ReadLimit);
    }
    let _scratch = memory.try_reserve(MemoryClass::Executor, u64::try_from(count)?)?;
    let mut tail = Vec::new();
    tail.try_reserve_exact(count)?;
    tail.resize(count, 0);
    file.seek(SeekFrom::Start(u64::try_from(length - count)?))?;
    CancellableReader::new(file, job).read_exact(&mut tail)?;
    // A marker only selects the canonical parser; it does not establish validity
    let mut candidate: Option<ZipCandidate> = None;
    for (offset, marker) in tail.windows(4).enumerate() {
        if marker != b"PK\x05\x06" {
            continue;
        }
        let Some(field) = tail.get(offset.saturating_add(20)..offset.saturating_add(22)) else {
            continue;
        };
        let Ok(raw) = <[u8; 2]>::try_from(field) else {
            continue;
        };
        let Some(end) = offset
            .checked_add(22)
            .and_then(|end| end.checked_add(usize::from(u16::from_le_bytes(raw))))
        else {
            continue;
        };
        if end > tail.len() {
            continue;
        }
        let boundary = length - count + end;
        if let Some(current) = &mut candidate {
            current.multiple_boundaries |= current.length != boundary;
            current.length = current.length.max(boundary);
        } else {
            candidate = Some(ZipCandidate {
                length: boundary,
                multiple_boundaries: false,
            });
        }
    }
    Ok(TailProbe::Scanned {
        candidate,
        work_bytes: requested,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "the source checks share one job and report leases"
)]
pub(super) fn inspect(
    file: &mut File,
    length: usize,
    source_sha256: &str,
    report: &mut ArtifactAnalysis,
    options: ArtifactAnalysisOptions,
    input: &InputSet,
    job: &Job,
    memory: &mut MemoryLease,
    omission_memory: &mut MemoryLease,
) -> Result<Option<ZipArtifactReport>, Box<dyn Error>> {
    let remaining_work = options
        .limits
        .max_total_work_bytes
        .saturating_sub(report.work_bytes);
    let retained = report
        .artifacts
        .iter()
        .try_fold(0_usize, |sum, artifact| {
            sum.checked_add(artifact.bytes.len())
        })
        .ok_or("retained artifact size overflow")?;
    let remaining_output = options
        .limits
        .max_total_output_bytes
        .saturating_sub(retained);
    let read_limit = usize::try_from(input.extra_read_bytes())
        .unwrap_or(usize::MAX)
        .min(remaining_work / 2);
    let expanded_limit = options
        .limits
        .max_zip_expanded_bytes
        .saturating_sub(report.zip_expanded_work_bytes)
        .min(remaining_output)
        .min(remaining_work - read_limit);
    let mut budget = ZipReaderBudget {
        read_bytes_remaining: read_limit,
        expanded_bytes_remaining: expanded_limit,
    };
    let archive_limits = ZipArtifactLimits {
        max_archive_bytes: length,
        max_entry_expanded_bytes: ZipArtifactLimits::default()
            .max_entry_expanded_bytes
            .min(remaining_output.max(1)),
        max_total_expanded_bytes: expanded_limit,
        max_depth: options.limits.max_depth,
        ..ZipArtifactLimits::default()
    };
    let limits = ZipReaderLimits {
        archive: archive_limits,
        max_directory_bytes: ZipReaderLimits::default()
            .max_directory_bytes
            .min(options.limits.max_input_bytes),
    };
    let mut reader = CancellableReader::new(file, job);
    let before = memory.bytes();
    let result = inspect_zip_from_reader_with_source_sha256_and_memory(
        &mut reader,
        length,
        source_sha256,
        limits,
        0,
        &mut budget,
        memory,
    );
    let read_work = read_limit - budget.read_bytes_remaining;
    let expanded_work = expanded_limit - budget.expanded_bytes_remaining;
    let charged = input.reserve_extra_reads(u64::try_from(read_work)?)?;
    if !charged {
        return Err("ZIP source read reservation was lost".into());
    }
    report.work_bytes = report
        .work_bytes
        .checked_add(read_work)
        .and_then(|work| work.checked_add(expanded_work))
        .ok_or("ZIP work counter overflow")?;
    // Failed parser attempts still consumed their admitted expansion work
    report.zip_expanded_work_bytes = report
        .zip_expanded_work_bytes
        .checked_add(expanded_work)
        .ok_or("ZIP expansion work counter overflow")?;
    report_inspection_result(result, report, memory, omission_memory, before)
}

fn report_inspection_result(
    result: Result<ZipArtifactReport, ZipReadError>,
    report: &mut ArtifactAnalysis,
    memory: &mut MemoryLease,
    omission_memory: &mut MemoryLease,
    before: u64,
) -> Result<Option<ZipArtifactReport>, Box<dyn Error>> {
    match result {
        Ok(archive)
            if archive.omissions.iter().any(|omission| {
                matches!(
                    omission.reason,
                    l2_workbench::artifact::zip::ZipArtifactOmissionReason::EntryCountLimit
                        | l2_workbench::artifact::zip::ZipArtifactOmissionReason::DepthLimit
                )
            }) =>
        {
            drop(archive);
            memory.try_resize(before)?;
            super::analysis_memory::reserve_omission(&mut report.omissions, omission_memory)?;
            let reason = super::analysis_memory::copy_message(
                "ZIP entry or depth limit prevented structural validation",
                omission_memory,
            )?;
            report
                .omissions
                .push(AnalysisOmission::SourceRangeValidationLimit {
                    format: AnalysisFormat::Zip,
                    reason,
                });
            Ok(None)
        }
        Ok(archive) => Ok(Some(archive)),
        Err(ZipReadError::Io(error)) => Err(error.into()),
        Err(ZipReadError::Memory(error)) => Err(error.into()),
        Err(ZipReadError::Format(
            l2_workbench::artifact::zip::ZipArtifactError::InvalidArchive
            | l2_workbench::artifact::zip::ZipArtifactError::AmbiguousEndRecords,
        )) => Ok(None),
        Err(error) => {
            super::analysis_memory::reserve_omission(&mut report.omissions, omission_memory)?;
            let reason =
                super::analysis_memory::format_message(format_args!("{error}"), omission_memory)?;
            report
                .omissions
                .push(AnalysisOmission::SourceRangeValidationLimit {
                    format: AnalysisFormat::Zip,
                    reason,
                });
            Ok(None)
        }
    }
}
