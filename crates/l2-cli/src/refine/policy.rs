//! Shared refinement resource policy

use super::invalid_input;
use crate::arguments::{RecoveryOptions, RecoveryProfile};
use l2_workbench::artifact::{AnalyzerLimits, ArtifactAnalysisOptions, RecoveryMode};
use std::error::Error;

pub(super) const MAX_ANALYSIS_FILE_BYTES: usize = 64 * 1024 * 1024;
pub(super) const STREAM_EXPANSION_RATIO: usize = 1000;

#[derive(Clone, Copy)]
pub(super) struct RefinePolicy {
    pub(super) memory_limit: usize,
    pub(super) source_read_limit: u64,
    pub(super) total_input_limit: usize,
    pub(super) per_file_limit: usize,
    pub(super) case_blob_limit: usize,
    pub(super) stream_output_limit: usize,
    pub(super) stream_work_limit: usize,
    pub(super) analyzer: ArtifactAnalysisOptions,
}

impl RefinePolicy {
    pub(super) fn new(recovery: &RecoveryOptions, salvage: bool) -> Result<Self, Box<dyn Error>> {
        let memory_limit = memory_budget(recovery.memory_limit)?;
        let input_limit = (memory_limit / 4).clamp(1, MAX_ANALYSIS_FILE_BYTES);
        let output_limit = (memory_limit / 3).max(1);
        let stream_output_limit = usize::try_from(recovery.source_read_limit).unwrap_or(usize::MAX);
        Ok(Self {
            memory_limit,
            source_read_limit: recovery.source_read_limit,
            total_input_limit: memory_limit / 4,
            per_file_limit: input_limit,
            case_blob_limit: (memory_limit / 3).max(1),
            // Disk-backed bytes have separate operation-wide limits from retained Case bytes
            stream_output_limit,
            stream_work_limit: stream_output_limit.saturating_mul(4),
            analyzer: analyzer_options(recovery, salvage, input_limit, output_limit),
        })
    }
}

pub(super) fn analyzer_options(
    recovery: &RecoveryOptions,
    salvage: bool,
    max_input_bytes: usize,
    max_total_output_bytes: usize,
) -> ArtifactAnalysisOptions {
    let mut limits = AnalyzerLimits::default();
    limits.max_input_bytes = limits.max_input_bytes.min(max_input_bytes);
    limits.max_total_output_bytes = max_total_output_bytes.max(limits.max_input_bytes);
    limits.max_total_work_bytes = usize::try_from(recovery.memory_limit)
        .unwrap_or(usize::MAX)
        .min(limits.max_total_work_bytes);
    limits.max_signature_scan_bytes = limits
        .max_signature_scan_bytes
        .min(limits.max_input_bytes.saturating_mul(2));
    match recovery.profile {
        RecoveryProfile::Fast => {
            limits.max_artifacts = 64;
            limits.max_depth = limits.max_depth.min(2);
            limits.max_total_work_bytes = limits.max_total_work_bytes.min(64 * 1024 * 1024);
            limits.max_zip_expanded_bytes = limits.max_zip_expanded_bytes.min(16 * 1024 * 1024);
        }
        RecoveryProfile::Normal => {}
        RecoveryProfile::Deep => {
            limits.max_artifacts = 512;
            limits.max_total_work_bytes = limits
                .max_total_work_bytes
                .max(512 * 1024 * 1024)
                .min(usize::try_from(recovery.memory_limit).unwrap_or(usize::MAX));
            limits.max_zip_expanded_bytes = limits
                .max_zip_expanded_bytes
                .max(128 * 1024 * 1024)
                .min(max_total_output_bytes);
        }
    }
    ArtifactAnalysisOptions {
        limits,
        recovery: if salvage {
            RecoveryMode::Salvage
        } else {
            RecoveryMode::Conservative
        },
    }
}

pub(super) fn memory_budget(memory_limit: u64) -> Result<usize, Box<dyn Error>> {
    let memory = usize::try_from(memory_limit).unwrap_or(usize::MAX);
    if memory < 12 {
        return Err(invalid_input(
            "recovery memory limit is too small for file refinement",
        ));
    }
    Ok(memory)
}
