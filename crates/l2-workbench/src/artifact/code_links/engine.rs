//! Runtime instruction-pointer mapping and trace association

use crate::endpoint::{TraceCodeFrame, TraceIoEvent};
use crate::endpoint::{TraceCorrelation, TraceIoReport, TraceMatchStatus};

use super::super::AnalysisReceipt;
use super::model::{
    CodeLink, CodeLinkError, CodeLinkLimits, CodeLinkReport, CodeLinkSourceChecks,
    CodeLinkSourceVerification, CodeLinkStatus, LIMITATIONS, RuntimeModuleMap,
};
use super::validation::{
    IndexedRangeMatch, IndexedTraceEvent, RangeLookupIndex, ValidatedFunction,
    ValidatedRuntimeRange, index_correlations, validate_functions, validate_limits,
    validate_mappings, validate_packet_ranges, validate_sha256, validate_trace_range,
};

struct LinkIndexes<'function> {
    runtime_ranges: Vec<ValidatedRuntimeRange>,
    runtime_range_index: RangeLookupIndex,
    functions: Vec<ValidatedFunction<'function>>,
    function_index: RangeLookupIndex,
    mapping_process_id: Option<u32>,
}

impl LinkIndexes<'_> {
    fn runtime_mapping(
        &self,
        instruction_pointer: u64,
        process_id: Option<u32>,
    ) -> Result<&ValidatedRuntimeRange, CodeLinkStatus> {
        match (self.mapping_process_id, process_id) {
            (Some(expected), Some(actual)) if expected != actual => {
                return Err(CodeLinkStatus::ProcessMismatch);
            }
            (Some(_), Some(_)) => {}
            _ => return Err(CodeLinkStatus::ProcessIdentityUnavailable),
        }
        match self.runtime_range_index.lookup(instruction_pointer) {
            IndexedRangeMatch::Missing => Err(CodeLinkStatus::UnmappedRuntimeAddress),
            IndexedRangeMatch::Ambiguous => Err(CodeLinkStatus::AmbiguousRuntimeMapping),
            IndexedRangeMatch::Unique(index) => self
                .runtime_ranges
                .get(index)
                .ok_or(CodeLinkStatus::UnmappedRuntimeAddress),
        }
    }

    fn static_function(&self, file_offset: u64) -> Result<&ValidatedFunction<'_>, CodeLinkStatus> {
        match self.function_index.lookup(file_offset) {
            IndexedRangeMatch::Missing => Err(CodeLinkStatus::NoFunctionAtMappedOffset),
            IndexedRangeMatch::Ambiguous => Err(CodeLinkStatus::AmbiguousStaticFunction),
            IndexedRangeMatch::Unique(index) => self
                .functions
                .get(index)
                .ok_or(CodeLinkStatus::NoFunctionAtMappedOffset),
        }
    }
}

struct LinkBatch {
    links: Vec<CodeLink>,
    omitted_links: usize,
    missing_correlations: usize,
}

/// Map trace instruction pointers through a source-qualified runtime map
///
/// The runtime map's binary hash must match the static receipt. Optional raw
/// binary and map-source bytes independently verify their stated hashes
///
/// # Errors
/// Returns an error when supplied hashes, mapping ranges, function bytes, or trace provenance are invalid
pub fn link_code_to_trace(
    receipt: &AnalysisReceipt,
    mapping: &RuntimeModuleMap,
    trace: &TraceIoReport,
    correlations: &[TraceCorrelation],
    sources: &CodeLinkSourceChecks<'_>,
    limits: CodeLinkLimits,
) -> Result<CodeLinkReport, CodeLinkError> {
    validate_limits(limits)?;
    let source_verification = verify_source_identities(receipt, mapping, trace, sources)?;
    let indexes = build_link_indexes(receipt, mapping, sources, limits)?;
    let trace_events = index_correlations(trace, correlations)?;
    let batch = link_events(trace, &trace_events, &indexes, limits.max_links)?;
    let partial = batch.omitted_links > 0
        || !receipt.complete
        || !trace.complete
        || batch.missing_correlations > 0;
    Ok(CodeLinkReport {
        analysis_source_sha256: receipt.source_sha256.clone(),
        source_verification,
        mapping_document_sha256: sources.mapping_document_sha256.to_ascii_lowercase(),
        mapping_source_sha256: mapping.mapping_source_sha256.clone(),
        mapping_process_id: mapping.process_id,
        trace_source_sha256: trace.source_sha256.clone(),
        evidence_complete: receipt.complete && trace.complete && batch.missing_correlations == 0,
        partial,
        omitted_links: batch.omitted_links,
        links: batch.links,
        limitations: LIMITATIONS.to_vec(),
    })
}

fn build_link_indexes<'receipt>(
    receipt: &'receipt AnalysisReceipt,
    mapping: &RuntimeModuleMap,
    sources: &CodeLinkSourceChecks<'_>,
    limits: CodeLinkLimits,
) -> Result<LinkIndexes<'receipt>, CodeLinkError> {
    let runtime_ranges = validate_mappings(mapping, limits, sources.binary_bytes.map(<[u8]>::len))?;
    let runtime_range_index = RangeLookupIndex::from_ranges(runtime_ranges.iter().map(|range| {
        (
            range.mapping.runtime_start,
            range.mapping.runtime_end,
            range.index,
        )
    }));
    let functions = validate_functions(&receipt.functions, sources.binary_bytes)?;
    let function_index = RangeLookupIndex::from_ranges(functions.iter().enumerate().filter_map(
        |(index, function)| {
            Some((
                u64::try_from(function.function.file_offset).ok()?,
                u64::try_from(function.file_end).ok()?,
                index,
            ))
        },
    ));
    Ok(LinkIndexes {
        runtime_ranges,
        runtime_range_index,
        functions,
        function_index,
        mapping_process_id: mapping.process_id,
    })
}

fn link_events(
    trace: &TraceIoReport,
    trace_events: &[IndexedTraceEvent<'_, '_>],
    indexes: &LinkIndexes<'_>,
    max_links: usize,
) -> Result<LinkBatch, CodeLinkError> {
    let mut links = Vec::new();
    let mut omitted_links = 0_usize;
    let mut missing_correlations = 0_usize;
    for indexed_event in trace_events {
        let event = indexed_event.event;
        let correlation = indexed_event.correlation;
        if let Some(data_source_range) = &event.data_source_range {
            validate_trace_range(data_source_range, &trace.source_sha256, trace.source_length)?;
        }
        if correlation.is_none() {
            missing_correlations = missing_correlations.saturating_add(1);
        }
        if let Some(correlation) = correlation {
            validate_packet_ranges(&correlation.captured_ranges)?;
            if correlation.status == TraceMatchStatus::ExactUniqueMatch
                && (correlation.candidate_count != 1 || correlation.captured_ranges.is_empty())
            {
                return Err(CodeLinkError::InvalidTraceCorrelation);
            }
        }
        let mut io_bytes_sha256 = None;
        for frame in &event.frames {
            validate_trace_range(
                &frame.source_range,
                &trace.source_sha256,
                trace.source_length,
            )?;
            if links.len() >= max_links {
                omitted_links = omitted_links.saturating_add(1);
                continue;
            }
            // Reuse one syscall digest for every retained frame in this event
            let io_bytes_sha256 =
                io_bytes_sha256.get_or_insert_with(|| crate::sha256(&event.bytes));
            links.push(make_link(
                event,
                frame,
                correlation,
                indexes,
                io_bytes_sha256,
            ));
        }
    }
    Ok(LinkBatch {
        links,
        omitted_links,
        missing_correlations,
    })
}

fn verify_source_identities(
    receipt: &AnalysisReceipt,
    mapping: &RuntimeModuleMap,
    trace: &TraceIoReport,
    sources: &CodeLinkSourceChecks<'_>,
) -> Result<CodeLinkSourceVerification, CodeLinkError> {
    validate_sha256(&receipt.source_sha256, "analysis receipt source")?;
    validate_sha256(&mapping.binary_sha256, "runtime map binary")?;
    validate_sha256(&mapping.mapping_source_sha256, "runtime map source")?;
    validate_sha256(sources.mapping_document_sha256, "runtime map document")?;
    let trace_digest =
        trace
            .source_sha256
            .strip_prefix("sha256:")
            .ok_or(CodeLinkError::InvalidHash {
                field: "trace source",
            })?;
    validate_sha256(trace_digest, "trace source")?;
    if !receipt
        .source_sha256
        .eq_ignore_ascii_case(&mapping.binary_sha256)
    {
        return Err(CodeLinkError::BinaryHashMismatch);
    }
    let binary_source_verified = if let Some(bytes) = sources.binary_bytes {
        if !crate::sha256(bytes).eq_ignore_ascii_case(&receipt.source_sha256) {
            return Err(CodeLinkError::BinarySourceHashMismatch);
        }
        true
    } else {
        false
    };
    let mapping_source_verified = if let Some(bytes) = sources.mapping_source_bytes {
        if !crate::sha256(bytes).eq_ignore_ascii_case(&mapping.mapping_source_sha256) {
            return Err(CodeLinkError::MappingSourceHashMismatch);
        }
        true
    } else {
        false
    };
    Ok(CodeLinkSourceVerification {
        binary_source_verified,
        mapping_source_verified,
    })
}

fn make_link(
    event: &TraceIoEvent,
    frame: &TraceCodeFrame,
    correlation: Option<&TraceCorrelation>,
    indexes: &LinkIndexes<'_>,
    io_bytes_sha256: &str,
) -> CodeLink {
    let mut link = initial_link(event, frame, correlation, io_bytes_sha256);
    let Some(instruction_pointer) = frame.instruction_pointer else {
        return link;
    };
    let runtime_mapping = match indexes.runtime_mapping(instruction_pointer, event.pid) {
        Ok(mapping) => mapping,
        Err(status) => {
            link.status = status;
            return link;
        }
    };
    let file_offset = runtime_mapping
        .mapping
        .file_offset
        .checked_add(instruction_pointer - runtime_mapping.mapping.runtime_start);
    let Some(file_offset) = file_offset else {
        link.status = CodeLinkStatus::UnmappedRuntimeAddress;
        return link;
    };
    link.mapping_index = Some(runtime_mapping.index);
    link.mapping_runtime_start = Some(runtime_mapping.mapping.runtime_start);
    link.mapping_runtime_end = Some(runtime_mapping.mapping.runtime_end);
    link.mapped_file_offset = Some(file_offset);
    let static_function = match indexes.static_function(file_offset) {
        Ok(function) => function,
        Err(status) => {
            link.status = status;
            return link;
        }
    };
    set_function_link(&mut link, static_function, correlation);
    link
}

fn initial_link(
    event: &TraceIoEvent,
    frame: &TraceCodeFrame,
    correlation: Option<&TraceCorrelation>,
    io_bytes_sha256: &str,
) -> CodeLink {
    CodeLink {
        trace_source_range: event.source_range.clone(),
        frame_source_range: frame.source_range.clone(),
        data_source_range: event.data_source_range.clone(),
        process_id: event.pid,
        syscall: event.syscall.clone(),
        direction: event.direction,
        unwinder_module: frame.module.clone(),
        unwinder_symbol: frame.symbol.clone(),
        instruction_pointer: frame.instruction_pointer,
        mapping_index: None,
        mapping_runtime_start: None,
        mapping_runtime_end: None,
        mapped_file_offset: None,
        function_name: None,
        function_address: None,
        function_file_offset: None,
        function_code_sha256: None,
        io_bytes_sha256: io_bytes_sha256.to_owned(),
        io_bytes_length: event.bytes.len(),
        trace_match_status: correlation.map(|value| value.status),
        trace_candidate_count: correlation.map(|value| value.candidate_count),
        captured_ranges: Vec::new(),
        association: "same_syscall_stack_context",
        status: CodeLinkStatus::MissingInstructionPointer,
    }
}

fn set_function_link(
    link: &mut CodeLink,
    static_function: &ValidatedFunction<'_>,
    correlation: Option<&TraceCorrelation>,
) {
    let function = static_function.function;
    link.function_name = Some(function.name.clone());
    link.function_address = Some(function.address);
    link.function_file_offset = Some(function.file_offset);
    link.function_code_sha256 = Some(function.code_sha256.clone());
    if let Some(correlation) = correlation {
        link.captured_ranges
            .clone_from(&correlation.captured_ranges);
    }
    link.status = match correlation {
        Some(correlation)
            if correlation.status == TraceMatchStatus::ExactUniqueMatch
                && correlation.candidate_count == 1
                && !correlation.captured_ranges.is_empty() =>
        {
            CodeLinkStatus::FunctionMatchedWithPacketEvidence
        }
        Some(correlation) if !correlation.captured_ranges.is_empty() => {
            CodeLinkStatus::FunctionMappedWithPacketCandidates
        }
        _ => CodeLinkStatus::FunctionMappedWithoutPacketMatch,
    };
}
