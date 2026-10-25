use l2_workbench::{
    artifact::{
        self, AnalysisReceipt, CodeLinkLimits, CodeLinkSourceChecks, CodeLinkStatus,
        RuntimeModuleMap, RuntimeModuleMapping,
    },
    endpoint::{
        IoDirection, TraceCodeFrame, TraceCorrelation, TraceIoEvent, TraceIoReport,
        TraceMatchStatus, TracePacketRange,
    },
    evidence::SourceRange,
};
use std::error::Error;

mod scaling;
mod source_verification;

const NO_XREFS: &[u8] = b"[]";

#[test]
fn relocated_stack_exact_packet_ranges() -> Result<(), Box<dyn Error>> {
    let binary = super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let mapping_source = b"00400000-00401000 r-xp 00000100 /sample/module\n";
    let module_map = one_mapping(
        &receipt,
        mapping_source,
        RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x100,
        },
    );
    let (trace, correlations) = trace_evidence(Some(0x7000_0002), true);
    let document_bytes = serde_json::to_vec(&module_map)?;
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &l2_workbench::sha256(&document_bytes),
        binary_bytes: Some(&binary),
        mapping_source_bytes: Some(mapping_source),
    };

    let report = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    )?;

    let link = report.links.first().ok_or("frame link is missing")?;
    assert_eq!(report.analysis_source_sha256, receipt.source_sha256);
    assert!(report.source_verification.binary_source_verified);
    assert!(report.source_verification.mapping_source_verified);
    assert_eq!(
        report.mapping_document_sha256,
        l2_workbench::sha256(&document_bytes)
    );
    assert_eq!(
        link.status,
        CodeLinkStatus::FunctionMatchedWithPacketEvidence
    );
    assert_eq!(link.instruction_pointer, Some(0x7000_0002));
    assert_eq!(link.mapped_file_offset, Some(0x102));
    assert_eq!(link.function_name.as_deref(), Some("sample_handler"));
    assert_eq!(link.function_address, Some(0x0040_0000));
    let static_function = receipt
        .functions
        .first()
        .ok_or("static function is missing")?;
    assert_eq!(
        link.function_code_sha256.as_deref(),
        Some(static_function.code_sha256.as_str())
    );
    assert_eq!(link.trace_source_range.source, trace.source_sha256);
    let correlation = correlations.first().ok_or("trace correlation is missing")?;
    assert_eq!(link.captured_ranges, correlation.captured_ranges);
    assert_eq!(link.association, "same_syscall_stack_context");
    assert!(report.limitations.iter().any(|limitation| {
        limitation.contains("does not establish") && limitation.contains("caused")
    }));
    Ok(())
}

#[test]
fn mismatched_binary_rejected_frame_linking() -> Result<(), Box<dyn Error>> {
    let binary = super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let map = one_mapping(
        &receipt,
        b"runtime map source",
        RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x100,
        },
    );
    let (trace, correlations) = trace_evidence(Some(0x7000_0002), true);
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&map)?);
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(&binary),
        mapping_source_bytes: None,
    };
    let mut wrong_map = map;
    wrong_map.binary_sha256 = l2_workbench::sha256(b"different module bytes");

    let result = artifact::link_code_to_trace(
        &receipt,
        &wrong_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    );

    assert!(matches!(
        result,
        Err(artifact::CodeLinkError::BinaryHashMismatch)
    ));
    Ok(())
}

#[test]
fn overlapping_runtime_mapping_is_ambiguous() -> Result<(), Box<dyn Error>> {
    let binary = super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let mapping_source = b"two overlapping runtime mappings";
    let mut module_map = one_mapping(
        &receipt,
        mapping_source,
        RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x100,
        },
    );
    module_map.mappings.push(RuntimeModuleMapping {
        runtime_start: 0x7000_0001,
        runtime_end: 0x7000_0011,
        file_offset: 0x100,
    });
    let (trace, correlations) = trace_evidence(Some(0x7000_0002), true);
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&module_map)?);
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(&binary),
        mapping_source_bytes: Some(mapping_source),
    };

    let report = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    )?;

    let link = report.links.first().ok_or("frame link is missing")?;
    assert_eq!(link.status, CodeLinkStatus::AmbiguousRuntimeMapping);
    assert_eq!(link.function_name, None);
    assert!(link.captured_ranges.is_empty());
    Ok(())
}

#[test]
fn process_identity_applying_runtime_addresses() -> Result<(), Box<dyn Error>> {
    let binary = super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let mut module_map = one_mapping(
        &receipt,
        b"runtime map source",
        RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x100,
        },
    );
    module_map.process_id = None;
    let (trace, correlations) = trace_evidence(Some(0x7000_0002), true);
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&module_map)?);
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(&binary),
        mapping_source_bytes: None,
    };

    let report = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    )?;

    let link = report.links.first().ok_or("frame link is missing")?;
    assert_eq!(link.status, CodeLinkStatus::ProcessIdentityUnavailable);
    assert_eq!(link.function_name, None);
    assert!(link.captured_ranges.is_empty());
    Ok(())
}

#[test]
fn malformed_overflowing_map_ranges_rejected() -> Result<(), Box<dyn Error>> {
    let binary = super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let (trace, correlations) = trace_evidence(Some(u64::MAX - 1), true);
    let mut module_map = one_mapping(
        &receipt,
        b"runtime map source",
        RuntimeModuleMapping {
            runtime_start: 1,
            runtime_end: u64::MAX,
            file_offset: 2,
        },
    );
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&module_map)?);
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(&binary),
        mapping_source_bytes: None,
    };

    let overflow = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    );
    assert!(matches!(
        overflow,
        Err(artifact::CodeLinkError::InvalidMapping { .. })
    ));

    let mapping = module_map
        .mappings
        .first_mut()
        .ok_or("runtime mapping is missing")?;
    mapping.runtime_start = 0x7000_0000;
    mapping.runtime_end = 0x7000_0010;
    mapping.file_offset = u64::MAX - 2;
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&module_map)?);
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(&binary),
        mapping_source_bytes: None,
    };
    let file_offset_overflow = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    );
    assert!(matches!(
        file_offset_overflow,
        Err(artifact::CodeLinkError::InvalidMapping { .. })
    ));
    Ok(())
}

#[test]
fn frame_outside_missing_ip_unresolved() -> Result<(), Box<dyn Error>> {
    let binary = super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let module_map = one_mapping(
        &receipt,
        b"runtime map source",
        RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x108,
        },
    );
    let (trace, correlations) = trace_evidence(Some(0x7000_0001), true);
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&module_map)?);
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(&binary),
        mapping_source_bytes: None,
    };
    let report = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    )?;
    assert_eq!(
        report.links.first().map(|link| link.status),
        Some(CodeLinkStatus::NoFunctionAtMappedOffset)
    );

    let (trace, correlations) = trace_evidence(None, false);
    let report = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    )?;
    assert_eq!(
        report.links.first().map(|link| link.status),
        Some(CodeLinkStatus::MissingInstructionPointer)
    );
    assert!(
        report
            .links
            .first()
            .is_some_and(|link| link.captured_ranges.is_empty())
    );
    Ok(())
}

#[test]
fn function_mapping_without_packet_match() -> Result<(), Box<dyn Error>> {
    let binary = super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let module_map = one_mapping(
        &receipt,
        b"runtime map source",
        RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x100,
        },
    );
    let (trace, correlations) = trace_evidence(Some(0x7000_0002), false);
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&module_map)?);
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(&binary),
        mapping_source_bytes: None,
    };

    let report = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    )?;

    let link = report.links.first().ok_or("frame link is missing")?;
    assert_eq!(
        link.status,
        CodeLinkStatus::FunctionMappedWithoutPacketMatch
    );
    assert!(link.captured_ranges.is_empty());
    assert_eq!(
        link.trace_match_status,
        Some(TraceMatchStatus::BytesNotObserved)
    );
    Ok(())
}

#[test]
fn incorrect_optional_binary_bytes_rejected() -> Result<(), Box<dyn Error>> {
    let binary = super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let mapping_source = b"runtime map source";
    let module_map = one_mapping(
        &receipt,
        mapping_source,
        RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x100,
        },
    );
    let (trace, correlations) = trace_evidence(Some(0x7000_0002), true);
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&module_map)?);
    let bad_map_source = b"a different raw map source";
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(&binary),
        mapping_source_bytes: Some(bad_map_source),
    };
    let map_result = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    );
    assert!(matches!(
        map_result,
        Err(artifact::CodeLinkError::MappingSourceHashMismatch)
    ));

    let bad_binary = b"not the analyzed module";
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(bad_binary),
        mapping_source_bytes: None,
    };
    let binary_result = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    );
    assert!(matches!(
        binary_result,
        Err(artifact::CodeLinkError::BinarySourceHashMismatch)
    ));
    Ok(())
}

#[test]
fn overlapping_static_ranges_marked_ambiguous() -> Result<(), Box<dyn Error>> {
    let binary = super::support::minimal_elf()?;
    let mut receipt = receipt_for(&binary)?;
    let mut duplicate = receipt
        .functions
        .first()
        .ok_or("static function is missing")?
        .clone();
    duplicate.name = "overlapping_handler".to_owned();
    receipt.functions.push(duplicate);
    let module_map = one_mapping(
        &receipt,
        b"runtime map source",
        RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x100,
        },
    );
    let (trace, correlations) = trace_evidence(Some(0x7000_0002), true);
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&module_map)?);
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(&binary),
        mapping_source_bytes: None,
    };

    let report = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits::default(),
    )?;

    assert_eq!(
        report.links.first().map(|link| link.status),
        Some(CodeLinkStatus::AmbiguousStaticFunction)
    );
    assert!(
        report
            .links
            .first()
            .is_some_and(|link| link.captured_ranges.is_empty())
    );
    Ok(())
}

#[test]
fn output_budget_omitted_frames_partial() -> Result<(), Box<dyn Error>> {
    let binary = super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let module_map = one_mapping(
        &receipt,
        b"runtime map source",
        RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x100,
        },
    );
    let (mut trace, correlations) = trace_evidence(Some(0x7000_0002), true);
    let frame = trace
        .events
        .first()
        .and_then(|event| event.frames.first())
        .cloned()
        .ok_or("stack frame is missing")?;
    trace
        .events
        .first_mut()
        .ok_or("trace event is missing")?
        .frames
        .push(frame);
    let document_hash = l2_workbench::sha256(&serde_json::to_vec(&module_map)?);
    let sources = CodeLinkSourceChecks {
        mapping_document_sha256: &document_hash,
        binary_bytes: Some(&binary),
        mapping_source_bytes: None,
    };

    let report = artifact::link_code_to_trace(
        &receipt,
        &module_map,
        &trace,
        &correlations,
        &sources,
        CodeLinkLimits {
            max_mappings: 1,
            max_links: 1,
        },
    )?;

    assert_eq!(report.links.len(), 1);
    assert_eq!(report.omitted_links, 1);
    assert!(report.partial);
    Ok(())
}

fn receipt_for(binary: &[u8]) -> Result<AnalysisReceipt, Box<dyn Error>> {
    Ok(artifact::import_r2_json(
        binary,
        &l2_workbench::sha256(binary),
        "6.2.2",
        b"[]",
        br#"[{"addr":4194304,"name":"sample_handler","size":8}]"#,
        NO_XREFS,
        NO_XREFS,
    )?)
}

fn one_mapping(
    receipt: &AnalysisReceipt,
    mapping_source: &[u8],
    mapping: RuntimeModuleMapping,
) -> RuntimeModuleMap {
    RuntimeModuleMap {
        binary_sha256: receipt.source_sha256.clone(),
        mapping_source_sha256: l2_workbench::sha256(mapping_source),
        process_id: Some(1_234),
        mappings: vec![mapping],
    }
}

fn trace_evidence(
    instruction_pointer: Option<u64>,
    exact_packet_match: bool,
) -> (TraceIoReport, Vec<TraceCorrelation>) {
    let trace_source = format!("sha256:{}", l2_workbench::sha256(b"observed syscall trace"));
    let frame_source = SourceRange {
        source: trace_source.clone(),
        packet: None,
        offset: 36,
        length: 54,
    };
    let event_source = SourceRange {
        source: trace_source.clone(),
        packet: None,
        offset: 0,
        length: 91,
    };
    let event = TraceIoEvent {
        pid: Some(1_234),
        syscall: "sendto".to_owned(),
        fd: Some(5),
        direction: IoDirection::OutOfProcess,
        socket: None,
        bytes: b"network payload".to_vec(),
        bytes_complete: true,
        frames: vec![TraceCodeFrame {
            module: Some("/sample/module".to_owned()),
            symbol: Some("sample_handler".to_owned()),
            symbol_offset: Some(2),
            instruction_pointer,
            raw: "> /sample/module(sample_handler+0x2) [0x70000002]".to_owned(),
            source_range: frame_source,
        }],
        return_value: Some(15),
        source_range: event_source.clone(),
        data_source_range: None,
    };
    let correlation = TraceCorrelation {
        trace_source_range: event_source,
        status: if exact_packet_match {
            TraceMatchStatus::ExactUniqueMatch
        } else {
            TraceMatchStatus::BytesNotObserved
        },
        candidate_count: u64::from(exact_packet_match),
        captured_ranges: if exact_packet_match {
            vec![TracePacketRange {
                source: "sha256:capture-source".to_owned(),
                packet: 7,
                offset: 128,
                length: 15,
            }]
        } else {
            Vec::new()
        },
        explanation: "fixture syscall match state".to_owned(),
    };
    (
        TraceIoReport {
            source_sha256: trace_source,
            source_length: 91,
            events: vec![event],
            incomplete_events: 0,
            unsupported_io_lines: 0,
            omitted_stack_frames: 0,
            omitted_events: 0,
            ignored_lines: 0,
            complete: true,
            stack_frames_observed: true,
            limitations: Vec::new(),
        },
        vec![correlation],
    )
}
