use super::*;

#[test]
fn ordered_frames_keep_mapping_hash() -> Result<(), Box<dyn Error>> {
    const RANGE_COUNT: usize = 1_024;
    const RANGE_STRIDE: u64 = 0x20;

    let binary = super::super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let mapping_source = b"large ordered runtime map";
    let mut mappings = Vec::with_capacity(RANGE_COUNT);
    let (mut trace, correlations) = trace_evidence(Some(0x7000_0002), true);
    let event = trace.events.first_mut().ok_or("trace event is missing")?;
    event.bytes = vec![0xA5; 4_096];
    let mut frames = Vec::with_capacity(RANGE_COUNT);
    let first_frame = event
        .frames
        .first()
        .cloned()
        .ok_or("stack frame is missing")?;

    for index in (0..RANGE_COUNT).rev() {
        let index_u64 = u64::try_from(index)?;
        let runtime_start = 0x7000_0000 + index_u64 * RANGE_STRIDE;
        mappings.push(RuntimeModuleMapping {
            runtime_start,
            runtime_end: runtime_start + 0x10,
            file_offset: 0x100,
        });
    }
    for index in 0..RANGE_COUNT {
        let index_u64 = u64::try_from(index)?;
        let runtime_start = 0x7000_0000 + index_u64 * RANGE_STRIDE;
        let mut frame = first_frame.clone();
        frame.instruction_pointer = Some(runtime_start + 2);
        frames.push(frame);
    }
    event.frames = frames;

    let module_map = RuntimeModuleMap {
        binary_sha256: receipt.source_sha256.clone(),
        mapping_source_sha256: l2_workbench::sha256(mapping_source),
        process_id: Some(1_234),
        mappings,
    };
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
        CodeLinkLimits {
            max_mappings: RANGE_COUNT,
            max_links: RANGE_COUNT,
        },
    )?;

    assert_eq!(report.links.len(), RANGE_COUNT);
    assert_eq!(report.omitted_links, 0);
    let event = trace.events.first().ok_or("trace event is missing")?;
    let expected_io_hash = l2_workbench::sha256(&event.bytes);
    for (index, link) in report.links.iter().enumerate() {
        assert_eq!(link.mapping_index, Some(RANGE_COUNT - index - 1));
        assert_eq!(link.io_bytes_sha256, expected_io_hash);
        assert_eq!(
            link.status,
            CodeLinkStatus::FunctionMatchedWithPacketEvidence
        );
    }
    Ok(())
}

#[test]
fn adjacent_ranges_use_half_open() -> Result<(), Box<dyn Error>> {
    let binary = super::super::support::minimal_elf()?;
    let receipt = receipt_for(&binary)?;
    let mapping_source = b"adjacent runtime ranges";
    let base = 0x7000_0000;
    let module_map = RuntimeModuleMap {
        binary_sha256: receipt.source_sha256.clone(),
        mapping_source_sha256: l2_workbench::sha256(mapping_source),
        process_id: Some(1_234),
        mappings: vec![
            RuntimeModuleMapping {
                runtime_start: base + 0x10,
                runtime_end: base + 0x20,
                file_offset: 0x100,
            },
            RuntimeModuleMapping {
                runtime_start: base,
                runtime_end: base + 0x10,
                file_offset: 0x100,
            },
            RuntimeModuleMapping {
                runtime_start: base + 0x20,
                runtime_end: base + 0x30,
                file_offset: 0x108,
            },
        ],
    };
    let (mut trace, correlations) = trace_evidence(Some(base), true);
    let event = trace.events.first_mut().ok_or("trace event is missing")?;
    let mut frames = Vec::new();
    let frame = event
        .frames
        .first()
        .cloned()
        .ok_or("stack frame is missing")?;
    for instruction_pointer in [base + 0x10, base + 0x20, base + 0x30] {
        let mut frame = frame.clone();
        frame.instruction_pointer = Some(instruction_pointer);
        frames.push(frame);
    }
    event.frames = frames;

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
        CodeLinkLimits {
            max_mappings: 3,
            max_links: 3,
        },
    )?;

    let adjacent = report
        .links
        .first()
        .ok_or("adjacent range link is missing")?;
    assert_eq!(adjacent.mapping_index, Some(0));
    assert_eq!(
        adjacent.status,
        CodeLinkStatus::FunctionMatchedWithPacketEvidence
    );
    let function_end = report.links.get(1).ok_or("function end link is missing")?;
    assert_eq!(function_end.mapping_index, Some(2));
    assert_eq!(
        function_end.status,
        CodeLinkStatus::NoFunctionAtMappedOffset
    );
    let runtime_end = report.links.get(2).ok_or("runtime end link is missing")?;
    assert_eq!(runtime_end.mapping_index, None);
    assert_eq!(runtime_end.status, CodeLinkStatus::UnmappedRuntimeAddress);
    Ok(())
}
