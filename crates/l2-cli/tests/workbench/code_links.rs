use super::support::{path_arg, run};
use l2_workbench::{
    artifact::{
        AnalysisFunction, AnalysisReceipt, AnalysisTool, RuntimeModuleMap, RuntimeModuleMapping,
    },
    endpoint::{
        IoDirection, TraceCodeFrame, TraceCorrelation, TraceIoEvent, TraceIoReport,
        TraceMatchStatus, TracePacketRange,
    },
    evidence::SourceRange,
};
use serde_json::Value;
use std::{error::Error, fs, path::Path};
use tempfile::tempdir;

#[test]
fn code_command_mapping_source_provenance() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let (receipt, mapping, trace) = synthetic_evidence();
    let receipt_path = save_json(directory.path(), "analysis.json", &receipt)?;
    let trace_path = save_json(directory.path(), "trace-matches.json", &trace)?;
    let mapping_path = save_json(directory.path(), "runtime-map.json", &mapping)?;
    let source_path = directory.path().join("maps.txt");
    fs::write(&source_path, b"mapping source record\n")?;

    let output = run(
        &[
            "code-links",
            path_arg(&receipt_path)?,
            "--trace-matches",
            path_arg(&trace_path)?,
            "--runtime-map",
            path_arg(&mapping_path)?,
            "--mapping-source",
            path_arg(&source_path)?,
        ],
        b"",
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        report.pointer("/mapping_source_verified"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        report.pointer("/binary_source_verified"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        report.pointer("/links/0/status"),
        Some(&Value::String(
            "function_matched_with_packet_evidence".to_owned()
        ))
    );
    assert_eq!(
        report.pointer("/links/0/association"),
        Some(&Value::String("same_syscall_stack_context".to_owned()))
    );
    assert!(
        report
            .pointer("/limitations")
            .and_then(Value::as_array)
            .is_some_and(|limitations| limitations.iter().any(|item| {
                item.as_str()
                    .is_some_and(|text| text.contains("does not establish"))
            }))
    );
    Ok(())
}

#[test]
fn code_command_mapping_hash_mismatch() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let (receipt, mut mapping, trace) = synthetic_evidence();
    let receipt_path = save_json(directory.path(), "analysis.json", &receipt)?;
    let trace_path = save_json(directory.path(), "trace-matches.json", &trace)?;
    let mapping_path = save_json(directory.path(), "runtime-map.json", &mapping)?;
    let limited = run(
        &[
            "code-links",
            path_arg(&receipt_path)?,
            "--trace-matches",
            path_arg(&trace_path)?,
            "--runtime-map",
            path_arg(&mapping_path)?,
            "--max-input-bytes",
            "1",
        ],
        b"",
    )?;
    assert_eq!(limited.status.code(), Some(1));
    assert!(limited.stdout.is_empty());
    assert!(String::from_utf8_lossy(&limited.stderr).contains("input exceeds 1 bytes"));

    mapping.binary_sha256 = l2_workbench::sha256(b"a different analyzed binary identity");
    let wrong_mapping_path = save_json(directory.path(), "wrong-runtime-map.json", &mapping)?;
    let mismatch = run(
        &[
            "code-links",
            path_arg(&receipt_path)?,
            "--trace-matches",
            path_arg(&trace_path)?,
            "--runtime-map",
            path_arg(&wrong_mapping_path)?,
        ],
        b"",
    )?;
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(mismatch.stdout.is_empty());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("differs from the static receipt"));
    Ok(())
}

fn synthetic_evidence() -> (AnalysisReceipt, RuntimeModuleMap, TraceMatchInput) {
    let binary_digest = l2_workbench::sha256(b"synthetic analyzed binary identity");
    let code = [0x90_u8, 0xc3];
    let code_digest = l2_workbench::sha256(&code);
    let receipt = AnalysisReceipt {
        tool: AnalysisTool {
            name: "r2".to_owned(),
            version: "test version".to_owned(),
        },
        source_sha256: binary_digest.clone(),
        complete: true,
        entrypoints: Vec::new(),
        functions: vec![AnalysisFunction {
            name: "synthetic_handler".to_owned(),
            address: 0x0040_1000,
            file_offset: 0x100,
            code_length: code.len(),
            code_bytes_hex: "90c3".to_owned(),
            code_sha256: code_digest,
            external_observations: Vec::new(),
        }],
        rejected_functions: Vec::new(),
        imports: Vec::new(),
        unassociated_observations: Vec::new(),
        limitations: Vec::new(),
    };
    let mapping_source = b"mapping source record\n";
    let mapping = RuntimeModuleMap {
        binary_sha256: binary_digest,
        mapping_source_sha256: l2_workbench::sha256(mapping_source),
        process_id: Some(4242),
        mappings: vec![RuntimeModuleMapping {
            runtime_start: 0x7000_0000,
            runtime_end: 0x7000_0010,
            file_offset: 0x100,
        }],
    };
    let trace = synthetic_trace_input();
    (receipt, mapping, trace)
}

fn synthetic_trace_input() -> TraceMatchInput {
    let trace_source = format!("sha256:{}", l2_workbench::sha256(b"synthetic trace"));
    let event_range = SourceRange {
        source: trace_source.clone(),
        packet: None,
        offset: 0,
        length: 20,
    };
    let frame_range = SourceRange {
        source: trace_source.clone(),
        packet: None,
        offset: 1,
        length: 8,
    };
    TraceMatchInput {
        trace: TraceIoReport {
            source_sha256: trace_source,
            source_length: 20,
            events: vec![TraceIoEvent {
                pid: Some(4242),
                syscall: "sendto".to_owned(),
                fd: Some(3),
                direction: IoDirection::OutOfProcess,
                socket: None,
                bytes: b"abc".to_vec(),
                bytes_complete: true,
                frames: vec![TraceCodeFrame {
                    module: Some("/sample/module".to_owned()),
                    symbol: Some("synthetic_handler".to_owned()),
                    symbol_offset: Some(2),
                    instruction_pointer: Some(0x7000_0001),
                    raw: "module(symbol+0x2) [0x70000002]".to_owned(),
                    source_range: frame_range,
                }],
                return_value: Some(3),
                source_range: event_range.clone(),
                data_source_range: None,
            }],
            incomplete_events: 0,
            unsupported_io_lines: 0,
            omitted_stack_frames: 0,
            omitted_events: 0,
            ignored_lines: 0,
            complete: true,
            stack_frames_observed: true,
            limitations: Vec::new(),
        },
        correlations: vec![TraceCorrelation {
            trace_source_range: event_range,
            status: TraceMatchStatus::ExactUniqueMatch,
            candidate_count: 1,
            captured_ranges: vec![TracePacketRange {
                source: format!("sha256:{}", l2_workbench::sha256(b"synthetic capture")),
                packet: 1,
                offset: 64,
                length: 3,
            }],
            explanation: "exact syscall bytes matched one captured range".to_owned(),
        }],
    }
}

#[derive(serde::Serialize)]
struct TraceMatchInput {
    trace: TraceIoReport,
    correlations: Vec<TraceCorrelation>,
}

fn save_json<T: serde::Serialize>(
    directory: &Path,
    name: &str,
    value: &T,
) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let path = directory.join(name);
    fs::write(&path, serde_json::to_vec(value)?)?;
    Ok(path)
}
