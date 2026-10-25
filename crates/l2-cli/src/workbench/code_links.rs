//! Build source-qualified links from explicit runtime maps and trace evidence

use super::{input, read_bounded};
use crate::arguments::CodeLinksArgs;
use l2_workbench::{
    artifact::{self, AnalysisReceipt, CodeLinkLimits, CodeLinkSourceChecks, RuntimeModuleMap},
    endpoint::{TraceCorrelation, TraceIoReport},
};
use serde::Deserialize;
use std::{error::Error, io::Write};

const MAX_BINARY_BYTES: usize = artifact::MAX_ARTIFACT_BYTES;

#[derive(Deserialize)]
struct TraceMatchInput {
    trace: TraceIoReport,
    correlations: Vec<TraceCorrelation>,
}

pub(super) fn run(args: &CodeLinksArgs, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    if args.max_input_bytes == 0 || args.max_mappings == 0 || args.max_links == 0 {
        return Err("code-link input and output limits must be positive".into());
    }
    let receipt: AnalysisReceipt = read_json(&args.receipt, args.max_input_bytes)?;
    let trace_matches: TraceMatchInput = read_json(&args.trace_matches, args.max_input_bytes)?;
    let mapping_bytes = read_bounded(input::regular(&args.runtime_map)?, args.max_input_bytes)?;
    let mapping: RuntimeModuleMap = serde_json::from_slice(&mapping_bytes)?;
    let binary_bytes = args
        .binary
        .as_ref()
        .map(|path| read_bounded(input::regular(path)?, MAX_BINARY_BYTES))
        .transpose()?;
    let mapping_source_bytes = args
        .mapping_source
        .as_ref()
        .map(|path| read_bounded(input::regular(path)?, args.max_input_bytes))
        .transpose()?;
    let mapping_document_sha256 = l2_workbench::sha256(&mapping_bytes);
    let report = artifact::link_code_to_trace(
        &receipt,
        &mapping,
        &trace_matches.trace,
        &trace_matches.correlations,
        &CodeLinkSourceChecks {
            mapping_document_sha256: &mapping_document_sha256,
            binary_bytes: binary_bytes.as_deref(),
            mapping_source_bytes: mapping_source_bytes.as_deref(),
        },
        CodeLinkLimits {
            max_mappings: args.max_mappings,
            max_links: args.max_links,
        },
    )?;
    serde_json::to_writer(&mut *output, &report)?;
    writeln!(output)?;
    Ok(report.evidence_complete && !report.partial)
}

fn read_json<T: serde::de::DeserializeOwned>(
    path: &std::path::Path,
    maximum: usize,
) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_slice(&read_bounded(
        input::regular(path)?,
        maximum,
    )?)?)
}
