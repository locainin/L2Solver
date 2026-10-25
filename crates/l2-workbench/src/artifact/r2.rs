use serde::Deserialize;

use super::{
    AnalysisFunction, AnalysisImport, AnalysisReceipt, AnalysisTool, ArtifactError, ArtifactReport,
    EntryPoint, ExternalObservation, FunctionRejectionReason, MAX_R2_CODE_BYTES,
    MAX_R2_FUNCTION_BYTES, MAX_R2_FUNCTIONS, MAX_R2_JSON_BYTES, MAX_REFERENCES, RejectedFunction,
};

const MAX_TOOL_VERSION_BYTES: usize = 128;
const MAX_FUNCTION_NAME_BYTES: usize = 512;
const MAX_REFERENCE_TEXT_BYTES: usize = 512;
const MAX_ENTRYPOINTS: usize = 256;
const R2_LIMITATIONS: [&str; 4] = [
    "Imported r2 names and cross-references are static tool observations, not verified runtime behavior",
    "A static cross-reference to an import does not prove that a function sends packets or derives keys at runtime",
    "Function bytes are copied from the original artifact and checked against the captured source hash",
    "Rejected function records remain in the receipt and make function coverage incomplete",
];

#[derive(Deserialize)]
struct R2EntryPoint {
    vaddr: u64,
    paddr: Option<u64>,
}

#[derive(Deserialize)]
struct R2Function {
    addr: u64,
    name: String,
    size: u64,
}

#[derive(Deserialize)]
struct R2Import {
    ordinal: Option<u64>,
    bind: Option<String>,
    #[serde(rename = "type")]
    symbol_type: Option<String>,
    name: String,
}

#[derive(Deserialize)]
struct R2Xref {
    from: u64,
    addr: u64,
    #[serde(rename = "type")]
    reference_type: String,
    refname: Option<String>,
}

struct BoundFunction {
    function: AnalysisFunction,
    address: u64,
    end: u64,
}

/// Translate bounded JSON arrays from r2 into a receipt tied to exact source bytes
///
/// The JSON values are the outputs of `iej`, `aflj`, `iij`, and `axlj` after a
/// read-only `aaa` analysis. Function bytes are re-read from the supplied image
/// through parsed executable mappings, rather than trusted from tool output
///
/// # Errors
/// Returns an error when source hashes, JSON records, ranges, or limits do not match
pub fn import_r2_json(
    source: &[u8],
    expected_source_sha256: &str,
    tool_version: &str,
    entrypoints_json: &[u8],
    functions_json: &[u8],
    imports_json: &[u8],
    xrefs_json: &[u8],
) -> Result<AnalysisReceipt, ArtifactError> {
    if crate::sha256(source) != expected_source_sha256 {
        return Err(ArtifactError::SourceHashMismatch);
    }
    if tool_version.is_empty() || tool_version.len() > MAX_TOOL_VERSION_BYTES {
        return Err(ArtifactError::InvalidR2Json {
            field: "tool version",
        });
    }
    check_json_budget(&[entrypoints_json, functions_json, imports_json, xrefs_json])?;
    let report = super::inspect(source)?;
    let entrypoints = parse_entrypoints(&report, entrypoints_json)?;
    let function_records = parse_functions(functions_json)?;
    let import_records = parse_imports(imports_json)?;
    let xref_records = parse_xrefs(xrefs_json)?;
    let (bound_functions, rejected_functions) = bind_functions(source, &report, function_records);
    let (functions, unassociated_observations) =
        bind_xrefs(&report, bound_functions, xref_records)?;
    let complete = rejected_functions.is_empty();
    Ok(AnalysisReceipt {
        tool: AnalysisTool {
            name: "radare2".to_owned(),
            version: tool_version.to_owned(),
        },
        source_sha256: report.sha256,
        complete,
        entrypoints,
        functions,
        rejected_functions,
        imports: import_records,
        unassociated_observations,
        limitations: R2_LIMITATIONS.to_vec(),
    })
}

fn check_json_budget(payloads: &[&[u8]]) -> Result<(), ArtifactError> {
    let total = payloads
        .iter()
        .try_fold(0_usize, |total, payload| total.checked_add(payload.len()));
    let total = total.ok_or(ArtifactError::R2JsonTooLarge {
        length: usize::MAX,
        maximum: MAX_R2_JSON_BYTES,
    })?;
    if total > MAX_R2_JSON_BYTES {
        return Err(ArtifactError::R2JsonTooLarge {
            length: total,
            maximum: MAX_R2_JSON_BYTES,
        });
    }
    Ok(())
}

fn parse_entrypoints(
    report: &ArtifactReport,
    json: &[u8],
) -> Result<Vec<EntryPoint>, ArtifactError> {
    let entries: Vec<R2EntryPoint> = parse_json(json, "entrypoints")?;
    if entries.len() > MAX_ENTRYPOINTS {
        return Err(ArtifactError::LimitExceeded {
            field: "r2 entrypoints",
            maximum: MAX_ENTRYPOINTS,
        });
    }
    entries
        .into_iter()
        .map(|entry| {
            let file_offset = report.executable_file_offset_for_address(entry.vaddr, 1)?;
            if entry
                .paddr
                .filter(|offset| *offset != u64::MAX)
                .is_some_and(|offset| usize::try_from(offset).ok() != Some(file_offset))
            {
                return Err(ArtifactError::InvalidR2Json {
                    field: "entrypoint file offset",
                });
            }
            Ok(EntryPoint {
                address: entry.vaddr,
                file_offset: Some(file_offset),
            })
        })
        .collect()
}

fn parse_functions(json: &[u8]) -> Result<Vec<R2Function>, ArtifactError> {
    let functions: Vec<R2Function> = parse_json(json, "functions")?;
    if functions.len() > MAX_R2_FUNCTIONS {
        return Err(ArtifactError::LimitExceeded {
            field: "r2 functions",
            maximum: MAX_R2_FUNCTIONS,
        });
    }
    if functions
        .iter()
        .any(|function| function.name.is_empty() || function.name.len() > MAX_FUNCTION_NAME_BYTES)
    {
        return Err(ArtifactError::InvalidR2Json {
            field: "function name",
        });
    }
    Ok(functions)
}

fn parse_imports(json: &[u8]) -> Result<Vec<AnalysisImport>, ArtifactError> {
    let imports: Vec<R2Import> = parse_json(json, "imports")?;
    if imports.len() > MAX_REFERENCES {
        return Err(ArtifactError::LimitExceeded {
            field: "r2 imports",
            maximum: MAX_REFERENCES,
        });
    }
    imports
        .into_iter()
        .map(|import| {
            if import.name.is_empty() || import.name.len() > MAX_REFERENCE_TEXT_BYTES {
                return Err(ArtifactError::InvalidR2Json {
                    field: "import name",
                });
            }
            Ok(AnalysisImport {
                ordinal: import.ordinal,
                binding: bounded_optional_text(import.bind, "import binding")?,
                symbol_type: bounded_optional_text(import.symbol_type, "import type")?,
                name: import.name,
            })
        })
        .collect()
}

fn parse_xrefs(json: &[u8]) -> Result<Vec<R2Xref>, ArtifactError> {
    let xrefs: Vec<R2Xref> = parse_json(json, "cross-references")?;
    if xrefs.len() > MAX_REFERENCES {
        return Err(ArtifactError::LimitExceeded {
            field: "r2 cross-references",
            maximum: MAX_REFERENCES,
        });
    }
    if xrefs.iter().any(|xref| {
        xref.reference_type.is_empty() || xref.reference_type.len() > MAX_REFERENCE_TEXT_BYTES
    }) {
        return Err(ArtifactError::InvalidR2Json {
            field: "cross-reference type",
        });
    }
    Ok(xrefs)
}

fn bind_xrefs(
    report: &ArtifactReport,
    mut functions: Vec<BoundFunction>,
    xrefs: Vec<R2Xref>,
) -> Result<(Vec<AnalysisFunction>, Vec<ExternalObservation>), ArtifactError> {
    let mut unassociated = Vec::new();
    for xref in xrefs {
        let observation = external_observation(report, xref)?;
        if let Some(index) = unique_containing_function(&functions, observation.from_address) {
            let function = functions
                .get_mut(index)
                .ok_or(ArtifactError::InvalidR2Json {
                    field: "cross-reference function index",
                })?;
            function.function.external_observations.push(observation);
        } else {
            unassociated.push(observation);
        }
    }
    Ok((
        functions.into_iter().map(|bound| bound.function).collect(),
        unassociated,
    ))
}

fn bind_functions(
    source: &[u8],
    report: &ArtifactReport,
    records: Vec<R2Function>,
) -> (Vec<BoundFunction>, Vec<RejectedFunction>) {
    let mut total_code_bytes = 0_usize;
    let mut functions = Vec::with_capacity(records.len());
    let mut rejected = Vec::new();
    for record in records {
        match bind_function(source, report, record, total_code_bytes) {
            Ok((function, next_total)) => {
                total_code_bytes = next_total;
                functions.push(function);
            }
            Err(rejected_function) => rejected.push(rejected_function),
        }
    }
    (functions, rejected)
}

fn bind_function(
    source: &[u8],
    report: &ArtifactReport,
    record: R2Function,
    total_code_bytes: usize,
) -> Result<(BoundFunction, usize), RejectedFunction> {
    let Some(size) = usize::try_from(record.size).ok() else {
        return Err(rejection(
            record,
            FunctionRejectionReason::FunctionSizeLimit,
        ));
    };
    if size == 0 {
        return Err(rejection(record, FunctionRejectionReason::EmptyRange));
    }
    if size > MAX_R2_FUNCTION_BYTES {
        return Err(rejection(
            record,
            FunctionRejectionReason::FunctionSizeLimit,
        ));
    }
    let Some(next_total) = total_code_bytes.checked_add(size) else {
        return Err(rejection(
            record,
            FunctionRejectionReason::AggregateCodeLimit,
        ));
    };
    if next_total > MAX_R2_CODE_BYTES {
        return Err(rejection(
            record,
            FunctionRejectionReason::AggregateCodeLimit,
        ));
    }
    let Some(virtual_end) = record.addr.checked_add(record.size) else {
        return Err(rejection(
            record,
            FunctionRejectionReason::AddressRangeOverflow,
        ));
    };
    let file_offset = match report.executable_file_offset_for_address(record.addr, size) {
        Ok(offset) => offset,
        Err(ArtifactError::UnmappedAddress { .. }) => {
            return Err(rejection(record, FunctionRejectionReason::UnmappedAddress));
        }
        Err(ArtifactError::AmbiguousAddress { .. }) => {
            return Err(rejection(record, FunctionRejectionReason::AmbiguousAddress));
        }
        Err(_) => {
            return Err(rejection(
                record,
                FunctionRejectionReason::SourceRangeUnavailable,
            ));
        }
    };
    let Some(file_end) = file_offset.checked_add(size) else {
        return Err(rejection(
            record,
            FunctionRejectionReason::SourceRangeUnavailable,
        ));
    };
    let Some(code) = source.get(file_offset..file_end) else {
        return Err(rejection(
            record,
            FunctionRejectionReason::SourceRangeUnavailable,
        ));
    };
    Ok((
        BoundFunction {
            address: record.addr,
            end: virtual_end,
            function: AnalysisFunction {
                name: record.name,
                address: record.addr,
                file_offset,
                code_length: size,
                code_bytes_hex: encode_hex(code),
                code_sha256: crate::sha256(code),
                external_observations: Vec::new(),
            },
        },
        next_total,
    ))
}

fn rejection(record: R2Function, reason: FunctionRejectionReason) -> RejectedFunction {
    RejectedFunction {
        name: record.name,
        address: record.addr,
        length: record.size,
        reason,
    }
}

fn unique_containing_function(functions: &[BoundFunction], address: u64) -> Option<usize> {
    let mut containing = functions
        .iter()
        .enumerate()
        .filter_map(|(index, function)| {
            (function.address <= address && address < function.end).then_some(index)
        });
    let first = containing.next()?;
    containing.next().is_none().then_some(first)
}

fn external_observation(
    report: &ArtifactReport,
    xref: R2Xref,
) -> Result<ExternalObservation, ArtifactError> {
    if xref
        .refname
        .as_ref()
        .is_some_and(|name| name.len() > MAX_REFERENCE_TEXT_BYTES)
    {
        return Err(ArtifactError::InvalidR2Json {
            field: "cross-reference name",
        });
    }
    Ok(ExternalObservation {
        from_address: xref.from,
        source_file_offset: report.file_offset_for_address(xref.from, 1).ok(),
        target_address: xref.addr,
        reference_type: xref.reference_type,
        reference_name: xref.refname,
    })
}

fn bounded_optional_text(
    value: Option<String>,
    field: &'static str,
) -> Result<Option<String>, ArtifactError> {
    if value
        .as_ref()
        .is_some_and(|text| text.len() > MAX_REFERENCE_TEXT_BYTES)
    {
        return Err(ArtifactError::InvalidR2Json { field });
    }
    Ok(value)
}

fn parse_json<T: serde::de::DeserializeOwned>(
    json: &[u8],
    field: &'static str,
) -> Result<T, ArtifactError> {
    serde_json::from_slice(json).map_err(|_| ArtifactError::InvalidR2Json { field })
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
