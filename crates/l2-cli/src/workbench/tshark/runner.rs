use super::{
    count,
    decode::decode_capture,
    executable::verify_executable_unchanged,
    inspection::inspect_tool,
    preparation::{prepare_capture, verify_prepared_capture},
    receipt::build_report,
    snapshot::HashControl,
};
use crate::arguments::TsharkOptions;
use std::{error::Error, io::Write};

/// Enrich one regular offline capture with `TShark` and emit its source-bound receipt
pub(in crate::workbench) fn run(
    options: &TsharkOptions,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let mut prepared = prepare_capture(options)?;
    let inspection = inspect_tool(&prepared)?;
    let counted = count::capture(&prepared)?;
    let decoded = decode_capture(&prepared)?;
    // A consecutive decoded prefix is complete only when it covers the separate source traversal
    if u64::try_from(decoded.packets.len())? != counted.receipt.count {
        return Err("TShark decoded packet count differs from the source packet count".into());
    }
    verify_prepared_capture(&mut prepared, None)?;
    verify_executable_unchanged(
        &mut prepared.executable.file,
        prepared.executable_bytes,
        &prepared.executable_sha256,
        HashControl {
            deadline: prepared.deadline,
            job: None,
        },
    )?;
    let report = build_report(prepared, inspection, counted, decoded);
    serde_json::to_writer(output, &report)?;
    Ok(true)
}
