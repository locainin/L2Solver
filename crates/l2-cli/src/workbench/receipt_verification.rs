use l2_workbench::evidence::{ReceiptVerificationLimits, verify_index_flow_selection};
use std::{error::Error, io::Write, path::Path};

pub fn run(
    path: &Path,
    node: u64,
    max_input_bytes: Option<usize>,
    max_receipt_bytes: Option<usize>,
    max_list_entries: Option<usize>,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let case = super::load_with_limit(path, max_input_bytes)?;
    let report = verify_index_flow_selection(
        &case,
        node,
        ReceiptVerificationLimits {
            max_receipt_bytes,
            max_list_entries,
        },
    )?;

    // Verification finishes before any report bytes become visible
    serde_json::to_writer(output, &report)?;
    Ok(true)
}
