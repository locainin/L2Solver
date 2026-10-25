use super::model::Manifest;
use crate::workbench::bundle_budget::charge_document;
use std::{error::Error, fs::File, io::Write, path::Path};

pub(super) fn write(
    directory: &Path,
    manifest: &Manifest,
    page_bytes: u64,
) -> Result<String, Box<dyn Error>> {
    let document = serde_json::to_vec(manifest)?;
    // The manifest consumes the same document budget as the retained pages
    charge_document(page_bytes, document.len())?;
    let mut output = File::create_new(directory.join("manifest.json"))?;
    output.write_all(&document)?;
    output.sync_all()?;
    Ok(l2_workbench::sha256(&document))
}

#[cfg(test)]
#[path = "../../../tests/workbench/stream/manifest.rs"]
mod tests;
