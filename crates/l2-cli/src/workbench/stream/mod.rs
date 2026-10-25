mod manifest;
mod model;
mod pages;
mod source;

use crate::{arguments::OutputFormat, input, publish};
use model::Manifest;
pub(super) use model::Receipt;
pub(super) use model::{Page, Source};
use std::{error::Error, fs::File, io::Write, path::Path};

pub(super) fn run(
    capture: &Path,
    directory: &Path,
    page_records: u16,
    context_records: u16,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    super::validate_directory_format(format)?;
    let mut file = input::regular(capture)?;
    let source = source::scan(&mut file, capture)?;
    let receipt = publish::create_directory(directory, |staging| {
        let analysis_complete = !l2_workbench::capture_collection::reports_incomplete_collection(
            source.collection_summary,
        );
        let mut manifest = Manifest { schema_version: 1, source, raw_collection_complete: true,
            analysis_complete, context_records, pages: Vec::new(), limitations: vec![
                "Pages retain all primary records with bounded prior-record context; protocol state and event chains beyond each window remain unresolved".to_owned(),
                "Page-local node identifiers require the page path; source packet numbers and file offsets remain global".to_owned(),
                "Raw coverage and analysis completeness are separate; parser, reconstruction, and evidence omissions remain explicit in every case".to_owned(),
            ] };
        let page_bytes = pages::write_pages(&mut file, staging, &mut manifest, page_records)?;
        let manifest_sha256 = manifest::write(staging, &manifest, page_bytes)?;
        File::open(staging)?.sync_all()?;
        Ok(Receipt {
            schema_version: 1,
            source_id: manifest.source.id,
            pages: manifest.pages.len(),
            manifest_sha256,
            raw_collection_complete: manifest.raw_collection_complete,
            analysis_complete: manifest.analysis_complete,
        })
    })?;
    write_receipt(output, format, directory, &receipt)?;
    Ok(receipt.raw_collection_complete && receipt.analysis_complete)
}

fn write_receipt(
    output: &mut impl Write,
    format: OutputFormat,
    directory: &Path,
    receipt: &Receipt,
) -> Result<(), Box<dyn Error>> {
    match format {
        OutputFormat::Json => serde_json::to_writer(output, receipt)?,
        OutputFormat::Text => {
            let path = directory.display().to_string();
            writeln!(output, "Created stream directory: {}", path.escape_debug())?;
            writeln!(
                output,
                "Pages: {}; raw collection: {}; analysis: {}",
                receipt.pages,
                completeness(receipt.raw_collection_complete),
                completeness(receipt.analysis_complete)
            )?;
        }
        OutputFormat::Html => return Err("directory summaries support only text or JSON".into()),
    }
    Ok(())
}

const fn completeness(complete: bool) -> &'static str {
    if complete { "complete" } else { "incomplete" }
}
