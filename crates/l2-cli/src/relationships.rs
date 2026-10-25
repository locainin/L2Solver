//! Human-readable capture relationships from the canonical passive audit

use crate::{relationships_report, survey};
use l2_audit::Policy;
use std::{error::Error, io::Write, path::Path};

pub fn run(capture: &Path, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let report = survey::from_file(capture, &Policy::default())?;
    writeln!(
        output,
        "Capture: {}",
        capture.display().to_string().escape_debug()
    )?;
    relationships_report::write(&report, output)?;
    Ok(report.collection_complete())
}
