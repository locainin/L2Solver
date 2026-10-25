mod collection;
mod presentation;

use crate::{
    arguments::{OutputFormat, ReviewArgs},
    output::BoundedWriter,
};
use std::{error::Error, io::Write};

pub(super) fn run(args: &ReviewArgs, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let report = collection::collect(args)?;
    // The preview is separate from retained evidence and has its own output budget
    let mut bounded =
        BoundedWriter::named(output, args.max_report_bytes.get(), "investigation review");
    match args.format {
        OutputFormat::Html => presentation::html(&report, args.limit.get(), &mut bounded)?,
        OutputFormat::Json => serde_json::to_writer(&mut bounded, &report)?,
        OutputFormat::Text => presentation::text(&report, &mut bounded)?,
    }
    Ok(if args.format == OutputFormat::Html {
        presentation::html_view_complete(&report, args.limit.get())
    } else {
        report.complete
    })
}
