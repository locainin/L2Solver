//! Route journal commands to bounded storage, review, and import helpers

#[path = "journal/derive.rs"]
mod derive;
#[path = "journal/imports.rs"]
mod imports;
#[path = "journal/read.rs"]
mod read;
#[path = "journal/review.rs"]
mod review;
#[path = "journal/write.rs"]
mod write;
pub(super) use review::write_html_entry;

use super::{input, load, read_bounded};
use crate::arguments::{JournalArgs, JournalCommand};
use l2_workbench::journal::{Journal, JournalOptions};
use serde::Serialize;
use std::{error::Error, io::Write, path::Path};

pub(super) fn run(args: &JournalArgs, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let options = JournalOptions {
        cache_mib: args.cache_mib,
        max_entry_bytes: args.max_entry_bytes,
        max_tool_report_bytes: args.max_tool_report_bytes,
    };
    if let JournalCommand::Create { case } = &args.operation {
        let base = load(case)?;
        crate::publish::create_directory(&args.directory, |stage| {
            drop(Journal::create(stage, &base, options)?);
            Ok(())
        })?;
    }
    if let JournalCommand::Migrate { destination } = &args.operation {
        crate::publish::create_directory(destination, |stage| {
            Journal::migrate_copy(&args.directory, stage, options)
        })?;
        let journal = Journal::open_readonly(destination, options)?;
        serde_json::to_writer(output, &journal.overview()?)?;
        return Ok(true);
    }

    let mut journal = if read::is_read_only(&args.operation) {
        Journal::open_readonly(&args.directory, options)?
    } else {
        Journal::open(&args.directory, options)?
    };
    match &args.operation {
        JournalCommand::Create { .. } => serde_json::to_writer(output, &journal.overview()?)?,
        JournalCommand::Derive {
            node,
            hypothesis,
            recipe,
        } => {
            return derive::run(
                &mut journal,
                *node,
                hypothesis.as_deref(),
                recipe,
                options.max_entry_bytes,
                output,
            );
        }
        JournalCommand::Verify
        | JournalCommand::Checks { .. }
        | JournalCommand::Entries { .. }
        | JournalCommand::Review { .. }
        | JournalCommand::Chains { .. }
        | JournalCommand::Export { .. }
        | JournalCommand::ExportEvidence { .. } => {
            read::run(&args.operation, &journal, options.max_entry_bytes, output)?;
        }
        JournalCommand::Add { .. }
        | JournalCommand::Check { .. }
        | JournalCommand::Events { .. }
        | JournalCommand::ImportTshark { .. } => {
            write::run(args, &mut journal, options.max_entry_bytes, output)?;
        }
        JournalCommand::Migrate { .. } => {}
    }
    Ok(true)
}

fn read_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    budget: usize,
) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_slice(&read_bounded(
        input::regular(path)?,
        budget,
    )?)?)
}

fn line(output: &mut impl Write, value: &impl Serialize) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer(&mut *output, value)?;
    output.write_all(b"\n")?;
    Ok(())
}
