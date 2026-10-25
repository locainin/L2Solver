//! Apply journal commands that add retained state

use crate::arguments::{JournalArgs, JournalCommand};
use l2_workbench::journal::{Check, Hypothesis, Journal};
use std::{error::Error, io::Write};

pub(super) fn run(
    args: &JournalArgs,
    journal: &mut Journal,
    max_entry_bytes: usize,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    match &args.operation {
        JournalCommand::Add { model } => {
            let model: Hypothesis = super::read_json(model, max_entry_bytes)?;
            let id = journal.record(&model)?;
            serde_json::to_writer(output, &journal.entry(&id)?)?;
        }
        JournalCommand::Check {
            hypothesis,
            check,
            evidence,
        } => {
            let check: Check = super::read_json(check, max_entry_bytes)?;
            let evidence = super::read_bounded(super::input::regular(evidence)?, max_entry_bytes)?;
            journal.record_check(hypothesis, &check, &evidence)?;
            serde_json::to_writer(output, &journal.entry(hypothesis)?)?;
        }
        JournalCommand::Events { case, index } => {
            let added =
                super::imports::events(journal, case.as_deref(), index.as_deref(), args.cache_mib)?;
            serde_json::to_writer(
                output,
                &serde_json::json!({"events_added":added,"summary":journal.overview()?}),
            )?;
        }
        JournalCommand::ImportTshark {
            report,
            source,
            max_report_mib,
            max_source_mib,
        } => {
            let evidence_sha256 = super::imports::tshark_report(
                journal,
                report,
                source,
                *max_report_mib,
                *max_source_mib,
            )?;
            serde_json::to_writer(
                output,
                &serde_json::json!({
                    "evidence_sha256": evidence_sha256,
                    "summary": journal.overview()?
                }),
            )?;
        }
        _ => return Err("journal command does not add retained state".into()),
    }
    Ok(())
}
