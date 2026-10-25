//! Handle journal commands that inspect retained state

use crate::arguments::JournalCommand;
use l2_workbench::journal::{ChainPlan, Journal};
use std::{error::Error, io::Write};

pub(super) const fn is_read_only(command: &JournalCommand) -> bool {
    matches!(
        command,
        JournalCommand::Create { .. }
            | JournalCommand::Verify
            | JournalCommand::Checks { .. }
            | JournalCommand::Entries { .. }
            | JournalCommand::Review { .. }
            | JournalCommand::Chains { .. }
            | JournalCommand::Export { .. }
            | JournalCommand::ExportEvidence { .. }
    )
}

pub(super) fn run(
    command: &JournalCommand,
    journal: &Journal,
    max_entry_bytes: usize,
    output: &mut impl Write,
) -> Result<(), Box<dyn Error>> {
    match command {
        JournalCommand::Verify => {
            journal.verify()?;
            serde_json::to_writer(
                output,
                &serde_json::json!({"verified":true,"summary":journal.overview()?}),
            )?;
        }
        JournalCommand::Checks {
            hypothesis,
            after,
            limit,
        } => journal.visit_checks(hypothesis, *after, *limit, |check| {
            super::line(output, &check)
        })?,
        JournalCommand::Entries { after, limit } => {
            journal.visit_entries(after.as_deref(), *limit, |entry| {
                super::line(output, &entry)
            })?;
        }
        JournalCommand::Review { format, limit } => {
            super::review::render(journal, *format, *limit, output)?;
        }
        JournalCommand::Chains { plan } => {
            let plan: ChainPlan = super::read_json(plan, max_entry_bytes)?;
            journal.visit_chains(&plan, |chain| super::line(output, &chain))?;
        }
        JournalCommand::Export { hypothesis } => output.write_all(&journal.output(hypothesis)?)?,
        JournalCommand::ExportEvidence { reference } => {
            journal.write_evidence(reference, output)?;
        }
        _ => return Err("journal command is not read-only".into()),
    }
    Ok(())
}
