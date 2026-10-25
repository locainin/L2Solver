mod presentation;

use super::{input, read_bounded};
use crate::{
    arguments::{CorrelationArgs, CorrelationResources, OutputFormat},
    output::BoundedWriter,
};
use l2_workbench::{
    identity::{CorrelationOptions, CorrelationPlan, CorrelationReport, correlate},
    journal::{Journal, JournalOptions},
};
use std::{
    error::Error,
    io::{self, Write},
    path::Path,
};

pub(super) fn run(args: &CorrelationArgs, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let plan: CorrelationPlan = serde_json::from_slice(&read_bounded(
        input::regular_no_follow(&args.plan)?,
        args.resources.max_plan_bytes.get(),
    )?)?;
    let report = collect(&args.directory, &plan, &args.resources)?;
    match args.format {
        OutputFormat::Json => serde_json::to_writer(output, &report)?,
        OutputFormat::Html => presentation::html(&report, output)?,
        OutputFormat::Text => presentation::text(&report, output)?,
    }
    Ok(report.complete)
}

pub(super) fn collect(
    directory: &Path,
    plan: &CorrelationPlan,
    args: &CorrelationResources,
) -> Result<CorrelationReport, Box<dyn Error>> {
    let journal = Journal::open_readonly(
        directory,
        JournalOptions {
            cache_mib: args.cache_mib.get(),
            max_entry_bytes: args.max_entry_bytes.get(),
            max_tool_report_bytes: args.max_tool_report_bytes.get(),
        },
    )?;
    journal.read_snapshot(|journal| collect_in_snapshot(journal, plan, args))
}

pub(super) fn collect_in_snapshot(
    journal: &Journal,
    plan: &CorrelationPlan,
    args: &CorrelationResources,
) -> Result<CorrelationReport, Box<dyn Error>> {
    let mut events = Vec::new();
    let mut retained_bytes = 0;
    let mut visited = 0_u64;
    let mut retain_prefix = true;
    journal.visit_events(0, None, |event| {
        if visited == args.max_work_items.get() {
            return Err("event scan exhausted the shared correlation work budget".into());
        }
        visited += 1;
        if events.len() == args.max_events.get() || !retain_prefix {
            return Ok(());
        }
        // A sink counts bytes before another event enters the retained working set
        let mut counter = BoundedWriter::named(
            io::sink(),
            args.max_retained_bytes.get() - retained_bytes,
            "correlation events",
        );
        match serde_json::to_writer(&mut counter, &event) {
            Ok(()) => {
                retained_bytes += counter.written();
                events.push(event);
            }
            Err(error) if error.is_io() => retain_prefix = false,
            Err(error) => return Err(error.into()),
        }
        Ok(())
    })?;
    let mut report = correlate(
        &events,
        plan,
        CorrelationOptions {
            max_events: args.max_events.get(),
            max_work_items: args.max_work_items.get() - visited,
        },
    )?;
    report.omitted_events = usize::try_from(visited)? - report.events.len();
    report.work_items += visited;
    report.complete = report.omitted_events == 0;
    Ok(report)
}
