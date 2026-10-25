//! Process boundary for bounded capture assessment and developer diagnostics

#![forbid(unsafe_code)]

mod baseline;
mod baseline_model;
mod bounded_json;
mod capture_compare;
mod capture_tcp;
mod completion;
mod dev;
mod export;
mod forensic_report;
mod html_report;
mod input;
mod inspect;
mod interfaces;
mod json;
mod observe;
mod outcome;
mod output;
mod presentation;
mod publish;
mod record;
mod relationships;
mod relationships_report;
mod render;
mod replay_time;
mod report;
mod safe_filename;
mod source_collection;
mod stp_render;
mod survey;
mod survey_report;
#[cfg(feature = "live")]
mod survey_stats;
mod wifi;
mod wifi_report;
mod workbench;

use l2_cli::arguments::{self, Command};
use outcome::RunOutcome;
use std::{
    env,
    error::Error,
    io::{self, IsTerminal, Write},
    path::Path,
    process::ExitCode,
};

fn run(command: &Command) -> Result<RunOutcome, Box<dyn Error>> {
    if let Some(path) = report_output(command) {
        // Rendering streams to a private inode; only a successful complete render is published
        return Ok(publish::create(path, |file| {
            let mut buffer = io::BufWriter::new(file);
            let outcome = execute(command, &mut buffer)
                .map_err(|error| io::Error::other(error.to_string()))?;
            buffer.flush()?;
            Ok(outcome)
        })?);
    }

    // Standard output permits an early consumer to close the pipe successfully
    let buffer = io::BufWriter::new(io::stdout().lock());
    let mut stdout = output::BrokenPipeWriter::new(buffer);
    // Closed output becomes a sink while the command finishes its semantic result
    let outcome = execute(command, &mut stdout)?;
    stdout.flush()?;
    Ok(outcome)
}

fn execute(command: &Command, output: &mut impl Write) -> Result<RunOutcome, Box<dyn Error>> {
    // One dispatcher keeps exit semantics identical across compatibility aliases
    match command {
        Command::Export(options) => Ok(completion_outcome(export::run(options, output)?)),
        Command::Inspect(path) => inspect_capture(path, output),
        Command::Relationships(path) => Ok(completion_outcome(relationships::run(path, output)?)),
        Command::Json(path) => {
            let mut link = l2_io::ReplayLink::new(input::capture(path)?)?;
            Ok(completion_outcome(json::write(&mut link, output)?))
        }
        Command::Observe(path) => observe_capture(path, output),
        Command::Wifi(options) => {
            Ok(wifi::run(options, output)?.process_outcome(options.report.fail_on_findings))
        }
        Command::Interfaces => Ok(completion_outcome(interfaces::run(
            output,
            &mut io::stderr().lock(),
        )?)),
        Command::Listen { interface, limit } => {
            Ok(completion_outcome(listen(interface, *limit, output)?))
        }
        Command::Record {
            interface,
            limit,
            output: path,
        } => Ok(completion_outcome(record::run(
            interface, *limit, path, output,
        )?)),
        Command::CaptureCompare(options) => {
            capture_compare::run(options, output)?;
            Ok(RunOutcome::Completed)
        }
        Command::CaptureTcp(options) => Ok(completion_outcome(capture_tcp::run(options, output)?)),
        Command::Workbench(command) => Ok(completion_outcome(workbench::run(command, output)?)),
        Command::Assess(options) => {
            // Compute the semantic result before presentation can encounter a closed pipe
            let assessment = survey::assess(options)?;
            let outcome = assessment
                .outcome
                .process_outcome(options.report.fail_on_findings);
            survey::render(options, &assessment, output)?;
            Ok(outcome)
        }
        Command::BaselineCreate {
            capture,
            output: path,
            sources,
        } => Ok(completion_outcome(baseline::create(
            capture, path, sources, output,
        )?)),
        Command::BaselineCompare {
            baseline: path,
            capture,
            fail_on_change,
            sources,
        } => compare_baseline(path, capture, sources, *fail_on_change, output),
        Command::PolicyValidate { policy } => {
            let policy: l2_audit::Policy = bounded_json::read(input::regular(policy)?, 65_536)?;
            policy.validate()?;
            writeln!(output, "Policy is valid")?;
            Ok(RunOutcome::Completed)
        }
        Command::Dev(command) => {
            dev::run(command, output)?;
            Ok(RunOutcome::Completed)
        }
    }
}

fn inspect_capture(path: &Path, output: &mut impl Write) -> Result<RunOutcome, Box<dyn Error>> {
    capture_path_header(output, path)?;
    let mut link = l2_io::ReplayLink::new(input::capture(path)?)
        .map_err(|error| input::capture_error(path, error))?;
    let summary = inspect::inspect(&mut link, output)
        .map_err(|error| input::boxed_capture_error(path, error))?;
    let complete =
        completion::complete(
            summary.malformed,
            summary.invalid,
            summary.unsupported,
            summary.truncated,
            [0, 0],
        ) && !l2_workbench::capture_collection::reports_incomplete_collection(summary.collection);
    writeln!(
        output,
        "Capture inspection: {}",
        if complete { "complete" } else { "incomplete" }
    )?;
    Ok(completion_outcome(complete))
}

fn observe_capture(path: &Path, output: &mut impl Write) -> Result<RunOutcome, Box<dyn Error>> {
    capture_path_header(output, path)?;
    let mut link = l2_io::ReplayLink::new(input::capture(path)?)
        .map_err(|error| input::capture_error(path, error))?;
    let complete = observe::observe(&mut link, output)
        .map_err(|error| input::boxed_capture_error(path, error))?;
    writeln!(
        output,
        "STP observation: {}",
        if complete { "complete" } else { "incomplete" }
    )?;
    Ok(completion_outcome(complete))
}

fn compare_baseline(
    path: &Path,
    capture: &Path,
    sources: &[arguments::SourceMapping],
    fail_on_change: bool,
    output: &mut impl Write,
) -> Result<RunOutcome, Box<dyn Error>> {
    let comparison = baseline::compare(path, capture, sources)?;
    // Incomplete evidence takes precedence over a change-sensitive exit
    let outcome = if comparison.status == baseline::BaselineCollectionStatus::Incomplete {
        RunOutcome::Incomplete
    } else if fail_on_change && !comparison.changes.is_empty() {
        RunOutcome::Findings
    } else {
        RunOutcome::Completed
    };
    baseline::render_comparison(&comparison, output)?;
    Ok(outcome)
}

const fn completion_outcome(complete: bool) -> RunOutcome {
    if complete {
        RunOutcome::Completed
    } else {
        RunOutcome::Incomplete
    }
}

fn capture_path_header(output: &mut impl Write, path: &Path) -> io::Result<()> {
    writeln!(
        output,
        "Capture: {}",
        path.display().to_string().escape_debug()
    )
}

fn report_output(command: &Command) -> Option<&Path> {
    match command {
        Command::Assess(options) => options.report.output.as_deref(),
        Command::Wifi(options) => options.report.output.as_deref(),
        Command::Workbench(command) => command.output(),
        _ => None,
    }
}

#[cfg(feature = "live")]
fn listen(
    interface: &str,
    limit: arguments::LiveLimit,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let packets = limit.packet_ceiling();
    let duration = limit.duration_ceiling();
    // Live inspection remains receive-only and bounded by both ceilings
    let mut link = l2_live::LiveLink::open_with_limits(interface, packets, duration)?;
    writeln!(
        io::stderr().lock(),
        "Listening on {} (inbound filter requested, non-promiscuous, receive-only; at most {packets} frames / {} seconds)",
        interface.escape_debug(),
        duration.as_secs()
    )?;
    let summary = inspect::inspect(&mut link, output)?;
    let stats = link.statistics()?;
    let reason = link.stop_reason();
    let quality =
        completion::LiveCaptureQuality::from_libpcap(reason, limit.duration_is_goal(), stats);
    let stop = match reason {
        Some(l2_live::StopReason::PacketLimit) => "packet-limit",
        Some(l2_live::StopReason::Deadline) => "deadline",
        None => "unavailable",
    };
    writeln!(
        output,
        "stop={stop} capture_received={} capture_dropped={} interface_dropped={} loss_counters_authoritative={}",
        stats.received(),
        stats.capture_dropped(),
        stats.interface_dropped(),
        stats.loss_counters_authoritative()
    )?;
    Ok(completion::complete_live(
        summary.malformed,
        summary.invalid,
        summary.unsupported,
        summary.truncated,
        &quality,
    ))
}

#[cfg(not(feature = "live"))]
fn listen(
    _interface: &str,
    _limit: arguments::LiveLimit,
    _output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    Err("live capture is optional; build with cargo build -p l2-cli --features live".into())
}

fn print_parse_error(error: &clap::Error) -> ExitCode {
    use clap::error::ErrorKind;

    // Missing top-level input prints help as a successful discovery action
    if error.kind() == ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand {
        // Diagnostic output cannot replace the command's semantic exit status
        let _ = write!(io::stdout().lock(), "{error}");
        return ExitCode::SUCCESS;
    }
    let success = matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    );
    // A closed diagnostic stream does not turn a usage error into success
    let _ = error.print();
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn main() -> ExitCode {
    // Argument parsing completes before any capture or filesystem operation starts
    let mut command = match arguments::parse_from(env::args_os()) {
        Ok(command) => command,
        Err(error) => return print_parse_error(&error),
    };
    resolve_color(&mut command);
    match run(&command) {
        Ok(outcome) => {
            // Publication and stdout flushing must finish before claiming an export succeeded
            print_export_notice(&command, outcome);
            print_output_notice(&command, outcome);
            outcome.exit_code()
        }
        Err(error) => {
            // Preserve failure even when stderr itself is unavailable
            let _ = writeln!(
                io::stderr().lock(),
                "error: {}",
                error.to_string().escape_debug()
            );
            ExitCode::FAILURE
        }
    }
}

fn print_output_notice(command: &Command, outcome: RunOutcome) {
    let path = match command {
        Command::Assess(options) => options.report.output.as_deref(),
        Command::Wifi(options) => options.report.output.as_deref(),
        Command::Workbench(
            arguments::WorkbenchCommand::Tshark(_)
            | arguments::WorkbenchCommand::ExtractNode { .. },
        ) => None,
        Command::Workbench(command) => command.output(),
        _ => None,
    };
    let Some(path) = path else {
        return;
    };
    let incomplete = if outcome == RunOutcome::Incomplete {
        " (result incomplete; exit status 3)"
    } else {
        ""
    };
    let _ = writeln!(
        io::stderr().lock(),
        "Output written to {}{incomplete}",
        path.display().to_string().escape_debug()
    );
}

fn print_export_notice(command: &Command, outcome: RunOutcome) {
    let Command::Workbench(arguments::WorkbenchCommand::ExtractNode { node, output, .. }) = command
    else {
        return;
    };
    let destination = match output {
        Some(path) => path.display().to_string(),
        None if outcome == RunOutcome::Incomplete => "stdout".to_owned(),
        // A complete binary stdout export stays quiet for callers that consume its bytes
        None => return,
    };
    let incomplete = if outcome == RunOutcome::Incomplete {
        "; case collection is incomplete (exit status 3)"
    } else {
        ""
    };
    // Diagnostics stay off binary stdout and cannot replace the semantic exit status
    let _ = writeln!(
        io::stderr().lock(),
        "Exported retained bytes from node {node} to {}{incomplete}",
        destination.escape_debug()
    );
}

fn resolve_color(command: &mut Command) {
    let report = match command {
        Command::Assess(options) => &mut options.report,
        Command::Wifi(options) => &mut options.report,
        _ => return,
    };

    // NO_COLOR takes precedence over an explicit command-line setting
    if env::var_os("NO_COLOR").is_some() {
        report.color = arguments::ColorChoice::Never;
        return;
    }
    // Automatic color is limited to an interactive terminal destination
    if report.color == arguments::ColorChoice::Auto {
        report.color = if report.output.is_none() && io::stdout().is_terminal() {
            arguments::ColorChoice::Always
        } else {
            arguments::ColorChoice::Never
        };
    }
}
