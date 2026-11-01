//! Open the fixed receive-only MPLS helper

use std::{
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    ActiveOutcome, Error, MplsObserveArgs, OutputFormat,
    preflight::{HelperStage, PreflightStop, write_stopped},
};

pub fn run(
    options: &MplsObserveArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    if cancelled.load(Ordering::Acquire) {
        return stopped(
            options,
            format,
            output,
            PreflightStop::Cancelled,
            HelperStage::NotStarted,
        );
    }
    run_platform(options, format, cancelled, output)
}

#[cfg(target_os = "linux")]
fn run_platform(
    options: &MplsObserveArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    use l2_active::mpls::MplsMonitor;
    use l2_active_linux::HelperLink;

    use crate::{
        listen_output::collection::Context, mpls_output, observer_session, session_options,
    };

    // Preparation shares one deadline across discovery, admission, and capture
    let prepared = match observer_session::prepare(&options.observe, cancelled) {
        Ok(prepared) => prepared,
        Err(Error::Discovery(error)) => {
            return stopped(
                options,
                format,
                output,
                crate::preflight::discovery_failure(error, cancelled)?,
                HelperStage::NotStarted,
            );
        }
        Err(error) => return Err(error),
    };
    // The helper verifies that the selected local MAC agrees with this monitor
    let monitor = MplsMonitor::new(
        prepared.info.mac(),
        options.expected_top_label,
        prepared.limits,
    )
    .map_err(|_| Error::CodesOnly {
        code: "invalid_scope",
        stage: "scope",
    })?;
    let mut link = match HelperLink::open_mpls(
        &prepared.helper,
        &options.observe.interface,
        &prepared.info,
        &monitor,
        prepared.deadline,
        cancelled,
    ) {
        Ok(link) => link,
        Err(error) => {
            return stopped(
                options,
                format,
                output,
                crate::preflight::open_failure(error, cancelled)?,
                HelperStage::Opening,
            );
        }
    };
    let admitted_deadline = link.deadline();
    let result = monitor.run_until(&mut link, cancelled, admitted_deadline);
    // Preserve the observations even when helper cleanup is unconfirmed
    let (report, close_error) = session_options::finish(result, link.close())?;
    let context = Context::new(
        &options.observe,
        prepared.info.vlan(),
        prepared.limits,
        close_error.as_ref(),
    );
    mpls_output::write(&context, &report, format, output)
}

#[cfg(not(target_os = "linux"))]
fn run_platform(
    _options: &MplsObserveArgs,
    _format: OutputFormat,
    _cancelled: &AtomicBool,
    _output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    Err(Error::Helper(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "active packet I/O requires Linux",
    )))
}

fn stopped(
    options: &MplsObserveArgs,
    format: OutputFormat,
    output: &mut impl Write,
    reason: PreflightStop,
    stage: HelperStage,
) -> Result<ActiveOutcome, Error> {
    write_stopped(
        "mpls_observe",
        &options.observe.interface,
        None,
        format,
        output,
        reason,
        stage,
    )
}
