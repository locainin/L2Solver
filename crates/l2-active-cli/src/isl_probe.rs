//! Run bounded receive-only ISL observations

use std::{
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    ActiveOutcome, Error, ObserveArgs, OutputFormat,
    preflight::{HelperStage, PreflightStop, write_stopped},
};

pub fn run(
    options: &ObserveArgs,
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
    options: &ObserveArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    use crate::{
        listen_output::{collection::Context, isl},
        observer_session::{self, Prepared},
        session_options,
    };

    let Prepared { info, limits, deadline, helper } = match observer_session::prepare(options, cancelled) {
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
    let monitor = l2_active::isl::IslMonitor::new(limits);
    let mut link = match l2_active_linux::HelperLink::open_isl(
        &helper,
        &options.interface,
        &info,
        &monitor,
        deadline,
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
    // Preserve the helper's deadline and close it even when collection fails
    let admitted_deadline = link.deadline();
    let result = monitor.run_until(&mut link, cancelled, admitted_deadline);
    let (report, close_error) = session_options::finish(result, link.close())?;
    let context = Context::new(options, info.vlan(), limits, close_error.as_ref());
    isl::write(&context, &report, format, output)
}

#[cfg(not(target_os = "linux"))]
fn run_platform(
    _options: &ObserveArgs,
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
    options: &ObserveArgs,
    format: OutputFormat,
    output: &mut impl Write,
    reason: PreflightStop,
    stage: HelperStage,
) -> Result<ActiveOutcome, Error> {
    write_stopped(
        "isl_observe",
        &options.interface,
        None,
        format,
        output,
        reason,
        stage,
    )
}
