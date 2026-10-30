//! Send an explicitly acknowledged EAPOL Start on a dedicated interface

use std::{
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    ActiveOutcome, Dot1xProbeArgs, Error, OutputFormat,
    preflight::{HelperStage, PreflightStop, write_stopped},
};

pub fn run(
    options: &Dot1xProbeArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    if !options.allow_eapol_start || !options.dedicated_interface {
        return Err(Error::Scope(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "EAPOL Start requires disruption consent and a dedicated interface acknowledgement",
        )));
    }
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
    options: &Dot1xProbeArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    use super::{dot1x_output, session_options};
    use l2_active_linux::HelperLink;

    let info = l2_active_linux::discover(&options.interface).map_err(Error::Discovery)?;
    let source = l2_onpath::MacAddress::new(info.mac()).map_err(Error::Address)?;
    let limits = session_options::limits(&options.session)?;
    let plan = l2_active::dot1x::Dot1xProbe::new(source, limits)
        .map_err(|error| Error::Encoding(io::Error::other(error)))?;
    if cancelled.load(Ordering::Acquire) {
        return stopped(
            options,
            format,
            output,
            PreflightStop::Cancelled,
            HelperStage::NotStarted,
        );
    }
    let helper = session_options::helper(options.session.helper.as_deref())?;
    let requested_deadline = session_options::deadline(limits)?;
    // The helper independently requires the dedication acknowledgement
    let mut link = match HelperLink::open_dot1x(
        &helper,
        &options.interface,
        &info,
        &plan,
        options.dedicated_interface,
        requested_deadline,
        cancelled,
    ) {
        Ok(link) => link,
        Err(error) => {
            return stopped(
                options,
                format,
                output,
                super::preflight::open_failure(error, cancelled)?,
                HelperStage::Opening,
            );
        }
    };
    let deadline = link.deadline();
    let result = plan.run_until(&mut link, cancelled, deadline);
    let (report, close_error) = session_options::finish(result, link.close())?;
    dot1x_output::write(
        options,
        &plan,
        &report,
        close_error.as_ref(),
        format,
        output,
    )
}

#[cfg(not(target_os = "linux"))]
fn run_platform(
    _options: &Dot1xProbeArgs,
    _format: OutputFormat,
    _cancelled: &AtomicBool,
    _output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    Err(Error::Helper(io::Error::new(
        io::ErrorKind::Unsupported,
        "active packet I/O requires Linux",
    )))
}

fn stopped(
    options: &Dot1xProbeArgs,
    format: OutputFormat,
    output: &mut impl Write,
    reason: PreflightStop,
    stage: HelperStage,
) -> Result<ActiveOutcome, Error> {
    write_stopped(
        "dot1x_probe",
        &options.interface,
        None,
        format,
        output,
        reason,
        stage,
    )
}
