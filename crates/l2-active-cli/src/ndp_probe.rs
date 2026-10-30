//! Prepare one link-local IPv6 probe with a pinned native interface

use std::{
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    ActiveOutcome, Error, NdpProbeArgs, OutputFormat,
    preflight::{HelperStage, PreflightStop, write_stopped},
};

pub fn run(
    options: &NdpProbeArgs,
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
    options: &NdpProbeArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    use l2_active_linux::HelperLink;

    use super::{ndp_output, session_options};

    let (info, plan) = prepare(options)?;
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
    let requested_deadline = session_options::deadline(plan.limits())?;
    // The helper repeats source assignment and scope validation before sending
    let mut link = match HelperLink::open_ndp(
        &helper,
        &options.interface,
        &info,
        &plan,
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
    ndp_output::write(
        options,
        &plan,
        &report,
        close_error.as_ref(),
        format,
        output,
    )
}

#[cfg(target_os = "linux")]
fn prepare(
    options: &NdpProbeArgs,
) -> Result<(l2_active_linux::ndp::NdpInterfaceInfo, l2_active::NdpProbe), Error> {
    let info = l2_active_linux::ndp::discover(&options.interface).map_err(Error::Discovery)?;
    let limits = super::session_options::limits(&options.session)?;
    let plan = l2_active_linux::ndp::prepare(
        &info,
        options.source_ip,
        options.target,
        options.expected_mac,
        limits,
    )
    .map_err(Error::Scope)?;
    Ok((info, plan))
}

#[cfg(not(target_os = "linux"))]
fn run_platform(
    _options: &NdpProbeArgs,
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
    options: &NdpProbeArgs,
    format: OutputFormat,
    output: &mut impl Write,
    reason: PreflightStop,
    stage: HelperStage,
) -> Result<ActiveOutcome, Error> {
    write_stopped(
        "ndp_probe",
        &options.interface,
        Some(options.target.into()),
        format,
        output,
        reason,
        stage,
    )
}
