//! Prepare one DHCP discovery using the selected interface's own identity

use std::{
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    ActiveOutcome, DhcpProbeArgs, Error, OutputFormat,
    preflight::{HelperStage, PreflightStop, write_stopped},
};

pub fn run(
    options: &DhcpProbeArgs,
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
    options: &DhcpProbeArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    use l2_active_linux::HelperLink;

    use super::{dhcp_output, session_options};

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
    // Helper startup and capture use the same admitted deadline
    let requested_deadline = session_options::deadline(plan.limits())?;
    let mut link = match HelperLink::open_dhcp(
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
    dhcp_output::write(
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
    options: &DhcpProbeArgs,
) -> Result<(l2_active_linux::InterfaceInfo, l2_active::dhcp::DhcpProbe), Error> {
    let info = l2_active_linux::discover(&options.interface).map_err(Error::Discovery)?;
    let source = l2_onpath::MacAddress::new(info.mac()).map_err(Error::Address)?;
    let limits = super::session_options::limits(&options.session)?;
    let allowed =
        (!options.expected_server.is_empty()).then_some(options.expected_server.as_slice());
    let plan = l2_active::dhcp::DhcpProbe::new(source, transaction()?, allowed, limits)
        .map_err(Error::DhcpPlan)?;
    Ok((info, plan))
}

#[cfg(target_os = "linux")]
fn transaction() -> Result<std::num::NonZeroU32, Error> {
    for _ in 0..8 {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes)
            .map_err(|error| Error::Entropy(std::io::Error::other(error.to_string())))?;
        if let Some(value) = std::num::NonZeroU32::new(u32::from_ne_bytes(bytes)) {
            return Ok(value);
        }
    }
    Err(Error::Entropy(std::io::Error::other(
        "random source returned only zero transaction IDs",
    )))
}

#[cfg(not(target_os = "linux"))]
fn run_platform(
    _options: &DhcpProbeArgs,
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
    options: &DhcpProbeArgs,
    format: OutputFormat,
    output: &mut impl Write,
    reason: PreflightStop,
    stage: HelperStage,
) -> Result<ActiveOutcome, Error> {
    write_stopped(
        "dhcp_probe",
        &options.interface,
        None,
        format,
        output,
        reason,
        stage,
    )
}
