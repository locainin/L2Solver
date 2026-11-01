//! Prepare a scoped ARP probe and use only the separately privileged helper

use std::{
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    ActiveOutcome, ArpProbeArgs, Error, OutputFormat,
    preflight::{HelperStage, PreflightStop, write_stopped},
};

pub fn run(
    options: &ArpProbeArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    if cancelled.load(Ordering::Acquire) {
        return write_stopped(
            "arp_probe",
            &options.interface,
            Some(options.target.into()),
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
    options: &ArpProbeArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    use l2_active_linux::HelperLink;

    use super::{arp_output, session_options};

    let Some((info, plan)) =
        super::preflight::cancelled_discovery(prepare(options, cancelled), cancelled)?
    else {
        return write_stopped(
            "arp_probe",
            &options.interface,
            Some(options.target.into()),
            format,
            output,
            PreflightStop::Cancelled,
            HelperStage::NotStarted,
        );
    };
    if cancelled.load(Ordering::Acquire) {
        return write_stopped(
            "arp_probe",
            &options.interface,
            Some(options.target.into()),
            format,
            output,
            PreflightStop::Cancelled,
            HelperStage::NotStarted,
        );
    }
    let helper = session_options::helper(options.session.helper.as_deref())?;
    // The same absolute deadline covers helper startup and packet collection
    let requested_deadline = session_options::deadline(plan.limits())?;
    // The worker rechecks this exact interface identity and plan before opening a socket
    let mut link = match HelperLink::open(
        &helper,
        &options.interface,
        &info,
        &plan,
        requested_deadline,
        cancelled,
    ) {
        Ok(link) => link,
        Err(error) => {
            return write_stopped(
                "arp_probe",
                &options.interface,
                Some(options.target.into()),
                format,
                output,
                super::preflight::open_failure(error, cancelled)?,
                HelperStage::Opening,
            );
        }
    };
    let admitted_deadline = link.deadline();
    let result = plan.run_until(&mut link, cancelled, admitted_deadline);
    let (report, close_error) = session_options::finish(result, link.close())?;
    arp_output::write(
        &options.interface,
        info.vlan(),
        &plan,
        &report,
        close_error.as_ref(),
        format,
        output,
    )
}

#[cfg(target_os = "linux")]
fn prepare(
    options: &ArpProbeArgs,
    cancelled: &AtomicBool,
) -> Result<(l2_active_linux::InterfaceInfo, l2_active::ArpProbe), Error> {
    let info = super::preflight::discover(&options.interface, cancelled)?;
    let source = l2_active_linux::select_arp_source(&info, options.source_ip, options.target)
        .map_err(Error::Scope)?;
    let mac = l2_onpath::MacAddress::new(info.mac()).map_err(Error::Address)?;
    let limits = super::session_options::limits(&options.session)?;
    let plan = l2_active::ArpProbe::new(mac, source, options.target, options.expected_mac, limits)
        .map_err(Error::Plan)?;
    Ok((info, plan))
}

#[cfg(not(target_os = "linux"))]
fn run_platform(
    _options: &ArpProbeArgs,
    _format: OutputFormat,
    _cancelled: &AtomicBool,
    _output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    Err(Error::Helper(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "active packet I/O requires Linux",
    )))
}
