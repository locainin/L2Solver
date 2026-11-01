//! Run bounded receive-only native discovery and spanning-tree collection

use std::{
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    ActiveOutcome, Error, ListenArgs, OutputFormat,
    preflight::{HelperStage, PreflightStop, write_stopped},
};

#[derive(Clone, Copy)]
pub enum Kind {
    Stp,
    Discovery,
}

impl Kind {
    const fn operation(self) -> &'static str {
        match self {
            Self::Stp => "stp_observe",
            Self::Discovery => "discovery_observe",
        }
    }
}

pub fn run(
    kind: Kind,
    options: &ListenArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    if cancelled.load(Ordering::Acquire) {
        return stopped(
            kind,
            options,
            format,
            output,
            PreflightStop::Cancelled,
            HelperStage::NotStarted,
        );
    }
    run_platform(kind, options, format, cancelled, output)
}

#[cfg(target_os = "linux")]
fn run_platform(
    kind: Kind,
    options: &ListenArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    use super::{listen_output, session_options};
    let Some(info) = super::preflight::cancelled_discovery(
        super::preflight::discover(&options.interface, cancelled),
        cancelled,
    )?
    else {
        return stopped(
            kind,
            options,
            format,
            output,
            PreflightStop::Cancelled,
            HelperStage::NotStarted,
        );
    };
    let limits = session_options::limits(&options.session)?;
    if cancelled.load(Ordering::Acquire) {
        return stopped(
            kind,
            options,
            format,
            output,
            PreflightStop::Cancelled,
            HelperStage::NotStarted,
        );
    }
    let helper = session_options::helper(options.session.helper.as_deref())?;
    let deadline = session_options::deadline(limits)?;
    // Each helper intent joins its configured receive-only multicast groups
    let opened = open(kind, &helper, options, &info, limits, deadline, cancelled);
    let mut link = match opened {
        Ok(link) => link,
        Err(error) => {
            return stopped(
                kind,
                options,
                format,
                output,
                super::preflight::open_failure(error, cancelled)?,
                HelperStage::Opening,
            );
        }
    };
    let deadline = link.deadline();
    let result = collect(kind, &mut link, limits, cancelled, deadline);
    let (report, close_error) = session_options::finish(result, link.close())?;
    match report {
        Collected::Stp(report) => listen_output::write_stp(
            &options.interface,
            info.vlan(),
            limits,
            &report,
            close_error.as_ref(),
            format,
            output,
        ),
        Collected::Discovery(report) => listen_output::write_discovery(
            &options.interface,
            info.vlan(),
            limits,
            &report,
            close_error.as_ref(),
            format,
            output,
        ),
    }
}

#[cfg(target_os = "linux")]
fn open(
    kind: Kind,
    helper: &std::path::Path,
    options: &ListenArgs,
    info: &l2_active_linux::InterfaceInfo,
    limits: l2_active::Limits,
    deadline: std::time::Instant,
    cancelled: &AtomicBool,
) -> std::io::Result<l2_active_linux::HelperLink> {
    match kind {
        Kind::Stp => l2_active_linux::HelperLink::open_stp(
            helper,
            &options.interface,
            info,
            limits,
            deadline,
            cancelled,
        ),
        Kind::Discovery => l2_active_linux::HelperLink::open_discovery(
            helper,
            &options.interface,
            info,
            limits,
            deadline,
            cancelled,
        ),
    }
}

#[cfg(target_os = "linux")]
fn collect(
    kind: Kind,
    link: &mut l2_active_linux::HelperLink,
    limits: l2_active::Limits,
    cancelled: &AtomicBool,
    deadline: std::time::Instant,
) -> Result<Collected, l2_active::RunError> {
    match kind {
        Kind::Stp => l2_active::stp::StpMonitor::new(limits)
            .run_until(link, cancelled, deadline)
            .map(Collected::Stp),
        Kind::Discovery => l2_active::discovery::DiscoveryMonitor::new(limits)
            .run_until(link, cancelled, deadline)
            .map(Collected::Discovery),
    }
}

#[cfg(target_os = "linux")]
enum Collected {
    Stp(l2_active::stp::StpReport),
    Discovery(l2_active::discovery::DiscoveryReport),
}

#[cfg(not(target_os = "linux"))]
fn run_platform(
    _kind: Kind,
    _options: &ListenArgs,
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
    kind: Kind,
    options: &ListenArgs,
    format: OutputFormat,
    output: &mut impl Write,
    reason: PreflightStop,
    stage: HelperStage,
) -> Result<ActiveOutcome, Error> {
    write_stopped(
        kind.operation(),
        &options.interface,
        None,
        format,
        output,
        reason,
        stage,
    )
}
