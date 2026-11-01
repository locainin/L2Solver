//! Run bounded receive-only DTP and VTP observations

use std::{
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    ActiveOutcome, Error, ObserveArgs, OutputFormat,
    preflight::{HelperStage, PreflightStop, write_stopped},
};

/// Select one Cisco switching protocol for observation
#[derive(Clone, Copy)]
pub enum Kind {
    Dtp,
    Vtp,
}

impl Kind {
    const fn operation(self) -> &'static str {
        match self {
            Self::Dtp => "dtp_observe",
            Self::Vtp => "vtp_observe",
        }
    }
}

pub fn run(
    kind: Kind,
    options: &ObserveArgs,
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
    options: &ObserveArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    use crate::{
        listen_output::{collection::Context, switching},
        observer_session::{self, Prepared},
        session_options,
    };

    let Prepared { info, limits, deadline, helper } = match observer_session::prepare(options, cancelled) {
        Ok(prepared) => prepared,
        Err(Error::Discovery(error)) => {
            return stopped(
                kind,
                options,
                format,
                output,
                crate::preflight::discovery_failure(error, cancelled)?,
                HelperStage::NotStarted,
            );
        }
        Err(error) => return Err(error),
    };
    let plan = Plan::new(kind, limits);
    let mut link = match plan.open(&helper, options, &info, deadline, cancelled) {
        Ok(link) => link,
        Err(error) => {
            return stopped(
                kind,
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
    let result = plan.collect(&mut link, cancelled, admitted_deadline);
    let (report, close_error) = session_options::finish(result, link.close())?;
    let context = Context::new(options, info.vlan(), limits, close_error.as_ref());
    match report {
        Collected::Dtp(report) => switching::write_dtp(&context, &report, format, output),
        Collected::Vtp(report) => switching::write_vtp(&context, &report, format, output),
    }
}

#[cfg(target_os = "linux")]
enum Plan {
    Dtp(l2_active::switching::dtp::DtpMonitor),
    Vtp(l2_active::switching::vtp::VtpMonitor),
}

#[cfg(target_os = "linux")]
impl Plan {
    const fn new(kind: Kind, limits: l2_active::Limits) -> Self {
        match kind {
            Kind::Dtp => Self::Dtp(l2_active::switching::dtp::DtpMonitor::new(limits)),
            Kind::Vtp => Self::Vtp(l2_active::switching::vtp::VtpMonitor::new(limits)),
        }
    }
    fn open(
        &self,
        helper: &std::path::Path,
        options: &ObserveArgs,
        info: &l2_active_linux::InterfaceInfo,
        deadline: std::time::Instant,
        cancelled: &AtomicBool,
    ) -> std::io::Result<l2_active_linux::HelperLink> {
        match self {
            Self::Dtp(monitor) => l2_active_linux::HelperLink::open_dtp(
                helper,
                &options.interface,
                info,
                monitor,
                deadline,
                cancelled,
            ),
            Self::Vtp(monitor) => l2_active_linux::HelperLink::open_vtp(
                helper,
                &options.interface,
                info,
                monitor,
                deadline,
                cancelled,
            ),
        }
    }
    fn collect(
        &self,
        link: &mut l2_active_linux::HelperLink,
        cancelled: &AtomicBool,
        deadline: std::time::Instant,
    ) -> Result<Collected, l2_active::RunError> {
        match self {
            Self::Dtp(monitor) => monitor
                .run_until(link, cancelled, deadline)
                .map(Collected::Dtp),
            Self::Vtp(monitor) => monitor
                .run_until(link, cancelled, deadline)
                .map(Collected::Vtp),
        }
    }
}

#[cfg(target_os = "linux")]
enum Collected {
    Dtp(l2_active::switching::dtp::DtpReport),
    Vtp(l2_active::switching::vtp::VtpReport),
}

#[cfg(not(target_os = "linux"))]
fn run_platform(
    _kind: Kind,
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
    kind: Kind,
    options: &ObserveArgs,
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

#[cfg(test)]
#[path = "../tests/switching/probe.rs"]
mod tests;
