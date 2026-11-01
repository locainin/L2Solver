//! Open native receive-only helpers for bounded first-hop observation

use std::{
    io::Write,
    num::NonZeroU8,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    ActiveOutcome, Error, HsrpObserveArgs, ObserveArgs, OutputFormat, VrrpObserveArgs,
    preflight::{HelperStage, PreflightStop, write_stopped},
};

#[derive(Clone, Copy)]
enum Kind {
    Vrrp(Option<NonZeroU8>),
    Hsrp(Option<u8>),
}

impl Kind {
    const fn operation(self) -> &'static str {
        match self {
            Self::Vrrp(_) => "vrrp_observe",
            Self::Hsrp(_) => "hsrp_observe",
        }
    }
}

pub fn vrrp(
    options: &VrrpObserveArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    run(
        Kind::Vrrp(options.vrid),
        &options.observe,
        format,
        cancelled,
        output,
    )
}

pub fn hsrp(
    options: &HsrpObserveArgs,
    format: OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    run(
        Kind::Hsrp(options.group),
        &options.observe,
        format,
        cancelled,
        output,
    )
}

fn run(
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
    use super::{
        first_hop_output::{self, Context},
        observer_session::{self, Prepared},
        session_options,
    };

    let Prepared { info, limits, deadline, helper } = match observer_session::prepare(options, cancelled) {
        Ok(prepared) => prepared,
        Err(Error::Discovery(error)) => return stopped(kind, options, format, output,
            super::preflight::discovery_failure(error, cancelled)?, HelperStage::NotStarted),
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
                super::preflight::open_failure(error, cancelled)?,
                HelperStage::Opening,
            );
        }
    };
    let admitted_deadline = link.deadline();
    let result = plan.collect(&mut link, cancelled, admitted_deadline);
    let (report, close_error) = session_options::finish(result, link.close())?;
    let context = Context::new(options, info.vlan(), limits, close_error.as_ref());
    match report {
        Collected::Vrrp(monitor, report) => {
            first_hop_output::write_vrrp(&context, monitor.vrid(), &report, format, output)
        }
        Collected::Hsrp(monitor, report) => {
            first_hop_output::write_hsrp(&context, monitor.group(), &report, format, output)
        }
    }
}

#[cfg(target_os = "linux")]
enum Plan {
    Vrrp(l2_active::first_hop::vrrp::VrrpMonitor),
    Hsrp(l2_active::first_hop::hsrp::HsrpMonitor),
}

#[cfg(target_os = "linux")]
impl Plan {
    const fn new(kind: Kind, limits: l2_active::Limits) -> Self {
        match kind {
            Kind::Vrrp(vrid) => {
                Self::Vrrp(l2_active::first_hop::vrrp::VrrpMonitor::new(vrid, limits))
            }
            Kind::Hsrp(group) => {
                Self::Hsrp(l2_active::first_hop::hsrp::HsrpMonitor::new(group, limits))
            }
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
            Self::Vrrp(monitor) => l2_active_linux::HelperLink::open_vrrp(
                helper,
                &options.interface,
                info,
                monitor,
                deadline,
                cancelled,
            ),
            Self::Hsrp(monitor) => l2_active_linux::HelperLink::open_hsrp(
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
            Self::Vrrp(monitor) => monitor
                .run_until(link, cancelled, deadline)
                .map(|report| Collected::Vrrp(*monitor, report)),
            Self::Hsrp(monitor) => monitor
                .run_until(link, cancelled, deadline)
                .map(|report| Collected::Hsrp(*monitor, report)),
        }
    }
}

#[cfg(target_os = "linux")]
enum Collected {
    Vrrp(
        l2_active::first_hop::vrrp::VrrpMonitor,
        l2_active::first_hop::vrrp::VrrpReport,
    ),
    Hsrp(
        l2_active::first_hop::hsrp::HsrpMonitor,
        l2_active::first_hop::hsrp::HsrpReport,
    ),
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
