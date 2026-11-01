//! Execute only explicitly scoped native operations

use std::{
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
};

use super::{
    ActiveArgs, ActiveCommand, ArpCommand, DhcpCommand, Dot1xCommand, Error, HsrpCommand,
    ListenCommand, MplsCommand, NdpCommand, ObserveCommand, VlanCommand, VrrpCommand, capabilities,
    dhcp_probe, dot1x_probe, first_hop_probe, interface_capabilities, isl_probe, listen_probe,
    mpls_probe, ndp_probe,
    preflight::{self, HelperStage, PreflightStop},
    probe, switching_probe,
};

/// Process outcome that the main application can map to its own exit policy
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveOutcome {
    /// The operation completed within the declared scope
    Completed,
    /// The evidence or bounded observation was incomplete
    Incomplete,
    /// An observed value differed from an explicitly supplied expectation
    Findings,
    /// The operation was cancelled
    Cancelled,
}

/// Execute an active command using an externally controlled cancellation token
///
/// # Errors
/// Returns a typed error for discovery, scope, helper, or output failures
pub fn execute(
    args: &ActiveArgs,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    match &args.command {
        ActiveCommand::Capabilities(options) => {
            query_capabilities(options, args.format, cancelled, output)
        }
        ActiveCommand::Arp {
            command: ArpCommand::Probe(options),
        } => probe::run(options, args.format, cancelled, output),
        ActiveCommand::Dhcp {
            command: DhcpCommand::Probe(options),
        } => dhcp_probe::run(options, args.format, cancelled, output),
        ActiveCommand::Ndp {
            command: NdpCommand::Probe(options),
        } => ndp_probe::run(options, args.format, cancelled, output),
        ActiveCommand::Stp {
            command: ListenCommand::Observe(options),
        } => listen_probe::run(
            listen_probe::Kind::Stp,
            options,
            args.format,
            cancelled,
            output,
        ),
        ActiveCommand::Discovery {
            command: ListenCommand::Observe(options),
        } => listen_probe::run(
            listen_probe::Kind::Discovery,
            options,
            args.format,
            cancelled,
            output,
        ),
        ActiveCommand::Dot1x {
            command: Dot1xCommand::Probe(options),
        } => dot1x_probe::run(options, args.format, cancelled, output),
        ActiveCommand::Vrrp {
            command: VrrpCommand::Observe(options),
        } => first_hop_probe::vrrp(options, args.format, cancelled, output)
            .map_err(Error::codes_only),
        ActiveCommand::Hsrp {
            command: HsrpCommand::Observe(options),
        } => first_hop_probe::hsrp(options, args.format, cancelled, output)
            .map_err(Error::codes_only),
        ActiveCommand::Vlan {
            command: VlanCommand::Assess(options),
        } => super::vlan_assessment::run(options, args.format, cancelled, output)
            .map_err(Error::codes_only),
        ActiveCommand::Dtp {
            command: ObserveCommand::Observe(options),
        } => switching_probe::run(
            switching_probe::Kind::Dtp,
            options,
            args.format,
            cancelled,
            output,
        )
        .map_err(Error::codes_only),
        ActiveCommand::Vtp {
            command: ObserveCommand::Observe(options),
        } => switching_probe::run(
            switching_probe::Kind::Vtp,
            options,
            args.format,
            cancelled,
            output,
        )
        .map_err(Error::codes_only),
        ActiveCommand::Isl {
            command: ObserveCommand::Observe(options),
        } => isl_probe::run(options, args.format, cancelled, output).map_err(Error::codes_only),
        ActiveCommand::Mpls {
            command: MplsCommand::Observe(options),
        } => mpls_probe::run(options, args.format, cancelled, output).map_err(Error::codes_only),
    }
}

fn query_capabilities(
    options: &super::InterfaceArgs,
    format: super::OutputFormat,
    cancelled: &AtomicBool,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    if cancelled.load(Ordering::Acquire) {
        return stopped_capabilities(options, format, output);
    }
    let Some(info) = preflight::cancelled_discovery(
        preflight::discover(&options.interface, cancelled),
        cancelled,
    )?
    else {
        return stopped_capabilities(options, format, output);
    };
    let Some(ethernet) = preflight::cancelled_discovery(
        l2_active_linux::ethernet_capabilities::discover(
            &options.interface,
            info.identity(),
            preflight::discovery_deadline()?,
            cancelled,
        )
        .map_err(Error::Discovery),
        cancelled,
    )?
    else {
        return stopped_capabilities(options, format, output);
    };
    let Some(wireless) = preflight::cancelled_discovery(
        interface_capabilities::discover(
            &options.interface,
            &info,
            preflight::discovery_deadline()?,
            cancelled,
        )
        .map_err(Error::Discovery),
        cancelled,
    )?
    else {
        return stopped_capabilities(options, format, output);
    };
    if cancelled.load(Ordering::Acquire) {
        return stopped_capabilities(options, format, output);
    }
    capabilities::write(&info, &wireless, ethernet, format, output)?;
    Ok(ActiveOutcome::Completed)
}

fn stopped_capabilities(
    options: &super::InterfaceArgs,
    format: super::OutputFormat,
    output: &mut impl Write,
) -> Result<ActiveOutcome, Error> {
    preflight::write_stopped(
        "capabilities",
        &options.interface,
        None,
        format,
        output,
        PreflightStop::Cancelled,
        HelperStage::NotStarted,
    )
}
