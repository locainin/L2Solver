//! Execute only explicitly scoped native operations

use std::{io::Write, sync::atomic::AtomicBool};

use super::{
    ActiveArgs, ActiveCommand, ArpCommand, DhcpCommand, Dot1xCommand, Error, ListenCommand,
    NdpCommand, capabilities, dhcp_probe, dot1x_probe, interface_capabilities, listen_probe,
    ndp_probe, probe,
};

/// Process outcome that the main application can map to its own exit policy
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveOutcome {
    /// The operation completed within the declared scope
    Completed,
    /// The evidence or bounded observation was incomplete
    Incomplete,
    /// An observed identity differed from the explicitly supplied expectation
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
            let info = l2_active_linux::discover(&options.interface).map_err(Error::Discovery)?;
            let wireless = interface_capabilities::discover(&options.interface, &info)
                .map_err(Error::Discovery)?;
            capabilities::write(&info, &wireless, args.format, output)?;
            Ok(ActiveOutcome::Completed)
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
    }
}
