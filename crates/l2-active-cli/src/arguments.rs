//! Typed arguments shared by the standalone and main application commands

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use l2_active_linux::InterfaceSelector;
use l2_onpath::MacAddress;

/// Standalone parser using the same active-command arguments as `L2Solver`
#[derive(Clone, Debug, Eq, Parser, PartialEq)]
#[command(
    name = "l2solver-active",
    version,
    about = "Bounded active Layer-2 assessments",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Active commands and output selection
    #[command(flatten)]
    pub active: ActiveArgs,
}

/// Active operations suitable for embedding beneath `l2solver active`
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct ActiveArgs {
    /// Select human-readable text or a machine-readable JSON result
    #[arg(long, value_enum, default_value = "text", global = true)]
    pub format: OutputFormat,

    /// Selected bounded operation
    #[command(subcommand)]
    pub command: ActiveCommand,
}

/// Presentation of a completed operation or runtime failure
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable output
    Text,
    /// One structured JSON result
    Json,
}

/// Operations backed by the native active-network implementation
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ActiveCommand {
    /// Inspect a selected interface without transmitting packets
    Capabilities(InterfaceArgs),
    /// Probe an explicit IPv4 neighbor using ARP
    Arp {
        /// Select an implemented ARP operation
        #[command(subcommand)]
        command: ArpCommand,
    },
    /// Discover DHCP offers on the selected interface
    Dhcp {
        /// Select a bounded DHCP operation
        #[command(subcommand)]
        command: DhcpCommand,
    },
    /// Probe an explicit IPv6 neighbor on the selected interface
    Ndp {
        /// Select a bounded NDP operation
        #[command(subcommand)]
        command: NdpCommand,
    },
    /// Observe spanning-tree frames without transmitting
    Stp {
        /// Select a receive-only operation
        #[command(subcommand)]
        command: ListenCommand,
    },
    /// Observe link discovery advertisements without transmitting
    Discovery {
        /// Select a receive-only operation
        #[command(subcommand)]
        command: ListenCommand,
    },
    /// Probe 802.1X on a dedicated interface with explicit opt-in
    Dot1x {
        /// Select a bounded EAPOL operation
        #[command(subcommand)]
        command: Dot1xCommand,
    },
}

/// Interface selection for a read-only capability query
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct InterfaceArgs {
    /// Explicit Linux network-interface name
    #[arg(long, value_name = "INTERFACE", value_parser = interface_selector)]
    pub interface: InterfaceSelector,
}

/// Supported bounded ARP operations
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ArpCommand {
    /// Send one ARP request and correlate observed replies
    Probe(ArpProbeArgs),
}

/// Supported bounded DHCP operations
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum DhcpCommand {
    /// Send one DHCP Discover and collect correlated offers
    Probe(DhcpProbeArgs),
}

/// Supported bounded IPv6 neighbor operations
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum NdpCommand {
    /// Send one neighbor solicitation and collect advertisements
    Probe(NdpProbeArgs),
}

/// Supported receive-only operations
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ListenCommand {
    /// Collect bounded observations on a selected interface
    Observe(ListenArgs),
}

/// Supported bounded 802.1X operations
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum Dot1xCommand {
    /// Send one EAPOL Start and collect scoped EAP Requests
    Probe(Dot1xProbeArgs),
}

/// A dedicated interface, explicit disruption acknowledgement, and limits
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct Dot1xProbeArgs {
    /// Explicit dedicated interface carrying the EAPOL Start
    #[arg(long, value_name = "INTERFACE", value_parser = interface_selector)]
    pub interface: InterfaceSelector,

    /// Acknowledge that EAPOL Start can disrupt an existing supplicant; use a dedicated interface
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    pub allow_eapol_start: bool,

    /// Assert that the selected interface is dedicated to this assessment
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    pub dedicated_interface: bool,

    /// Shared helper selection and finite observation budgets
    #[command(flatten)]
    pub session: SessionArgs,
}

/// A selected interface and finite receive-only limits
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct ListenArgs {
    /// Explicit interface to observe
    #[arg(long, value_name = "INTERFACE", value_parser = interface_selector)]
    pub interface: InterfaceSelector,

    /// Shared helper selection and finite observation budgets
    #[command(flatten)]
    pub session: SessionArgs,
}

/// One explicit IPv6 target and optional selected source
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct NdpProbeArgs {
    /// Explicit interface carrying the solicitation
    #[arg(long, value_name = "INTERFACE", value_parser = interface_selector)]
    pub interface: InterfaceSelector,

    /// One IPv6 neighbor on this interface; global targets require a direct route
    #[arg(long, value_name = "IPV6")]
    pub target: Ipv6Addr,

    /// Select an assigned IPv6 source when needed
    #[arg(long, value_name = "IPV6")]
    pub source_ip: Option<Ipv6Addr>,

    /// Compare observed target MAC addresses with this expected identity
    #[arg(long, value_name = "MAC", value_parser = mac_address)]
    pub expected_mac: Option<MacAddress>,

    /// Shared helper selection and finite observation budgets
    #[command(flatten)]
    pub session: SessionArgs,
}

/// An explicit interface, optional server expectations, and receive limits
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct DhcpProbeArgs {
    /// Explicit interface carrying the discovery request
    #[arg(long, value_name = "INTERFACE", value_parser = interface_selector)]
    pub interface: InterfaceSelector,

    /// Compare offered server identifiers with this allowlist; repeat for multiple IDs
    #[arg(long, value_name = "IPV4", value_parser = ipv4_address)]
    pub expected_server: Vec<Ipv4Addr>,

    /// Shared helper selection and finite observation budgets
    #[command(flatten)]
    pub session: SessionArgs,
}

/// Helper selection and finite receive budgets
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct SessionArgs {
    /// Path to the trusted helper when it is not beside this program
    #[arg(long, value_name = "PATH")]
    pub helper: Option<PathBuf>,

    /// Maximum helper startup and probe time in milliseconds
    #[arg(long, default_value_t = 2_000, value_parser = clap::value_parser!(u64).range(1..=l2_active::MAX_TIMEOUT.as_secs() * 1_000))]
    pub timeout_ms: u64,

    /// Maximum total received frames examined during the probe
    #[arg(long, default_value_t = 2_048, value_parser = clap::value_parser!(u32).range(1..=i64::from(l2_active::MAX_RECEIVED_PACKETS)))]
    pub max_received_packets: u32,

    /// Maximum total received frame bytes examined during the probe
    #[arg(long, default_value_t = 8_388_608, value_parser = clap::value_parser!(u64).range(1..=l2_active::MAX_RECEIVED_BYTES))]
    pub max_received_bytes: u64,
}

/// Explicit scope and finite receive limits for one ARP probe
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct ArpProbeArgs {
    /// Explicit interface carrying the probe
    #[arg(long, value_name = "INTERFACE", value_parser = interface_selector)]
    pub interface: InterfaceSelector,

    /// One target IPv4 address on the selected interface's network
    #[arg(long, value_name = "IPV4", value_parser = ipv4_address)]
    pub target: Ipv4Addr,

    /// Select one IPv4 address assigned to the interface when needed
    #[arg(long, value_name = "IPV4", value_parser = ipv4_address)]
    pub source_ip: Option<Ipv4Addr>,

    /// Compare observed sender MAC addresses with this expected identity
    #[arg(long, value_name = "MAC", value_parser = mac_address)]
    pub expected_mac: Option<MacAddress>,

    /// Shared helper selection and finite observation budgets
    #[command(flatten)]
    pub session: SessionArgs,
}

fn interface_selector(name: &str) -> Result<InterfaceSelector, String> {
    InterfaceSelector::new(name).map_err(|error| error.to_string())
}

fn ipv4_address(value: &str) -> Result<Ipv4Addr, String> {
    let address = value
        .parse::<Ipv4Addr>()
        .map_err(|error| error.to_string())?;
    l2_active::validate_ipv4_target(address).map_err(|error| error.to_string())?;
    Ok(address)
}

fn mac_address(value: &str) -> Result<MacAddress, String> {
    let mut parts = value.split(':');
    let mut bytes = [0_u8; 6];
    for byte in &mut bytes {
        let Some(part) = parts.next() else {
            return Err("MAC address requires six hexadecimal octets".into());
        };
        if part.len() != 2 {
            return Err("MAC address requires two digits per octet".into());
        }
        *byte = u8::from_str_radix(part, 16).map_err(|_| "invalid hexadecimal MAC address")?;
    }
    if parts.next().is_some() {
        return Err("MAC address requires six hexadecimal octets".into());
    }
    MacAddress::new(bytes).map_err(|error| error.to_string())
}
