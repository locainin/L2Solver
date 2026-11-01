//! Arguments for an explicitly scoped VLAN canary assessment

use std::net::Ipv4Addr;

use clap::{Args, Subcommand};
use l2_active_linux::InterfaceSelector;
use l2_onpath::MacAddress;

use super::{
    SessionArgs,
    arguments::{interface_selector, ipv4_address, mac_address},
};

/// Supported bounded VLAN assessments
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum VlanCommand {
    /// Compare an ARP canary across control and test interfaces
    Assess(VlanAssessmentArgs),
}

/// Two explicit interfaces and an operator-supplied canary identity
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct VlanAssessmentArgs {
    /// Test interface on the segment being assessed
    #[arg(long, value_name = "INTERFACE", value_parser = interface_selector)]
    pub interface: InterfaceSelector,

    /// Control interface that can reach the same canary
    #[arg(long, value_name = "INTERFACE", value_parser = interface_selector)]
    pub control_interface: InterfaceSelector,

    /// One canary IPv4 address that is on-link for both interfaces
    #[arg(long, value_name = "IPV4", value_parser = ipv4_address)]
    pub target: Ipv4Addr,

    /// Operator-supplied expected canary MAC address
    #[arg(long, value_name = "MAC", value_parser = mac_address)]
    pub expected_mac: MacAddress,

    /// Select an assigned test-interface source address when needed
    #[arg(long, value_name = "IPV4", value_parser = ipv4_address)]
    pub source_ip: Option<Ipv4Addr>,

    /// Select an assigned control-interface source address when needed
    #[arg(long, value_name = "IPV4", value_parser = ipv4_address)]
    pub control_source_ip: Option<Ipv4Addr>,

    /// Include retained ARP reply frame bytes, which may contain sensitive padding
    #[arg(long)]
    pub include_raw: bool,

    /// One deadline and per-interface cumulative receive budgets for all three phases
    #[command(flatten)]
    pub session: SessionArgs,
}
