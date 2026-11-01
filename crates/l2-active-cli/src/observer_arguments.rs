//! Arguments for bounded receive-only first-hop observation

use std::num::NonZeroU8;

use clap::{Args, Subcommand};
use l2_active_linux::InterfaceSelector;

use super::{SessionArgs, arguments::interface_selector};

/// Shared interface, disclosure, and limits for sensitive receive-only evidence
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct ObserveArgs {
    /// Explicit interface to observe without transmitting
    #[arg(long, value_name = "INTERFACE", value_parser = interface_selector)]
    pub interface: InterfaceSelector,

    /// Include retained candidate frame bytes, which may contain sensitive data
    #[arg(long)]
    pub include_raw: bool,

    /// Shared helper selection and finite observation budgets
    #[command(flatten)]
    pub session: SessionArgs,
}

/// Supported receive-only operations without an additional protocol filter
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ObserveCommand {
    /// Collect bounded observations without transmitting
    Observe(ObserveArgs),
}

/// Supported bounded MPLS operations
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum MplsCommand {
    /// Observe MPLS stacks addressed to the selected interface
    Observe(MplsObserveArgs),
}

/// Scope and optional expected top label for an MPLS observation
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct MplsObserveArgs {
    /// Shared receive-only scope and limits
    #[command(flatten)]
    pub observe: ObserveArgs,

    /// Compare the top label with this operator-supplied 20-bit value
    #[arg(long, value_name = "LABEL", value_parser = clap::value_parser!(u32).range(0..=1_048_575))]
    pub expected_top_label: Option<u32>,
}

/// Supported bounded IPv4 VRRP version 3 operations
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum VrrpCommand {
    /// Observe VRRP version 3 advertisements without transmitting
    Observe(VrrpObserveArgs),
}

/// Scope and disclosure for an IPv4 VRRP version 3 observation
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct VrrpObserveArgs {
    /// Shared receive-only scope and limits
    #[command(flatten)]
    pub observe: ObserveArgs,

    /// Observe only this nonzero virtual router identifier
    #[arg(long, value_name = "VRID")]
    pub vrid: Option<NonZeroU8>,
}

/// Supported bounded IPv4 HSRP version 1 operations
#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum HsrpCommand {
    /// Observe HSRP version 1 messages without transmitting
    Observe(HsrpObserveArgs),
}

/// Scope and disclosure for an IPv4 HSRP version 1 observation
#[derive(Clone, Debug, Eq, Args, PartialEq)]
pub struct HsrpObserveArgs {
    /// Shared receive-only scope and limits
    #[command(flatten)]
    pub observe: ObserveArgs,

    /// Observe only this HSRP group number
    #[arg(long, value_name = "GROUP")]
    pub group: Option<u8>,
}
